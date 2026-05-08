//! Integration tests for the "explicit device" fix in `Fat32Volume::open_esp`.
//!
//! These tests create a synthetic, minimal FAT32 image in a temporary file
//! (no `mkfs.vfat` and no real ESP required) and exercise the public API the
//! way BlueVein does:
//!
//!   * pass an explicit path to `Fat32Volume::open_esp(Some(path))`
//!   * verify `is_explicit_device()` reports the flag correctly
//!   * write a file and read it back (round-trip)
//!   * verify that the bytes actually land *inside the given image file*
//!     (regression: before the fix, on Windows with multiple ESPs, the bytes
//!     were silently routed to whichever ESP `find_esp_volume_path()`
//!     auto-detected first \u2014 typically a different disk).
//!
//! These run on every platform where the crate compiles, including Linux \u2014
//! which is exactly what we want, since the bug was platform-specific but the
//! fix is structural (an `explicit_device` flag plus path normalization).

use fat32_raw::{normalize_explicit_device_path, Fat32Volume};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

// ---- BPB shape of the synthetic image ---------------------------------------
// Chosen to be the smallest layout the validator in `Fat32Volume::open_esp`
// will accept while still leaving enough free clusters to write a few small
// files. The image is ~80 KB.
const BYTES_PER_SECTOR: u16 = 512;
const SECTORS_PER_CLUSTER: u8 = 1;
const RESERVED_SECTORS: u16 = 32;
const NUM_FATS: u8 = 1;
const SECTORS_PER_FAT: u32 = 1; // 1 sector = 128 FAT32 entries
const ROOT_CLUSTER: u32 = 2;
// 128 FAT entries minus reserved 0 and 1 minus the in-use root cluster (#2)
// leaves 125 free clusters (#3..#127). The data area must physically cover
// every cluster the FAT can address, so we provision 126 clusters.
const DATA_CLUSTERS: u32 = 126;

/// Write a synthetic, minimal FAT32 image at `path`. The image:
///   - has a valid BPB and the 0xAA55 boot signature,
///   - reserves clusters 0 and 1 per the FAT32 spec,
///   - marks the root directory cluster (#2) as end-of-chain,
///   - has an empty root directory (cluster filled with zeros, which means
///     "no entries; stop scanning at the first slot" per the FAT spec).
fn create_minimal_fat32_image(path: &Path) -> std::io::Result<()> {
    let total_sectors = RESERVED_SECTORS as u64
        + (SECTORS_PER_FAT as u64) * (NUM_FATS as u64)
        + (DATA_CLUSTERS as u64) * (SECTORS_PER_CLUSTER as u64);
    let total_size = (total_sectors as usize) * (BYTES_PER_SECTOR as usize);
    let mut data = vec![0u8; total_size];

    // ---- BPB (sector 0) -----------------------------------------------------
    // jmp short + nop
    data[0] = 0xEB;
    data[1] = 0x58;
    data[2] = 0x90;
    // OEM name (8 bytes)
    data[3..11].copy_from_slice(b"MSWIN4.1");
    // bytes_per_sector
    data[0x0B..0x0D].copy_from_slice(&BYTES_PER_SECTOR.to_le_bytes());
    // sectors_per_cluster
    data[0x0D] = SECTORS_PER_CLUSTER;
    // reserved_sectors
    data[0x0E..0x10].copy_from_slice(&RESERVED_SECTORS.to_le_bytes());
    // num_fats
    data[0x10] = NUM_FATS;
    // 0x11..0x13 max_root_entries: 0 for FAT32 (already zero)
    // 0x13..0x15 total_sectors_16: 0 for FAT32 (already zero)
    // media descriptor
    data[0x15] = 0xF8;
    // 0x16..0x18 sectors_per_fat_16: 0 for FAT32 (already zero)
    // sectors_per_track / num_heads (cosmetic)
    data[0x18..0x1A].copy_from_slice(&32u16.to_le_bytes());
    data[0x1A..0x1C].copy_from_slice(&64u16.to_le_bytes());
    // hidden_sectors: 0 (already zero)
    // total_sectors_32
    data[0x20..0x24].copy_from_slice(&(total_sectors as u32).to_le_bytes());
    // sectors_per_fat_32
    data[0x24..0x28].copy_from_slice(&SECTORS_PER_FAT.to_le_bytes());
    // ext_flags / fs_version: 0
    // root_cluster
    data[0x2C..0x30].copy_from_slice(&ROOT_CLUSTER.to_le_bytes());
    // fs_info_sector / backup_boot_sector (cosmetic)
    data[0x30..0x32].copy_from_slice(&1u16.to_le_bytes());
    data[0x32..0x34].copy_from_slice(&6u16.to_le_bytes());
    // drive number / boot signature
    data[0x40] = 0x80;
    data[0x42] = 0x29;
    // volume serial (random-ish constant is fine)
    data[0x43..0x47].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    // volume label (11 bytes)
    data[0x47..0x52].copy_from_slice(b"BLUEVEINTST");
    // fs_type (8 bytes)
    data[0x52..0x5A].copy_from_slice(b"FAT32   ");
    // boot signature
    data[0x1FE] = 0x55;
    data[0x1FF] = 0xAA;

    // ---- FAT[0] -------------------------------------------------------------
    // entry[0] = 0x0FFFFFF8 (media descriptor in low byte)
    // entry[1] = 0x0FFFFFFF (reserved end-of-chain)
    // entry[2] = 0x0FFFFFFF (root cluster: end-of-chain, single-cluster root)
    // entry[3..] = 0 (free)
    let fat_offset = (RESERVED_SECTORS as usize) * (BYTES_PER_SECTOR as usize);
    data[fat_offset..fat_offset + 4].copy_from_slice(&0x0FFF_FFF8u32.to_le_bytes());
    data[fat_offset + 4..fat_offset + 8].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());
    data[fat_offset + 8..fat_offset + 12].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());

    // Root cluster (#2) data is already zero, which means "empty directory".

    let mut f = fs::File::create(path)?;
    f.write_all(&data)?;
    f.sync_all()?;
    Ok(())
}

/// Build a unique-per-process tempfile path so parallel `cargo test` runs do
/// not stomp on each other.
fn unique_image_path(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("fat32-raw-test-{}-{}.img", std::process::id(), tag));
    p
}

/// Tiny RAII helper so a failing assertion does not leave the image lying
/// around in `/tmp`.
struct ImageGuard {
    path: PathBuf,
}

impl ImageGuard {
    fn new(tag: &str) -> Self {
        let path = unique_image_path(tag);
        // Pre-clean in case a previous run crashed mid-test.
        let _ = fs::remove_file(&path);
        create_minimal_fat32_image(&path).expect("create minimal FAT32 image");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn path_str(&self) -> &str {
        self.path.to_str().expect("non-UTF8 temp path")
    }
}

impl Drop for ImageGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

// =============================================================================
// Tests
// =============================================================================

/// `open_esp(Some(image))` must succeed and report `is_explicit_device() == true`.
///
/// This is the single most important behavioural guarantee of the fix: the
/// rest of the crate's helpers branch on this flag.
#[test]
fn open_esp_with_explicit_image_sets_explicit_device_flag() {
    let img = ImageGuard::new("flag");
    let mut volume = Fat32Volume::open_esp(Some(img.path_str()))
        .expect("open_esp must succeed on a valid image")
        .expect("open_esp must yield Some(volume) for an explicit path");

    assert!(
        volume.is_explicit_device(),
        "explicit_device flag MUST be set after open_esp(Some(path))"
    );

    // Sanity: the freshly-formatted image has an empty root directory.
    let entries = volume.list_root().expect("list_root");
    assert!(
        entries.is_empty(),
        "fresh image must have an empty root directory, got: {:?}",
        entries.iter().map(|e| e.name.clone()).collect::<Vec<_>>()
    );
}

/// Round-trip: write a file via the public API, read it back, contents match.
///
/// Exercises the raw write path (`#[cfg(not(windows))]` branch) on Linux. On
/// Windows the same call goes through the `if !self.explicit_device` guard
/// and lands on the same raw path, which is exactly what we want.
#[test]
fn write_then_read_roundtrip_on_explicit_image() {
    let img = ImageGuard::new("roundtrip");
    let mut volume = Fat32Volume::open_esp(Some(img.path_str()))
        .expect("open_esp")
        .expect("Some(volume)");
    assert!(volume.is_explicit_device());

    let payload = br#"{"hello":"world","answer":42}"#.to_vec();
    let wrote = volume
        .write_file("config.json", &payload)
        .expect("write_file");
    assert!(wrote, "write_file must report success");

    let read_back = volume
        .read_file("config.json")
        .expect("read_file")
        .expect("file must be present after write");
    assert_eq!(read_back, payload, "round-trip content mismatch");
}

/// **Regression test for the multi-ESP routing bug.**
///
/// Confirms that bytes written via a `Fat32Volume` opened with an explicit
/// image path end up *inside that image file* and nowhere else. Before the
/// fix, on Windows with two ESPs, the Windows API short-circuit in
/// `write_file_with_path` would call `find_esp_volume_path()` which returned
/// the *first* ESP found (typically on disk 0), so the bytes silently went
/// to a different volume than the caller asked for.
///
/// On Linux the short-circuit was never used, but checking that the marker
/// is physically present in the target file still pins down the structural
/// invariant.
#[test]
fn write_targets_explicit_image_and_not_a_different_volume() {
    let img = ImageGuard::new("targeting");

    // Pick a marker that cannot occur in a freshly-formatted blank image
    // (which is mostly zeros plus a small BPB header).
    let marker: &[u8] = b"BLUEVEIN_REGRESSION_MARKER_0xC0FFEE_DEADBEEF";

    // Sanity: marker must NOT be present in the freshly-created image.
    {
        let pristine = fs::read(img.path()).expect("read pristine image");
        assert!(
            !contains_subslice(&pristine, marker),
            "marker is unexpectedly present in pristine image -- pick another"
        );
    }

    // Open via explicit path and write the marker.
    {
        let mut volume = Fat32Volume::open_esp(Some(img.path_str()))
            .expect("open_esp")
            .expect("Some(volume)");
        assert!(volume.is_explicit_device());

        volume.write_file("marker.bin", marker).expect("write_file");

        // Drop closes the underlying file handle and flushes pending data.
    }

    // Marker must now appear inside the target image file.
    let written = fs::read(img.path()).expect("read written image");
    assert!(
        contains_subslice(&written, marker),
        "marker not found inside the explicit image -- \
         the write was routed somewhere else (regression)"
    );
}

/// Directory creation should also use the raw FAT path on an explicit image,
/// not the auto-detect Windows API.
#[test]
fn create_directory_works_on_explicit_image() {
    let img = ImageGuard::new("mkdir");
    let mut volume = Fat32Volume::open_esp(Some(img.path_str()))
        .expect("open_esp")
        .expect("Some(volume)");
    assert!(volume.is_explicit_device());

    let ok = volume
        .create_directory_path("EFI/BOOT")
        .expect("create_directory_path");
    assert!(ok, "create_directory_path must succeed");

    // Top-level "EFI" must now be visible from the root.
    let entries = volume.list_root().expect("list_root");
    let has_efi = entries
        .iter()
        .any(|e| e.is_directory && e.name.trim().eq_ignore_ascii_case("EFI"));
    assert!(
        has_efi,
        "EFI directory should be visible at root, got: {:?}",
        entries
            .iter()
            .map(|e| (&e.name, e.is_directory))
            .collect::<Vec<_>>()
    );
}

/// Two volumes opened against two different image files must remain isolated:
/// writing to image A must not change image B in any way. This catches a
/// future regression where some shared global state (e.g. cached ESP path)
/// would leak across instances.
#[test]
fn two_explicit_volumes_are_independent() {
    let img_a = ImageGuard::new("isolated-a");
    let img_b = ImageGuard::new("isolated-b");

    let snapshot_b_before = fs::read(img_b.path()).expect("snapshot b");

    {
        let mut vol_a = Fat32Volume::open_esp(Some(img_a.path_str()))
            .expect("open A")
            .expect("Some(A)");
        vol_a
            .write_file("only-in-a.txt", b"this should never reach image B")
            .expect("write to A");
    }

    let snapshot_b_after = fs::read(img_b.path()).expect("snapshot b after");
    assert_eq!(
        snapshot_b_before, snapshot_b_after,
        "image B was modified while writing to image A -- volumes are not isolated"
    );

    // And A must contain the marker, so we know the write actually happened.
    let bytes_a = fs::read(img_a.path()).expect("read A");
    assert!(
        contains_subslice(&bytes_a, b"this should never reach image B"),
        "marker missing from A -- write seemingly lost"
    );
}

/// `normalize_explicit_device_path` is publicly re-exported and callable from
/// downstream crates. This is mostly a smoke check that the re-export does
/// not silently disappear in a future refactor.
#[test]
fn normalize_path_is_publicly_re_exported() {
    assert_eq!(normalize_explicit_device_path("/dev/sda1"), "/dev/sda1");
    assert_eq!(normalize_explicit_device_path(""), "");
}

// =============================================================================
// Helpers
// =============================================================================

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}
