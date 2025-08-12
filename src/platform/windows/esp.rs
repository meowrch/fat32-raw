//! ESP (EFI System Partition) detection and access on Windows

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::ptr;

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{FindFirstVolumeW, FindNextVolumeW, FindVolumeClose};
use windows_sys::Win32::System::Ioctl::{
    DISK_EXTENT, DRIVE_LAYOUT_INFORMATION_EX, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, PARTITION_STYLE_GPT,
    VOLUME_DISK_EXTENTS,
};
use windows_sys::Win32::System::IO::DeviceIoControl;

use super::volume::{is_fat_fs, open_handle};
use crate::error::Result;

// IOCTL codes
const IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS: u32 = 0x00560000;
const IOCTL_DISK_GET_PARTITION_INFO_EX: u32 = 0x00070048;

/// ESP GUID as defined by UEFI specification
fn esp_guid() -> GUID {
    GUID {
        data1: 0xc12a7328,
        data2: 0xf81f,
        data3: 0x11d2,
        data4: [0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b],
    }
}

/// Check if a GUID matches the ESP GUID
fn is_esp_guid(guid: &GUID) -> bool {
    let esp = esp_guid();
    guid.data1 == esp.data1
        && guid.data2 == esp.data2
        && guid.data3 == esp.data3
        && guid.data4 == esp.data4
}

/// Partition information for getting partition number
#[repr(C)]
#[allow(non_snake_case)]
struct PARTITION_INFORMATION_EX {
    PartitionStyle: u32,
    StartingOffset: i64,
    PartitionLength: i64,
    PartitionNumber: u32,
    RewritePartition: u32,
    // Other fields omitted for simplicity
}

/// Get partition number for a volume handle
unsafe fn get_partition_number(h_vol: *mut std::ffi::c_void) -> u32 {
    let mut part_info: PARTITION_INFORMATION_EX = std::mem::zeroed();
    let mut bytes: u32 = 0;

    if DeviceIoControl(
        h_vol as isize,
        IOCTL_DISK_GET_PARTITION_INFO_EX,
        ptr::null_mut(),
        0,
        &mut part_info as *mut _ as *mut std::ffi::c_void,
        std::mem::size_of::<PARTITION_INFORMATION_EX>() as u32,
        &mut bytes,
        ptr::null_mut(),
    ) != 0
    {
        part_info.PartitionNumber
    } else {
        0 // Fallback
    }
}

/// Find ESP by scanning physical disks directly
unsafe fn find_esp_by_scanning_disks() -> Option<PathBuf> {
    // Scan physical drives 0..15 to find GPT ESP partition
    for disk_num in 0..16 {
        let phys_path_str = format!("\\\\.\\PhysicalDrive{}", disk_num);
        let phys_path: Vec<u16> = OsStr::new(&phys_path_str)
            .encode_wide()
            .chain(Some(0))
            .collect();

        if let Some(h_phys) = open_handle(&phys_path) {
            let mut layout_buf = vec![0u8; 8192];
            let mut bytes: u32 = 0;

            if DeviceIoControl(
                h_phys,
                IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
                ptr::null_mut(),
                0,
                layout_buf.as_mut_ptr().cast(),
                layout_buf.len() as u32,
                &mut bytes,
                ptr::null_mut(),
            ) != 0
            {
                let layout = &*(layout_buf.as_ptr() as *const DRIVE_LAYOUT_INFORMATION_EX);

                if layout.PartitionStyle == PARTITION_STYLE_GPT as u32 {
                    let part_entry_ptr = layout.PartitionEntry.as_ptr();

                    for i in 0..layout.PartitionCount {
                        let part_info = &*part_entry_ptr.add(i as usize);

                        if part_info.PartitionStyle == PARTITION_STYLE_GPT
                            && is_esp_guid(&part_info.Anonymous.Gpt.PartitionType)
                        {
                            CloseHandle(h_phys);

                            // Try to find corresponding volume
                            if let Some(volume_path) =
                                find_volume_for_partition(disk_num, part_info.PartitionNumber)
                            {
                                return Some(volume_path);
                            }

                            // Fallback: direct harddisk partition path
                            return Some(PathBuf::from(format!(
                                "\\\\.\\Harddisk{}Partition{}",
                                disk_num, part_info.PartitionNumber
                            )));
                        }
                    }
                }
            }
            CloseHandle(h_phys);
        }
    }
    None
}

/// Find Volume GUID path for a specific partition
unsafe fn find_volume_for_partition(disk_num: u32, partition_num: u32) -> Option<PathBuf> {
    let mut name_buf = vec![0u16; 128];
    let h_find = FindFirstVolumeW(name_buf.as_mut_ptr(), name_buf.len() as u32);

    if h_find == INVALID_HANDLE_VALUE {
        return None;
    }

    loop {
        let len = name_buf.iter().position(|&c| c == 0).unwrap_or(0);
        if len > 0 {
            let vol_path_slice = &name_buf[..len + 1];
            let mut vol_no_slash = vol_path_slice.to_vec();
            vol_no_slash.pop(); // Remove trailing null

            if vol_no_slash.last() == Some(&('\\' as u16)) {
                vol_no_slash.pop(); // Remove trailing slash
            }

            if let Some(h_vol) = open_handle(&vol_no_slash) {
                let mut ext_buf: Vec<u8> = vec![
                    0;
                    std::mem::size_of::<VOLUME_DISK_EXTENTS>()
                        + 8 * std::mem::size_of::<DISK_EXTENT>()
                ];
                let mut bytes: u32 = 0;

                if DeviceIoControl(
                    h_vol,
                    IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                    ptr::null(),
                    0,
                    ext_buf.as_mut_ptr().cast(),
                    ext_buf.len() as u32,
                    &mut bytes,
                    ptr::null_mut(),
                ) != 0
                {
                    let extents = &*(ext_buf.as_ptr() as *const VOLUME_DISK_EXTENTS);
                    if extents.NumberOfDiskExtents > 0 {
                        let first_extent = extents.Extents[0];

                        // Get partition number through additional IOCTL
                        let part_num = get_partition_number(h_vol as *mut std::ffi::c_void);

                        if first_extent.DiskNumber == disk_num && part_num == partition_num {
                            CloseHandle(h_vol);
                            FindVolumeClose(h_find);
                            let s = String::from_utf16_lossy(&name_buf[..len]);
                            return Some(PathBuf::from(s));
                        }
                    }
                }
                CloseHandle(h_vol);
            }
        }

        if FindNextVolumeW(h_find, name_buf.as_mut_ptr(), name_buf.len() as u32) == 0 {
            break;
        }
    }

    FindVolumeClose(h_find);
    None
}

/// Find ESP volume path by scanning volumes
unsafe fn find_esp_volume_path_by_volumes() -> Option<PathBuf> {
    let mut name_buf = vec![0u16; 128];
    let h_find = FindFirstVolumeW(name_buf.as_mut_ptr(), name_buf.len() as u32);

    if h_find == INVALID_HANDLE_VALUE {
        return None;
    }

    loop {
        let len = name_buf.iter().position(|&c| c == 0).unwrap_or(0);
        if len > 0 {
            // Got a volume GUID path like \\?\Volume{...}\
            let vol_path_slice = &name_buf[..len + 1];

            // Check if it's a FAT filesystem, common for ESPs
            if is_fat_fs(vol_path_slice) {
                // To be sure, check partition type via IOCTL
                let mut vol_no_slash = vol_path_slice.to_vec();
                vol_no_slash.pop(); // Remove trailing null
                if vol_no_slash.last() == Some(&('\\' as u16)) {
                    vol_no_slash.pop(); // Remove trailing slash for CreateFileW
                }

                if let Some(h_vol) = open_handle(&vol_no_slash) {
                    let mut ext_buf: Vec<u8> = vec![
                        0;
                        std::mem::size_of::<VOLUME_DISK_EXTENTS>()
                            + 8 * std::mem::size_of::<DISK_EXTENT>()
                    ];
                    let mut bytes: u32 = 0;

                    if DeviceIoControl(
                        h_vol,
                        IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                        ptr::null(),
                        0,
                        ext_buf.as_mut_ptr().cast(),
                        ext_buf.len() as u32,
                        &mut bytes,
                        ptr::null_mut(),
                    ) != 0
                    {
                        let extents = &*(ext_buf.as_ptr() as *const VOLUME_DISK_EXTENTS);
                        if extents.NumberOfDiskExtents > 0 {
                            let first_extent = extents.Extents[0];
                            let phys_path_str =
                                format!("\\\\.\\PhysicalDrive{}", first_extent.DiskNumber);
                            let phys_path: Vec<u16> = OsStr::new(&phys_path_str)
                                .encode_wide()
                                .chain(Some(0))
                                .collect();

                            if let Some(h_phys) = open_handle(&phys_path) {
                                let mut layout_buf = vec![0u8; 4096];
                                if DeviceIoControl(
                                    h_phys,
                                    IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
                                    ptr::null_mut(),
                                    0,
                                    layout_buf.as_mut_ptr().cast(),
                                    layout_buf.len() as u32,
                                    &mut bytes,
                                    ptr::null_mut(),
                                ) != 0
                                {
                                    let layout = &*(layout_buf.as_ptr()
                                        as *const DRIVE_LAYOUT_INFORMATION_EX);
                                    if layout.PartitionStyle == PARTITION_STYLE_GPT as u32 {
                                        let part_entry_ptr = layout.PartitionEntry.as_ptr();
                                        for i in 0..layout.PartitionCount {
                                            let part_info = &*part_entry_ptr.add(i as usize);
                                            if part_info.PartitionStyle == PARTITION_STYLE_GPT
                                                && is_esp_guid(
                                                    &part_info.Anonymous.Gpt.PartitionType,
                                                )
                                            {
                                                // Found it
                                                CloseHandle(h_phys);
                                                CloseHandle(h_vol);
                                                FindVolumeClose(h_find);
                                                let s = String::from_utf16_lossy(&name_buf[..len]);
                                                return Some(PathBuf::from(s));
                                            }
                                        }
                                    }
                                }
                                CloseHandle(h_phys);
                            }
                        }
                    }
                    CloseHandle(h_vol);
                }
            }
        }

        if FindNextVolumeW(h_find, name_buf.as_mut_ptr(), name_buf.len() as u32) == 0 {
            break;
        }
    }

    FindVolumeClose(h_find);
    None
}

/// Find ESP volume path on Windows
pub fn find_esp_volume_path() -> Option<PathBuf> {
    unsafe {
        // First try the new method of direct physical disk scanning
        if let Some(path) = find_esp_by_scanning_disks() {
            return Some(path);
        }

        // Fallback to scanning volumes
        find_esp_volume_path_by_volumes()
    }
}

/// Find ESP device for raw access
pub fn find_esp_device() -> Result<Option<(String, u64)>> {
    unsafe {
        // Scan physical drives to find ESP
        for disk_num in 0..16 {
            let phys_path_str = format!("\\\\.\\PhysicalDrive{}", disk_num);
            let phys_path: Vec<u16> = OsStr::new(&phys_path_str)
                .encode_wide()
                .chain(Some(0))
                .collect();

            if let Some(h_phys) = open_handle(&phys_path) {
                let mut layout_buf = vec![0u8; 8192];
                let mut bytes: u32 = 0;

                if DeviceIoControl(
                    h_phys,
                    IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
                    ptr::null_mut(),
                    0,
                    layout_buf.as_mut_ptr().cast(),
                    layout_buf.len() as u32,
                    &mut bytes,
                    ptr::null_mut(),
                ) != 0
                {
                    let layout = &*(layout_buf.as_ptr() as *const DRIVE_LAYOUT_INFORMATION_EX);

                    if layout.PartitionStyle == PARTITION_STYLE_GPT as u32 {
                        let part_entry_ptr = layout.PartitionEntry.as_ptr();

                        for i in 0..layout.PartitionCount {
                            let part_info = &*part_entry_ptr.add(i as usize);

                            if part_info.PartitionStyle == PARTITION_STYLE_GPT
                                && is_esp_guid(&part_info.Anonymous.Gpt.PartitionType)
                            {
                                let lba = (part_info.StartingOffset / 512) as u64;
                                log::info!("Found ESP on PhysicalDrive{} at LBA {}", disk_num, lba);
                                CloseHandle(h_phys);
                                return Ok(Some((phys_path_str, lba)));
                            }
                        }
                    }
                }
                CloseHandle(h_phys);
            }
        }
    }

    log::warn!("ESP device not found after scanning all physical drives");
    Ok(None)
}
