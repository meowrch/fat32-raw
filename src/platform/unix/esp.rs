//! ESP (EFI System Partition) detection on Unix systems

use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use crate::error::Result;

/// Find ESP device on Unix/Linux systems
pub fn find_esp_device() -> Result<Option<(String, u64)>> {
    // Try to find ESP partition using various methods

    // Method 1: Check /boot/efi mount point
    if let Ok(contents) = std::fs::read_to_string("/proc/mounts") {
        for line in contents.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 && (parts[1] == "/boot/efi" || parts[1] == "/efi") {
                let device = parts[0];
                log::info!("Found ESP mounted at {} on device {}", parts[1], device);

                // Try to get partition offset
                if let Some(lba) = get_partition_offset(device) {
                    return Ok(Some((device.to_string(), lba)));
                }
            }
        }
    }

    // Method 2: Check for GPT partitions with ESP type GUID
    // This requires parsing GPT headers, which is complex
    // For now, we'll try common device paths
    for disk_num in 0..4 {
        for part_num in 1..5 {
            let device = format!("/dev/nvme{}n{}p{}", disk_num, 1, part_num);
            if is_esp_partition(&device) {
                if let Some(lba) = get_partition_offset(&device) {
                    log::info!("Found ESP at {} with LBA {}", device, lba);
                    return Ok(Some((device, lba)));
                }
            }

            let device = format!("/dev/sda{}", part_num);
            if is_esp_partition(&device) {
                if let Some(lba) = get_partition_offset(&device) {
                    log::info!("Found ESP at {} with LBA {}", device, lba);
                    return Ok(Some((device, lba)));
                }
            }
        }
    }

    log::warn!("ESP device not found on Unix system");
    Ok(None)
}

/// Check if a device is an ESP partition by checking filesystem type
fn is_esp_partition(device: &str) -> bool {
    // Try to read the partition and check for FAT32 signature
    if let Ok(mut file) = File::open(device) {
        let mut buffer = [0u8; 512];
        if file.read_exact(&mut buffer).is_ok() {
            // Check for FAT32 signature
            if buffer[0x52] == b'F' && buffer[0x53] == b'A' && buffer[0x54] == b'T' {
                return true;
            }
            // Check for FAT16 signature
            if buffer[0x36] == b'F' && buffer[0x37] == b'A' && buffer[0x38] == b'T' {
                return true;
            }
        }
    }
    false
}

/// Get partition offset in LBA for a device
fn get_partition_offset(_device: &str) -> Option<u64> {
    // When we open a partition device directly (e.g., /dev/sda1, /dev/nvme0n1p1),
    // the kernel already handles the offset, so we use offset 0.
    // 
    // LBA offset would only be needed if we were accessing the raw disk device
    // and needed to skip to the partition start ourselves.
    
    // For partition devices, the offset is always 0
    Some(0)
}

/// Find ESP mount point on Unix systems
pub fn find_esp_mount_point() -> Option<PathBuf> {
    // Check common ESP mount points
    let mount_points = ["/boot/efi", "/efi", "/boot/EFI"];

    for mount_point in &mount_points {
        let path = PathBuf::from(mount_point);
        if path.exists() && path.is_dir() {
            // Check if it's actually mounted
            if let Ok(contents) = std::fs::read_to_string("/proc/mounts") {
                for line in contents.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 && parts[1] == *mount_point {
                        log::info!("Found ESP mount point at {}", mount_point);
                        return Some(path);
                    }
                }
            }
        }
    }

    None
}
