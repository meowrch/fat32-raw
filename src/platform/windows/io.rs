//! Windows I/O operations with OS Error 5 bypass strategies

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use uuid::Uuid;

use super::esp::find_esp_volume_path;
use super::privileges::try_enable_esp_privileges;
use super::volume::{
    dismount_locked_volume, guid_volume_root_from_drive_root, try_lock_volume, unlock_and_close,
};
use crate::error::{Fat32Error, Result};

/// Write file with atomic operation (using temp file and rename)
fn write_file_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    // Create parent directories if needed
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    // Create temp file with unique name
    let tmp = path.with_file_name(format!(".tmp-{}.tmp", Uuid::new_v4()));

    // Try multiple times in case of transient errors
    let mut last_err: Option<std::io::Error> = None;
    for _ in 0..5 {
        match (|| -> std::io::Result<()> {
            let mut f = File::create(&tmp)?;
            f.write_all(data)?;
            f.flush()?;
            fs::rename(&tmp, path)?;
            Ok(())
        })() {
            Ok(()) => return Ok(()),
            Err(e) => {
                last_err = Some(e);
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        }
    }

    Err(last_err.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::Other, "write retry loop failed")
    }))
}

/// Get ESP root and relative path from absolute path
fn get_esp_root_and_relative_path(path: &Path) -> Option<(PathBuf, PathBuf)> {
    // If the path already looks like an ESP volume path, use it directly
    let path_str = path.to_string_lossy();

    // Check if it's already a volume path (\\?\Volume{...}\...)
    if path_str.starts_with("\\\\?\\Volume{") {
        // Extract the volume part and the relative part
        if let Some(end_idx) = path_str.find("}\\").map(|i| i + 2) {
            let volume = PathBuf::from(&path_str[..end_idx]);
            let relative = PathBuf::from(&path_str[end_idx..]);
            return Some((volume, relative));
        }
    }

    // Otherwise try to find ESP volume path
    if let Some(esp_root) = find_esp_volume_path() {
        // Try to extract relative path
        if path.is_absolute() {
            // If it's an absolute path like C:\test_dir\file.txt,
            // convert to relative path test_dir\file.txt
            let components: Vec<_> = path.components().collect();
            if components.len() > 1 {
                let relative = PathBuf::from_iter(components[1..].iter());
                return Some((esp_root, relative));
            }
        } else {
            // It's already a relative path
            return Some((esp_root, path.to_path_buf()));
        }
    }

    None
}

/// Write file to ESP with multiple strategies to bypass OS Error 5
pub fn write_file_to_esp(rel_path: &Path, data: &[u8]) -> Result<()> {
    let root = find_esp_volume_path().ok_or_else(|| Fat32Error::EspNotFound)?;
    let dst = root.join(rel_path);

    let mut tried_strategies = Vec::new();

    // Enable privileges first
    try_enable_esp_privileges();

    // Strategy 1: Try direct write
    tried_strategies.push("direct write".to_string());
    if write_file_atomic(&dst, data).is_ok() {
        // Try to ensure data is flushed to disk for raw reader visibility
        if let Ok(f) = File::open(&dst) {
            let _ = f.sync_all();
        }
        log::info!("Wrote {} bytes to {} (plain)", data.len(), dst.display());
        return Ok(());
    }

    // Strategy 2: Try with volume lock/unlock
    tried_strategies.push("volume lock/unlock".to_string());
    unsafe {
        if let Some(h) = try_lock_volume(&root) {
            let _ = dismount_locked_volume(h);
            unlock_and_close(h);
            std::thread::sleep(std::time::Duration::from_millis(800));
        }
    }

    if write_file_atomic(&dst, data).is_ok() {
        if let Ok(f) = File::open(&dst) {
            let _ = f.sync_all();
        }
        log::info!(
            "Wrote {} bytes to {} (after remount)",
            data.len(),
            dst.display()
        );
        return Ok(());
    }

    // Strategy 3: Try GUID path
    tried_strategies.push("GUID volume path".to_string());
    if let Some(guid_root) = guid_volume_root_from_drive_root(&root) {
        let alt_dst = guid_root.join(rel_path);
        if write_file_atomic(&alt_dst, data).is_ok() {
            if let Ok(f) = File::open(&alt_dst) {
                let _ = f.sync_all();
            }
            log::info!(
                "Wrote {} bytes to {} (GUID path)",
                data.len(),
                alt_dst.display()
            );
            return Ok(());
        }
    }

    Err(Fat32Error::access_denied(
        dst.display().to_string(),
        tried_strategies,
    ))
}

/// Create directory on ESP with multiple strategies
pub fn create_directory_on_esp(rel_path: &Path) -> Result<()> {
    let root = find_esp_volume_path().ok_or_else(|| Fat32Error::EspNotFound)?;
    let dst = root.join(rel_path);

    let mut tried_strategies = Vec::new();

    // Enable privileges first
    try_enable_esp_privileges();

    // Strategy 1: Try simple directory creation
    tried_strategies.push("direct creation".to_string());
    if fs::create_dir_all(&dst).is_ok() {
        log::info!("Created directory {} (plain)", dst.display());
        return Ok(());
    }

    // Strategy 2: Try with volume lock/unlock
    tried_strategies.push("volume lock/unlock".to_string());
    unsafe {
        if let Some(h) = try_lock_volume(&root) {
            let _ = dismount_locked_volume(h);
            unlock_and_close(h);
            std::thread::sleep(std::time::Duration::from_millis(800));
        }
    }

    if fs::create_dir_all(&dst).is_ok() {
        log::info!("Created directory {} (after remount)", dst.display());
        return Ok(());
    }

    // Strategy 3: Try GUID path
    tried_strategies.push("GUID volume path".to_string());
    if let Some(guid_root) = guid_volume_root_from_drive_root(&root) {
        let alt_dst = guid_root.join(rel_path);
        if fs::create_dir_all(&alt_dst).is_ok() {
            log::info!("Created directory {} (GUID path)", alt_dst.display());
            return Ok(());
        }
    }

    Err(Fat32Error::access_denied(
        dst.display().to_string(),
        tried_strategies,
    ))
}

/// Delete file from ESP with multiple strategies
pub fn delete_file_from_esp(path: &Path) -> Result<()> {
    log::info!("Attempting to delete file from ESP: {:?}", path);

    // Try to get ESP root and relative path
    let (root, rel_path) = match get_esp_root_and_relative_path(path) {
        Some((r, p)) => (r, p),
        None => {
            // Fallback to direct deletion
            return fs::remove_file(path).map_err(|e| e.into());
        }
    };

    let dst = root.join(&rel_path);
    let mut tried_strategies = Vec::new();

    // Strategy 1: Try direct deletion
    tried_strategies.push("direct deletion".to_string());
    match fs::remove_file(&dst) {
        Ok(()) => {
            log::info!(
                "Successfully deleted file via direct method: {}",
                dst.display()
            );
            return Ok(());
        }
        Err(ref e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            log::warn!("Direct deletion failed with permission denied, trying other strategies");
        }
        Err(e) => return Err(e.into()),
    }

    // Strategy 2: Try with privileges
    tried_strategies.push("with privileges".to_string());
    try_enable_esp_privileges();
    match fs::remove_file(&dst) {
        Ok(()) => {
            log::info!(
                "Successfully deleted file with elevated privileges: {}",
                dst.display()
            );
            return Ok(());
        }
        Err(e) => {
            log::warn!("Deletion with privileges failed: {}", e);
        }
    }

    // Strategy 3: Try with volume lock/dismount
    tried_strategies.push("volume lock/dismount".to_string());
    unsafe {
        if let Some(h) = try_lock_volume(&root) {
            let _dismounted = dismount_locked_volume(h);
            unlock_and_close(h);

            // Wait for volume to be accessible again
            std::thread::sleep(std::time::Duration::from_millis(800));

            match fs::remove_file(&dst) {
                Ok(()) => {
                    log::info!(
                        "Successfully deleted file after volume remount: {}",
                        dst.display()
                    );
                    return Ok(());
                }
                Err(e) => {
                    log::warn!("Deletion after remount failed: {}", e);
                }
            }
        }
    }

    // Strategy 4: Try GUID path
    tried_strategies.push("GUID volume path".to_string());
    if let Some(guid_root) = guid_volume_root_from_drive_root(&root) {
        let alt_dst = guid_root.join(&rel_path);
        match fs::remove_file(&alt_dst) {
            Ok(()) => {
                log::info!(
                    "Successfully deleted file via GUID path: {}",
                    alt_dst.display()
                );
                return Ok(());
            }
            Err(e) => {
                log::warn!("Deletion via GUID path failed: {}", e);
            }
        }
    }

    Err(Fat32Error::access_denied(
        dst.display().to_string(),
        tried_strategies,
    ))
}

/// Delete directory from ESP with multiple strategies
pub fn delete_directory_from_esp(path: &Path) -> Result<()> {
    log::info!("Attempting to delete directory from ESP: {:?}", path);

    // Try to get ESP root and relative path
    let (root, rel_path) = match get_esp_root_and_relative_path(path) {
        Some((r, p)) => (r, p),
        None => {
            // Fallback to direct deletion - use remove_dir for empty dirs only
            return fs::remove_dir(path).map_err(|e| e.into());
        }
    };

    let dst = root.join(&rel_path);
    let mut tried_strategies = Vec::new();

    // Strategy 1: Try direct deletion (remove_dir for empty directories only)
    tried_strategies.push("direct deletion".to_string());
    match fs::remove_dir(&dst) {
        Ok(()) => {
            log::info!(
                "Successfully deleted directory via direct method: {}",
                dst.display()
            );
            return Ok(());
        }
        Err(ref e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            log::warn!("Direct deletion failed with permission denied, trying other strategies");
        }
        Err(e) => return Err(e.into()),
    }

    // Strategy 2: Try with privileges
    tried_strategies.push("with privileges".to_string());
    try_enable_esp_privileges();
    match fs::remove_dir(&dst) {
        Ok(()) => {
            log::info!(
                "Successfully deleted directory with elevated privileges: {}",
                dst.display()
            );
            return Ok(());
        }
        Err(e) => {
            log::warn!("Deletion with privileges failed: {}", e);
        }
    }

    // Strategy 3: Try with volume lock/dismount
    tried_strategies.push("volume lock/dismount".to_string());
    unsafe {
        if let Some(h) = try_lock_volume(&root) {
            let _dismounted = dismount_locked_volume(h);
            unlock_and_close(h);

            // Wait for volume to be accessible again
            std::thread::sleep(std::time::Duration::from_millis(800));

            match fs::remove_dir(&dst) {
                Ok(()) => {
                    log::info!(
                        "Successfully deleted directory after volume remount: {}",
                        dst.display()
                    );
                    return Ok(());
                }
                Err(e) => {
                    log::warn!("Deletion after remount failed: {}", e);
                }
            }
        }
    }

    // Strategy 4: Try GUID path
    tried_strategies.push("GUID volume path".to_string());
    if let Some(guid_root) = guid_volume_root_from_drive_root(&root) {
        let alt_dst = guid_root.join(&rel_path);
            match fs::remove_dir(&alt_dst) {
            Ok(()) => {
                log::info!(
                    "Successfully deleted directory via GUID path: {}",
                    alt_dst.display()
                );
                return Ok(());
            }
            Err(e) => {
                log::warn!("Deletion via GUID path failed: {}", e);
            }
        }
    }

    Err(Fat32Error::access_denied(
        dst.display().to_string(),
        tried_strategies,
    ))
}
