//! Windows I/O operations with OS Error 5 bypass strategies

use std::fs::{self, File};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
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

/// Normalize and validate a path that must stay relative to an explicit ESP root.
fn normalize_relative_path_for_root(rel_path: &Path) -> Result<PathBuf> {
    if rel_path.as_os_str().is_empty() {
        return Err(Fat32Error::invalid_file_name(
            "",
            "relative path must not be empty",
        ));
    }

    if rel_path.is_absolute() {
        return Err(Fat32Error::invalid_file_name(
            rel_path.display().to_string(),
            "path must be relative to ESP root",
        ));
    }

    let mut normalized = PathBuf::new();
    for component in rel_path.components() {
        match component {
            Component::Normal(seg) => normalized.push(seg),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(Fat32Error::invalid_file_name(
                    rel_path.display().to_string(),
                    "path traversal (`..`) is not allowed",
                ));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(Fat32Error::invalid_file_name(
                    rel_path.display().to_string(),
                    "absolute or prefixed path is not allowed",
                ));
            }
        }
    }

    if normalized.as_os_str().is_empty() {
        return Err(Fat32Error::invalid_file_name(
            rel_path.display().to_string(),
            "relative path has no usable segments",
        ));
    }

    Ok(normalized)
}

/// Write file to ESP with multiple strategies to bypass OS Error 5
pub fn write_file_to_esp(rel_path: &Path, data: &[u8]) -> Result<()> {
    let root = find_esp_volume_path().ok_or_else(|| Fat32Error::EspNotFound)?;
    let rel_path = normalize_relative_path_for_root(rel_path)?;
    let dst = root.join(&rel_path);

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
        let alt_dst = guid_root.join(&rel_path);
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

#[cfg(test)]
mod tests {
    use super::normalize_relative_path_for_root;
    use std::path::Path;

    #[test]
    fn normalize_relative_path_rejects_empty() {
        let err = normalize_relative_path_for_root(Path::new("")).unwrap_err();
        assert!(
            err.to_string().contains("must not be empty"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn normalize_relative_path_rejects_parent_traversal() {
        let err = normalize_relative_path_for_root(Path::new("EFI/../BOOT/bootx64.efi"))
            .unwrap_err();
        assert!(
            err.to_string().contains("traversal"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn normalize_relative_path_collapses_current_dir_segments() {
        let normalized =
            normalize_relative_path_for_root(Path::new("./EFI/./BOOT/bootx64.efi")).unwrap();
        assert_eq!(normalized, Path::new("EFI/BOOT/bootx64.efi"));
    }
}

/// Write file to a specific ESP root with multiple strategies to bypass OS Error 5.
/// Unlike `write_file_to_esp`, this does NOT call `find_esp_volume_path()`;
/// it uses the provided `root` directly. This is required when the caller
/// explicitly opened a specific volume and we must not auto-detect a different one.
pub fn write_file_to_esp_with_root(root: &Path, rel_path: &Path, data: &[u8]) -> Result<()> {
    let rel_path = normalize_relative_path_for_root(rel_path)?;
    let dst = root.join(&rel_path);

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
        if let Some(h) = try_lock_volume(root) {
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

    // Strategy 3: Try GUID path derived from the provided root
    tried_strategies.push("GUID volume path".to_string());
    if let Some(guid_root) = guid_volume_root_from_drive_root(root) {
        let alt_dst = guid_root.join(&rel_path);
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
    let rel_path = normalize_relative_path_for_root(rel_path)?;
    let dst = root.join(&rel_path);

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

/// Create directory on a specific ESP root with multiple strategies.
pub fn create_directory_on_esp_with_root(root: &Path, rel_path: &Path) -> Result<()> {
    let rel_path = normalize_relative_path_for_root(rel_path)?;
    let dst = root.join(&rel_path);

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
        if let Some(h) = try_lock_volume(root) {
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
    if let Some(guid_root) = guid_volume_root_from_drive_root(root) {
        let alt_dst = guid_root.join(&rel_path);
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

/// Delete file from a specific ESP root with multiple strategies.
pub fn delete_file_from_esp_with_root(root: &Path, rel_path: &Path) -> Result<()> {
    log::info!(
        "Attempting to delete file from ESP root {:?}: {:?}",
        root,
        rel_path
    );

    let rel_path = normalize_relative_path_for_root(rel_path)?;
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
        if let Some(h) = try_lock_volume(root) {
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
    if let Some(guid_root) = guid_volume_root_from_drive_root(root) {
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

/// Delete directory from a specific ESP root with multiple strategies.
pub fn delete_directory_from_esp_with_root(root: &Path, rel_path: &Path) -> Result<()> {
    log::info!(
        "Attempting to delete directory from ESP root {:?}: {:?}",
        root,
        rel_path
    );

    let rel_path = normalize_relative_path_for_root(rel_path)?;
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
        if let Some(h) = try_lock_volume(root) {
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
    if let Some(guid_root) = guid_volume_root_from_drive_root(root) {
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
