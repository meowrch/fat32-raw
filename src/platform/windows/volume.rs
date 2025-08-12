//! Windows volume management (lock/unlock for ESP access)

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetVolumeInformationW, GetVolumeNameForVolumeMountPointW, FILE_ATTRIBUTE_NORMAL,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::IO::DeviceIoControl;


// IOCTL codes for volume operations
const FSCTL_LOCK_VOLUME: u32 = 0x00090018;
const FSCTL_DISMOUNT_VOLUME: u32 = 0x00090020;

/// Convert a root path to a volume path for CreateFileW
/// For example: "C:\" -> "\\.\C:"
pub fn volume_path_from_root(root: &Path) -> Option<Vec<u16>> {
    let s = root.as_os_str().to_string_lossy();
    let drive = s.chars().next()?;

    if !drive.is_ascii_alphabetic() {
        return None;
    }

    // Use \\.\C: style path (with colon) to open a volume handle correctly
    let path = format!("\\\\.\\{}: ", drive.to_ascii_uppercase());
    let mut w: Vec<u16> = OsStr::new(&path).encode_wide().collect();
    w.push(0);
    Some(w)
}

/// Get the GUID volume path from a drive root
/// For example: "C:\" -> "\\?\Volume{GUID}\"
pub fn guid_volume_root_from_drive_root(root: &Path) -> Option<PathBuf> {
    let mut drive = root.as_os_str().encode_wide().collect::<Vec<u16>>();
    if !drive.ends_with(&[0]) {
        drive.push(0);
    }

    let mut buf = vec![0u16; 64];
    let ok = unsafe {
        GetVolumeNameForVolumeMountPointW(drive.as_ptr(), buf.as_mut_ptr(), buf.len() as u32)
    };

    if ok == 0 {
        return None;
    }

    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    let s = String::from_utf16_lossy(&buf[..len]);
    Some(PathBuf::from(s))
}

/// Check if a volume uses FAT/FAT32 filesystem
pub fn is_fat_fs(volume_path: &[u16]) -> bool {
    unsafe {
        let mut fs_name = [0u16; 32];
        let ok = GetVolumeInformationW(
            volume_path.as_ptr(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            fs_name.as_mut_ptr(),
            fs_name.len() as u32,
        );

        if ok == 0 {
            return false;
        }

        let len = fs_name
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(fs_name.len());
        let name = String::from_utf16_lossy(&fs_name[..len]).to_uppercase();
        name == "FAT" || name == "FAT32"
    }
}

/// Open a handle to a device or volume
pub fn open_handle(path_w: &[u16]) -> Option<HANDLE> {
    unsafe {
        let h = CreateFileW(
            path_w.as_ptr(),
            (FILE_GENERIC_READ | FILE_GENERIC_WRITE) as u32,
            (FILE_SHARE_READ | FILE_SHARE_WRITE) as u32,
            ptr::null_mut(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            0,
        );

        if h == INVALID_HANDLE_VALUE || h == 0 {
            None
        } else {
            Some(h)
        }
    }
}

/// Try to lock a volume for exclusive access
/// Returns a handle that must be closed with unlock_and_close
pub unsafe fn try_lock_volume(root: &Path) -> Option<HANDLE> {
    if let Some(wpath) = volume_path_from_root(root) {
        let h = CreateFileW(
            wpath.as_ptr(),
            (FILE_GENERIC_READ | FILE_GENERIC_WRITE) as u32,
            (FILE_SHARE_READ | FILE_SHARE_WRITE) as u32,
            ptr::null_mut(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            0,
        );

        if h == INVALID_HANDLE_VALUE || h == 0 {
            return None;
        }

        let mut bytes: u32 = 0;
        let ok = DeviceIoControl(
            h,
            FSCTL_LOCK_VOLUME,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            0,
            &mut bytes as *mut u32,
            ptr::null_mut(),
        );

        if ok == 0 {
            let _ = CloseHandle(h);
            return None;
        }

        return Some(h);
    }
    None
}

/// Dismount a locked volume
pub unsafe fn dismount_locked_volume(h: HANDLE) -> bool {
    let mut bytes: u32 = 0;
    DeviceIoControl(
        h,
        FSCTL_DISMOUNT_VOLUME,
        ptr::null_mut(),
        0,
        ptr::null_mut(),
        0,
        &mut bytes as *mut u32,
        ptr::null_mut(),
    ) != 0
}

/// Unlock and close a volume handle
pub unsafe fn unlock_and_close(h: HANDLE) {
    let _ = CloseHandle(h);
}

/// Volume lock guard for RAII pattern
pub struct VolumeLock {
    handle: HANDLE,
}

impl VolumeLock {
    /// Try to lock a volume
    pub fn lock(root: &Path) -> Option<Self> {
        unsafe { try_lock_volume(root).map(|handle| Self { handle }) }
    }

    /// Dismount the locked volume
    pub fn dismount(&self) -> bool {
        unsafe { dismount_locked_volume(self.handle) }
    }
}

impl Drop for VolumeLock {
    fn drop(&mut self) {
        unsafe { unlock_and_close(self.handle) }
    }
}
