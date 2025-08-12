//! Windows privilege management for accessing ESP partitions

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, LUID};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::error::{Fat32Error, Result};

/// Enable a specific Windows privilege by name
pub fn enable_privilege(name: &str) -> Result<()> {
    unsafe {
        let mut token: HANDLE = 0;

        // Open process token
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        ) == 0
        {
            let error_code = GetLastError();
            return Err(Fat32Error::platform_error(
                format!("OpenProcessToken failed: {}", error_code),
                Some(error_code),
            ));
        }

        // Convert privilege name to wide string
        let wname: Vec<u16> = OsStr::new(name).encode_wide().chain(Some(0)).collect();

        // Look up privilege value
        let mut luid = LUID {
            LowPart: 0,
            HighPart: 0,
        };

        if LookupPrivilegeValueW(ptr::null(), wname.as_ptr(), &mut luid) == 0 {
            let error_code = GetLastError();
            let _ = CloseHandle(token);
            return Err(Fat32Error::platform_error(
                format!("LookupPrivilegeValueW failed for {}: {}", name, error_code),
                Some(error_code),
            ));
        }

        // Prepare privilege structure
        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        // Adjust token privileges
        if AdjustTokenPrivileges(token, 0, &tp, 0, ptr::null_mut(), ptr::null_mut()) == 0 {
            let error_code = GetLastError();
            let _ = CloseHandle(token);
            return Err(Fat32Error::platform_error(
                format!("AdjustTokenPrivileges failed for {}: {}", name, error_code),
                Some(error_code),
            ));
        }

        let _ = CloseHandle(token);

        log::debug!("Enabled Windows privilege: {}", name);
        Ok(())
    }
}

/// Enable core privileges needed for ESP access
/// These privileges help bypass OS Error 5 (Access Denied)
pub fn enable_esp_privileges() -> Result<()> {
    // Try to enable each privilege, but don't fail if some can't be enabled
    // (user might not have permission for all of them)
    let privileges = [
        "SeBackupPrivilege",        // Allows reading files without access checks
        "SeRestorePrivilege",       // Allows writing files without access checks
        "SeTakeOwnershipPrivilege", // Allows taking ownership of files
    ];

    let mut any_enabled = false;
    let mut last_error = None;

    for privilege in &privileges {
        match enable_privilege(privilege) {
            Ok(()) => {
                any_enabled = true;
                log::info!("Enabled privilege: {}", privilege);
            }
            Err(e) => {
                log::warn!("Failed to enable privilege {}: {:?}", privilege, e);
                last_error = Some(e);
            }
        }
    }

    if any_enabled {
        Ok(())
    } else {
        Err(last_error.unwrap_or_else(|| {
            Fat32Error::platform_error("Failed to enable any ESP privileges", None)
        }))
    }
}

/// Try to enable ESP privileges without failing if unsuccessful
pub fn try_enable_esp_privileges() {
    if let Err(e) = enable_esp_privileges() {
        log::debug!(
            "Could not enable ESP privileges (might not be needed): {:?}",
            e
        );
    }
}
