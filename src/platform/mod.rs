//! Platform-specific implementations

#[cfg(windows)]
pub mod windows;

#[cfg(unix)]
pub mod unix;

use crate::error::Result;

/// Find ESP device for raw access
/// Returns device path and LBA offset
pub fn find_esp_device() -> Result<Option<(String, u64)>> {
    #[cfg(windows)]
    {
        windows::esp::find_esp_device()
    }

    #[cfg(unix)]
    {
        unix::esp::find_esp_device()
    }

    #[cfg(not(any(windows, unix)))]
    {
        log::warn!("ESP detection not implemented for this platform");
        Ok(None)
    }
}
