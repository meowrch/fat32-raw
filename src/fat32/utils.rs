#[cfg(windows)]
use log::info;
use log::warn;
#[cfg(windows)]
use std::ffi::OsStr;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use std::ptr;

#[cfg(windows)]
use windows_sys::core::GUID;
#[cfg(windows)]
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING,
};
#[cfg(windows)]
use windows_sys::Win32::System::Ioctl::{
    DRIVE_LAYOUT_INFORMATION_EX, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, PARTITION_STYLE_GPT,
};
#[cfg(windows)]
use windows_sys::Win32::System::IO::DeviceIoControl;

#[cfg(windows)]
#[allow(dead_code)]
const IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS: u32 = 0x00560000;

#[cfg(windows)]
fn esp_guid() -> GUID {
    GUID {
        data1: 0xc12a7328,
        data2: 0xf81f,
        data3: 0x11d2,
        data4: [0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b],
    }
}

#[cfg(windows)]
fn is_esp_guid(guid: &GUID) -> bool {
    let esp = esp_guid();
    guid.data1 == esp.data1
        && guid.data2 == esp.data2
        && guid.data3 == esp.data3
        && guid.data4 == esp.data4
}

#[cfg(windows)]
fn open_handle(path_w: &[u16]) -> Option<HANDLE> {
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

#[cfg(windows)]
pub fn find_esp_device() -> std::io::Result<Option<(String, u64)>> {
    info!("Scanning for ESP device using Windows API...");
    unsafe {
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
                                let lba = (part_info.StartingOffset / 512) as u64; // Assuming 512 bytes per sector
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
    warn!("ESP device not found after scanning all physical drives.");
    Ok(None)
}

#[cfg(not(windows))]
pub fn find_esp_device() -> std::io::Result<Option<(String, u64)>> {
    warn!("find_esp_device is only implemented on Windows; returning None");
    Ok(None)
}
