//! Windows-specific platform implementation

pub mod esp;
pub mod io;
pub mod privileges;
pub mod volume;

// Re-export commonly used functions
pub use esp::{find_esp_device, find_esp_volume_path};
pub use io::{
    create_directory_on_esp, delete_directory_from_esp, delete_file_from_esp, write_file_to_esp,
};
pub use privileges::{enable_esp_privileges, try_enable_esp_privileges};
pub use volume::VolumeLock;
