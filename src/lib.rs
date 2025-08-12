//! FAT32-raw: A lightweight Rust library for working with FAT32 partitions and images

pub mod error;
pub mod fat32;
pub mod platform;

// Re-export main types
pub use error::{Fat32Error, Result};
pub use fat32::{volume::Fat32Volume, Fat32FileEntry, Fat32Params};

// Platform-specific re-exports
#[cfg(windows)]
pub use platform::windows::{
    create_directory_on_esp, delete_directory_from_esp, delete_file_from_esp, write_file_to_esp,
};

