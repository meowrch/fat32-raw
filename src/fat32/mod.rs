pub mod volume;
pub mod file;
pub mod directory;
pub mod utils;

#[cfg(target_os = "linux")]
use glob::glob;

use log;
use std::path::Path;

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::string::String;

pub(crate) const DIR_ENTRY_SIZE: usize = 32;
pub(crate) const LFN_ATTRIBUTE: u8 = 0x0F;

#[derive(Debug)]
pub struct Fat32FileEntry {
    pub name: String,
    pub start_cluster: u32,
    pub size: u32,
    pub is_directory: bool,
}

#[derive(Debug)]
pub struct Fat32Params {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub num_fats: u8,
    pub sectors_per_fat: u32,
    pub root_cluster: u32,
}
