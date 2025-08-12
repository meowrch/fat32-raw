//! File operations for FAT32

use super::LFN_ATTRIBUTE;
use crate::fat32::lfn;

// Re-export LFN functions for backward compatibility
pub use crate::fat32::lfn::{lfn_checksum, make_lfn_entries};

/// Generate a short name from a long name
/// Returns (base, extension) tuple
pub fn generate_short_name(long_name: &str, existing: &[String]) -> (String, String) {
    let mut base = String::new();
    let mut ext = String::new();
    let parts: Vec<&str> = long_name.split('.').collect();
    let name_part = parts.get(0).unwrap_or(&"");
    let ext_part = parts.get(1).unwrap_or(&"");

    for c in name_part.chars() {
        if base.len() >= 6 {
            break;
        }
        if c.is_ascii_alphanumeric() {
            base.push(c.to_ascii_uppercase());
        }
    }

    if base.is_empty() {
        base.push('X');
    }

    let mut num = 1;
    let mut candidate = format!("{}~{}", base, num);
    while existing.iter().any(|n| n.starts_with(&candidate)) {
        num += 1;
        candidate = format!("{}~{}", base, num);
    }
    base = candidate;

    for c in ext_part.chars() {
        if ext.len() >= 3 {
            break;
        }
        if c.is_ascii_alphanumeric() {
            ext.push(c.to_ascii_uppercase());
        }
    }

    (base, ext)
}

pub fn parse_dir_entry(entry: &[u8]) -> Option<(String, u32, u32)> {
    if entry[0] == 0x00 || entry[0] == 0xE5 {
        return None;
    }
    let attr = entry[11];
    if attr == LFN_ATTRIBUTE {
        return None;
    }
    let name_raw = &entry[0..8];
    let ext_raw = &entry[8..11];
    let name = String::from_utf8_lossy(name_raw).trim_end().to_string();
    let ext = String::from_utf8_lossy(ext_raw).trim_end().to_string();
    let filename = if ext.is_empty() {
        name
    } else {
        format!("{}.{}", name, ext)
    };
    let high = u16::from_le_bytes([entry[20], entry[21]]) as u32;
    let low = u16::from_le_bytes([entry[26], entry[27]]) as u32;
    let start_cluster = (high << 16) | low;
    let file_size = u32::from_le_bytes([entry[28], entry[29], entry[30], entry[31]]);
    Some((filename, start_cluster, file_size))
}

/// Parse a LFN directory entry
pub fn parse_lfn_entry(entry: &[u8]) -> Option<String> {
    lfn::parse_lfn_entry(entry)
        .map(|lfn_entry| String::from_utf16(&lfn_entry.chars).unwrap_or_default())
}
