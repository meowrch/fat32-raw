//! Long File Name (LFN) support for FAT32

use super::DIR_ENTRY_SIZE;

/// LFN entry attribute marker
pub const LFN_ATTRIBUTE: u8 = 0x0F;

/// Maximum number of characters in a LFN entry
const LFN_CHARS_PER_ENTRY: usize = 13;

/// LFN entry structure
#[derive(Debug, Clone)]
pub struct LfnEntry {
    pub sequence: u8,
    pub chars: Vec<u16>,
    pub checksum: u8,
}

/// Parse a LFN directory entry
pub fn parse_lfn_entry(entry: &[u8]) -> Option<LfnEntry> {
    if entry.len() < DIR_ENTRY_SIZE {
        return None;
    }

    // Check if it's a LFN entry
    if entry[0x0B] != LFN_ATTRIBUTE {
        return None;
    }

    let sequence = entry[0];
    let checksum = entry[0x0D];

    // Extract characters from LFN entry
    let mut chars = Vec::with_capacity(LFN_CHARS_PER_ENTRY);

    // First 5 characters (bytes 1-10)
    for i in 0..5 {
        let c = u16::from_le_bytes([entry[1 + i * 2], entry[2 + i * 2]]);
        if c == 0 || c == 0xFFFF {
            break;
        }
        chars.push(c);
    }

    // Next 6 characters (bytes 14-25)
    for i in 0..6 {
        let c = u16::from_le_bytes([entry[14 + i * 2], entry[15 + i * 2]]);
        if c == 0 || c == 0xFFFF {
            break;
        }
        chars.push(c);
    }

    // Last 2 characters (bytes 28-31)
    for i in 0..2 {
        let c = u16::from_le_bytes([entry[28 + i * 2], entry[29 + i * 2]]);
        if c == 0 || c == 0xFFFF {
            break;
        }
        chars.push(c);
    }

    Some(LfnEntry {
        sequence,
        chars,
        checksum,
    })
}

/// Calculate checksum for a short name
pub fn lfn_checksum(name: &[u8; 11]) -> u8 {
    let mut sum: u8 = 0;
    for &byte in name {
        sum = (((sum & 1) << 7) | ((sum & 0xFE) >> 1)).wrapping_add(byte);
    }
    sum
}

/// Generate short name from a long name
pub fn generate_short_name(long_name: &str, existing_names: &[String]) -> [u8; 11] {
    let mut short_name = [b' '; 11];

    // Extract base name and extension
    let (base, ext) = if let Some(dot_pos) = long_name.rfind('.') {
        (&long_name[..dot_pos], &long_name[dot_pos + 1..])
    } else {
        (long_name.as_ref(), "")
    };

    // Convert base name to uppercase and truncate to 8 characters
    let base_upper = base.to_uppercase();
    let base_clean: String = base_upper
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .take(6) // Leave room for ~N suffix
        .collect();

    // Convert extension to uppercase and truncate to 3 characters
    let ext_upper = ext.to_uppercase();
    let ext_clean: String = ext_upper
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(3)
        .collect();

    // Find a unique name with ~N suffix
    for n in 1..=999 {
        // Create the short name with suffix
        let suffix = format!("~{}", n);
        let name_len = (8 - suffix.len()).min(base_clean.len());

        // Fill in the base name
        for (i, c) in base_clean.chars().take(name_len).enumerate() {
            short_name[i] = c as u8;
        }

        // Add the suffix
        for (i, c) in suffix.chars().enumerate() {
            short_name[name_len + i] = c as u8;
        }

        // Fill in the extension
        for (i, c) in ext_clean.chars().take(3).enumerate() {
            short_name[8 + i] = c as u8;
        }

        // Check if this name already exists
        let test_name = String::from_utf8_lossy(&short_name).trim().to_string();

        if !existing_names.contains(&test_name) {
            return short_name;
        }
    }

    // If we can't find a unique name, use a fallback
    short_name
}

/// Create LFN entries for a long filename
pub fn make_lfn_entries(long_name: &str, short_name: &[u8; 11]) -> Vec<[u8; 32]> {
    let mut entries = Vec::new();
    let checksum = lfn_checksum(short_name);

    // Convert long name to UTF-16
    let utf16: Vec<u16> = long_name.encode_utf16().collect();

    // Calculate number of LFN entries needed
    let num_entries = (utf16.len() + LFN_CHARS_PER_ENTRY - 1) / LFN_CHARS_PER_ENTRY;

    // Create LFN entries in reverse order (last fragment first)
    for i in (0..num_entries).rev() {
        let mut entry = [0u8; 32];

        // Set sequence number (0x40 marks the last entry)
        entry[0] = (i + 1) as u8;
        if i == num_entries - 1 {
            entry[0] |= 0x40;
        }

        // Set attribute to LFN
        entry[0x0B] = LFN_ATTRIBUTE;

        // Set checksum
        entry[0x0D] = checksum;

        // Fill in characters for this entry
        let start = i * LFN_CHARS_PER_ENTRY;
        let chars_in_entry = (utf16.len() - start).min(LFN_CHARS_PER_ENTRY);

        for j in 0..chars_in_entry {
            let c = utf16[start + j];

            if j < 5 {
                // First 5 chars (bytes 1-10)
                entry[1 + j * 2] = (c & 0xFF) as u8;
                entry[2 + j * 2] = (c >> 8) as u8;
            } else if j < 11 {
                // Next 6 chars (bytes 14-25)
                let idx = j - 5;
                entry[14 + idx * 2] = (c & 0xFF) as u8;
                entry[15 + idx * 2] = (c >> 8) as u8;
            } else {
                // Last 2 chars (bytes 28-31)
                let idx = j - 11;
                entry[28 + idx * 2] = (c & 0xFF) as u8;
                entry[29 + idx * 2] = (c >> 8) as u8;
            }
        }

        // Add null terminator if this is the last entry and we have space
        if i == num_entries - 1 && chars_in_entry < LFN_CHARS_PER_ENTRY {
            // Add 0x0000 after the last character
            if chars_in_entry < 5 {
                entry[1 + chars_in_entry * 2] = 0x00;
                entry[2 + chars_in_entry * 2] = 0x00;
            } else if chars_in_entry < 11 {
                let idx = chars_in_entry - 5;
                entry[14 + idx * 2] = 0x00;
                entry[15 + idx * 2] = 0x00;
            } else {
                let idx = chars_in_entry - 11;
                entry[28 + idx * 2] = 0x00;
                entry[29 + idx * 2] = 0x00;
            }
            
            // Pad the rest with 0xFFFF
            for j in (chars_in_entry + 1)..LFN_CHARS_PER_ENTRY {
                if j < 5 {
                    entry[1 + j * 2] = 0xFF;
                    entry[2 + j * 2] = 0xFF;
                } else if j < 11 {
                    let idx = j - 5;
                    entry[14 + idx * 2] = 0xFF;
                    entry[15 + idx * 2] = 0xFF;
                } else {
                    let idx = j - 11;
                    entry[28 + idx * 2] = 0xFF;
                    entry[29 + idx * 2] = 0xFF;
                }
            }
        } else {
            // Not the last entry or no space for terminator - pad with 0xFFFF
            for j in chars_in_entry..LFN_CHARS_PER_ENTRY {
                if j < 5 {
                    entry[1 + j * 2] = 0xFF;
                    entry[2 + j * 2] = 0xFF;
                } else if j < 11 {
                    let idx = j - 5;
                    entry[14 + idx * 2] = 0xFF;
                    entry[15 + idx * 2] = 0xFF;
                } else {
                    let idx = j - 11;
                    entry[28 + idx * 2] = 0xFF;
                    entry[29 + idx * 2] = 0xFF;
                }
            }
        }

        entries.push(entry);
    }

    entries
}
