use super::{*};

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

pub fn lfn_checksum(short_name: &[u8; 11]) -> u8 {
    let mut sum = 0u8;
    for &b in short_name {
        sum = sum.rotate_right(1).wrapping_add(b);
    }
    sum
}

pub fn make_lfn_entries(long_name: &str, checksum: u8) -> Vec<[u8; 32]> {
    let utf16: Vec<u16> = long_name.encode_utf16().collect();
    let lfn_count = (utf16.len() + 12) / 13;
    let mut entries = Vec::new();
    for i in 0..lfn_count {
        let mut entry = [0u8; 32];
        entry[11] = 0x0F;
        entry[13] = checksum;
        let seq = (lfn_count - i) as u8; // номер LFN-записи (от lfn_count до 1)
        entry[0] = if i == 0 { seq | 0x40 } else { seq };
        let start = i * 13;
        let end = ((i + 1) * 13).min(utf16.len());
        let chunk = &utf16[start..end];
        for (j, &c) in chunk.iter().enumerate() {
            let pos = match j {
                0..=4 => 1 + j * 2,
                5..=10 => 14 + (j - 5) * 2,
                11..=12 => 28 + (j - 11) * 2,
                _ => 0,
            };
            if pos > 0 {
                entry[pos..pos + 2].copy_from_slice(&c.to_le_bytes());
            }
        }
        // Остальные байты - 0xFF
        for pos in [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30] {
            if entry[pos] == 0 && entry[pos + 1] == 0 {
                entry[pos] = 0xFF;
                entry[pos + 1] = 0xFF;
            }
        }
        entries.push(entry);
    }
    entries.reverse();
    entries
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

pub fn parse_lfn_entry(entry: &[u8]) -> Option<String> {
    if entry[11] != LFN_ATTRIBUTE {
        return None;
    }
    let mut name_utf16 = Vec::new();
    let read_u16 = |b: &[u8]| u16::from_le_bytes([b[0], b[1]]);
    for i in (1..=10).step_by(2) {
        let c = read_u16(&entry[i..i + 2]);
        if c == 0x0000 || c == 0xFFFF {
            break;
        }
        name_utf16.push(c);
    }
    for i in (14..=25).step_by(2) {
        let c = read_u16(&entry[i..i + 2]);
        if c == 0x0000 || c == 0xFFFF {
            break;
        }
        name_utf16.push(c);
    }
    for i in (28..=31).step_by(2) {
        let c = read_u16(&entry[i..i + 2]);
        if c == 0x0000 || c == 0xFFFF {
            break;
        }
        name_utf16.push(c);
    }
    String::from_utf16(&name_utf16).ok()
}
