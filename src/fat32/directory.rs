use super::{*};
use crate::fat32::file::{parse_dir_entry, parse_lfn_entry};

pub fn parse_directory_entries(cluster_data: &[u8]) -> Vec<(String, u32, u32, u8)> {
    let mut results = Vec::new();
    let mut lfn_stack = Vec::new();
    for i in 0..(cluster_data.len() / DIR_ENTRY_SIZE) {
        let entry = &cluster_data[i * DIR_ENTRY_SIZE..(i + 1) * DIR_ENTRY_SIZE];
        if entry[0] == 0x00 {
            break;
        }
        if entry[11] == LFN_ATTRIBUTE {
            if let Some(name_part) = parse_lfn_entry(entry) {
                lfn_stack.insert(0, name_part);
            }
            continue;
        }
        if entry[0] == 0xE5 {
            lfn_stack.clear();
            continue;
        }
        if let Some((_short_name, start_cluster, file_size)) = parse_dir_entry(entry) {
            let full_name = if !lfn_stack.is_empty() {
                let name = lfn_stack.join("");
                lfn_stack.clear();
                name
            } else {
                _short_name
            };
            let attr = entry[11];
            if !full_name.is_empty() {
                results.push((full_name, start_cluster, file_size, attr));
            }
        } else {
            lfn_stack.clear();
        }
    }
    results
}
