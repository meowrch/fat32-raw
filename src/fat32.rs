use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::string::String;

const DIR_ENTRY_SIZE: usize = 32;
const LFN_ATTRIBUTE: u8 = 0x0F;

#[derive(Debug)]
pub struct Fat32FileEntry {
    pub name: String,
    pub start_cluster: u32,
    pub size: u32,
    pub is_directory: bool,
}

pub struct Fat32Params {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub num_fats: u8,
    pub sectors_per_fat: u32,
    pub root_cluster: u32,
}

pub fn read_bpb(file: &mut std::fs::File, offset: u64) -> std::io::Result<Fat32Params> {
    use std::io::Seek;
    file.seek(std::io::SeekFrom::Start(offset))?;
    let mut bpb = [0u8; 512];
    file.read_exact(&mut bpb)?;
    Ok(Fat32Params {
        bytes_per_sector: u16::from_le_bytes([bpb[0x0B], bpb[0x0C]]),
        sectors_per_cluster: bpb[0x0D],
        reserved_sectors: u16::from_le_bytes([bpb[0x0E], bpb[0x0F]]),
        num_fats: bpb[0x10],
        sectors_per_fat: u32::from_le_bytes([bpb[0x24], bpb[0x25], bpb[0x26], bpb[0x27]]),
        root_cluster: u32::from_le_bytes([bpb[0x2C], bpb[0x2D], bpb[0x2E], bpb[0x2F]]),
    })
}

pub struct Fat32Volume {
    file: File,
    esp_offset: u64,
    fat_offset: u64,
    data_offset: u64,
    bytes_per_sector: u16,
    sectors_per_cluster: u32,
    reserved_sectors: u32,
    num_fats: u32,
    sectors_per_fat: u32,
    root_cluster: u32,
    fat: Vec<u8>,
}


impl Fat32Volume {
    pub fn open(
        device_path: &str,
        esp_start_lba: u64,
        bytes_per_sector: u16,
        sectors_per_cluster: u32,
        reserved_sectors: u32,
        num_fats: u32,
        sectors_per_fat: u32,
        root_cluster: u32,
    ) -> io::Result<Self> {
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(device_path)?;

        let esp_offset = esp_start_lba * bytes_per_sector as u64;
        let fat_offset = esp_offset + reserved_sectors as u64 * bytes_per_sector as u64;
        let data_offset = esp_offset + (reserved_sectors + num_fats * sectors_per_fat) as u64 * bytes_per_sector as u64;

        let fat_size_bytes = (sectors_per_fat * bytes_per_sector as u32) as usize;
        file.seek(SeekFrom::Start(fat_offset))?;
        let mut fat = vec![0u8; fat_size_bytes];
        file.read_exact(&mut fat)?;

        Ok(Fat32Volume {
            file,
            esp_offset,
            fat_offset,
            data_offset,
            bytes_per_sector,
            sectors_per_cluster,
            reserved_sectors,
            num_fats,
            sectors_per_fat,
            root_cluster,
            fat,
        })
    }

    fn read_cluster(&mut self, cluster_num: u32) -> io::Result<Vec<u8>> {
        let cluster_size = self.sectors_per_cluster as u64 * self.bytes_per_sector as u64;
        let cluster_offset = self.data_offset + (cluster_num as u64 - 2) * cluster_size;
        self.file.seek(SeekFrom::Start(cluster_offset))?;
        let mut buf = vec![0u8; cluster_size as usize];
        self.file.read_exact(&mut buf)?;
        Ok(buf)
    }

    fn get_fat_entry(&self, cluster_num: u32) -> u32 {
        let offset = (cluster_num * 4) as usize;
        u32::from_le_bytes(self.fat[offset..offset + 4].try_into().unwrap()) & 0x0FFFFFFF
    }

    pub fn list_root(&mut self) -> io::Result<Vec<Fat32FileEntry>> {
        self.list_directory(self.root_cluster)
    }

    pub fn list_directory(&mut self, start_cluster: u32) -> io::Result<Vec<Fat32FileEntry>> {
        let mut entries = Vec::new();
        let mut current_cluster = start_cluster;

        loop {
            let cluster_data = self.read_cluster(current_cluster)?;
            let parsed_entries = parse_directory_entries(&cluster_data);

            for (name, cluster, size) in parsed_entries {
                let is_dir = size == 0 && name != "." && name != "..";
                entries.push(Fat32FileEntry {
                    name,
                    start_cluster: cluster,
                    size,
                    is_directory: is_dir,
                });
            }

            current_cluster = self.get_fat_entry(current_cluster);
            if current_cluster >= 0x0FFFFFF8 {
                break;
            }
        }
        Ok(entries)
    }

    pub fn read_file(&mut self, filename: &str) -> io::Result<Option<Vec<u8>>> {
        let entries = self.list_root()?;
        for entry in entries {
            if entry.name.eq_ignore_ascii_case(filename) && !entry.is_directory {
                let mut cluster = entry.start_cluster;
                let mut remaining = entry.size;
                let mut content = Vec::new();

                while cluster < 0x0FFFFFF8 {
                    let data = self.read_cluster(cluster)?;
                    let to_take = remaining.min(data.len() as u32) as usize;
                    content.extend_from_slice(&data[..to_take]);
                    remaining -= to_take as u32;
                    if remaining == 0 {
                        break;
                    }
                    cluster = self.get_fat_entry(cluster);
                }
                return Ok(Some(content));
            }
        }
        Ok(None)
    }

    pub fn write_file(&mut self, filename: &str, new_content: &[u8]) -> io::Result<bool> {
        // 1. Найти файл в корне
        let mut entries = self.list_root()?;
        let mut entry_opt = None;
        for entry in &entries {
            if entry.name.eq_ignore_ascii_case(filename) && !entry.is_directory {
                entry_opt = Some(entry);
                break;
            }
        }
        let entry = match entry_opt {
            Some(e) => e,
            None => return Ok(false),
        };

        let cluster_size = self.sectors_per_cluster as usize * self.bytes_per_sector as usize;
        let needed_clusters = (new_content.len() + cluster_size - 1) / cluster_size;

        // 2. Собрать текущую цепочку кластеров
        let mut clusters = Vec::new();
        let mut cluster = entry.start_cluster;
        while cluster < 0x0FFFFFF8 {
            clusters.push(cluster);
            cluster = self.get_fat_entry(cluster);
        }

        // 3. Если не хватает кластеров — выделить новые
        while clusters.len() < needed_clusters {
            let free = self.find_free_cluster().ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Нет свободных кластеров"))?;
            self.set_fat_entry(*clusters.last().unwrap(), free);
            clusters.push(free);
        }
        // 4. Если лишние — освободить
        while clusters.len() > needed_clusters {
            let last = clusters.pop().unwrap();
            self.set_fat_entry(last, 0);
        }
        // 5. Завершить цепочку
        if let Some(&last) = clusters.last() {
            self.set_fat_entry(last, 0x0FFFFFFF);
        }

        // 6. Записать новые данные по кластерам
        let mut offset = 0;
        for &cl in &clusters {
            let cluster_offset = self.data_offset + (cl as u64 - 2) * cluster_size as u64;
            self.file.seek(SeekFrom::Start(cluster_offset))?;
            let to_write = (new_content.len() - offset).min(cluster_size);
            self.file.write_all(&new_content[offset..offset + to_write])?;
            if to_write < cluster_size {
                let zeroes = vec![0u8; cluster_size - to_write];
                self.file.write_all(&zeroes)?;
            }
            offset += to_write;
        }

        // 7. Обновить размер файла в директории
        self.update_file_size_in_dir(entry.start_cluster, new_content.len() as u32)?;

        // 8. Сохранить FAT на диск
        self.flush_fat()?;

        Ok(true)
    }

    fn find_free_cluster(&self) -> Option<u32> {
        for i in 2..(self.fat.len() as u32 / 4) {
            if self.get_fat_entry(i) == 0 {
                return Some(i);
            }
        }
        None
    }
    fn set_fat_entry(&mut self, cluster: u32, value: u32) {
        let offset = (cluster * 4) as usize;
        self.fat[offset..offset+4].copy_from_slice(&(value & 0x0FFFFFFF).to_le_bytes());
    }
    fn flush_fat(&mut self) -> io::Result<()> {
        self.file.seek(SeekFrom::Start(self.fat_offset))?;
        self.file.write_all(&self.fat)?;
        Ok(())
    }
    fn update_file_size_in_dir(&mut self, start_cluster: u32, new_size: u32) -> io::Result<()> {
        // Найти запись в директории и обновить размер (4 байта)
        let mut dir_cluster = self.root_cluster;
        loop {
            let cluster_offset = self.data_offset + (dir_cluster as u64 - 2) * self.sectors_per_cluster as u64 * self.bytes_per_sector as u64;
            self.file.seek(SeekFrom::Start(cluster_offset))?;
            let mut buf = vec![0u8; self.sectors_per_cluster as usize * self.bytes_per_sector as usize];
            self.file.read_exact(&mut buf)?;
            for i in 0..(buf.len() / 32) {
                let entry = &mut buf[i * 32..(i + 1) * 32];
                let high = u16::from_le_bytes([entry[20], entry[21]]) as u32;
                let low = u16::from_le_bytes([entry[26], entry[27]]) as u32;
                let cl = (high << 16) | low;
                if cl == start_cluster {
                    entry[28..32].copy_from_slice(&new_size.to_le_bytes());
                    // Записать обратно
                    self.file.seek(SeekFrom::Start(cluster_offset + (i * 32) as u64))?;
                    self.file.write_all(entry)?;
                    return Ok(());
                }
            }
            dir_cluster = self.get_fat_entry(dir_cluster);
            if dir_cluster >= 0x0FFFFFF8 { break; }
        }
        Err(io::Error::new(io::ErrorKind::NotFound, "dir entry not found"))
    }
}

fn parse_dir_entry(entry: &[u8]) -> Option<(String, u32, u32)> {
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
    let filename = if ext.is_empty() { name } else { format!("{}.{}", name, ext) };
    let high = u16::from_le_bytes([entry[20], entry[21]]) as u32;
    let low = u16::from_le_bytes([entry[26], entry[27]]) as u32;
    let start_cluster = (high << 16) | low;
    let file_size = u32::from_le_bytes([entry[28], entry[29], entry[30], entry[31]]);
    Some((filename, start_cluster, file_size))
}

fn parse_lfn_entry(entry: &[u8]) -> Option<String> {
    if entry[11] != LFN_ATTRIBUTE {
        return None;
    }
    let mut name_utf16 = Vec::new();
    let read_u16 = |b: &[u8]| u16::from_le_bytes([b[0], b[1]]);
    for i in (1..=10).step_by(2) {
        let c = read_u16(&entry[i..i + 2]);
        if c == 0x0000 || c == 0xFFFF { break; }
        name_utf16.push(c);
    }
    for i in (14..=25).step_by(2) {
        let c = read_u16(&entry[i..i + 2]);
        if c == 0x0000 || c == 0xFFFF { break; }
        name_utf16.push(c);
    }
    for i in (28..=31).step_by(2) {
        let c = read_u16(&entry[i..i + 2]);
        if c == 0x0000 || c == 0xFFFF { break; }
        name_utf16.push(c);
    }
    String::from_utf16(&name_utf16).ok()
}

fn parse_directory_entries(cluster_data: &[u8]) -> Vec<(String, u32, u32)> {
    let mut results = Vec::new();
    let mut lfn_stack = Vec::new();

    for i in 0..(cluster_data.len() / DIR_ENTRY_SIZE) {
        let entry = &cluster_data[i * DIR_ENTRY_SIZE..(i + 1) * DIR_ENTRY_SIZE];
        if entry[0] == 0x00 { break; }
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
            results.push((full_name, start_cluster, file_size));
        } else {
            lfn_stack.clear();
        }
    }
    results
}
