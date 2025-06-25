#[cfg(target_os = "linux")]
use glob::glob;

use log;
use std::path::Path;

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

#[derive(Debug)]
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
    sync_on_write: bool,
    file: File,
    fat_offset: u64,
    data_offset: u64,
    bytes_per_sector: u16,
    sectors_per_cluster: u32,
    root_cluster: u32,
    fat: Vec<u8>,
}

impl Fat32Volume {
    pub fn open(
        sync_on_write: bool,
        device_path: &str,
        esp_start_lba: u64,
        bytes_per_sector: u16,
        sectors_per_cluster: u32,
        reserved_sectors: u32,
        num_fats: u32,
        sectors_per_fat: u32,
        root_cluster: u32,
    ) -> io::Result<Fat32Volume> {
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(device_path)?;

        // Преобразуем в u64 перед умножением
        let bytes_per_sector_u64 = bytes_per_sector as u64;
        let esp_offset = esp_start_lba * bytes_per_sector_u64;

        // Остальные вычисления
        let fat_offset = esp_offset + (reserved_sectors as u64 * bytes_per_sector_u64);
        let fat_size_bytes = (sectors_per_fat as u64 * bytes_per_sector_u64) as usize;

        file.seek(SeekFrom::Start(fat_offset))?;
        let mut fat = vec![0u8; fat_size_bytes];
        file.read_exact(&mut fat)?;

        let data_offset = esp_offset
            + (reserved_sectors as u64 + (num_fats as u64) * (sectors_per_fat as u64))
                * bytes_per_sector_u64;

        Ok(Fat32Volume {
            sync_on_write,
            file,
            fat_offset,
            data_offset,
            bytes_per_sector,
            sectors_per_cluster,
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
            for (name, cluster, size, attr) in parsed_entries {
                let is_dir = (attr & 0x10) != 0;
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
            if entry.name.trim().eq_ignore_ascii_case(filename) && !entry.is_directory {
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
        // 1. Находим файл в корне
        let entries = self.list_root()?;
        let mut entry_opt = None;
        for entry in &entries {
            if entry.name.trim().eq_ignore_ascii_case(filename) && !entry.is_directory {
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
        // 2. Собираем текущую цепочку кластеров
        let mut clusters = Vec::new();
        let mut cluster = entry.start_cluster;
        while cluster < 0x0FFFFFF8 {
            clusters.push(cluster);
            cluster = self.get_fat_entry(cluster);
        }
        // 3. Если не хватает кластеров — выделяем новые
        while clusters.len() < needed_clusters {
            let free = self
                .find_free_cluster()
                .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Нет свободных кластеров"))?;
            self.set_fat_entry(*clusters.last().unwrap(), free);
            clusters.push(free);
        }
        // 4. Если лишние — освобождаем
        while clusters.len() > needed_clusters {
            let last = clusters.pop().unwrap();
            self.set_fat_entry(last, 0);
        }
        // 5. Завершаем цепочку
        if let Some(&last) = clusters.last() {
            self.set_fat_entry(last, 0x0FFFFFFF);
        }
        // 6. Записываем новые данные по кластерам
        let mut offset = 0;
        for &cl in &clusters {
            let cluster_offset = self.data_offset + (cl as u64 - 2) * cluster_size as u64;
            self.file.seek(SeekFrom::Start(cluster_offset))?;
            let to_write = (new_content.len() - offset).min(cluster_size);
            self.file
                .write_all(&new_content[offset..offset + to_write])?;
            if to_write < cluster_size {
                let zeroes = vec![0u8; cluster_size - to_write];
                self.file.write_all(&zeroes)?;
            }
            offset += to_write;
        }
        // 7. Обновляем размер файла в директории
        self.update_file_size_in_dir(entry.start_cluster, new_content.len() as u32)?;
        // 8. Сохраняем FAT на диск
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
        self.fat[offset..offset + 4].copy_from_slice(&(value & 0x0FFFFFFF).to_le_bytes());
    }

    fn flush_fat(&mut self) -> io::Result<()> {
        self.file.seek(SeekFrom::Start(self.fat_offset))?;
        self.file.write_all(&self.fat)?;
        if self.sync_on_write {
            self.file.sync_all()?;
        }
        Ok(())
    }

    fn update_file_size_in_dir(&mut self, start_cluster: u32, new_size: u32) -> io::Result<()> {
        // Находим запись в директории и обновляем размер (4 байта)
        let mut dir_cluster = self.root_cluster;
        loop {
            let cluster_offset = self.data_offset
                + (dir_cluster as u64 - 2)
                    * self.sectors_per_cluster as u64
                    * self.bytes_per_sector as u64;
            self.file.seek(SeekFrom::Start(cluster_offset))?;
            let mut buf =
                vec![0u8; self.sectors_per_cluster as usize * self.bytes_per_sector as usize];
            self.file.read_exact(&mut buf)?;
            for i in 0..(buf.len() / 32) {
                let entry = &mut buf[i * 32..(i + 1) * 32];
                let high = u16::from_le_bytes([entry[20], entry[21]]) as u32;
                let low = u16::from_le_bytes([entry[26], entry[27]]) as u32;
                let cl = (high << 16) | low;
                if cl == start_cluster {
                    entry[28..32].copy_from_slice(&new_size.to_le_bytes());
                    // Записываем обратно
                    self.file
                        .seek(SeekFrom::Start(cluster_offset + (i * 32) as u64))?;
                    self.file.write_all(entry)?;
                    return Ok(());
                }
            }
            dir_cluster = self.get_fat_entry(dir_cluster);
            if dir_cluster >= 0x0FFFFFF8 {
                break;
            }
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "dir entry not found",
        ))
    }

    fn create_entry_lfn(
        &mut self,
        name: &str,
        attr: u8,
        parent_cluster: u32, // кластер родителя (обычно root_cluster для корня)
    ) -> io::Result<Option<u32>> {
        let entries = self.list_directory(parent_cluster)?;
        if entries.iter().any(|e| e.name.eq_ignore_ascii_case(name)) {
            return Ok(None);
        }
        let (base, ext) = generate_short_name(
            name,
            &entries.iter().map(|e| e.name.clone()).collect::<Vec<_>>(),
        );
        let mut short_name = [b' '; 11];
        for (i, b) in base.as_bytes().iter().take(8).enumerate() {
            short_name[i] = *b;
        }
        for (i, b) in ext.as_bytes().iter().take(3).enumerate() {
            short_name[8 + i] = *b;
        }
        let checksum = lfn_checksum(&short_name);

        let new_cluster = self
            .find_free_cluster()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Нет свободных кластеров"))?;
        self.set_fat_entry(new_cluster, 0x0FFFFFFF);

        let lfn_entries = make_lfn_entries(name, checksum);

        let mut dir_entry = [0u8; 32];
        dir_entry[0..8].copy_from_slice(&short_name[0..8]);
        dir_entry[8..11].copy_from_slice(&short_name[8..11]);
        dir_entry[11] = attr; // 0x20 файл, 0x10 директория
        dir_entry[20..22].copy_from_slice(&((new_cluster >> 16) as u16).to_le_bytes());
        dir_entry[26..28].copy_from_slice(&(new_cluster as u16).to_le_bytes());
        dir_entry[28..32].copy_from_slice(&0u32.to_le_bytes());

        self.write_lfn_and_short_entry(parent_cluster, lfn_entries, dir_entry)?;
        self.flush_fat()?;
        Ok(Some(new_cluster))
    }

    pub fn create_file_lfn(&mut self, filename: &str) -> io::Result<bool> {
        Ok(self
            .create_entry_lfn(filename, 0x20, self.root_cluster)?
            .is_some())
    }

    pub fn delete_file_lfn(&mut self, filename: &str) -> io::Result<bool> {
        let mut dir_cluster = self.root_cluster;
        loop {
            let cluster_offset = self.data_offset
                + (dir_cluster as u64 - 2)
                    * self.sectors_per_cluster as u64
                    * self.bytes_per_sector as u64;
            self.file.seek(SeekFrom::Start(cluster_offset))?;
            let mut buf =
                vec![0u8; self.sectors_per_cluster as usize * self.bytes_per_sector as usize];
            self.file.read_exact(&mut buf)?;

            let mut i = 0;
            while i < buf.len() / 32 {
                // Собираем LFN-цепочку
                let mut lfn_stack = Vec::new();
                let mut j = i;
                while j < buf.len() / 32
                    && buf[j * 32 + 11] == LFN_ATTRIBUTE
                    && buf[j * 32] != 0xE5
                    && buf[j * 32] != 0x00
                {
                    lfn_stack.push(j);
                    j += 1;
                }
                if j >= buf.len() / 32 || buf[j * 32] == 0x00 {
                    break;
                }
                // Проверяем короткую запись
                if let Some((_short_name, start_cluster, _file_size)) =
                    parse_dir_entry(&buf[j * 32..(j + 1) * 32])
                {
                    let full_name = if !lfn_stack.is_empty() {
                        let mut name_parts = Vec::new();
                        for &lfn_idx in lfn_stack.iter().rev() {
                            if let Some(part) =
                                parse_lfn_entry(&buf[lfn_idx * 32..(lfn_idx + 1) * 32])
                            {
                                name_parts.push(part);
                            }
                        }
                        name_parts.concat()
                    } else {
                        _short_name.clone()
                    };
                    if full_name.eq_ignore_ascii_case(filename) {
                        // 1. Освобождаем цепочку кластеров
                        let mut cl = start_cluster;
                        while cl < 0x0FFFFFF8 && cl != 0 {
                            let next = self.get_fat_entry(cl);
                            self.set_fat_entry(cl, 0);
                            cl = next;
                        }
                        // 2. Помечаем LFN-записи как удалённые
                        for &lfn_idx in &lfn_stack {
                            buf[lfn_idx * 32] = 0xE5;
                        }
                        // 3. Помечаем короткую запись как удалённую
                        buf[j * 32] = 0xE5;
                        self.file.seek(SeekFrom::Start(cluster_offset))?;
                        self.file.write_all(&buf)?;
                        self.flush_fat()?;
                        return Ok(true);
                    }
                }
                i = j + 1;
            }
            dir_cluster = self.get_fat_entry(dir_cluster);
            if dir_cluster >= 0x0FFFFFF8 {
                break;
            }
        }
        Ok(false)
    }

    pub fn create_dir_lfn(&mut self, dirname: &str) -> io::Result<bool> {
        if let Some(new_cluster) = self.create_entry_lfn(dirname, 0x10, self.root_cluster)? {
            let cluster_size = self.sectors_per_cluster as usize * self.bytes_per_sector as usize;
            let mut buf = vec![0u8; cluster_size];

            // Запись "."
            let mut dot_entry = [b' '; 32];
            dot_entry[0] = b'.';
            dot_entry[11] = 0x10; // атрибут директории
            dot_entry[20..22].copy_from_slice(&((new_cluster >> 16) as u16).to_le_bytes());
            dot_entry[26..28].copy_from_slice(&(new_cluster as u16).to_le_bytes());

            // Запись ".."
            let mut dotdot_entry = [b' '; 32];
            dotdot_entry[0] = b'.';
            dotdot_entry[1] = b'.';
            dotdot_entry[11] = 0x10; // атрибут директории
            dotdot_entry[20..22].copy_from_slice(&((self.root_cluster >> 16) as u16).to_le_bytes());
            dotdot_entry[26..28].copy_from_slice(&(self.root_cluster as u16).to_le_bytes());

            // Копируем записи в буфер
            buf[0..32].copy_from_slice(&dot_entry);
            buf[32..64].copy_from_slice(&dotdot_entry);

            let cluster_offset = self.data_offset + (new_cluster as u64 - 2) * cluster_size as u64;
            self.file.seek(SeekFrom::Start(cluster_offset))?;
            self.file.write_all(&buf)?;
            self.flush_fat()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn delete_dir_lfn(&mut self, dirname: &str) -> io::Result<bool> {
        let mut dir_cluster = self.root_cluster;
        loop {
            let cluster_offset = self.data_offset
                + (dir_cluster as u64 - 2)
                    * self.sectors_per_cluster as u64
                    * self.bytes_per_sector as u64;
            self.file.seek(SeekFrom::Start(cluster_offset))?;
            let mut buf =
                vec![0u8; self.sectors_per_cluster as usize * self.bytes_per_sector as usize];
            self.file.read_exact(&mut buf)?;

            let mut i = 0;
            while i < buf.len() / 32 {
                let mut lfn_stack = Vec::new();
                let mut j = i;
                while j < buf.len() / 32
                    && buf[j * 32 + 11] == LFN_ATTRIBUTE
                    && buf[j * 32] != 0xE5
                    && buf[j * 32] != 0x00
                {
                    lfn_stack.push(j);
                    j += 1;
                }
                if j >= buf.len() / 32 || buf[j * 32] == 0x00 {
                    break;
                }
                if let Some((_short_name, start_cluster, _file_size)) =
                    parse_dir_entry(&buf[j * 32..(j + 1) * 32])
                {
                    let full_name = if !lfn_stack.is_empty() {
                        let mut name_parts = Vec::new();
                        for &lfn_idx in lfn_stack.iter().rev() {
                            if let Some(part) =
                                parse_lfn_entry(&buf[lfn_idx * 32..(lfn_idx + 1) * 32])
                            {
                                name_parts.push(part);
                            }
                        }
                        name_parts.concat()
                    } else {
                        _short_name.clone()
                    };
                    let attr = buf[j * 32 + 11];
                    if full_name.eq_ignore_ascii_case(dirname) && (attr & 0x10) != 0 {
                        // Проверяем, пуста ли директория
                        let entries = self.list_directory(start_cluster)?;
                        let only_dot = entries.iter().all(|e| e.name == "." || e.name == "..");
                        if !only_dot {
                            return Ok(false); // не пуста!
                        }
                        // Освободить кластер
                        let mut cl = start_cluster;
                        while cl < 0x0FFFFFF8 && cl != 0 {
                            let next = self.get_fat_entry(cl);
                            self.set_fat_entry(cl, 0);
                            cl = next;
                        }
                        // Пометить LFN и короткую запись как удалённые
                        for &lfn_idx in &lfn_stack {
                            buf[lfn_idx * 32] = 0xE5;
                        }
                        buf[j * 32] = 0xE5;
                        self.file.seek(SeekFrom::Start(cluster_offset))?;
                        self.file.write_all(&buf)?;
                        self.flush_fat()?;
                        return Ok(true);
                    }
                }
                i = j + 1;
            }
            dir_cluster = self.get_fat_entry(dir_cluster);
            if dir_cluster >= 0x0FFFFFF8 {
                break;
            }
        }
        Ok(false)
    }

    fn write_lfn_and_short_entry(
        &mut self,
        dir_cluster: u32,
        lfn_entries: Vec<[u8; 32]>,
        short_entry: [u8; 32],
    ) -> io::Result<()> {
        // Находим подряд N+1 свободных записей в директории
        let cluster_offset = self.data_offset
            + (dir_cluster as u64 - 2)
                * self.sectors_per_cluster as u64
                * self.bytes_per_sector as u64;
        self.file.seek(SeekFrom::Start(cluster_offset))?;
        let mut buf = vec![0u8; self.sectors_per_cluster as usize * self.bytes_per_sector as usize];
        self.file.read_exact(&mut buf)?;

        let total = lfn_entries.len() + 1;
        let mut free_idx = None;
        let mut count = 0;
        for i in 0..(buf.len() / 32) {
            let entry = &buf[i * 32..(i + 1) * 32];
            if entry[0] == 0x00 || entry[0] == 0xE5 {
                count += 1;
                if count == total {
                    free_idx = Some(i + 1 - total);
                    break;
                }
            } else {
                count = 0;
            }
        }
        let idx = free_idx
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Нет свободных записей"))?;
        // Записываем LFN
        for (j, lfn) in lfn_entries.iter().enumerate() {
            buf[(idx + j) * 32..(idx + j + 1) * 32].copy_from_slice(lfn);
        }
        // Записываем короткую запись
        buf[(idx + lfn_entries.len()) * 32..(idx + lfn_entries.len() + 1) * 32]
            .copy_from_slice(&short_entry);

        // Записываем обратно
        self.file.seek(SeekFrom::Start(cluster_offset))?;
        self.file.write_all(&buf)?;

        Ok(())
    }

    pub fn is_dir_empty(&mut self, dir_cluster: u32) -> std::io::Result<bool> {
        let mut current_cluster = dir_cluster;
        loop {
            let cluster_data = self.read_cluster(current_cluster)?;
            for i in 0..(cluster_data.len() / 32) {
                let entry = &cluster_data[i * 32..(i + 1) * 32];
                if entry[0] == 0x00 {
                    // Все последующие записи свободны
                    break;
                }
                if entry[0] == 0xE5 || entry[11] == LFN_ATTRIBUTE {
                    continue;
                }
                // Это короткая запись, не удалённая, не LFN
                let name_raw = &entry[0..8];
                let ext_raw = &entry[8..11];
                let name = String::from_utf8_lossy(name_raw).trim_end().to_string();
                let ext = String::from_utf8_lossy(ext_raw).trim_end().to_string();
                let filename = if ext.is_empty() {
                    name.clone()
                } else {
                    format!("{}.{}", name, ext)
                };
                if filename != "." && filename != ".." {
                    return Ok(false);
                }
            }
            current_cluster = self.get_fat_entry(current_cluster);
            if current_cluster >= 0x0FFFFFF8 {
                break;
            }
        }
        Ok(true)
    }

    pub fn open_esp<P: AsRef<str>>(path: Option<P>) -> io::Result<Option<Fat32Volume>> {
        if let Some(p) = path {
            // Открываем указанный образ или устройство
            let path_str = p.as_ref();
            let mut file = std::fs::File::open(path_str)?;
            // BPB обычно в самом начале
            let params = read_bpb(&mut file, 0)?;

            // Валидация параметров BPB
            if params.bytes_per_sector < 512 || params.bytes_per_sector > 4096 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "bytes_per_sector out of range",
                ));
            }
            if params.sectors_per_cluster == 0 || params.sectors_per_cluster > 128 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "sectors_per_cluster out of range",
                ));
            }
            if params.num_fats == 0 || params.num_fats > 4 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "num_fats out of range",
                ));
            }
            if params.sectors_per_fat == 0 || params.sectors_per_fat > 1_000_000 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "sectors_per_fat out of range",
                ));
            }

            Fat32Volume::open(
                false,
                path_str,
                0, // lba = 0 для образа
                params.bytes_per_sector,
                params.sectors_per_cluster as u32,
                params.reserved_sectors as u32,
                params.num_fats as u32,
                params.sectors_per_fat,
                params.root_cluster,
            )
            .map(Some)
        } else {
            match find_esp_device()? {
                Some((path, lba)) => {
                    let mut file = File::open(&path)?;

                    let bpb_offset = lba * 512;
                    let params = read_bpb(&mut file, bpb_offset)?;

                    log::info!(
                        "BPB: bytes_per_sector={}, sectors_per_cluster={}, reserved_sectors={}, num_fats={}, sectors_per_fat={}, root_cluster={}",
                        params.bytes_per_sector,
                        params.sectors_per_cluster,
                        params.reserved_sectors,
                        params.num_fats,
                        params.sectors_per_fat,
                        params.root_cluster
                    );

                    if params.bytes_per_sector < 512 || params.bytes_per_sector > 4096 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "bytes_per_sector out of range",
                        ));
                    }
                    if params.sectors_per_cluster == 0 || params.sectors_per_cluster > 128 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "sectors_per_cluster out of range",
                        ));
                    }
                    if params.num_fats == 0 || params.num_fats > 4 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "num_fats out of range",
                        ));
                    }
                    if params.sectors_per_fat == 0 || params.sectors_per_fat > 1_000_000 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "sectors_per_fat out of range",
                        ));
                    }

                    Fat32Volume::open(
                        true, // sync_on_write = true для реальных устройств (безопаснее)
                        &path,
                        lba, // LBA
                        params.bytes_per_sector,
                        params.sectors_per_cluster as u32,
                        params.reserved_sectors as u32,
                        params.num_fats as u32,
                        params.sectors_per_fat,
                        params.root_cluster,
                    )
                    .map(Some)
                }
                None => Ok(None),
            }
        }
    }
}

fn generate_short_name(long_name: &str, existing: &[String]) -> (String, String) {
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

fn lfn_checksum(short_name: &[u8; 11]) -> u8 {
    let mut sum = 0u8;
    for &b in short_name {
        sum = sum.rotate_right(1).wrapping_add(b);
    }
    sum
}

fn make_lfn_entries(long_name: &str, checksum: u8) -> Vec<[u8; 32]> {
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

fn parse_lfn_entry(entry: &[u8]) -> Option<String> {
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

fn parse_directory_entries(cluster_data: &[u8]) -> Vec<(String, u32, u32, u8)> {
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

pub fn find_esp_device() -> io::Result<Option<(String, u64)>> {
    #[cfg(target_os = "linux")]
    {
        use std::fs;

        // Проверка стандартных путей ESP
        let known_paths = [
            "/boot/efi",
            "/efi",
        ];

        // 1. Поиск устройства, на котором смонтирован ESP
        for mount_point in &known_paths {
            let path = Path::new(mount_point);
            if path.exists() {
                if let Ok(mounts) = fs::read_to_string("/proc/mounts") {
                    for line in mounts.lines() {
                        let fields: Vec<&str> = line.split_whitespace().collect();
                        if fields.len() >= 2 && fields[1] == *mount_point {
                            // fields[0] — это устройство, например /dev/sda1
                            return Ok(Some((fields[0].to_string(), 0)));
                        }
                    }
                }
            }
        }

        // 2. Проверка по /dev/disk/by-*
        let known_dev_paths = [
            "/dev/disk/by-label/ESP",
            "/dev/disk/by-label/EFI",
            "/dev/disk/by-partlabel/ESP",
            "/dev/disk/by-partlabel/EFI",
        ];
        for path in &known_dev_paths {
            let path = Path::new(path);
            if path.exists() {
                if let Ok(real_path) = fs::canonicalize(path) {
                    if let Some(path_str) = real_path.to_str() {
                        return Ok(Some((path_str.to_string(), 0)));
                    }
                }
            }
        }

        // 3. Сканирование физических устройств
        let sys_block = Path::new("/sys/block");
        for entry in fs::read_dir(sys_block)? {
            let entry = entry?;
            let dev_name = entry.file_name();
            let dev_path = entry.path();
            let dev_name_str = dev_name.to_string_lossy();

            // Пропуск виртуальных устройств
            if dev_name_str.starts_with("loop")
                || dev_name_str.starts_with("ram")
                || dev_name_str.starts_with("sr")
            {
                continue;
            }

            // Поиск разделов
            let pattern = format!("{}/{}*", dev_path.display(), dev_name_str);
            let entries = match glob(&pattern) {
                Ok(e) => e,
                Err(_) => continue,
            };

            for entry in entries.flatten() {
                // Проверка что это раздел
                if !entry.join("partition").exists() {
                    continue;
                }

                // Читаем PARTLABEL или PARTUUID для проверки, что это ESP
                let partlabel_path = entry.join("partlabel");
                let is_esp = if partlabel_path.exists() {
                    if let Ok(label) = fs::read_to_string(&partlabel_path) {
                        label.trim().eq_ignore_ascii_case("EFI System Partition") ||
                        label.trim().eq_ignore_ascii_case("ESP") ||
                        label.trim().eq_ignore_ascii_case("EFI")
                    } else {
                        false
                    }
                } else {
                    false
                };

                if !is_esp {
                    // Альтернативно: можно проверить type_guid, если есть
                    let type_path = entry.join("type");
                    if type_path.exists() {
                        if let Ok(type_guid) = fs::read_to_string(&type_path) {
                            // GUID ESP: c12a7328-f81f-11d2-ba4b-00a0c93ec93b
                            if !type_guid.trim().eq_ignore_ascii_case("c12a7328-f81f-11d2-ba4b-00a0c93ec93b") {
                                continue;
                            }
                        } else {
                            continue;
                        }
                    } else {
                        continue;
                    }
                }

                let part_name = entry.file_name().unwrap().to_str().unwrap();
                let dev_file = format!("/dev/{}", part_name);

                // Получаем LBA начала раздела
                let start_lba_path = entry.join("start");
                let start_lba = if start_lba_path.exists() {
                    fs::read_to_string(&start_lba_path)
                        .ok()
                        .and_then(|s| s.trim().parse::<u64>().ok())
                        .unwrap_or(0)
                } else {
                    0
                };

                // Проверка сигнатуры FAT
                if let Ok(mut f) = File::open(&dev_file) {
                    let mut header = [0u8; 3];
                    if f.read_exact(&mut header).is_ok() {
                        if &header == b"FAT" || &header == b"MSD" {
                            // Это FAT-раздел
                            return Ok(Some((dev_file, start_lba)));
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    #[cfg(target_os = "windows")]
    {
        use std::fs::OpenOptions;
        use std::io::Seek;
        use std::os::windows::fs::OpenOptionsExt;
        use std::path::PathBuf;
        use winapi::um::fileapi::{GetDriveTypeW, GetLogicalDrives};
        use winapi::um::winbase::{DRIVE_FIXED, DRIVE_NO_ROOT_DIR};

        // 1. Поиск по буквам дисков через файловую систему
        let drives = unsafe { GetLogicalDrives() };
        log::debug!("Logical drives bitmap: {:b}", drives);

        for i in 0..26 {
            if (drives & (1 << i)) != 0 {
                let drive_letter_char = (b'A' + i) as char;
                let drive_letter = format!(r"{}:\", drive_letter_char);
                log::debug!("Checking drive: {}", drive_letter);

                let wide_path: Vec<u16> = drive_letter.encode_utf16().chain(Some(0)).collect();

                let drive_type = unsafe { GetDriveTypeW(wide_path.as_ptr()) };
                log::debug!("Drive type: {}", drive_type);

                if drive_type == DRIVE_FIXED || drive_type == DRIVE_NO_ROOT_DIR {
                    // Проверяем наличие стандартных EFI путей
                    let test_paths = [
                        PathBuf::from(&drive_letter).join(r"EFI\BOOT\BOOTX64.EFI"),
                        PathBuf::from(&drive_letter).join(r"EFI\MICROSOFT\BOOT\BOOTMGFW.EFI"),
                    ];

                    for test_path in &test_paths {
                        log::debug!("Checking path: {}", test_path.display());
                        if test_path.exists() {
                            log::debug!("Found bootloader at: {}", test_path.display());
                            return Ok(Some((format!(r"\\.\{}:", drive_letter_char), 0)));
                        }
                    }
                }
            }
        }

        log::debug!("No drives with bootloader found, checking physical drives...");

        // 2. Поиск по GPT разделам
        for disk_num in 0..4 {
            let device_path = format!(r"\\.\PhysicalDrive{}", disk_num);
            log::debug!("Checking physical drive: {}", device_path);

            match OpenOptions::new()
                .read(true)
                .share_mode(0)
                .open(&device_path)
            {
                Ok(mut f) => {
                    // Проверяем GPT сигнатуру
                    let mut header = [0u8; 512];
                    if let Err(e) = f.read_exact(&mut header) {
                        log::debug!("Failed to read header: {}", e);
                        continue;
                    }

                    // Проверка защитного MBR (тип 0xEE)
                    let mbr_valid = header[510] == 0x55 && header[511] == 0xAA;
                    let protective_mbr = mbr_valid && header[450] == 0xEE;

                    if protective_mbr {
                        log::debug!("Found protective MBR (GPT disk)");

                        // Читаем GPT header
                        let mut gpt_header = [0u8; 512];
                        f.seek(SeekFrom::Start(512))?;
                        if let Err(e) = f.read_exact(&mut gpt_header) {
                            log::debug!("Failed to read GPT header: {}", e);
                            continue;
                        }

                        // Сигнатура GPT
                        if &gpt_header[0..8] != b"EFI PART" {
                            log::debug!("Invalid GPT signature");
                            continue;
                        }

                        // Ищем раздел с типом ESP
                        let part_entry_start =
                            u64::from_le_bytes(gpt_header[72..80].try_into().unwrap());
                        let part_entry_size =
                            u32::from_le_bytes(gpt_header[84..88].try_into().unwrap());
                        let num_part_entries =
                            u32::from_le_bytes(gpt_header[80..84].try_into().unwrap());

                        log::debug!(
                            "Partition entries start: {} size: {} count: {}",
                            part_entry_start, part_entry_size, num_part_entries
                        );

                        // Читаем таблицу разделов
                        f.seek(SeekFrom::Start(part_entry_start * 512))?;
                        let mut part_table =
                            vec![0u8; (part_entry_size * num_part_entries) as usize];
                        f.read_exact(&mut part_table)?;

                        for i in 0..num_part_entries {
                            let offset = (i * part_entry_size) as usize;
                            let part_type = &part_table[offset..offset + 16];

                            // GUID для ESP раздела: C12A7328-F81F-11D2-BA4B-00A0C93EC93B
                            if part_type
                                == [
                                    0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B,
                                    0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B,
                                ]
                            {
                                let part_start = u64::from_le_bytes(
                                    part_table[offset + 32..offset + 40].try_into().unwrap(),
                                );
                                log::debug!("Found ESP partition at LBA: {}", part_start);

                                // Возвращаем путь к физическому диску
                                return Ok(Some((device_path, part_start)));
                            }
                        }
                    }
                }
                Err(e) => {
                    log::debug!("Error opening device: {}", e);
                }
            }
        }

        log::debug!("No ESP partition found after full scan");
        Ok(None)
    }

    // Для других ОС или если ничего не найдено
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    Ok(None)
}
