use super::*;
use crate::fat32::directory::parse_directory_entries;
use crate::fat32::file::{
    lfn_checksum, make_lfn_entries, parse_dir_entry, parse_lfn_entry,
};
use crate::fat32::lfn::generate_short_name;

// Используем платформозависимую функцию поиска ESP
use crate::platform::find_esp_device;

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
    #[cfg(windows)]
    volume_path: Option<std::path::PathBuf>, // Путь к Volume для Windows (\\?\Volume{GUID}\)
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
        // На Windows открываем PhysicalDrive без специальных флагов, чтобы избежать требований выравнивания буферов
        #[cfg(windows)]
        let mut file = {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(device_path)?
        };
        
        #[cfg(not(windows))]
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
            #[cfg(windows)]
            volume_path: None, // Will be set in open_esp if needed
        })
    }

    /// Обновляет кеш FAT из файловой системы (перечитывает FAT таблицу с диска)
    pub fn refresh_fat_cache(&mut self) -> io::Result<()> {
        self.file.seek(SeekFrom::Start(self.fat_offset))?;
        self.file.read_exact(&mut self.fat)?;
        log::debug!("FAT cache refreshed from disk");
        Ok(())
    }

    /// Полностью сбрасывает все кеши и синхронизирует с диском
    pub fn refresh_all_caches(&mut self) -> io::Result<()> {
        // Синхронизируем все записи на диск
        self.file.sync_all()?;

        // На Windows: если знаем GUID-путь тома, открываем именно том и выполняем Flush + LOCK/UNLOCK
        #[cfg(windows)]
        {
            use std::ffi::OsStr;
            use std::os::windows::ffi::OsStrExt;
            use winapi::um::fileapi::{CreateFileW, FlushFileBuffers, OPEN_EXISTING};
            use winapi::um::handleapi::INVALID_HANDLE_VALUE;
            use winapi::um::ioapiset::DeviceIoControl;
            use winapi::um::winioctl::{FSCTL_LOCK_VOLUME, FSCTL_UNLOCK_VOLUME};
            use winapi::um::winnt::{FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, GENERIC_WRITE};

            if let Some(ref vol_path) = self.volume_path {
                // Удаляем завершающий обратный слэш, чтобы CreateFileW открыл том
                let mut s = vol_path.as_os_str().to_string_lossy().to_string();
                if s.ends_with('\\') {
                    s.pop();
                }
                let wide: Vec<u16> = OsStr::new(&s).encode_wide().chain(Some(0)).collect();
                unsafe {
                    let h = CreateFileW(
                        wide.as_ptr(),
                        GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        std::ptr::null_mut(),
                        OPEN_EXISTING,
                        0,
                        std::ptr::null_mut(),
                    );
                    if h != INVALID_HANDLE_VALUE {
                        // Сброс буферов тома
                        let _ = FlushFileBuffers(h);
                        // Лёгкая последовательность LOCK/UNLOCK, чтобы заставить систему синхронизировать состояние
                        let mut br: u32 = 0;
                        let _ = DeviceIoControl(
                            h,
                            FSCTL_LOCK_VOLUME,
                            std::ptr::null_mut(),
                            0,
                            std::ptr::null_mut(),
                            0,
                            &mut br,
                            std::ptr::null_mut(),
                        );
                        std::thread::sleep(std::time::Duration::from_millis(100));
                        let _ = DeviceIoControl(
                            h,
                            FSCTL_UNLOCK_VOLUME,
                            std::ptr::null_mut(),
                            0,
                            std::ptr::null_mut(),
                            0,
                            &mut br,
                            std::ptr::null_mut(),
                        );
                        // Закрываем дескриптор
                        winapi::um::handleapi::CloseHandle(h);
                    }
                }
            }
        }

        // Обновляем FAT кеш после всех операций
        self.refresh_fat_cache()?;

        log::info!("All caches refreshed and synced with disk");
        Ok(())
    }

    fn read_cluster(&mut self, cluster_num: u32) -> io::Result<Vec<u8>> {
        // Validate cluster number
        if cluster_num < 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid cluster number {} (must be >= 2)", cluster_num),
            ));
        }

        let cluster_size = self.sectors_per_cluster as u64 * self.bytes_per_sector as u64;
        let cluster_offset = self.data_offset + (cluster_num as u64 - 2) * cluster_size;

        // Всегда делаем seek перед чтением, чтобы гарантировать чтение с диска
        self.file.seek(SeekFrom::Start(cluster_offset))?;

        let mut buf = vec![0u8; cluster_size as usize];
        self.file.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// Читает цепочку кластеров начиная с указанного
    fn read_chain(&mut self, start_cluster: u32) -> io::Result<Vec<u8>> {
        let mut data = Vec::new();
        let mut current_cluster = start_cluster;

        while current_cluster < 0x0FFFFFF8 && current_cluster != 0 {
            let cluster_data = self.read_cluster(current_cluster)?;
            data.extend_from_slice(&cluster_data);
            current_cluster = self.get_fat_entry(current_cluster);
        }

        Ok(data)
    }

    /// Записывает данные в цепочку кластеров начиная с указанного
    fn write_chain(&mut self, start_cluster: u32, data: &[u8]) -> io::Result<()> {
        let cluster_size = self.sectors_per_cluster as usize * self.bytes_per_sector as usize;
        let mut current_cluster = start_cluster;
        let mut offset = 0;

        while current_cluster < 0x0FFFFFF8 && current_cluster != 0 && offset < data.len() {
            let cluster_offset =
                self.data_offset + (current_cluster as u64 - 2) * cluster_size as u64;
            self.file.seek(SeekFrom::Start(cluster_offset))?;

            let to_write = (data.len() - offset).min(cluster_size);
            self.file.write_all(&data[offset..offset + to_write])?;

            // Если данные не помещаются полностью в кластер, заполняем остаток нулями
            if to_write < cluster_size {
                let zeros = vec![0u8; cluster_size - to_write];
                self.file.write_all(&zeros)?;
            }

            offset += to_write;
            current_cluster = self.get_fat_entry(current_cluster);
        }

        if self.sync_on_write {
            self.file.sync_all()?;
        }

        Ok(())
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

    pub fn read_file(&mut self, path: &str) -> io::Result<Option<Vec<u8>>> {
        log::debug!("read_file: Reading file at path: {}", path);
        
        // Normalize path
        let path_normalized = path.replace('\\', "/");
        let parts: Vec<&str> = path_normalized
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();
        
        log::debug!("read_file: Path parts: {:?}", parts);
        
        if parts.is_empty() {
            return Ok(None);
        }
        
        // Determine parent directory and filename
        let filename = parts.last().unwrap();
        let parent_cluster = if parts.len() > 1 {
            // Find the parent directory
            let dir_path = parts[..parts.len() - 1].join("/");
            log::debug!("read_file: Looking for parent directory: {}", dir_path);
            match self.find_directory(&dir_path)? {
                Some(cluster) => {
                    log::debug!("read_file: Parent directory found at cluster {}", cluster);
                    cluster
                },
                None => {
                    log::debug!("read_file: Parent directory not found");
                    return Ok(None);
                }
            }
        } else {
            // File is in root directory
            log::debug!("read_file: File is in root directory (cluster {})", self.root_cluster);
            self.root_cluster
        };
        
        // List files in parent directory
        log::debug!("read_file: Listing directory at cluster {}", parent_cluster);
        let entries = self.list_directory(parent_cluster)?;
        log::debug!("read_file: Found {} entries in directory", entries.len());
        
        // Find the file
        for entry in entries {
            log::debug!("read_file: Checking entry: name='{}', is_dir={}, size={}, cluster={}", 
                       entry.name.trim(), entry.is_directory, entry.size, entry.start_cluster);
            if entry.name.trim().eq_ignore_ascii_case(filename) && !entry.is_directory {
                log::debug!("read_file: Found matching file, reading {} bytes from cluster {}", 
                           entry.size, entry.start_cluster);
                
                let mut cluster = entry.start_cluster;
                let mut remaining = entry.size;
                let mut content = Vec::new();
                
                while cluster < 0x0FFFFFF8 && cluster != 0 {
                    log::debug!("read_file: Reading cluster {}, {} bytes remaining", cluster, remaining);
                    let data = self.read_cluster(cluster)?;
                    let to_take = remaining.min(data.len() as u32) as usize;
                    content.extend_from_slice(&data[..to_take]);
                    remaining -= to_take as u32;
                    if remaining == 0 {
                        break;
                    }
                    cluster = self.get_fat_entry(cluster);
                }
                
                log::debug!("read_file: Successfully read {} bytes", content.len());
                return Ok(Some(content));
            }
        }
        
        log::debug!("read_file: File '{}' not found in directory", filename);
        Ok(None)
    }

    /// Записывает файл по пути (с созданием директорий если необходимо)
    pub fn write_file_with_path(&mut self, path: &str, new_content: &[u8]) -> io::Result<bool> {
        // На Windows пытаемся сначала использовать filesystem-based write
        #[cfg(windows)]
        {
            use std::path::Path;

            // Создаём директории если нужно
            let path_normalized = path.replace('\\', "/");
            let parts: Vec<&str> = path_normalized
                .split('/')
                .filter(|s| !s.is_empty())
                .collect();

            if parts.len() > 1 {
                let dir_path = parts[..parts.len() - 1].join("/");
                self.create_directory_path(&dir_path)?;
            }

            if let Err(e) = crate::platform::windows::write_file_to_esp(Path::new(path), new_content) {
                log::warn!(
                    "write_file_to_esp failed for {}, falling back to raw write: {}",
                    path,
                    e
                );
            } else {
                // После успешной записи через Windows API максимально синхронизируемся
                if let Err(e) = self.refresh_all_caches() {
                    log::warn!("Failed to refresh caches after write: {}", e);
                }

                // Подождём, пока файловая система отразит изменения (ESP часто кешируется)
                let path_normalized = path.replace('\\', "/");
                let parts: Vec<&str> = path_normalized
                    .split('/')
                    .filter(|s| !s.is_empty())
                    .collect();
                let filename = parts.last().copied().unwrap_or("");
                let parent_cluster = if parts.len() > 1 {
                    let dir_path = parts[..parts.len() - 1].join("/");
                    match self.find_directory(&dir_path)? {
                        Some(cluster) => cluster,
                        None => self.root_cluster,
                    }
                } else {
                    self.root_cluster
                };

                let mut visible = false;
                for attempt in 0..30 {
                    let entries = self.list_directory(parent_cluster)?;
                    if entries.iter().any(|e| !e.is_directory && e.name.trim().eq_ignore_ascii_case(filename)) {
                        visible = true;
                        log::info!("File '{}' visible after {} attempt(s)", filename, attempt + 1);
                        break;
                    }
                    log::debug!("File '{}' not yet visible (attempt {}/30), sleeping...", filename, attempt + 1);
                    std::thread::sleep(std::time::Duration::from_millis(200));
                    // Попробуем так же обновить FAT кеш между попытками
                    let _ = self.refresh_fat_cache();
                }
                if !visible {
                    log::warn!("File '{}' not visible after write via Windows API, continuing anyway", filename);
                }

                return Ok(true);
            }
        }

        // Разделяем путь на директории и имя файла
        let path_normalized = path.replace('\\', "/");
        let parts: Vec<&str> = path_normalized
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        if parts.is_empty() {
            return Ok(false);
        }

        let filename = parts.last().unwrap();
        let dir_path = if parts.len() > 1 {
            parts[..parts.len() - 1].join("/")
        } else {
            String::new()
        };

        // Создаём директории если нужно
        if !dir_path.is_empty() {
            self.create_directory_path(&dir_path)?;
        }

        // Находим родительскую директорию
        let parent_cluster = if dir_path.is_empty() {
            self.root_cluster
        } else {
            self.find_directory(&dir_path)?.ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "Parent directory not found")
            })?
        };

        // Ищем файл в родительской директории
        let entries = self.list_directory(parent_cluster)?;
        let mut existing_entry = None;
        for entry in &entries {
            if entry.name.trim().eq_ignore_ascii_case(filename) && !entry.is_directory {
                existing_entry = Some(entry.clone());
                break;
            }
        }

        // Если файл не существует, создаём его
        let entry = match existing_entry {
            Some(e) => e,
            None => {
                // Создаём новый файл
                if let Some(new_cluster) = self.create_entry_lfn(filename, 0x20, parent_cluster)? {
                    // Создаём новую структуру для нового файла
                    Fat32FileEntry {
                        name: filename.to_string(),
                        start_cluster: new_cluster,
                        size: 0,
                        is_directory: false,
                    }
                } else {
                    return Ok(false);
                }
            }
        };

        // Далее логика записи содержимого (как в оригинале)
        self.write_file_content(&entry, new_content, parent_cluster)
    }

    pub fn write_file(&mut self, filename: &str, new_content: &[u8]) -> io::Result<bool> {
        self.write_file_with_path(filename, new_content)
    }

    // Вспомогательный метод для записи содержимого файла
    fn write_file_content(
        &mut self,
        entry: &Fat32FileEntry,
        new_content: &[u8],
        parent_cluster: u32,
    ) -> io::Result<bool> {
        let cluster_size = self.sectors_per_cluster as usize * self.bytes_per_sector as usize;
        let needed_clusters = (new_content.len() + cluster_size - 1) / cluster_size;

        // Собираем текущую цепочку кластеров
        let mut clusters = Vec::new();
        let mut cluster = entry.start_cluster;

        // Если это новый файл с кластером 0, выделяем первый кластер
        if cluster == 0 || cluster >= 0x0FFFFFF8 {
            let free = self
                .find_free_cluster()
                .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Нет свободных кластеров"))?;
            // Сразу помечаем как занятый (EOC), чтобы не выбрать повторно
            self.set_fat_entry(free, 0x0FFFFFFF);
            clusters.push(free);
            // Обновляем запись в директории с новым start_cluster
            self.update_file_start_cluster_in_dir(parent_cluster, &entry.name, free)?;
        } else {
            while cluster < 0x0FFFFFF8 {
                clusters.push(cluster);
                cluster = self.get_fat_entry(cluster);
            }
        }

        // Если не хватает кластеров — выделяем новые
        while clusters.len() < needed_clusters {
            let free = self
                .find_free_cluster()
                .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Нет свободных кластеров"))?;
            // Сразу помечаем новый кластер как EOC (занят), затем свяжем предыдущий на него
            self.set_fat_entry(free, 0x0FFFFFFF);
            self.set_fat_entry(*clusters.last().unwrap(), free);
            clusters.push(free);
        }

        // Если лишние — освобождаем
        while clusters.len() > needed_clusters {
            let last = clusters.pop().unwrap();
            self.set_fat_entry(last, 0);
        }

        // Завершаем цепочку
        if let Some(&last) = clusters.last() {
            self.set_fat_entry(last, 0x0FFFFFFF);
        }

        // Записываем новые данные по кластерам
        let mut offset = 0;
        for &cl in &clusters {
            let cluster_offset = self.data_offset + (cl as u64 - 2) * cluster_size as u64;
            self.file.seek(SeekFrom::Start(cluster_offset))?;
            let to_write = (new_content.len() - offset).min(cluster_size);

            #[cfg(windows)]
            {
                // На Windows используем улучшенную стратегию записи для ESP
                match self.write_data_with_retry(&new_content[offset..offset + to_write]) {
                    Ok(_) => {}
                    Err(e) => return Err(e),
                }
                if to_write < cluster_size {
                    let zeroes = vec![0u8; cluster_size - to_write];
                    match self.write_data_with_retry(&zeroes) {
                        Ok(_) => {}
                        Err(e) => return Err(e),
                    }
                }
            }
            #[cfg(not(windows))]
            {
                self.file
                    .write_all(&new_content[offset..offset + to_write])?;
                if to_write < cluster_size {
                    let zeroes = vec![0u8; cluster_size - to_write];
                    self.file.write_all(&zeroes)?;
                }
            }

            offset += to_write;
        }

        // Обновляем размер файла в директории
        let first_cluster = clusters.first().copied();
        self.update_file_size_in_dir_by_name(
            parent_cluster,
            &entry.name,
            new_content.len() as u32,
            first_cluster,
        )?;

        // Сохраняем FAT на диск
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
        let short_name = generate_short_name(
            name,
            &entries.iter().map(|e| e.name.clone()).collect::<Vec<_>>(),
        );
        let _checksum = lfn_checksum(&short_name);

        // Для файлов НЕ выделяем кластер сразу, он будет выделен при записи
        // Для директорий выделяем кластер сразу, так как нужно инициализировать . и ..
        let new_cluster = if attr == 0x10 {
            // Директория - выделяем кластер
            let cluster = self
                .find_free_cluster()
                .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Нет свободных кластеров"))?;
            self.set_fat_entry(cluster, 0x0FFFFFFF);
            cluster
        } else {
            // Файл - не выделяем кластер, используем 0
            0
        };

        let lfn_entries = make_lfn_entries(name, &short_name);

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

    /// Находит директорию по пути и возвращает её кластер
    pub fn find_directory(&mut self, path: &str) -> io::Result<Option<u32>> {
        // Нормализуем путь
        let path_normalized = path.replace('\\', "/");
        let parts: Vec<&str> = path_normalized
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        if parts.is_empty() {
            return Ok(Some(self.root_cluster));
        }

        let mut current_cluster = self.root_cluster;

        for part in parts {
            let entries = self.list_directory(current_cluster)?;
            let mut found = false;

            // Пробуем найти точное совпадение или совпадение без учёта регистра
            for entry in &entries {
                let entry_name = entry.name.trim();

                // Проверяем разные варианты имени:
                // 1. Точное совпадение без учёта регистра
                // 2. Совпадение с подчёркиванием вместо пробелов
                // 3. Совпадение коротких имён 8.3
                if entry.is_directory
                    && (entry_name.eq_ignore_ascii_case(part) ||
                    entry_name.replace('_', " ").eq_ignore_ascii_case(part) ||
                    entry_name.replace(' ', "_").eq_ignore_ascii_case(part) ||
                    // Проверяем короткое имя 8.3 (если длинное имя обрезано)
                    (part.len() > 8 && entry_name.eq_ignore_ascii_case(&part[..8.min(part.len())])))
                {
                    current_cluster = entry.start_cluster;
                    found = true;
                    log::debug!("Found directory '{}' as '{}'", part, entry_name);
                    break;
                }
            }

            if !found {
                log::debug!(
                    "Directory '{}' not found in cluster {}",
                    part,
                    current_cluster
                );
                log::debug!(
                    "Available entries: {:?}",
                    entries
                        .iter()
                        .filter(|e| e.is_directory)
                        .map(|e| e.name.clone())
                        .collect::<Vec<_>>()
                );
                return Ok(None);
            }
        }

        Ok(Some(current_cluster))
    }

    /// Создаёт директории по пути (mkdir -p)
    pub fn create_directory_path(&mut self, path: &str) -> io::Result<bool> {
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

        if parts.is_empty() {
            return Ok(true); // Корневая директория уже существует
        }

        // На Windows пытаемся сначала использовать Windows API для создания директорий
        #[cfg(windows)]
        {
            use std::path::Path;

            // Пробуем создать всю структуру директорий через Windows API
            if let Err(e) = crate::platform::windows::create_directory_on_esp(Path::new(path)) {
                log::warn!(
                    "create_directory_on_esp failed for {}, falling back to raw write: {}",
                    path,
                    e
                );
            } else {
                log::info!("Created directory path {} via Windows API", path);
                // После успешного создания через Windows API обновляем все кеши
                if let Err(e) = self.refresh_all_caches() {
                    log::warn!("Failed to refresh caches after directory creation: {}", e);
                }
                return Ok(true);
            }
        }

        // Fallback на raw метод для не-Windows или если Windows API не работает
        let mut current_cluster = self.root_cluster;

        for part in parts {
            let entries = self.list_directory(current_cluster)?;
            let mut found = false;

            for entry in entries {
                if entry.name.trim().eq_ignore_ascii_case(part) && entry.is_directory {
                    current_cluster = entry.start_cluster;
                    found = true;
                    break;
                }
            }

            if !found {
                // Создаём директорию
                if let Some(new_cluster) = self.create_entry_lfn(part, 0x10, current_cluster)? {
                    // Инициализируем новую директорию с . и ..
                    let cluster_size =
                        self.sectors_per_cluster as usize * self.bytes_per_sector as usize;
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
                    dotdot_entry[20..22]
                        .copy_from_slice(&((current_cluster >> 16) as u16).to_le_bytes());
                    dotdot_entry[26..28].copy_from_slice(&(current_cluster as u16).to_le_bytes());

                    // Копируем записи в буфер
                    buf[0..32].copy_from_slice(&dot_entry);
                    buf[32..64].copy_from_slice(&dotdot_entry);

                    let cluster_offset =
                        self.data_offset + (new_cluster as u64 - 2) * cluster_size as u64;
                    self.file.seek(SeekFrom::Start(cluster_offset))?;
                    self.file.write_all(&buf)?;
                    self.flush_fat()?;

                    current_cluster = new_cluster;
                } else {
                    return Ok(false); // Не удалось создать директорию
                }
            }
        }

        Ok(true)
    }

    /// Создаёт файл по пути (с созданием директорий если необходимо)
    pub fn create_file_with_path(&mut self, path: &str) -> io::Result<bool> {
        // Разделяем путь на директории и имя файла
        let path_normalized = path.replace('\\', "/");
        let parts: Vec<&str> = path_normalized
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        if parts.is_empty() {
            return Ok(false);
        }

        let filename = parts.last().unwrap();
        let dir_path = if parts.len() > 1 {
            parts[..parts.len() - 1].join("/")
        } else {
            String::new()
        };

        // Создаём директории если нужно
        if !dir_path.is_empty() {
            self.create_directory_path(&dir_path)?;
        }

        // Находим родительскую директорию
        let parent_cluster = if dir_path.is_empty() {
            self.root_cluster
        } else {
            self.find_directory(&dir_path)?.ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "Parent directory not found")
            })?
        };

        // На Windows используем write_file_to_esp для создания пустого файла
        #[cfg(windows)]
        {
            use std::path::Path;

            // Проверяем, существует ли файл
            let entries = self.list_directory(parent_cluster)?;
            for entry in entries {
                if entry.name.trim().eq_ignore_ascii_case(filename) {
                    return Ok(false); // Файл уже существует
                }
            }

            // Создаём пустой файл через write_file_to_esp
            match crate::platform::windows::write_file_to_esp(Path::new(path), b"") {
                Ok(_) => {
                    log::info!("Created file {} via write_file_to_esp", path);
                    // После успешной записи через Windows API обновляем все кеши
                    if let Err(e) = self.refresh_all_caches() {
                        log::warn!("Failed to refresh caches after file creation: {}", e);
                    }
                    return Ok(true);
                }
                Err(e) => {
                    log::warn!(
                        "Failed to create file via write_file_to_esp: {}, falling back to raw",
                        e
                    );
                    // Падаем на raw метод
                }
            }
        }

        // Fallback на raw метод для не-Windows или если write_file_to_esp не работает
        Ok(self
            .create_entry_lfn(filename, 0x20, parent_cluster)?
            .is_some())
    }

    pub fn create_file_lfn(&mut self, filename: &str) -> io::Result<bool> {
        self.create_file_with_path(filename)
    }

    pub fn delete_file_lfn(&mut self, filename: &str) -> io::Result<bool> {
        // На Windows пытаемся сначала использовать Windows API для удаления
        #[cfg(windows)]
        {
            use std::path::Path;

            // Пробуем удалить через Windows API
            if let Err(e) = crate::platform::windows::delete_file_from_esp(Path::new(filename)) {
                log::warn!(
                    "delete_file_from_esp failed for {}, falling back to raw delete: {}",
                    filename,
                    e
                );
            } else {
                log::info!("Deleted file {} via Windows API", filename);
                // После успешного удаления через Windows API обновляем все кеши
                if let Err(e) = self.refresh_all_caches() {
                    log::warn!("Failed to refresh caches after file deletion: {}", e);
                }
                return Ok(true);
            }
        }

        // Нормализуем путь и вычисляем директорию-родителя и имя файла
        let path_normalized = filename.replace('\\', "/");
        let parts: Vec<&str> = path_normalized.split('/').filter(|s| !s.is_empty()).collect();
        if parts.is_empty() {
            return Ok(false);
        }
        let target_name = parts.last().unwrap().trim().to_string();
        let mut dir_cluster = if parts.len() > 1 {
            let dir_path = parts[..parts.len() - 1].join("/");
            match self.find_directory(&dir_path)? {
                Some(c) => c,
                None => return Ok(false),
            }
        } else {
            self.root_cluster
        };

        // Raw удаление в пределах найденной директории
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
                    if full_name.trim().eq_ignore_ascii_case(&target_name) {
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
        // На Windows пытаемся сначала использовать Windows API для удаления
        #[cfg(windows)]
        {
            use std::path::Path;

            // Пробуем удалить через Windows API
            if let Err(e) = crate::platform::windows::delete_directory_from_esp(Path::new(dirname)) {
                log::warn!(
                    "delete_directory_from_esp failed for {}, falling back to raw delete: {}",
                    dirname,
                    e
                );
            } else {
                log::info!("Deleted directory {} via Windows API", dirname);
                // После успешного удаления через Windows API обновляем все кеши
                if let Err(e) = self.refresh_all_caches() {
                    log::warn!("Failed to refresh caches after directory deletion: {}", e);
                }
                return Ok(true);
            }
        }

        // Нормализуем путь, определяем родителя и целевое имя каталога
        let path_normalized = dirname.replace('\\', "/");
        let parts: Vec<&str> = path_normalized.split('/').filter(|s| !s.is_empty()).collect();
        if parts.is_empty() {
            return Ok(false);
        }
        let target_name = parts.last().unwrap().trim().to_string();
        let mut dir_cluster = if parts.len() > 1 {
            let parent_path = parts[..parts.len() - 1].join("/");
            match self.find_directory(&parent_path)? {
                Some(c) => c,
                None => return Ok(false),
            }
        } else {
            self.root_cluster
        };

        // Raw удаление каталога в пределах найденной директории
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
                    if full_name.trim().eq_ignore_ascii_case(&target_name) && (attr & 0x10) != 0 {
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

    #[cfg(windows)]
    fn write_data_with_retry(&mut self, data: &[u8]) -> io::Result<()> {
        // Сначала пробуем обычную запись
        match self.file.write_all(data) {
            Ok(_) => return Ok(()),
            Err(ref e) if e.kind() == io::ErrorKind::PermissionDenied => {
                // Если получили ACCESS_DENIED, применяем стратегии из прототипа
                log::warn!("Got ACCESS_DENIED, trying advanced ESP writing strategies");
            }
            Err(e) => return Err(e),
        }

        // Стратегии записи для ESP на Windows (из прототипа)
        use crate::platform::windows::write_file_to_esp;
        use std::path::Path;
        use uuid::Uuid;

        // Создаем временный файл для данных
        let tmp_filename = format!("tmp-{}.bin", Uuid::new_v4());
        let tmp_path = Path::new(&tmp_filename);

        // Используем write_file_to_esp для записи временных данных
        match write_file_to_esp(tmp_path, data) {
            Ok(_) => {
                log::info!("Successfully wrote data using ESP writing strategies");
                Ok(())
            }
            Err(e) => {
                log::error!("Failed to write data using ESP strategies: {}", e);
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("ESP write failed: {}", e),
                ))
            }
        }
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
            match find_esp_device().map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))? {
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

                    #[cfg_attr(not(windows), allow(unused_mut))]
                    let mut volume = Fat32Volume::open(
                        true, // sync_on_write = true для реальных устройств (безопаснее)
                        &path,
                        lba, // LBA
                        params.bytes_per_sector,
                        params.sectors_per_cluster as u32,
                        params.reserved_sectors as u32,
                        params.num_fats as u32,
                        params.sectors_per_fat,
                        params.root_cluster,
                    )?;

                    // На Windows пытаемся получить Volume path для ESP
                    #[cfg(windows)]
                    {
                        if let Some(vol_path) = crate::platform::windows::find_esp_volume_path() {
                            volume.volume_path = Some(vol_path);
                            log::info!("ESP volume path set: {:?}", volume.volume_path);
                        }
                    }

                    Ok(Some(volume))
                }
                None => Ok(None),
            }
        }
    }

    // Вспомогательный метод для обновления размера файла в директории по стартовому кластеру
    #[allow(dead_code)]
    fn update_file_size_in_dir(
        &mut self,
        dir_cluster: u32,
        start_cluster: u32,
        new_size: u32,
    ) -> io::Result<()> {
        let mut dir_data = self.read_chain(dir_cluster)?;
        let cluster_size = self.sectors_per_cluster as usize * self.bytes_per_sector as usize;
        let entries_per_cluster = cluster_size / 32;

        for cluster_idx in 0..dir_data.len() / cluster_size {
            let cluster_offset = cluster_idx * cluster_size;

            for i in 0..entries_per_cluster {
                let offset = cluster_offset + i * 32;
                if offset + 32 > dir_data.len() {
                    break;
                }

                let entry = &dir_data[offset..offset + 32];
                if entry[0] == 0x00 {
                    break; // Конец директории
                }
                if entry[0] == 0xE5 || entry[11] == 0x0F {
                    continue; // Удаленная запись или LFN
                }

                // Проверяем стартовый кластер (FAT32: high 16 bits at 20..21, low 16 bits at 26..27)
                let high = u16::from_le_bytes([entry[20], entry[21]]) as u32;
                let low = u16::from_le_bytes([entry[26], entry[27]]) as u32;
                let entry_start_cluster = (high << 16) | low;

                if entry_start_cluster == start_cluster {
                    // Обновляем размер файла
                    dir_data[offset + 28] = (new_size & 0xFF) as u8;
                    dir_data[offset + 29] = ((new_size >> 8) & 0xFF) as u8;
                    dir_data[offset + 30] = ((new_size >> 16) & 0xFF) as u8;
                    dir_data[offset + 31] = ((new_size >> 24) & 0xFF) as u8;

                    // Записываем обновленные данные обратно
                    self.write_chain(dir_cluster, &dir_data)?;
                    return Ok(());
                }
            }
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "File entry not found in directory",
        ))
    }

    // Вспомогательный метод для обновления размера и кластера файла по имени
    fn update_file_size_in_dir_by_name(
        &mut self,
        dir_cluster: u32,
        filename: &str,
        new_size: u32,
        new_start_cluster: Option<u32>,
    ) -> io::Result<()> {
        let mut dir_data = self.read_chain(dir_cluster)?;
        let cluster_size = self.sectors_per_cluster as usize * self.bytes_per_sector as usize;
        let entries_per_cluster = cluster_size / 32;

        let filename_upper = filename.to_uppercase();
        let mut lfn_entries = Vec::new();

        for cluster_idx in 0..dir_data.len() / cluster_size {
            let cluster_offset = cluster_idx * cluster_size;

            for i in 0..entries_per_cluster {
                let offset = cluster_offset + i * 32;
                if offset + 32 > dir_data.len() {
                    break;
                }

                let entry = &dir_data[offset..offset + 32];
                if entry[0] == 0x00 {
                    break; // Конец директории
                }
                if entry[0] == 0xE5 {
                    lfn_entries.clear();
                    continue; // Удаленная запись
                }

                if entry[11] == 0x0F {
                    // LFN запись
                    lfn_entries.push(entry.to_vec());
                } else {
                    // Обычная запись - проверяем имя
                    let mut short_name = String::new();

                    // Имя (первые 8 байт)
                    for j in 0..8 {
                        if entry[j] != 0x20 {
                            short_name.push(entry[j] as char);
                        }
                    }

                    // Расширение (байты 8-10)
                    let mut has_ext = false;
                    for j in 8..11 {
                        if entry[j] != 0x20 {
                            if !has_ext {
                                short_name.push('.');
                                has_ext = true;
                            }
                            short_name.push(entry[j] as char);
                        }
                    }

                    // Проверяем LFN если есть
                    let mut full_name = String::new();
                    if !lfn_entries.is_empty() {
                        // Собираем LFN из записей
                        lfn_entries.reverse();
                        for lfn_entry in &lfn_entries {
                            // Извлекаем символы из LFN записи
                            for j in 0..5 {
                                let ch = (lfn_entry[1 + j * 2] as u16)
                                    | ((lfn_entry[2 + j * 2] as u16) << 8);
                                if ch != 0 && ch != 0xFFFF {
                                    if let Some(c) = char::from_u32(ch as u32) {
                                        full_name.push(c);
                                    }
                                }
                            }
                            for j in 0..6 {
                                let ch = (lfn_entry[14 + j * 2] as u16)
                                    | ((lfn_entry[15 + j * 2] as u16) << 8);
                                if ch != 0 && ch != 0xFFFF {
                                    if let Some(c) = char::from_u32(ch as u32) {
                                        full_name.push(c);
                                    }
                                }
                            }
                            for j in 0..2 {
                                let ch = (lfn_entry[28 + j * 2] as u16)
                                    | ((lfn_entry[29 + j * 2] as u16) << 8);
                                if ch != 0 && ch != 0xFFFF {
                                    if let Some(c) = char::from_u32(ch as u32) {
                                        full_name.push(c);
                                    }
                                }
                            }
                        }
                    } else {
                        full_name = short_name.clone();
                    }

                    // Сравниваем имена
                    if full_name.to_uppercase() == filename_upper || short_name == filename_upper {
                        // Обновляем размер файла только если передано не u32::MAX
                        if new_size != u32::MAX {
                            dir_data[offset + 28] = (new_size & 0xFF) as u8;
                            dir_data[offset + 29] = ((new_size >> 8) & 0xFF) as u8;
                            dir_data[offset + 30] = ((new_size >> 16) & 0xFF) as u8;
                            dir_data[offset + 31] = ((new_size >> 24) & 0xFF) as u8;
                        }

                        // Обновляем стартовый кластер если нужно (FAT32: high 16 bits at 20..21, low 16 bits at 26..27)
                        if let Some(cluster) = new_start_cluster {
                            let high: u16 = (cluster >> 16) as u16;
                            let low: u16 = (cluster & 0xFFFF) as u16;
                            let high_bytes = high.to_le_bytes();
                            let low_bytes = low.to_le_bytes();
                            dir_data[offset + 20] = high_bytes[0];
                            dir_data[offset + 21] = high_bytes[1];
                            dir_data[offset + 26] = low_bytes[0];
                            dir_data[offset + 27] = low_bytes[1];
                        }

                        // Записываем обновленные данные обратно
                        self.write_chain(dir_cluster, &dir_data)?;
                        return Ok(());
                    }

                    lfn_entries.clear();
                }
            }
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("File '{}' not found in directory", filename),
        ))
    }

    // Вспомогательный метод для обновления стартового кластера файла
    fn update_file_start_cluster_in_dir(
        &mut self,
        dir_cluster: u32,
        filename: &str,
        new_start_cluster: u32,
    ) -> io::Result<()> {
        // Передаём u32::MAX как специальное значение, чтобы не обновлять размер
        self.update_file_size_in_dir_by_name(dir_cluster, filename, u32::MAX, Some(new_start_cluster))?;
        Ok(())
    }
}
