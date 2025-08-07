use super::{*};

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
                let drive_letter = format!(r"{}:\\", drive_letter_char);
                log::debug!("Checking drive: {}", drive_letter);

                let wide_path: Vec<u16> = drive_letter.encode_utf16().chain(Some(0)).collect();

                let drive_type = unsafe { GetDriveTypeW(wide_path.as_ptr()) };
                log::debug!("Drive type: {}", drive_type);

                if drive_type == DRIVE_FIXED || drive_type == DRIVE_NO_ROOT_DIR {
                    // Проверяем наличие стандартных EFI путей
                    let test_paths = [
                        PathBuf::from(&drive_letter).join(r"EFI\\BOOT\\BOOTX64.EFI"),
                        PathBuf::from(&drive_letter).join(r"EFI\\MICROSOFT\\BOOT\\BOOTMGFW.EFI"),
                    ];

                    for test_path in &test_paths {
                        log::debug!("Checking path: {}", test_path.display());
                        if test_path.exists() {
                            log::debug!("Found bootloader at: {}", test_path.display());
                            return Ok(Some((format!(r"\\\\.\\{}:", drive_letter_char), 0)));
                        }
                    }
                }
            }
        }

        log::debug!("No drives with bootloader found, checking physical drives...");

        // 2. Поиск по GPT разделам
        for disk_num in 0..4 {
            let device_path = format!(r"\\\\.\\PhysicalDrive{}", disk_num);
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
