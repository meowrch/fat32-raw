# fat32-raw 🚀
Лёгкая и безопасная Rust-библиотека для работы с FAT32-разделами и образами, с поддержкой чтения, записи и автодетектом параметров.

## ✨ Особенности

- 💾 Работа с raw-образами и raw-дисками FAT32 (ESP, SD-карты, флешки)  
- 🔍 Автоматическое определение параметров раздела (BPB)  
- 📖 Чтение и ✍️ запись файлов с поддержкой изменения размера  
- 📝 Поддержка длинных имён файлов (LFN)  
- 🔒 Минимум unsafe, максимум безопасности и стабильности  
- ⚙️ Простое и понятное API для интеграции в проекты  
- 🔄 Идеально подходит для синхронизации данных между системами (например, Bluetooth keys между Windows и Linux)

## 🚀 Пример использования с образом
```rust
use std::fs::OpenOptions;
use fat32_raw::{Fat32Volume, read_bpb};

fn main() -> std::io::Result {
    let device_path = r"C:\path\to\esp.img";
    let esp_start_lba = 0;

    let mut file = OpenOptions::new().read(true).write(true).open(device_path)?;
    let params = read_bpb(&mut file, esp_start_lba * 512)?;

    let mut volume = Fat32Volume::open(
        device_path,
        esp_start_lba,
        params.bytes_per_sector,
        params.sectors_per_cluster as u32,
        params.reserved_sectors as u32,
        params.num_fats as u32,
        params.sectors_per_fat,
        params.root_cluster,
    )?;

    let filename = "file.json";

    if let Some(content) = volume.read_file(filename)? {
        println!("Старое содержимое файла '{}':\n{}", filename, String::from_utf8_lossy(&content));
    }

    let new_json = br#"{"foo": "bar", "count": 123}"#;
    volume.write_file(filename, new_json)?;

    if let Some(content) = volume.read_file(filename)? {
        println!("Новое содержимое файла '{}':\n{}", filename, String::from_utf8_lossy(&content));
    }

    Ok(())
}
```

### Пример открытия реального ESP-раздела (Windows):
> ![WARNING] **⚠️ ВНИМАНИЕ:** 
> Работа с реальными физическими дисками или разделами требует прав администратора и может привести к потере данных, если что-то пойдёт не так!  
> Всегда делайте резервные копии и тестируйте на образах!  

```rust
use std::fs::OpenOptions;
use fat32_raw::{Fat32Volume, read_bpb};

fn main() -> std::io::Result {
    let device_path = r"\\.\PhysicalDrive0";
    let esp_start_lba = 2048; // Обычно ESP начинается с 2048 сектора, уточните для вашего диска

    let mut file = OpenOptions::new().read(true).write(true).open(device_path)?;
    let params = read_bpb(&mut file, esp_start_lba * 512)?;

    let mut volume = Fat32Volume::open(
        device_path,
        esp_start_lba,
        params.bytes_per_sector,
        params.sectors_per_cluster as u32,
        params.reserved_sectors as u32,
        params.num_fats as u32,
        params.sectors_per_fat,
        params.root_cluster,
    )?;

    // Работа с файлами как обычно...
    Ok(())
}
```

## 📦 Установка
Добавьте в `Cargo.toml`:
```ini
[dependencies]
fat32-raw = "0.1"
```

## 🚧 Планы на будущее
- 📂 Поддержка создания и удаления файлов и директорий  
- 📁 Работа с поддиректориями  
- 💻 Интеграция с реальными дисками Windows и Linux  
- 🧩 Автоматическое определение разделов на диске (GPT/MBR парсинг)  
- 🧪 Тесты и CI

## 📄 Лицензия
Проект распространяется под лицензией [GPLv3](./LICENSE).
