mod fat32;

use std::fs::OpenOptions;
use fat32::{Fat32Volume, read_bpb};

fn main() -> std::io::Result<()> {
    let device_path = r"C:\Users\dimflix\Desktop\esp.img";
    let esp_start_lba = 0;

    // Открываем файл для чтения и записи
    let mut file = OpenOptions::new().read(true).write(true).open(device_path)?;

    // Читаем BPB
    let params = read_bpb(&mut file, esp_start_lba * 512)?;

    // Теперь создаём Fat32Volume с этими параметрами
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

    let filename = "bt_keys.json";

    if let Some(content) = volume.read_file(filename)? {
        println!("Старое содержимое файла '{}':\n{}", filename, String::from_utf8_lossy(&content));
    } else {
        println!("Файл '{}' не найден", filename);
    }

    // Пример нового json
    let new_json = br#"{"foo": "bar", "count": 123}"#;

    if volume.write_file(filename, new_json)? {
        println!("Файл успешно перезаписан!");
    } else {
        println!("Файл не найден для записи");
    }

    // Проверь результат
    if let Some(content) = volume.read_file(filename)? {
        println!("Новое содержимое файла '{}':\n{}", filename, String::from_utf8_lossy(&content));
    }


    Ok(())
}
