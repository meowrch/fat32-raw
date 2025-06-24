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
use fat32_raw::fat32::Fat32Volume;

fn main() -> std::io::Result<()> {
    // Открываем FAT32-образ (рекомендуется для тестов)
    let image_path = "esp.img";
    let mut volume = Fat32Volume::open_esp(Some(image_path))?
        .expect("Не удалось открыть FAT32-образ");

    // Создаём файл с длинным именем
    let filename = "test.conf";
    if volume.create_file_lfn(filename)? {
        println!("Файл '{}' создан", filename);
    } else {
        println!("Файл '{}' уже существует", filename);
    }

    // Записываем данные в файл
    let content = b"Привет из fat32-raw!";
    volume.write_file(filename, content)?;
    println!("Данные записаны в '{}'", filename);

    // Читаем данные из файла
    if let Some(data) = volume.read_file(filename)? {
        println!("Содержимое '{}': {}", filename, String::from_utf8_lossy(&data));
    }

    // Удаляем файл
    if volume.delete_file_lfn(filename)? {
        println!("Файл '{}' удалён", filename);
    }

    Ok(())
}
```

> [!tip] 
> Полный пример использования находится в `./src/bin/main.rs`
> Для запуска используйте команду `cargo run --bin main`

## 📦 Установка
Добавьте в `Cargo.toml`:
```ini
[dependencies]
fat32-raw = "0.1"
```

## 🚧 Планы на будущее
- [X] Поддержка создания и удаления файлов и директорий  
- [X] Автоматический поиск ESP раздела на дисках
- [ ] Работа с поддиректориями  
- [X] Интеграция с реальными дисками Windows и Linux  
- [ ] Поддержка MBR
- [ ] Тесты и CI

## 📄 Лицензия
Проект распространяется под лицензией [GPLv3](./LICENSE).
