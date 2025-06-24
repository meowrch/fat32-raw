//! Пример использования библиотеки для работы с FAT32-томом или образом ESP-раздела.
//!
//! **ВНИМАНИЕ:** Для тестов рекомендуется использовать файл-образ (например, esp.img),
//! а не реальный раздел диска, чтобы избежать потери данных!

use fat32_raw::fat32::{Fat32Volume};
use std::io::Result;

/// Основная функция: демонстрирует работу с образом и с реальным ESP-разделом.
fn main() -> Result<()> {
    // === Рекомендуемый вариант: работа с образом ===
    let image_path = "esp.img";
    println!("Открытие FAT32-тома по образу '{}'", image_path);
    if let Some(mut volume) = Fat32Volume::open_esp(Some(image_path))? {
        run_demo(&mut volume)?;
    } else {
        println!("Не удалось открыть FAT32-образ '{}'", image_path);
    }

    // === Альтернативный вариант: автоматический поиск ESP-раздела ===
    //
    // ВНИМАНИЕ!
    // При разработке и тестировании библиотеки рекомендуется использовать только образы дисков (например, esp.img),
    // чтобы избежать риска повреждения данных на реальных разделах.
    //
    // Если вы используете библиотеку в реальных приложениях и уверены в стабильности,
    // автоматический поиск и работа с настоящим ESP-разделом возможны.
    // Однако, вся ответственность за сохранность данных лежит на вас:
    // библиотека не гарантирует 100% корректность работы с каждым конкретным диском.
    //
    /*
    println!("Автоматический поиск и открытие ESP-раздела на реальном диске...");
    if let Some(mut volume) = Fat32Volume::open_esp::<&str>(None)? {
        run_demo(&mut volume)?;
    } else {
        println!("ESP раздел не найден!");
    }
    */

    Ok(())
}

/// Демонстрирует создание, запись, чтение и удаление файлов и директорий.
fn run_demo(volume: &mut Fat32Volume) -> Result<()> {
    println!("Содержимое корня до операций:");
    print_dir(volume)?;

    test_file_workflow(volume)?;
    test_dir_workflow(volume)?;

    println!("Содержимое корня после всех операций:");
    print_dir(volume)?;

    Ok(())
}


/// Демонстрирует создание, запись, чтение и удаление файла.
fn test_file_workflow(volume: &mut Fat32Volume) -> std::io::Result<()> {
    let filename = "test.conf";
    if volume.create_file_lfn(filename)? {
        println!("Файл '{}' создан.", filename);
    } else {
        println!("Файл '{}' уже существует.", filename);
    }

    println!("Содержимое корня после создания файла:");
    print_dir(volume)?;

    let content = b"hello from rust & fat32!";
    if volume.write_file(filename, content)? {
        println!("Файл '{}' записан.", filename);
    } else {
        println!("Не удалось записать в файл '{}'.", filename);
    }

    match volume.read_file(filename)? {
        Some(data) => println!(
            "Содержимое '{}': {}",
            filename,
            String::from_utf8_lossy(&data)
        ),
        None => println!("Файл '{}' не найден после записи!", filename),
    }

    if volume.delete_file_lfn(filename)? {
        println!("Файл '{}' удалён.", filename);
    } else {
        println!("Не удалось удалить файл '{}'.", filename);
    }

    println!("Содержимое корня после удаления файла:");
    print_dir(volume)?;

    Ok(())
}

/// Демонстрирует создание, проверку и удаление директории.
fn test_dir_workflow(volume: &mut Fat32Volume) -> std::io::Result<()> {
    let dirname = "testdir";
    if volume.create_dir_lfn(dirname)? {
        println!("Директория '{}' создана.", dirname);
    } else {
        println!("Директория '{}' уже существует.", dirname);
    }

    println!("Содержимое корня после создания директории:");
    print_dir(volume)?;

    println!("Содержимое папки testdir:");
    print_dir_contents(volume, dirname)?;

    // Проверяем, пуста ли директория
    let dir_cluster = {
        let entries = volume.list_root()?;
        entries
            .iter()
            .find(|e| e.name.eq_ignore_ascii_case(dirname) && e.is_directory)
            .map(|e| e.start_cluster)
    };
    if let Some(cluster) = dir_cluster {
        if volume.is_dir_empty(cluster)? {
            println!("Директория '{}' пуста.", dirname);
        } else {
            println!("Директория '{}' не пуста!", dirname);
        }
    } else {
        println!("Директория '{}' не найдена!", dirname);
    }

    if volume.delete_dir_lfn(dirname)? {
        println!("Директория '{}' удалена.", dirname);
    } else {
        println!(
            "Не удалось удалить директорию '{}'. Возможно, она не пуста.",
            dirname
        );
    }

    println!("Содержимое корня после удаления директории:");
    print_dir(volume)?;

    Ok(())
}

/// Красиво выводит содержимое корневой директории.
fn print_dir(volume: &mut Fat32Volume) -> std::io::Result<()> {
    let entries = volume.list_root()?;
    if entries.is_empty() {
        println!("(пусто)");
    } else {
        for e in entries {
            let typ = if e.is_directory { "<DIR>" } else { "     " };
            println!(
                "{:20} {}  кластер={}  размер={}",
                e.name, typ, e.start_cluster, e.size
            );
        }
    }
    Ok(())
}

/// Красиво выводит содержимое указанной директории.
fn print_dir_contents(volume: &mut Fat32Volume, dirname: &str) -> std::io::Result<()> {
    let entries = list_directory_by_name(volume, dirname)?;
    if entries.is_empty() {
        println!("(пусто)");
    } else {
        for e in entries {
            let typ = if e.is_directory { "<DIR>" } else { "     " };
            println!(
                "{:20} {}  кластер={}  размер={}",
                e.name, typ, e.start_cluster, e.size
            );
        }
    }
    Ok(())
}

/// Получает содержимое директории по имени.
fn list_directory_by_name(
    volume: &mut Fat32Volume,
    dirname: &str,
) -> std::io::Result<Vec<fat32_raw::fat32::Fat32FileEntry>> {
    let entries = volume.list_root()?;
    let dir = entries
        .iter()
        .find(|e| e.name.eq_ignore_ascii_case(dirname) && e.is_directory);
    if let Some(dir_entry) = dir {
        let all = volume.list_directory(dir_entry.start_cluster)?;
        Ok(all.into_iter().filter(|e| !e.name.is_empty()).collect())
    } else {
        Ok(Vec::new())
    }
}
