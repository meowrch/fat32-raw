use fat32_raw::fat32::{read_bpb, Fat32Volume};
use std::fs::OpenOptions;

fn main() -> std::io::Result<()> {
    let device_path = r"C:\path\to\esp.img";
    let esp_start_lba = 0;

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(device_path)?;
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

    println!("Содержимое корня до создания:");
    print_dir(&mut volume)?;

    test_file_workflow(&mut volume)?;
    test_dir_workflow(&mut volume)?;

    println!("Содержимое корня после всех операций:");
    print_dir(&mut volume)?;

    Ok(())
}

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

fn print_dir_contents(volume: &mut Fat32Volume, dirname: &str) -> std::io::Result<()> {
    let entries = volume.list_directory_by_name(dirname)?;
    println!("Содержимое директории '{}':", dirname);
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
    print_dir_contents(volume, "testdir")?;

    // Проверяем, что директория пуста (только . и ..)
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

// Вспомогательная функция для красивого вывода содержимого папки
fn print_dir(volume: &mut Fat32Volume) -> std::io::Result<()> {
    let entries = &volume.list_root()?;
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

// Вспомогательная функция для получения содержимого директории по имени
trait Fat32DirExt {
    fn list_directory_by_name(
        &mut self,
        dirname: &str,
    ) -> std::io::Result<Vec<fat32_raw::fat32::Fat32FileEntry>>;
}

impl Fat32DirExt for Fat32Volume {
    fn list_directory_by_name(
        &mut self,
        dirname: &str,
    ) -> std::io::Result<Vec<fat32_raw::fat32::Fat32FileEntry>> {
        let entries = self.list_root()?;
        let dir = entries
            .iter()
            .find(|e| e.name.eq_ignore_ascii_case(dirname) && e.is_directory);
        if let Some(dir_entry) = dir {
            let all = self.list_directory(dir_entry.start_cluster)?;
            // Оставляем только реально существующие записи (имя не пустое)
            Ok(all.into_iter().filter(|e| !e.name.is_empty()).collect())
        } else {
            Ok(Vec::new())
        }
    }
}
