<div align="center">
	<h1> FAT32-Raw 🚀</h1>
	<a href="https://github.com/meowrch/fat32-raw/issues">
		<img src="https://img.shields.io/github/issues/meowrch/fat32-raw?color=ffb29b&labelColor=1C2325&style=for-the-badge">
	</a>
	<a href="https://github.com/meowrch/fat32-raw/stargazers">
		<img src="https://img.shields.io/github/stars/meowrch/fat32-raw?color=fab387&labelColor=1C2325&style=for-the-badge">
	</a>
	<a href="./LICENSE">
		<img src="https://img.shields.io/github/license/meowrch/fat32-raw?color=FCA2AA&labelColor=1C2325&style=for-the-badge">
	</a>
    <br>
	<br>
	<a href="./README.ru.md">
		<img src="https://img.shields.io/badge/README-RU-blue?color=cba6f7&labelColor=1C2325&style=for-the-badge">
	</a>
	<a href="./README.md">
		<img src="https://img.shields.io/badge/README-ENG-blue?color=C9CBFF&labelColor=C9CBFF&style=for-the-badge">
	</a>
</div>

A fully featured Rust library for direct work with FAT32 partitions and images. Provides low-level access to the FAT32 file system with support for reading, writing, creating and deleting files and directories.

## ✨ Key features

### 🎯 Core capabilities
- **Direct partition access**: Native support for ESP (EFI System Partition), SD cards, USB flash drives
- **Cross‑platform**: Full support for Windows and Linux with handling of OS‑specific nuances
- **Full FAT32 feature set**: Read, write, create, delete files and directories
- **Nested directories**: Support for creating and navigating deeply nested directory structures
- **Long file names (LFN)**: Full Unicode name support up to 255 characters
- **Auto parameter detection**: Automatic parsing of BPB (BIOS Parameter Block)

### 🔧 Technical advantages
- **Safety**: Minimal use of `unsafe` code, strong typing
- **Performance**: Optimized read/write operations with buffering
- **Reliability**: Proper error handling, protection against data corruption
- **Windows specifics**: Solves access rights issues (OS Error 5) via special file opening flags

## 🚀 Quick start

### Working with a disk image
```rust
use fat32_raw::Fat32Volume;

fn main() -> std::io::Result<()> {
    // Open a FAT32 image
    let mut volume = Fat32Volume::open_esp(Some("esp.img"))?
        .expect("Failed to open FAT32 image");

    // Create directories
    volume.create_dir_lfn("config")?;
    
    // Create and write a file
    volume.create_file_lfn("test.txt")?;
    let content = b"Hello from fat32-raw!";
    volume.write_file("test.txt", content)?;
    
    // Read the file back
    if let Some(data) = volume.read_file("test.txt")? {
        println!("Content: {}", String::from_utf8_lossy(&data));
    }
    
    // Delete the file
    volume.delete_file_lfn("test.txt")?;
    
    Ok(())
}
```

### Working with a real ESP partition
```rust
use fat32_raw::Fat32Volume;

fn main() -> std::io::Result<()> {
    // Automatic search and opening of the ESP partition
    // On Windows, administrator rights are required
    // On Linux, sudo may be required
    let mut volume = Fat32Volume::open_esp(None::<&str>)?
        .expect("ESP partition not found");
    
    // Work with the partition the same way as with an image
    volume.create_dir_lfn("MyApp")?;
    volume.create_file_lfn("MyApp_config.txt")?;
    volume.write_file("MyApp_config.txt", b"Configuration")?;
    
    // List files in the root
    let entries = volume.list_root()?;
    for entry in entries {
        println!("{} - {}", 
            entry.name, 
            if entry.is_directory { "DIR" } else { "FILE" }
        );
    }
    
    Ok(())
}
```

## 📦 Installation

Add to `Cargo.toml`:
```toml
[dependencies]
fat32-raw = "1.0"
```

## 🧪 Testing

The project includes a test suite that covers all operations:


```bash
# Run regular tests
cargo test

# Run tests on a real ESP (requires sudo/Administrator)
# WARNING: this test works with a real ESP partition!
sudo cargo test --test real_esp_test
```

## 🏗️ Project structure

```
fat32-raw/
├── src/
│   ├── lib.rs              # Main library module
│   ├── error.rs            # Error handling
│   ├── fat32/
│   │   ├── mod.rs          # FAT32 module
│   │   ├── volume.rs       # Core volume logic
│   │   ├── directory.rs    # Directory operations
│   │   ├── file.rs         # File operations
│   │   ├── fat_table.rs    # FAT table handling
│   │   ├── lfn.rs          # Long file name support
│   │   └── utils.rs        # Helper functions
│   └── platform/
│       ├── mod.rs          # Platform abstractions
│       ├── windows/        # Windows‑specific code
│       └── unix/           # Unix/Linux‑specific code
└── tests/
    └── real_esp_test.rs    # Integration tests with real ESP
```

## 🚧 Roadmap

- [X] Support for creating and deleting files and directories  
- [X] Automatic ESP partition discovery on disks  
- [X] Working with nested directories  
- [X] Full integration with Windows and Linux  
- [X] Handling access rights issues on Windows  
- [ ] ⏳ MBR partition support  
- [ ] ⏳ Defragmentation and optimization  
- [ ] ⏳ FAT12/FAT16 support  
- [X] ⏳ Integration with GitHub Actions CI/CD  

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository  
2. Create a branch for your changes  
3. Make sure all tests pass  
4. Open a pull request  

## 📄 License

This project is distributed under the [GPLv3](./LICENSE) license.

## 🙏 Acknowledgements

- The Rust community for great tools and documentation  
- The authors of the FAT32 specification from Microsoft  
- All project contributors and users  

---

<div align="center">
Made with ❤️ using Rust
</div>
