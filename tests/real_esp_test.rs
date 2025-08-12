use fat32_raw::Fat32Volume;
use std::io::Result;
use std::time::{SystemTime, UNIX_EPOCH};

fn run_comprehensive_test() -> Result<()> {
    println!("\n=== COMPREHENSIVE FAT32 TEST ===");
    println!("Attempting to open real ESP partition...");
    let mut volume = match Fat32Volume::open_esp::<&str>(None)? {
        Some(v) => {
            println!("✅ Successfully opened ESP partition.");
            v
        }
        None => {
            println!("⚠️ ESP partition not found. Skipping test.");
            return Ok(());
        }
    };

    // Create a unique root directory for all tests
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let root_test_dir = format!("fat32test{}", timestamp % 1000000); // Use shorter name
    
    println!("\n📁 Test root directory: {}", root_test_dir);
    
    // Cleanup function
    let cleanup = |volume: &mut Fat32Volume| {
        println!("\n🧹 Cleaning up test directory...");
        let _ = volume.delete_dir_lfn(&root_test_dir);
    };

    // TEST 1: Basic directory operations
    println!("\n--- TEST 1: Basic Directory Operations ---");
    
    println!("1.1 Creating root test directory: '{}'", root_test_dir);
    match volume.create_directory_path(&root_test_dir) {
        Ok(true) => println!("   ✅ Directory created."),
        Ok(false) => {
            println!("   ⚠️ Directory already exists, cleaning up...");
            cleanup(&mut volume);
            volume.create_directory_path(&root_test_dir)?;
            println!("   ✅ Directory recreated.");
        }
        Err(e) => {
            eprintln!("   ❌ Failed to create directory: {}", e);
            return Err(e.into());
        }
    }
    
    // TEST 2: Nested directory creation
    println!("\n--- TEST 2: Nested Directory Creation ---");
    
    let nested_dir1 = format!("{}/level1", root_test_dir);
    let nested_dir2 = format!("{}/level1/level2", root_test_dir);
    let nested_dir3 = format!("{}/level1/level2/level3", root_test_dir);
    
    println!("2.1 Creating nested directories...");
    for (idx, dir) in [&nested_dir1, &nested_dir2, &nested_dir3].iter().enumerate() {
        println!("   Creating level {}: '{}'", idx + 1, dir);
        match volume.create_directory_path(dir) {
            Ok(_) => println!("      ✅ Created"),
            Err(e) => {
                eprintln!("      ❌ Failed: {}", e);
                cleanup(&mut volume);
                return Err(e.into());
            }
        }
    }
    
    // TEST 3: File operations in different directories
    println!("\n--- TEST 3: File Operations ---");
    
    // 3.1 Small file
    let small_file = format!("{}/small.txt", root_test_dir);
    let small_content = b"Small file content";
    
    println!("3.1 Writing small file: '{}'", small_file);
    volume.write_file_with_path(&small_file, small_content)?;
    println!("   ✅ Written {} bytes", small_content.len());
    
    volume.refresh_all_caches()?;
    
    println!("   Reading back...");
    match volume.read_file(&small_file)? {
        Some(content) => {
            assert_eq!(content, small_content);
            println!("   ✅ Content verified");
        }
        None => {
            eprintln!("   ❌ File not found after write");
            cleanup(&mut volume);
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Small file not found",
            ));
        }
    }
    
    // 3.2 Medium file (1KB)
    let medium_file = format!("{}/medium.dat", nested_dir1);
    let medium_content: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
    
    println!("\n3.2 Writing medium file (1KB): '{}'", medium_file);
    volume.write_file_with_path(&medium_file, &medium_content)?;
    println!("   ✅ Written {} bytes", medium_content.len());
    
    volume.refresh_all_caches()?;
    
    println!("   Reading back...");
    match volume.read_file(&medium_file)? {
        Some(content) => {
            assert_eq!(content, medium_content);
            println!("   ✅ Content verified");
        }
        None => {
            eprintln!("   ❌ File not found after write");
            cleanup(&mut volume);
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Medium file not found",
            ));
        }
    }
    
    // 3.3 Large file (64KB)
    let large_file = format!("{}/large.bin", nested_dir2);
    let large_content: Vec<u8> = (0..65536).map(|i| ((i * 7) % 256) as u8).collect();
    
    println!("\n3.3 Writing large file (64KB): '{}'", large_file);
    volume.write_file_with_path(&large_file, &large_content)?;
    println!("   ✅ Written {} bytes", large_content.len());
    
    volume.refresh_all_caches()?;
    
    println!("   Reading back...");
    match volume.read_file(&large_file)? {
        Some(content) => {
            assert_eq!(content.len(), large_content.len());
            // Verify first and last 1KB
            assert_eq!(&content[..1024], &large_content[..1024]);
            assert_eq!(&content[content.len()-1024..], &large_content[large_content.len()-1024..]);
            println!("   ✅ Content verified (size and samples)");
        }
        None => {
            eprintln!("   ❌ File not found after write");
            cleanup(&mut volume);
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Large file not found",
            ));
        }
    }
    
    // TEST 4: Multiple files in same directory
    println!("\n--- TEST 4: Multiple Files in Same Directory ---");
    
    let multi_dir = format!("{}/multifile", root_test_dir);
    volume.create_directory_path(&multi_dir)?;
    
    println!("4.1 Creating 10 files in '{}'", multi_dir);
    for i in 0..10 {
        let filename = format!("{}/file{:02}.txt", multi_dir, i);
        let content = format!("This is file number {}", i);
        volume.write_file_with_path(&filename, content.as_bytes())?;
        print!(".");
    }
    println!(" ✅ Created 10 files");
    
    volume.refresh_all_caches()?;
    
    println!("4.2 Verifying all files...");
    for i in 0..10 {
        let filename = format!("{}/file{:02}.txt", multi_dir, i);
        let expected = format!("This is file number {}", i);
        match volume.read_file(&filename)? {
            Some(content) => {
                assert_eq!(content, expected.as_bytes());
                print!(".");
            }
            None => {
                eprintln!("\n   ❌ File {} not found", filename);
                cleanup(&mut volume);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("File {} not found", filename),
                ));
            }
        }
    }
    println!(" ✅ All files verified");
    
    // TEST 5: File overwrite
    println!("\n--- TEST 5: File Overwrite ---");
    
    let overwrite_file = format!("{}/overwrite.txt", root_test_dir);
    let original_content = b"Original content";
    let new_content = b"This is the new content that replaces the original";
    
    println!("5.1 Writing original file: '{}'", overwrite_file);
    volume.write_file_with_path(&overwrite_file, original_content)?;
    println!("   ✅ Written {} bytes", original_content.len());
    
    volume.refresh_all_caches()?;
    
    println!("5.2 Overwriting with new content...");
    volume.write_file_with_path(&overwrite_file, new_content)?;
    println!("   ✅ Written {} bytes", new_content.len());
    
    volume.refresh_all_caches()?;
    
    println!("5.3 Verifying new content...");
    match volume.read_file(&overwrite_file)? {
        Some(content) => {
            assert_eq!(content, new_content);
            assert_ne!(content, original_content);
            println!("   ✅ Overwrite successful");
        }
        None => {
            eprintln!("   ❌ File not found after overwrite");
            cleanup(&mut volume);
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Overwritten file not found",
            ));
        }
    }
    
    // TEST 6: Empty file
    println!("\n--- TEST 6: Empty File ---");
    
    let empty_file = format!("{}/empty.txt", root_test_dir);
    
    println!("6.1 Creating empty file: '{}'", empty_file);
    volume.write_file_with_path(&empty_file, b"")?;
    println!("   ✅ Created");
    
    volume.refresh_all_caches()?;
    
    println!("6.2 Reading empty file...");
    match volume.read_file(&empty_file)? {
        Some(content) => {
            assert_eq!(content.len(), 0);
            println!("   ✅ Empty file verified");
        }
        None => {
            eprintln!("   ❌ Empty file not found");
            cleanup(&mut volume);
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Empty file not found",
            ));
        }
    }
    
    // TEST 7: File deletion
    println!("\n--- TEST 7: File Deletion ---");
    
    println!("7.1 Deleting small file: '{}'", small_file);
    match volume.delete_file_lfn(&small_file) {
        Ok(true) => println!("   ✅ Deleted"),
        Ok(false) => println!("   ⚠️ File not found"),
        Err(e) => {
            eprintln!("   ❌ Failed: {}", e);
            cleanup(&mut volume);
            return Err(e.into());
        }
    }
    
    volume.refresh_all_caches()?;
    
    println!("7.2 Verifying deletion...");
    match volume.read_file(&small_file)? {
        Some(_) => {
            eprintln!("   ❌ File still exists after deletion");
            cleanup(&mut volume);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "File not deleted",
            ));
        }
        None => println!("   ✅ File successfully deleted"),
    }
    
    println!("7.3 Deleting all files in multifile directory...");
    for i in 0..10 {
        let filename = format!("{}/file{:02}.txt", multi_dir, i);
        volume.delete_file_lfn(&filename)?;
        print!(".");
    }
    println!(" ✅ All files deleted");
    
    // TEST 8: Directory deletion
    println!("\n--- TEST 8: Directory Deletion ---");
    
    println!("8.1 Attempting to delete non-empty directory (should fail)...");
    match volume.delete_dir_lfn(&nested_dir1) {
        Ok(false) | Err(_) => println!("   ✅ Correctly refused to delete non-empty directory"),
        Ok(true) => {
            eprintln!("   ❌ Incorrectly deleted non-empty directory");
            cleanup(&mut volume);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Non-empty directory was deleted",
            ));
        }
    }
    
    println!("8.2 Deleting files from nested directories...");
    volume.delete_file_lfn(&medium_file)?;
    println!("   ✅ Deleted medium file");
    volume.delete_file_lfn(&large_file)?;
    println!("   ✅ Deleted large file");
    
    println!("8.3 Deleting empty nested directories (bottom-up)...");
    volume.delete_dir_lfn(&nested_dir3)?;
    println!("   ✅ Deleted level3");
    volume.delete_dir_lfn(&nested_dir2)?;
    println!("   ✅ Deleted level2");
    volume.delete_dir_lfn(&nested_dir1)?;
    println!("   ✅ Deleted level1");
    
    println!("8.4 Deleting empty multifile directory...");
    volume.delete_dir_lfn(&multi_dir)?;
    println!("   ✅ Deleted multifile directory");
    
    // TEST 9: Special characters and edge cases
    println!("\n--- TEST 9: Special Characters and Edge Cases ---");
    
    let special_dir = format!("{}/special", root_test_dir);
    volume.create_directory_path(&special_dir)?;
    
    // Test files with various names
    let test_names = vec![
        ("test.txt", b"normal name" as &[u8]),
        ("test-123.txt", b"with numbers" as &[u8]),
        ("test_file.txt", b"with underscore" as &[u8]),
        ("upper.txt", b"uppercase" as &[u8]),
        ("a.txt", b"single char" as &[u8]),
        ("123.txt", b"starts with number" as &[u8]),
    ];
    
    println!("9.1 Creating files with various names...");
    for (name, content) in &test_names {
        let filepath = format!("{}/{}", special_dir, name);
        volume.write_file_with_path(&filepath, content)?;
        println!("   ✅ Created: {}", name);
    }
    
    volume.refresh_all_caches()?;
    
    println!("9.2 Verifying all special files...");
    for (name, expected_content) in &test_names {
        let filepath = format!("{}/{}", special_dir, name);
        match volume.read_file(&filepath)? {
            Some(content) => {
                assert_eq!(content, *expected_content);
                println!("   ✅ Verified: {}", name);
            }
            None => {
                eprintln!("   ❌ Not found: {}", name);
                cleanup(&mut volume);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("Special file {} not found", name),
                ));
            }
        }
    }
    
    // TEST 10: Final cleanup
    println!("\n--- TEST 10: Final Cleanup ---");
    
    println!("10.1 Deleting remaining test files...");
    volume.delete_file_lfn(&overwrite_file)?;
    println!("   ✅ Deleted overwrite test file");
    volume.delete_file_lfn(&empty_file)?;
    println!("   ✅ Deleted empty file");
    
    for (name, _) in &test_names {
        let filepath = format!("{}/{}", special_dir, name);
        volume.delete_file_lfn(&filepath)?;
    }
    println!("   ✅ Deleted all special test files");
    
    println!("10.2 Deleting special directory...");
    volume.delete_dir_lfn(&special_dir)?;
    println!("   ✅ Deleted special directory");
    
    println!("10.3 Deleting root test directory: '{}'", root_test_dir);
    match volume.delete_dir_lfn(&root_test_dir) {
        Ok(true) => println!("   ✅ Successfully deleted root test directory"),
        Ok(false) => {
            eprintln!("   ⚠️ Directory not found or not empty");
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Could not delete root test directory",
            ));
        }
        Err(e) => {
            eprintln!("   ❌ Failed to delete: {}", e);
            return Err(e.into());
        }
    }
    
    println!("\n✅✅✅ ALL TESTS PASSED SUCCESSFULLY! ✅✅✅");
    Ok(())
}

#[test]
#[ignore]
fn comprehensive_fat32_test() {
    println!("\n🚀 Starting comprehensive FAT32 test.");
    println!("⚠️  This test requires elevated privileges (sudo/Administrator).");
    println!("⚠️  It will create and delete test files on your ESP partition.\n");
    
    if let Err(e) = run_comprehensive_test() {
        eprintln!("\n❌❌❌ COMPREHENSIVE TEST FAILED ❌❌❌");
        eprintln!("Error: {}", e);
        panic!("Comprehensive FAT32 test failed: {}", e);
    }
}

