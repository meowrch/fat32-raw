//! FAT table management for FAT32

use std::io::{self, Read, Seek, SeekFrom, Write};

/// FAT32 end-of-chain marker
pub const FAT32_EOC: u32 = 0x0FFFFFF8;

/// FAT32 bad cluster marker
pub const FAT32_BAD_CLUSTER: u32 = 0x0FFFFFF7;

/// FAT32 free cluster marker
pub const FAT32_FREE_CLUSTER: u32 = 0x00000000;

/// FAT table manager
pub struct FatTable {
    /// FAT data in memory
    data: Vec<u8>,
    /// Offset of FAT in the file/device
    offset: u64,
    /// Whether to sync on write
    sync_on_write: bool,
}

impl FatTable {
    /// Create a new FAT table manager
    pub fn new(data: Vec<u8>, offset: u64, sync_on_write: bool) -> Self {
        Self {
            data,
            offset,
            sync_on_write,
        }
    }

    /// Load FAT table from file
    pub fn load<F: Read + Seek>(file: &mut F, offset: u64, size: usize) -> io::Result<Self> {
        file.seek(SeekFrom::Start(offset))?;
        let mut data = vec![0u8; size];
        file.read_exact(&mut data)?;
        Ok(Self::new(data, offset, false))
    }

    /// Get a FAT entry value
    pub fn get_entry(&self, cluster: u32) -> u32 {
        let offset = (cluster * 4) as usize;
        if offset + 4 > self.data.len() {
            return FAT32_EOC;
        }
        u32::from_le_bytes(self.data[offset..offset + 4].try_into().unwrap()) & 0x0FFFFFFF
    }

    /// Set a FAT entry value
    pub fn set_entry(&mut self, cluster: u32, value: u32) {
        let offset = (cluster * 4) as usize;
        if offset + 4 > self.data.len() {
            return;
        }
        let bytes = (value & 0x0FFFFFFF).to_le_bytes();
        self.data[offset..offset + 4].copy_from_slice(&bytes);
    }

    /// Find a free cluster
    pub fn find_free_cluster(&self, start_hint: u32) -> Option<u32> {
        let max_clusters = (self.data.len() / 4) as u32;

        // Try from hint first
        for cluster in start_hint..max_clusters {
            if cluster < 2 {
                continue; // Skip reserved clusters
            }
            if self.get_entry(cluster) == FAT32_FREE_CLUSTER {
                return Some(cluster);
            }
        }

        // Try from beginning
        for cluster in 2..start_hint.min(max_clusters) {
            if self.get_entry(cluster) == FAT32_FREE_CLUSTER {
                return Some(cluster);
            }
        }

        None
    }

    /// Allocate a chain of clusters
    pub fn allocate_chain(&mut self, count: usize) -> Option<Vec<u32>> {
        let mut clusters = Vec::with_capacity(count);
        let mut last_allocated = 2;

        for _ in 0..count {
            if let Some(free) = self.find_free_cluster(last_allocated) {
                clusters.push(free);
                last_allocated = free + 1;

                // Mark as end-of-chain for now
                self.set_entry(free, FAT32_EOC);
            } else {
                // Not enough free clusters, rollback
                for &cluster in &clusters {
                    self.set_entry(cluster, FAT32_FREE_CLUSTER);
                }
                return None;
            }
        }

        // Link the chain
        for i in 0..clusters.len() - 1 {
            self.set_entry(clusters[i], clusters[i + 1]);
        }

        Some(clusters)
    }

    /// Free a cluster chain
    pub fn free_chain(&mut self, start_cluster: u32) {
        let mut current = start_cluster;

        while current < FAT32_EOC && current != 0 {
            let next = self.get_entry(current);
            self.set_entry(current, FAT32_FREE_CLUSTER);
            current = next;
        }
    }

    /// Extend a cluster chain
    pub fn extend_chain(&mut self, last_cluster: u32, additional_count: usize) -> Option<Vec<u32>> {
        let new_clusters = self.allocate_chain(additional_count)?;

        if !new_clusters.is_empty() {
            // Link the old chain to the new clusters
            self.set_entry(last_cluster, new_clusters[0]);
        }

        Some(new_clusters)
    }

    /// Get the last cluster in a chain
    pub fn get_last_cluster(&self, start_cluster: u32) -> u32 {
        let mut current = start_cluster;

        loop {
            let next = self.get_entry(current);
            if next >= FAT32_EOC || next == 0 {
                return current;
            }
            current = next;
        }
    }

    /// Count clusters in a chain
    pub fn count_chain(&self, start_cluster: u32) -> usize {
        let mut count = 0;
        let mut current = start_cluster;

        while current < FAT32_EOC && current != 0 {
            count += 1;
            current = self.get_entry(current);
        }

        count
    }

    /// Write FAT table back to file
    pub fn write<F: Write + Seek>(&self, file: &mut F) -> io::Result<()> {
        file.seek(SeekFrom::Start(self.offset))?;
        file.write_all(&self.data)?;
        if self.sync_on_write {
            file.flush()?;
        }
        Ok(())
    }

    /// Refresh FAT table from file
    pub fn refresh<F: Read + Seek>(&mut self, file: &mut F) -> io::Result<()> {
        file.seek(SeekFrom::Start(self.offset))?;
        file.read_exact(&mut self.data)?;
        Ok(())
    }

    /// Get reference to raw FAT data
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get mutable reference to raw FAT data
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}
