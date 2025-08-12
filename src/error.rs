//! Error types for the fat32-raw library

use std::fmt;
use std::io;

/// Result type for fat32-raw operations
pub type Result<T> = std::result::Result<T, Fat32Error>;

/// Main error type for fat32-raw operations
#[derive(Debug)]
pub enum Fat32Error {
    /// I/O error from underlying file operations
    Io(io::Error),

    /// Invalid FAT32 structure or parameters
    InvalidFat32 { message: String },

    /// File or directory not found
    NotFound { path: String },

    /// File or directory already exists
    AlreadyExists { path: String },

    /// No free clusters available
    NoFreeSpace,

    /// Invalid file name
    InvalidFileName { name: String, reason: String },

    /// Platform-specific error
    PlatformError {
        message: String,
        #[cfg(windows)]
        code: Option<u32>,
    },

    /// Access denied (typically on Windows ESP partitions)
    AccessDenied {
        path: String,
        tried_strategies: Vec<String>,
    },

    /// ESP partition not found
    EspNotFound,
}

impl fmt::Display for Fat32Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "I/O error: {}", err),
            Self::InvalidFat32 { message } => write!(f, "Invalid FAT32: {}", message),
            Self::NotFound { path } => write!(f, "Not found: {}", path),
            Self::AlreadyExists { path } => write!(f, "Already exists: {}", path),
            Self::NoFreeSpace => write!(f, "No free space available"),
            Self::InvalidFileName { name, reason } => {
                write!(f, "Invalid file name '{}': {}", name, reason)
            }
            Self::PlatformError { message, .. } => write!(f, "Platform error: {}", message),
            Self::AccessDenied {
                path,
                tried_strategies,
            } => {
                write!(
                    f,
                    "Access denied for '{}'. Tried strategies: {:?}",
                    path, tried_strategies
                )
            }
            Self::EspNotFound => write!(f, "ESP partition not found"),
        }
    }
}

impl std::error::Error for Fat32Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for Fat32Error {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

// Convenience constructors
impl Fat32Error {
    pub fn invalid_fat32(message: impl Into<String>) -> Self {
        Self::InvalidFat32 {
            message: message.into(),
        }
    }

    pub fn not_found(path: impl Into<String>) -> Self {
        Self::NotFound { path: path.into() }
    }

    pub fn already_exists(path: impl Into<String>) -> Self {
        Self::AlreadyExists { path: path.into() }
    }

    pub fn invalid_file_name(name: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidFileName {
            name: name.into(),
            reason: reason.into(),
        }
    }

    #[cfg(windows)]
    pub fn platform_error(message: impl Into<String>, code: Option<u32>) -> Self {
        Self::PlatformError {
            message: message.into(),
            code,
        }
    }

    #[cfg(not(windows))]
    pub fn platform_error(message: impl Into<String>) -> Self {
        Self::PlatformError {
            message: message.into(),
        }
    }

    pub fn access_denied(path: impl Into<String>, tried_strategies: Vec<String>) -> Self {
        Self::AccessDenied {
            path: path.into(),
            tried_strategies,
        }
    }
}
