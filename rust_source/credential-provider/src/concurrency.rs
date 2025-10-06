// ABOUTME: File-based locking for concurrent authentication

use anyhow::Result;
use std::fs::{File, OpenOptions};
use std::io::ErrorKind;
use std::path::PathBuf;
use std::time::Duration;

pub struct PortLock {
    _file: Option<File>,
    lock_path: PathBuf,
}

impl PortLock {
    /// Try to acquire the port lock using file-based locking
    pub fn try_acquire(port: u16) -> Result<Option<Self>> {
        let lock_path = Self::get_lock_path(port);

        // Create parent directory if it doesn't exist
        if let Some(parent) = lock_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Try to create and lock the file
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .open(&lock_path)?;

        // Try to acquire exclusive lock (non-blocking)
        match Self::try_lock_exclusive(&file) {
            Ok(true) => Ok(Some(Self {
                _file: Some(file),
                lock_path,
            })),
            Ok(false) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn get_lock_path(port: u16) -> PathBuf {
        dirs::cache_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("credential-provider")
            .join(format!("port-{}.lock", port))
    }

    #[cfg(unix)]
    fn try_lock_exclusive(file: &File) -> std::io::Result<bool> {
        use std::os::unix::io::AsRawFd;

        let fd = file.as_raw_fd();
        let result = unsafe {
            libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB)
        };

        if result == 0 {
            Ok(true)
        } else {
            let err = std::io::Error::last_os_error();
            if err.kind() == ErrorKind::WouldBlock {
                Ok(false)
            } else {
                Err(err)
            }
        }
    }

    #[cfg(not(unix))]
    fn try_lock_exclusive(_file: &File) -> std::io::Result<bool> {
        // For non-Unix systems, always succeed (no locking)
        Ok(true)
    }

    /// Wait for the lock to be released and check for cached credentials
    pub fn wait_for_release<F>(
        port: u16,
        timeout_secs: u64,
        check_credentials: F,
    ) -> Result<Option<serde_json::Value>>
    where
        F: Fn() -> Result<Option<serde_json::Value>>,
    {
        let timeout = Duration::from_secs(timeout_secs);
        let start = std::time::Instant::now();
        let lock_path = Self::get_lock_path(port);

        loop {
            if start.elapsed() >= timeout {
                return Ok(None);
            }

            // Check if lock file still exists and is locked
            if !lock_path.exists() {
                if let Some(cached) = check_credentials()? {
                    return Ok(Some(cached));
                } else {
                    return Ok(None);
                }
            }

            // Try to acquire the lock to see if it's free
            if let Some(test_lock) = Self::try_acquire(port)? {
                drop(test_lock); // Release immediately

                if let Some(cached) = check_credentials()? {
                    return Ok(Some(cached));
                } else {
                    return Ok(None);
                }
            }

            std::thread::sleep(Duration::from_millis(500));
        }
    }
}

impl Drop for PortLock {
    fn drop(&mut self) {
        // Drop the file handle (releases the flock)
        self._file = None;

        // Try to remove the lock file (best effort)
        let _ = std::fs::remove_file(&self.lock_path);
    }
}
