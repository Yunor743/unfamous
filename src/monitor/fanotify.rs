//! fanotify FFI: init, mount marks, event parsing, permission responses.
//!
//! The metadata layout is read from raw bytes so it does not depend on Rust
//! struct layout. Only the fields unfamous uses are decoded; the rest of
//! each record is skipped using `event_len`.

use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::RawFd;
use std::path::Path;

use libc::{AT_FDCWD, FAN_ALLOW, FAN_DENY};

/// Parsed subset of `struct fanotify_event_metadata`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FanotifyEvent {
    pub mask: u64,
    pub fd: RawFd,
    pub pid: i32,
    pub event_len: usize,
}

pub struct Fanotify {
    fd: RawFd,
}

const BUFFER_LEN: usize = 64 * 1024;

impl Drop for Fanotify {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

impl Fanotify {
    /// Initialize fanotify with the content permission class so permission
    /// events can be answered. Requires `CAP_SYS_ADMIN`.
    pub fn init() -> io::Result<Self> {
        let fd = unsafe {
            libc::fanotify_init(
                libc::FAN_CLASS_CONTENT | libc::FAN_UNLIMITED_QUEUE,
                (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_LARGEFILE) as u32,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd })
    }

    #[must_use]
    pub fn raw_fd(&self) -> RawFd {
        self.fd
    }

    /// Mark the entire filesystem containing `path`. Directory-only marks do
    /// not deliver events on some filesystems (for example the initramfs
    /// rootfs a microvm boots from), while filesystem marks do.
    /// Mark the entire filesystem containing `path`. Directory-only marks do
    /// not deliver events on some filesystems (for example the initramfs
    /// rootfs a microvm boots from), while filesystem marks do.
    pub fn mark_filesystem(&self, path: &Path, mask: u64) -> io::Result<()> {
        let c_path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::other("path contains NUL"))?;
        let flags = libc::FAN_MARK_ADD | libc::FAN_MARK_FILESYSTEM;
        let ret = unsafe { libc::fanotify_mark(self.fd, flags, mask, AT_FDCWD, c_path.as_ptr()) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Build the event mask from monitoring configuration.
    #[must_use]
    pub fn mask_for(execution: bool, file_access: bool, close_write: bool) -> u64 {
        let mut mask = 0u64;
        if execution {
            mask |= libc::FAN_OPEN_EXEC_PERM;
        }
        if file_access {
            mask |= libc::FAN_OPEN_PERM;
        }
        if close_write {
            mask |= libc::FAN_CLOSE_WRITE;
        }
        mask
    }

    /// Read and parse a batch of events from the fanotify fd. Blocking.
    pub fn read_events(&self) -> io::Result<Vec<FanotifyEvent>> {
        let mut buffer = vec![0u8; BUFFER_LEN];
        let read = unsafe { libc::read(self.fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        if read < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                return Ok(Vec::new());
            }
            return Err(e);
        }
        let read = read as usize;
        Ok(parse_events(&buffer[..read]))
    }

    /// Answer a permission event. Must be called exactly once per permission
    /// event, otherwise the monitored process blocks until it times out.
    pub fn respond(&self, fd: RawFd, allow: bool) -> io::Result<()> {
        let response = if allow { FAN_ALLOW } else { FAN_DENY };
        let resp = libc::fanotify_response { fd, response };
        let ret = unsafe {
            libc::write(
                self.fd,
                std::ptr::addr_of!(resp).cast(),
                std::mem::size_of::<libc::fanotify_response>(),
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn close(self) {}
}

/// Parse raw fanotify records. Malformed records are skipped; the loop is
/// bounded by `FAN_EVENT_OK`-style checks so a truncated buffer cannot
/// overread.
#[must_use]
pub fn parse_events(data: &[u8]) -> Vec<FanotifyEvent> {
    let mut events = Vec::new();
    let metadata_len = std::mem::size_of::<libc::fanotify_event_metadata>();
    let mut offset = 0usize;
    while offset + metadata_len <= data.len() {
        let record = &data[offset..];
        let event_len = u32::from_le_bytes([record[0], record[1], record[2], record[3]]) as usize;
        if event_len < metadata_len || offset + event_len > data.len() {
            break;
        }
        let mask = u64::from_le_bytes(record[8..16].try_into().expect("mask bytes"));
        let fd = i32::from_le_bytes(record[16..20].try_into().expect("fd bytes"));
        let pid = i32::from_le_bytes(record[20..24].try_into().expect("pid bytes"));
        events.push(FanotifyEvent {
            mask,
            fd,
            pid,
            event_len,
        });
        offset += event_len;
    }
    events
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAN_OPEN_EXEC_PERM: u64 = libc::FAN_OPEN_EXEC_PERM;
    const FAN_CLOSE_WRITE: u64 = libc::FAN_CLOSE_WRITE;

    fn record(mask: u64, fd: i32, pid: i32) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(24u32.to_le_bytes());
        buf.push(1); // vers
        buf.push(0); // reserved
        buf.extend(24u16.to_le_bytes());
        buf.extend(mask.to_le_bytes());
        buf.extend(fd.to_le_bytes());
        buf.extend(pid.to_le_bytes());
        buf
    }

    #[test]
    fn parses_single_event() {
        let data = record(FAN_OPEN_EXEC_PERM, 5, 1234);
        let events = parse_events(&data);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].mask, FAN_OPEN_EXEC_PERM);
        assert_eq!(events[0].fd, 5);
        assert_eq!(events[0].pid, 1234);
    }

    #[test]
    fn parses_multiple_events() {
        let mut data = record(FAN_OPEN_EXEC_PERM, 5, 1);
        data.extend(record(FAN_CLOSE_WRITE, 6, 2));
        let events = parse_events(&data);
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].fd, 6);
    }

    #[test]
    fn truncated_buffer_is_safe() {
        let data = record(FAN_OPEN_EXEC_PERM, 5, 1);
        let events = parse_events(&data[..9]);
        assert_eq!(events.len(), 0);
        let short = [0u8; 10];
        assert_eq!(parse_events(&short).len(), 0);
    }

    #[test]
    fn oversized_event_len_stops_parsing() {
        let mut data = vec![0xff, 0xff, 0xff, 0xff];
        data.extend(vec![0u8; 12]);
        assert_eq!(parse_events(&data).len(), 0);
    }

    #[test]
    fn mask_composition() {
        let mask = Fanotify::mask_for(true, false, true);
        assert_ne!(mask & FAN_OPEN_EXEC_PERM, 0);
        assert_eq!(mask & libc::FAN_OPEN_PERM, 0);
        assert_ne!(mask & FAN_CLOSE_WRITE, 0);
    }
}
