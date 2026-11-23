//! Streaming multi-algorithm hashing with TOCTOU protection.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use digest::{Digest, DynDigest};
use md5::Md5;
use serde::Serialize;
use sha1::Sha1;
use sha2::Sha256;
use thiserror::Error;

pub const BUFFER_SIZE: usize = 64 * 1024;

#[derive(Debug, Error)]
pub enum HashError {
    #[error("cannot open file {path}: {source}")]
    Open {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot read file {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("file changed during hashing: {path}")]
    Unstable { path: String },
    #[error("file too large: {path} is {size} bytes, limit is {limit} bytes")]
    TooLarge { path: String, size: u64, limit: u64 },
    #[error("unknown hash algorithm {0}")]
    UnknownAlgorithm(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgo {
    Sha256,
    Sha1,
    Md5,
}

impl HashAlgo {
    pub fn parse(value: &str) -> Result<Self, HashError> {
        match value {
            "sha256" => Ok(Self::Sha256),
            "sha1" => Ok(Self::Sha1),
            "md5" => Ok(Self::Md5),
            other => Err(HashError::UnknownAlgorithm(other.to_string())),
        }
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha1 => "sha1",
            Self::Md5 => "md5",
        }
    }

    fn new_hasher(self) -> Box<dyn DynDigest> {
        match self {
            Self::Sha256 => Box::new(Sha256::new()),
            Self::Sha1 => Box::new(Sha1::new()),
            Self::Md5 => Box::new(Md5::new()),
        }
    }

    #[must_use]
    pub fn is_valid_hex(self, value: &str) -> bool {
        let expected = match self {
            Self::Sha256 => 64,
            Self::Sha1 => 40,
            Self::Md5 => 32,
        };
        value.len() == expected && value.chars().all(|c| c.is_ascii_hexdigit())
    }
}

/// Hash values for one file, keyed by algorithm.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct Hashes {
    #[serde(flatten)]
    pub values: BTreeMap<HashAlgo, String>,
}

impl Hashes {
    pub fn get(&self, algo: HashAlgo) -> Option<&str> {
        self.values.get(&algo).map(String::as_str)
    }

    #[must_use]
    pub fn primary_sha256(&self) -> Option<&str> {
        self.get(HashAlgo::Sha256)
    }
}

/// Identity snapshot used to detect a file that changed while being read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileIdentity {
    dev: u64,
    ino: u64,
    size: u64,
    mtime_seconds: i64,
}

impl FileIdentity {
    #[must_use]
    pub fn from_metadata(meta: &std::fs::Metadata) -> Self {
        Self {
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.size(),
            mtime_seconds: meta.mtime(),
        }
    }

    #[must_use]
    pub fn matches(&self, meta: &std::fs::Metadata) -> bool {
        Self::from_metadata(meta) == *self
    }

    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }
}

/// Hash an already open file descriptor. The identity is verified before and
/// after reading so an unstable file produces `Unstable` instead of a
/// trustworthy-looking hash.
pub fn hash_file_from(
    file: &File,
    path_for_errors: &Path,
    algorithms: &[HashAlgo],
    max_file_size: u64,
) -> Result<Hashes, HashError> {
    let display = path_for_errors.display().to_string();
    let start_meta = file.metadata().map_err(|e| HashError::Open {
        path: display.clone(),
        source: e,
    })?;
    let identity = FileIdentity::from_metadata(&start_meta);
    if start_meta.len() > max_file_size.saturating_mul(1024 * 1024) {
        return Err(HashError::TooLarge {
            path: display,
            size: start_meta.len(),
            limit: max_file_size * 1024 * 1024,
        });
    }

    let mut hashers: Vec<(HashAlgo, Box<dyn DynDigest>)> =
        algorithms.iter().map(|a| (*a, a.new_hasher())).collect();
    let mut reader = BufReader::with_capacity(BUFFER_SIZE, file);
    let mut buffer = vec![0u8; BUFFER_SIZE];
    loop {
        let read = reader.read(&mut buffer).map_err(|e| HashError::Read {
            path: display.clone(),
            source: e,
        })?;
        if read == 0 {
            break;
        }
        for (_, hasher) in &mut hashers {
            hasher.update(&buffer[..read]);
        }
    }

    let end_meta = file.metadata().map_err(|e| HashError::Read {
        path: display.clone(),
        source: e,
    })?;
    if !identity.matches(&end_meta) {
        return Err(HashError::Unstable { path: display });
    }

    let values = hashers
        .into_iter()
        .map(|(algo, hasher)| {
            let bytes = hasher.finalize();
            (algo, hex::encode(bytes))
        })
        .collect();
    Ok(Hashes { values })
}

/// Open `path` and hash it. Symlinks are followed or rejected depending on
/// `follow_symlinks`, which maps to `O_NOFOLLOW`.
pub fn hash_file(
    path: &Path,
    algorithms: &[HashAlgo],
    max_file_size: u64,
    follow_symlinks: bool,
) -> Result<Hashes, HashError> {
    let file = open_regular_file(path, follow_symlinks).map_err(|(e, source)| match e {
        OpenError::Io => HashError::Open {
            path: path.display().to_string(),
            source,
        },
        OpenError::Symlink => HashError::Open {
            path: path.display().to_string(),
            source: symlink_rejection(),
        },
    })?;
    hash_file_from(&file, path, algorithms, max_file_size)
}

pub enum OpenError {
    Io,
    Symlink,
}

fn symlink_rejection() -> std::io::Error {
    std::io::Error::from_raw_os_error(libc::ELOOP)
}

/// Open a file for hashing. With `follow_symlinks == false` a symlink is
/// rejected instead of silently dereferenced, so the operator controls what
/// gets hashed.
pub fn open_regular_file(
    path: &Path,
    follow_symlinks: bool,
) -> Result<File, (OpenError, std::io::Error)> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(if follow_symlinks { 0 } else { libc::O_NOFOLLOW });
    let file = options.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            (OpenError::Io, e)
        } else if !follow_symlinks && path.symlink_metadata().is_ok() && path.metadata().is_err() {
            (OpenError::Symlink, e)
        } else {
            (OpenError::Io, e)
        }
    })?;
    let meta = file.metadata().map_err(|e| (OpenError::Io, e))?;
    if !meta.is_file() {
        return Err((OpenError::Io, std::io::Error::other("not a regular file")));
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    fn write_temp(content: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(content).expect("write");
        f.flush().expect("flush");
        f
    }

    #[test]
    fn empty_file_hashes() {
        let f = write_temp(b"");
        let hashes = hash_file(
            f.path(),
            &[HashAlgo::Sha256, HashAlgo::Sha1, HashAlgo::Md5],
            512,
            false,
        )
        .expect("hash");
        assert_eq!(
            hashes.primary_sha256(),
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert_eq!(
            hashes.get(HashAlgo::Sha1),
            Some("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        );
        assert_eq!(
            hashes.get(HashAlgo::Md5),
            Some("d41d8cd98f00b204e9800998ecf8427e")
        );
    }

    #[test]
    fn known_vector_multi_algorithm() {
        let f = write_temp(b"hello world");
        let hashes = hash_file(
            f.path(),
            &[HashAlgo::Sha256, HashAlgo::Sha1, HashAlgo::Md5],
            512,
            false,
        )
        .expect("hash");
        assert_eq!(
            hashes.primary_sha256(),
            Some("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
        );
        assert_eq!(
            hashes.get(HashAlgo::Sha1),
            Some("2aae6c35c94fcfb415dbe95f408b9ce91ee846ed")
        );
        assert_eq!(
            hashes.get(HashAlgo::Md5),
            Some("5eb63bbbe01eeed093cb22bb8f5acdc3")
        );
    }

    #[test]
    fn larger_than_buffer_file() {
        let content: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let f = write_temp(&content);
        let hashes = hash_file(f.path(), &[HashAlgo::Sha256], 512, false).expect("hash");
        assert_eq!(hashes.primary_sha256().expect("sha256").len(), 64);
    }

    #[test]
    fn file_too_large_rejected() {
        let f = write_temp(&[0u8; 4096]);
        let err = hash_file(f.path(), &[HashAlgo::Sha256], 0, false).unwrap_err();
        assert!(matches!(err, HashError::TooLarge { .. }));
    }

    #[test]
    fn symlink_rejected_when_not_following() {
        let f = write_temp(b"target content");
        let link_path = f.path().with_extension("link");
        std::os::unix::fs::symlink(f.path(), &link_path).expect("symlink");
        let err = hash_file(&link_path, &[HashAlgo::Sha256], 512, false).unwrap_err();
        assert!(matches!(err, HashError::Open { .. }));
        let ok = hash_file(&link_path, &[HashAlgo::Sha256], 512, true).expect("follow");
        assert_eq!(
            ok.primary_sha256(),
            Some(
                hash_file(f.path(), &[HashAlgo::Sha256], 512, false)
                    .expect("direct")
                    .primary_sha256()
                    .expect("h")
            )
        );
    }

    #[test]
    fn permission_error_is_graceful() {
        let f = write_temp(b"secret");
        let mut perms = std::fs::metadata(f.path()).expect("meta").permissions();
        perms.set_mode(0o000);
        std::fs::set_permissions(f.path(), perms).expect("chmod");
        if std::fs::read(f.path()).is_ok() {
            // Running as root would still read the file; skip in that case.
            return;
        }
        let err = hash_file(f.path(), &[HashAlgo::Sha256], 512, false);
        assert!(err.is_err());
    }

    #[test]
    fn unstable_file_detected() {
        // Simulate the identity check: stat before, mutate mtime, stat after.
        let f = write_temp(b"content");
        let meta = std::fs::metadata(f.path()).expect("meta");
        let identity = FileIdentity::from_metadata(&meta);
        let new_time = libc::timeval {
            tv_sec: meta.mtime() + 5,
            tv_usec: 0,
        };
        let times = [new_time, new_time];
        let c_path = std::ffi::CString::new(f.path().to_str().expect("utf8")).expect("cstring");
        unsafe {
            assert_eq!(libc::utimes(c_path.as_ptr(), times.as_ptr()), 0);
        }
        let after = std::fs::metadata(f.path()).expect("meta");
        assert!(!identity.matches(&after));
    }

    #[test]
    fn algo_parse() {
        assert_eq!(HashAlgo::parse("sha256").expect("ok"), HashAlgo::Sha256);
        assert!(HashAlgo::parse("crc32").is_err());
        assert!(HashAlgo::Sha1.is_valid_hex("da39a3ee5e6b4b0d3255bfef95601890afd80709"));
        assert!(!HashAlgo::Md5.is_valid_hex("zz"));
    }
}
