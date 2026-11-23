//! Local allowlist and denylist handling.

use std::collections::BTreeSet;
use std::path::Path;

use crate::hashing::{HashAlgo, Hashes};

/// In-memory hash lists for one purpose (allow or deny).
#[derive(Debug, Clone, Default)]
pub struct HashListSet {
    sha256: BTreeSet<String>,
    sha1: BTreeSet<String>,
    md5: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListKind {
    Allow,
    Deny,
}

impl HashListSet {
    pub fn from_config(list: &crate::config::HashList, kind: ListKind) -> Result<Self, String> {
        let mut set = Self::default();
        let label = match kind {
            ListKind::Allow => "allowlist",
            ListKind::Deny => "denylist",
        };
        let mut add = |algo: HashAlgo, value: &str| -> Result<(), String> {
            let normalized = value.trim().to_lowercase();
            if !algo.is_valid_hex(&normalized) {
                return Err(format!(
                    "lists.{label}: {value:?} is not a valid {} hash",
                    algo.name()
                ));
            }
            match algo {
                HashAlgo::Sha256 => set.sha256.insert(normalized),
                HashAlgo::Sha1 => set.sha1.insert(normalized),
                HashAlgo::Md5 => set.md5.insert(normalized),
            };
            Ok(())
        };
        for value in &list.sha256 {
            add(HashAlgo::Sha256, value)?;
        }
        for value in &list.sha1 {
            add(HashAlgo::Sha1, value)?;
        }
        for value in &list.md5 {
            add(HashAlgo::Md5, value)?;
        }
        for file in &list.files {
            load_file(file, &mut set).map_err(|e| format!("lists.{label}: {e}"))?;
        }
        Ok(set)
    }

    #[must_use]
    pub fn contains(&self, algo: HashAlgo, hash: &str) -> bool {
        let normalized = hash.to_lowercase();
        match algo {
            HashAlgo::Sha256 => self.sha256.contains(&normalized),
            HashAlgo::Sha1 => self.sha1.contains(&normalized),
            HashAlgo::Md5 => self.md5.contains(&normalized),
        }
    }

    /// Check a computed hash set against this list.
    #[must_use]
    pub fn check(&self, hashes: &Hashes) -> Option<HashAlgo> {
        for (algo, value) in &hashes.values {
            if self.contains(*algo, value) {
                return Some(*algo);
            }
        }
        None
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.sha256.len() + self.sha1.len() + self.md5.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Load a hash list file: one hash per line, `#` comments and blank lines
/// ignored. Entries are validated against their length.
fn load_file(path: &str, set: &mut HashListSet) -> Result<(), String> {
    let content = std::fs::read_to_string(Path::new(path))
        .map_err(|e| format!("cannot read list file {path}: {e}"))?;
    for (line_no, line) in content.lines().enumerate() {
        let entry = line.trim();
        if entry.is_empty() || entry.starts_with('#') {
            continue;
        }
        let algo = match entry.len() {
            64 => HashAlgo::Sha256,
            40 => HashAlgo::Sha1,
            32 => HashAlgo::Md5,
            _ => {
                return Err(format!(
                    "{path}:{line_no}: {entry:?} is not a 32, 40 or 64 character hash"
                ))
            }
        };
        if !algo.is_valid_hex(&entry.to_lowercase()) {
            return Err(format!("{path}:{line_no}: {entry:?} is not valid hex"));
        }
        let normalized = entry.to_lowercase();
        match algo {
            HashAlgo::Sha256 => set.sha256.insert(normalized),
            HashAlgo::Sha1 => set.sha1.insert(normalized),
            HashAlgo::Md5 => set.md5.insert(normalized),
        };
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_entries_validated() {
        let config = crate::config::HashList {
            sha256: vec!["E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855".into()],
            sha1: vec!["ZZ".into()],
            md5: vec![],
            files: vec![],
        };
        assert!(HashListSet::from_config(&config, ListKind::Deny).is_err());
    }

    #[test]
    fn lookup_across_algorithms() {
        let config = crate::config::HashList {
            sha256: vec!["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into()],
            sha1: vec![],
            md5: vec!["d41d8cd98f00b204e9800998ecf8427e".into()],
            files: vec![],
        };
        let set = HashListSet::from_config(&config, ListKind::Allow).expect("valid");
        let hashes = Hashes {
            values: [(
                HashAlgo::Md5,
                "d41d8cd98f00b204e9800998ecf8427e".to_string(),
            )]
            .into_iter()
            .collect(),
        };
        assert_eq!(set.check(&hashes), Some(HashAlgo::Md5));
        assert!(set.contains(
            HashAlgo::Sha256,
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        ));
        assert!(!set.contains(HashAlgo::Sha1, "da39a3ee5e6b4b0d3255bfef95601890afd80709"));
    }

    #[test]
    fn list_file_with_comments() {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        std::io::Write::write_all(&mut f, b"# comment\n\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\nda39a3ee5e6b4b0d3255bfef95601890afd80709\n").expect("write");
        let config = crate::config::HashList {
            files: vec![f.path().display().to_string()],
            ..Default::default()
        };
        let set = HashListSet::from_config(&config, ListKind::Deny).expect("valid");
        assert_eq!(set.len(), 2);
        assert!(set.contains(HashAlgo::Sha1, "da39a3ee5e6b4b0d3255bfef95601890afd80709"));
    }

    #[test]
    fn list_file_rejects_bad_entries() {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        std::io::Write::write_all(&mut f, b"not-a-hash\n").expect("write");
        let config = crate::config::HashList {
            files: vec![f.path().display().to_string()],
            ..Default::default()
        };
        assert!(HashListSet::from_config(&config, ListKind::Deny).is_err());
    }
}
