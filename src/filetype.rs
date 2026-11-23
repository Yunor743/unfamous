//! File classification from magic bytes and extensions.
//!
//! Extensions are weak signals: every category is confirmed by magic bytes or
//! content heuristics when possible, and extension-only matches are reported
//! as such so downstream policy can treat them with lower confidence.

use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::Path;

use serde::Serialize;

pub const SNIFF_SIZE: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Pe32,
    Pe32Plus,
    Elf,
    SharedObject,
    JavaScript,
    Hta,
    Vba,
    Cpl,
    ShellScript,
    Python,
    PowerShell,
}

impl Category {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Category::Pe32 => "pe32",
            Category::Pe32Plus => "pe32plus",
            Category::Elf => "elf",
            Category::SharedObject => "shared_object",
            Category::JavaScript => "javascript",
            Category::Hta => "hta",
            Category::Vba => "vba",
            Category::Cpl => "cpl",
            Category::ShellScript => "shell_script",
            Category::Python => "python",
            Category::PowerShell => "powershell",
        }
    }
}

/// A user defined category from `[file_types.custom.<name>]`.
#[derive(Debug, Clone)]
pub struct CustomCategory {
    pub name: String,
    pub extensions: Vec<String>,
    pub magic_hex: Vec<String>,
    pub require_magic: bool,
}

/// What matched. `magic` means the signature bytes were found in the file
/// itself; `extension` means the name matched and the sniff was inconclusive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Detection {
    pub category: String,
    pub confidence: MatchKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchKind {
    Magic,
    Extension,
}

/// Configuration needed to decide whether a file belongs to an enabled
/// category. Built once from `FileTypes`.
#[derive(Debug, Clone, Default)]
pub struct Classifier {
    pe: bool,
    elf: bool,
    shared_objects: bool,
    javascript: bool,
    hta: bool,
    vba: bool,
    cpl: bool,
    shell_scripts: bool,
    python: bool,
    powershell: bool,
    custom: Vec<CustomCategory>,
}

impl Classifier {
    #[must_use]
    pub fn from_config(types: &crate::config::FileTypes) -> Self {
        Self {
            pe: types.pe,
            elf: types.elf,
            shared_objects: types.shared_objects,
            javascript: types.javascript,
            hta: types.hta,
            vba: types.vba,
            cpl: types.cpl,
            shell_scripts: types.shell_scripts,
            python: types.python,
            powershell: types.powershell,
            custom: types
                .custom
                .iter()
                .map(|(name, c)| CustomCategory {
                    name: name.clone(),
                    extensions: c.extensions.clone(),
                    magic_hex: c.magic_hex.clone(),
                    require_magic: c.require_magic,
                })
                .collect(),
        }
    }

    /// Classify from a sniffed prefix and a file name.
    #[must_use]
    pub fn classify(&self, name: &str, sniff: &[u8]) -> Option<Detection> {
        self.classify_custom(name, sniff)
            .or_else(|| self.classify_builtin(name, sniff))
    }

    fn classify_custom(&self, name: &str, sniff: &[u8]) -> Option<Detection> {
        let lower = name.to_lowercase();
        for custom in &self.custom {
            let ext_match = custom
                .extensions
                .iter()
                .any(|ext| lower.ends_with(&ext.to_lowercase()));
            let magic_match = custom
                .magic_hex
                .iter()
                .filter_map(|m| hex::decode(m).ok())
                .any(|sig| sniff.starts_with(&sig));
            // require_magic demands the signature bytes; an extension alone
            // never selects the category.
            let hit = if custom.require_magic {
                magic_match
            } else {
                magic_match || ext_match
            };
            if hit {
                return Some(Detection {
                    category: custom.name.clone(),
                    confidence: if magic_match {
                        MatchKind::Magic
                    } else {
                        MatchKind::Extension
                    },
                });
            }
        }
        None
    }

    fn classify_builtin(&self, name: &str, sniff: &[u8]) -> Option<Detection> {
        let lower = name.to_lowercase();
        let has_ext = |exts: &[&str]| exts.iter().any(|e| lower.ends_with(e));
        let text = std::str::from_utf8(&sniff[..sniff.len().min(1024)]).ok();
        let lowered_text = text.map(str::to_lowercase);

        if sniff.starts_with(b"MZ") && sniff.len() > 0x40 {
            let pe_offset =
                u32::from_le_bytes([sniff[0x3c], sniff[0x3d], sniff[0x3e], sniff[0x3f]]) as usize;
            let pe_sig =
                sniff.len() > pe_offset + 4 && &sniff[pe_offset..pe_offset + 4] == b"PE\0\0";
            if pe_sig {
                let pe_plus = sniff.len() >= pe_offset + 26
                    && u16::from_le_bytes([sniff[pe_offset + 24], sniff[pe_offset + 25]]) == 0x20b;
                if has_ext(&[".cpl"]) && self.cpl {
                    return Some(Detection {
                        category: "cpl".into(),
                        confidence: MatchKind::Magic,
                    });
                }
                if pe_plus && self.pe {
                    return Some(Detection {
                        category: "pe32plus".into(),
                        confidence: MatchKind::Magic,
                    });
                }
                if self.pe {
                    return Some(Detection {
                        category: "pe32".into(),
                        confidence: MatchKind::Magic,
                    });
                }
            }
            return None;
        }

        if sniff.starts_with(&[0x7f, b'E', b'L', b'F']) && sniff.len() >= 18 {
            let etype = u16::from_le_bytes([sniff[16], sniff[17]]);
            if etype == 3 && has_ext(&[".so", ".so.1", ".so.2"]) && self.shared_objects {
                return Some(Detection {
                    category: "shared_object".into(),
                    confidence: MatchKind::Magic,
                });
            }
            if etype == 2 && self.elf {
                return Some(Detection {
                    category: "elf".into(),
                    confidence: MatchKind::Magic,
                });
            }
            if etype == 3 && self.elf {
                return Some(Detection {
                    category: "elf".into(),
                    confidence: MatchKind::Magic,
                });
            }
            return None;
        }

        if sniff.starts_with(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]) && self.vba {
            return Some(Detection {
                category: "vba".into(),
                confidence: MatchKind::Magic,
            });
        }

        if self.javascript {
            let ext_hit = has_ext(&[".js", ".mjs", ".cjs", ".jse"]);
            let looks_js = lowered_text.as_deref().is_some_and(|t| {
                [
                    "function ",
                    "var ",
                    "const ",
                    "let ",
                    "=>",
                    "document.",
                    "wscript.",
                    "require(",
                ]
                .iter()
                .any(|k| t.contains(k))
            });
            if ext_hit {
                return Some(Detection {
                    category: "javascript".into(),
                    confidence: MatchKind::Extension,
                });
            }
            if looks_js && has_ext(&[".txt", ""]) {
                return Some(Detection {
                    category: "javascript".into(),
                    confidence: MatchKind::Extension,
                });
            }
        }

        if self.hta {
            let ext_hit = has_ext(&[".hta"]);
            let looks_hta = lowered_text.as_deref().is_some_and(|t| {
                t.contains("<hta:application") || (t.contains("<html") && t.contains("vbscript"))
            });
            if ext_hit || looks_hta {
                return Some(Detection {
                    category: "hta".into(),
                    confidence: MatchKind::Extension,
                });
            }
        }

        if self.shell_scripts {
            let shebang = text.is_some_and(|t| t.starts_with("#!"));
            let ext_hit = has_ext(&[".sh", ".bash"]);
            if shebang || ext_hit {
                return Some(Detection {
                    category: "shell_script".into(),
                    confidence: MatchKind::Extension,
                });
            }
        }

        if self.python
            && (has_ext(&[".py", ".pyw"])
                || text.is_some_and(|t| t.starts_with("#!") && t.contains("python")))
        {
            return Some(Detection {
                category: "python".into(),
                confidence: MatchKind::Extension,
            });
        }

        if self.powershell && has_ext(&[".ps1", ".psm1", ".psd1"]) {
            return Some(Detection {
                category: "powershell".into(),
                confidence: MatchKind::Extension,
            });
        }

        None
    }
}

/// Sniff the first bytes of an open file and classify it.
pub fn classify_file(
    file: &File,
    name: &str,
    classifier: &Classifier,
) -> std::io::Result<Option<Detection>> {
    let mut sniff = vec![0u8; SNIFF_SIZE];
    let mut offset = 0;
    while offset < sniff.len() {
        let n = file.read_at(&mut sniff[offset..], offset as u64)?;
        if n == 0 {
            break;
        }
        offset += n;
    }
    sniff.truncate(offset);
    Ok(classifier.classify(name, &sniff))
}

/// Classify a path by opening and sniffing it.
pub fn classify_path(path: &Path, classifier: &Classifier) -> std::io::Result<Option<Detection>> {
    let file = std::fs::File::open(path)?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    classify_file(&file, name, classifier)
}

/// True when the category is enabled in the classifier configuration.
#[must_use]
pub fn category_enabled(classifier: &Classifier, category: &str) -> bool {
    if classifier.custom.iter().any(|c| c.name == category) {
        return true;
    }
    match category {
        "pe32" | "pe32plus" => classifier.pe,
        "elf" => classifier.elf,
        "shared_object" => classifier.shared_objects,
        "javascript" => classifier.javascript,
        "hta" => classifier.hta,
        "vba" => classifier.vba,
        "cpl" => classifier.cpl,
        "shell_script" => classifier.shell_scripts,
        "python" => classifier.python,
        "powershell" => classifier.powershell,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_on() -> Classifier {
        let types = crate::config::FileTypes {
            shell_scripts: true,
            python: true,
            powershell: true,
            ..crate::config::FileTypes::default()
        };
        Classifier::from_config(&types)
    }

    #[test]
    fn pe32_detected() {
        let mut mz = vec![b'M', b'Z'];
        mz.extend(vec![0u8; 0x3c - 2]);
        mz.extend((0x80u32).to_le_bytes());
        mz.extend(vec![0u8; 0x80 - mz.len()]);
        mz.extend(b"PE\0\0");
        mz.extend(vec![0u8; 20]);
        mz.extend(0x20bu16.to_le_bytes());
        let c = all_on();
        let d = c.classify("innocent.txt", &mz).expect("pe");
        assert_eq!(d.category, "pe32plus");
        assert_eq!(d.confidence, MatchKind::Magic);
    }

    #[test]
    fn cpl_detected() {
        let mut mz = vec![b'M', b'Z'];
        mz.extend(vec![0u8; 0x3c - 2]);
        mz.extend((0x80u32).to_le_bytes());
        mz.extend(vec![0u8; 0x80 - mz.len()]);
        mz.extend(b"PE\0\0");
        mz.extend(vec![0u8; 20]);
        mz.extend(0x10cu16.to_le_bytes());
        let c = all_on();
        let d = c.classify("control.cpl", &mz).expect("cpl");
        assert_eq!(d.category, "cpl");
    }

    #[test]
    fn elf_exec_and_shared_object() {
        let mut elf = vec![0x7f, b'E', b'L', b'F'];
        elf.extend(vec![0u8; 12]);
        elf.extend(2u16.to_le_bytes());
        let c = all_on();
        assert_eq!(c.classify("binary", &elf).expect("d").category, "elf");
        let mut so = vec![0x7f, b'E', b'L', b'F'];
        so.extend(vec![0u8; 12]);
        so.extend(3u16.to_le_bytes());
        assert_eq!(
            c.classify("libfoo.so", &so).expect("d").category,
            "shared_object"
        );
        assert_eq!(
            c.classify("libfoo.so.1", &so).expect("d").category,
            "shared_object"
        );
    }

    #[test]
    fn misleading_extension_not_pe() {
        let c = all_on();
        let mut junk = vec![b'M', b'Z'];
        junk.extend(vec![0xEEu8; 0x80]);
        assert!(c.classify("evil.exe", &junk).is_none());
    }

    #[test]
    fn ole_cfb_is_vba() {
        let ole = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1, 0, 0];
        let c = all_on();
        assert_eq!(c.classify("invoice.doc", &ole).expect("d").category, "vba");
    }

    #[test]
    fn text_categories() {
        let c = all_on();
        assert_eq!(
            c.classify("run.js", b"var x = 1; function f() {}".to_vec().as_slice())
                .expect("d")
                .category,
            "javascript"
        );
        assert_eq!(
            c.classify("page.hta", b"<html><hta:application></html>")
                .expect("d")
                .category,
            "hta"
        );
        assert_eq!(
            c.classify("build.sh", b"#!/bin/sh\necho hi")
                .expect("d")
                .category,
            "shell_script"
        );
        assert_eq!(
            c.classify("main.py", b"print('x')").expect("d").category,
            "python"
        );
        assert_eq!(
            c.classify("tool.ps1", b"Get-Process").expect("d").category,
            "powershell"
        );
    }

    #[test]
    fn unknown_file_format() {
        let c = all_on();
        assert!(c.classify("data.bin", &[0x89, b'P', b'N', b'G']).is_none());
        assert!(c.classify("readme", b"just text".as_slice()).is_none());
    }

    #[test]
    fn disabled_category_not_matched() {
        let types = crate::config::FileTypes {
            javascript: false,
            ..crate::config::FileTypes::default()
        };
        let c = Classifier::from_config(&types);
        assert!(c.classify("run.js", b"var x = 1;").is_none());
    }

    #[test]
    fn custom_category() {
        let mut types = crate::config::FileTypes::default();
        types.custom.insert(
            "firmware".to_string(),
            crate::config::CustomType {
                extensions: vec![".fw".to_string()],
                magic_hex: vec!["deadbeef".to_string()],
                require_magic: true,
            },
        );
        let c = Classifier::from_config(&types);
        assert!(c.classify("thing.fw", &[0x12, 0x34]).is_none());
        assert_eq!(
            c.classify("thing.fw", &[0xde, 0xad, 0xbe, 0xef])
                .expect("d")
                .category,
            "firmware"
        );
    }
}
