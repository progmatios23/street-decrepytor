//! Open project format (JSON). One file, entity-level, Git-diffable.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use street_core::{sha256_bytes, Confidence};
use street_links::LinkReport;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub schema_version: u32,
    pub path: String,
    pub sha256: String,
    pub names: BTreeMap<String, String>,
    pub comments: BTreeMap<String, String>,
    pub links: Option<LinkReport>,
    pub notes: Vec<String>,
}

impl Project {
    pub fn new(path: &Path, data: &[u8]) -> Self {
        Self {
            schema_version: 1,
            path: path.display().to_string(),
            sha256: sha256_bytes(data),
            names: BTreeMap::new(),
            comments: BTreeMap::new(),
            links: None,
            notes: vec![],
        }
    }

    pub fn rename(&mut self, addr: u64, name: String) {
        self.names.insert(format!("0x{addr:x}"), name);
    }

    pub fn comment(&mut self, addr: u64, text: String, _conf: Confidence) {
        self.comments.insert(format!("0x{addr:x}"), text);
    }

    pub fn save(&self, out: &Path) -> std::io::Result<()> {
        std::fs::write(out, serde_json::to_vec_pretty(self).unwrap())
    }

    pub fn load(p: &Path) -> std::io::Result<Self> {
        let t = std::fs::read_to_string(p)?;
        serde_json::from_str(&t).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    pub fn default_path(bin: &Path) -> PathBuf {
        bin.with_extension("street.json")
    }
}
