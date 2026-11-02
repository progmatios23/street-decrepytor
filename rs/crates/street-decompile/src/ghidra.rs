//! Consume ghidra-bridge / reagent JSON exports. schema_version must be 1.

use crate::backend::*;
use serde_json::Value;
use std::path::{Path, PathBuf};

#[derive(Default)]
pub struct GhidraJsonBackend {
    pub export_dir: Option<PathBuf>,
}

impl GhidraJsonBackend {
    pub fn with_dir(dir: PathBuf) -> Self {
        Self { export_dir: Some(dir) }
    }

    fn load(&self, addr: u64) -> Result<Value, EvidenceGap> {
        let dir = self.export_dir.as_ref().ok_or_else(|| EvidenceGap {
            kind: "unavailable".into(),
            site: format!("0x{addr:x}"),
            reason: "ghidra_export_dir_not_set".into(),
        })?;
        let path = find_addr_json(dir, addr).ok_or_else(|| EvidenceGap {
            kind: "unavailable".into(),
            site: format!("0x{addr:x}"),
            reason: "no_export_json".into(),
        })?;
        let text = std::fs::read_to_string(&path).map_err(|e| EvidenceGap {
            kind: "query_failed".into(),
            site: path.display().to_string(),
            reason: e.to_string(),
        })?;
        let v: Value = serde_json::from_str(&text).map_err(|e| EvidenceGap {
            kind: "query_failed".into(),
            site: path.display().to_string(),
            reason: e.to_string(),
        })?;
        let ver = v.get("schema_version").and_then(|x| x.as_u64()).unwrap_or(0);
        if ver != 0 && ver != 1 {
            return Err(EvidenceGap {
                kind: "unsupported".into(),
                site: path.display().to_string(),
                reason: format!("schema_version {ver} != 1"),
            });
        }
        Ok(v)
    }
}

impl Decompiler for GhidraJsonBackend {
    fn caps(&self) -> BackendCaps {
        BackendCaps {
            decompile: self.export_dir.is_some(),
            asm: self.export_dir.is_some(),
            xrefs: self.export_dir.is_some(),
            cfg: self.export_dir.is_some(),
            pcode: self.export_dir.is_some(),
            structs: self.export_dir.is_some(),
            strings: true,
            live: false,
            note: "reads reagent/ghidra-bridge export JSON; no Ghidra process",
        }
    }

    fn decompile(&self, req: &DecompileRequest) -> Result<DecompileText, EvidenceGap> {
        let v = self.load(req.addr)?;
        let c = v
            .get("decompiled")
            .and_then(|x| x.as_str())
            .or_else(|| v.get("c").and_then(|x| x.as_str()))
            .ok_or_else(|| EvidenceGap {
                kind: "unavailable".into(),
                site: format!("0x{:x}", req.addr),
                reason: "missing_decompiled_field".into(),
            })?
            .to_string();
        if c.is_empty() {
            return Err(EvidenceGap {
                kind: "unavailable".into(),
                site: format!("0x{:x}", req.addr),
                reason: "empty_decompiled".into(),
            });
        }
        let (c, _) = truncate_c(c, req.max_chars);
        Ok(DecompileText {
            schema_version: 1,
            backend: "ghidra-json".into(),
            addr: req.addr,
            name: v.get("name").and_then(|x| x.as_str()).unwrap_or(&req.name).into(),
            signature: v
                .get("signature")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .into(),
            c,
            insn_count: 0,
            structured: true,
        })
    }
}

fn find_addr_json(dir: &Path, addr: u64) -> Option<PathBuf> {
    let names = [
        format!("{addr:x}.json"),
        format!("0x{addr:x}.json"),
        format!("{addr:X}.json"),
        format!("0x{addr:X}.json"),
    ];
    for n in names {
        let p = dir.join(&n);
        if p.is_file() {
            return Some(p);
        }
        let p2 = dir.join("functions").join(&n);
        if p2.is_file() {
            return Some(p2);
        }
    }
    None
}
