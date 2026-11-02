use crate::backend::*;
use std::path::PathBuf;

#[derive(Default)]
pub struct BinjaJsonBackend {
    pub export_dir: Option<PathBuf>,
}

impl Decompiler for BinjaJsonBackend {
    fn caps(&self) -> BackendCaps {
        BackendCaps {
            decompile: self.export_dir.is_some(),
            asm: self.export_dir.is_some(),
            xrefs: true,
            cfg: true,
            pcode: false,
            structs: true,
            strings: true,
            live: false,
            note: "reads Binary Ninja hlil/hlil json dumps",
        }
    }

    fn decompile(&self, req: &DecompileRequest) -> Result<DecompileText, EvidenceGap> {
        let dir = self.export_dir.as_ref().ok_or_else(|| EvidenceGap {
            kind: "unavailable".into(),
            site: format!("0x{:x}", req.addr),
            reason: "binja_export_dir_not_set".into(),
        })?;
        let p = dir.join(format!("{:x}.json", req.addr));
        let text = std::fs::read_to_string(&p).map_err(|e| EvidenceGap {
            kind: "query_failed".into(),
            site: p.display().to_string(),
            reason: e.to_string(),
        })?;
        let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| EvidenceGap {
            kind: "query_failed".into(),
            site: p.display().to_string(),
            reason: e.to_string(),
        })?;
        let c = v
            .get("hlil")
            .or_else(|| v.get("pseudocode"))
            .or_else(|| v.get("decompiled"))
            .and_then(|x| x.as_str())
            .ok_or_else(|| EvidenceGap {
                kind: "unavailable".into(),
                site: format!("0x{:x}", req.addr),
                reason: "missing_hlil".into(),
            })?
            .to_string();
        let (c, _) = truncate_c(c, req.max_chars);
        Ok(DecompileText {
            schema_version: 1,
            backend: "binja-json".into(),
            addr: req.addr,
            name: req.name.clone(),
            signature: String::new(),
            c,
            insn_count: 0,
            structured: true,
        })
    }
}
