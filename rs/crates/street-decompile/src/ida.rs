use crate::backend::*;
use std::path::PathBuf;

/// IDA / Hex-Rays JSON dump (idalib / ida_hexrays.get_pseudocode style).
#[derive(Default)]
pub struct IdaJsonBackend {
    pub export_dir: Option<PathBuf>,
}

impl Decompiler for IdaJsonBackend {
    fn caps(&self) -> BackendCaps {
        BackendCaps {
            decompile: self.export_dir.is_some(),
            asm: self.export_dir.is_some(),
            xrefs: self.export_dir.is_some(),
            cfg: false,
            pcode: false,
            structs: true,
            strings: true,
            live: false,
            note: "reads IDA json dumps {addr}.json with field `pseudocode`",
        }
    }

    fn decompile(&self, req: &DecompileRequest) -> Result<DecompileText, EvidenceGap> {
        let dir = self.export_dir.as_ref().ok_or_else(|| EvidenceGap {
            kind: "unavailable".into(),
            site: format!("0x{:x}", req.addr),
            reason: "ida_export_dir_not_set".into(),
        })?;
        let p = dir.join(format!("{:x}.json", req.addr));
        let p = if p.is_file() {
            p
        } else {
            dir.join(format!("0x{:x}.json", req.addr))
        };
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
            .get("pseudocode")
            .or_else(|| v.get("decompiled"))
            .and_then(|x| x.as_str())
            .ok_or_else(|| EvidenceGap {
                kind: "unavailable".into(),
                site: format!("0x{:x}", req.addr),
                reason: "missing_pseudocode".into(),
            })?
            .to_string();
        let (c, _) = truncate_c(c, req.max_chars);
        Ok(DecompileText {
            schema_version: 1,
            backend: "ida-json".into(),
            addr: req.addr,
            name: req.name.clone(),
            signature: v.get("signature").and_then(|x| x.as_str()).unwrap_or("").into(),
            c,
            insn_count: 0,
            structured: true,
        })
    }
}
