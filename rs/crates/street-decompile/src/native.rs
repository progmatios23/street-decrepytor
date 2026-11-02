use crate::backend::*;
use street_lift::{lift_bytes, LiftOptions};

pub struct NativeBackend;

impl Decompiler for NativeBackend {
    fn caps(&self) -> BackendCaps {
        BackendCaps {
            decompile: true,
            asm: true,
            xrefs: true,
            cfg: true,
            pcode: false,
            structs: false,
            strings: true,
            live: false,
            note: "street-lift native C printer (x86/x64 full, arm64 linear)",
        }
    }

    fn decompile(&self, req: &DecompileRequest) -> Result<DecompileText, EvidenceGap> {
        if req.code.is_empty() {
            return Err(EvidenceGap {
                kind: "unavailable".into(),
                site: format!("0x{:x}", req.addr),
                reason: "empty_code".into(),
            });
        }
        let opt = LiftOptions {
            abi: req.abi,
            asm_comments: req.asm_comments,
            max_insns: 4096,
        };
        let r = lift_bytes(&req.code, req.addr, req.arch, &req.name, &opt);
        let (c, _) = truncate_c(r.c, req.max_chars);
        Ok(DecompileText {
            schema_version: 1,
            backend: r.backend.into(),
            addr: req.addr,
            name: r.name,
            signature: r.signature,
            c,
            insn_count: r.insn_count,
            structured: r.structured,
        })
    }
}
