//! Live x64dbg companion: the plugin writes a JSON snapshot; this backend reads it.

use crate::backend::*;
use std::path::PathBuf;

#[derive(Default)]
pub struct X64dbgLive {
    pub snapshot: Option<PathBuf>,
}

impl Decompiler for X64dbgLive {
    fn caps(&self) -> BackendCaps {
        BackendCaps {
            decompile: false, // plugin calls native motor; this is a snapshot reader
            asm: self.snapshot.is_some(),
            xrefs: false,
            cfg: false,
            pcode: false,
            structs: false,
            strings: false,
            live: true,
            note: "x64dbg plugin dumps CIP bytes; native motor decompiles them",
        }
    }

    fn decompile(&self, req: &DecompileRequest) -> Result<DecompileText, EvidenceGap> {
        // If the request already carries code (plugin filled it), fall through to native.
        if !req.code.is_empty() {
            let n = crate::native::NativeBackend;
            return n.decompile(req);
        }
        Err(EvidenceGap {
            kind: "unavailable".into(),
            site: format!("0x{:x}", req.addr),
            reason: "x64dbg_no_live_bytes".into(),
        })
    }
}
