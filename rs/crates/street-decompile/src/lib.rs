//! Multi-backend decompiler registry.
//! native is always present. ghidra/ida/binja consume JSON exports (reagent-style).

pub mod backend;
pub mod binja;
pub mod ghidra;
pub mod ida;
pub mod native;
pub mod x64dbg_live;

pub use backend::{BackendCaps, BackendKind, DecompileRequest, DecompileText, EvidenceGap};

use backend::Decompiler;
use native::NativeBackend;

pub struct Registry {
    pub native: NativeBackend,
    pub ghidra: ghidra::GhidraJsonBackend,
    pub ida: ida::IdaJsonBackend,
    pub binja: binja::BinjaJsonBackend,
    pub x64dbg: x64dbg_live::X64dbgLive,
}

impl Registry {
    pub fn new() -> Self {
        Self {
            native: NativeBackend,
            ghidra: ghidra::GhidraJsonBackend::default(),
            ida: ida::IdaJsonBackend::default(),
            binja: binja::BinjaJsonBackend::default(),
            x64dbg: x64dbg_live::X64dbgLive::default(),
        }
    }

    pub fn list(&self) -> Vec<(BackendKind, BackendCaps)> {
        vec![
            (BackendKind::Native, self.native.caps()),
            (BackendKind::Ghidra, self.ghidra.caps()),
            (BackendKind::Ida, self.ida.caps()),
            (BackendKind::Binja, self.binja.caps()),
            (BackendKind::X64dbg, self.x64dbg.caps()),
        ]
    }

    pub fn get(&self, kind: BackendKind) -> &dyn Decompiler {
        match kind {
            BackendKind::Native => &self.native,
            BackendKind::Ghidra => &self.ghidra,
            BackendKind::Ida => &self.ida,
            BackendKind::Binja => &self.binja,
            BackendKind::X64dbg => &self.x64dbg,
        }
    }

    pub fn decompile(&self, kind: BackendKind, req: &DecompileRequest) -> Result<DecompileText, EvidenceGap> {
        self.get(kind).decompile(req)
    }

    /// Compare backends; each body is truncated (token-first).
    pub fn compare(&self, req: &DecompileRequest, max_chars: usize) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        for (kind, caps) in self.list() {
            if !caps.decompile {
                map.insert(
                    kind.as_str().into(),
                    serde_json::json!({"available": false, "reason": "capability_off"}),
                );
                continue;
            }
            match self.decompile(kind, req) {
                Ok(t) => {
                    let mut c = t.c;
                    let truncated = c.len() > max_chars;
                    if truncated {
                        c.truncate(max_chars);
                        c.push_str("\n/* truncated */");
                    }
                    map.insert(
                        kind.as_str().into(),
                        serde_json::json!({
                            "available": true,
                            "name": t.name,
                            "signature": t.signature,
                            "c": c,
                            "truncated": truncated,
                            "backend": t.backend,
                        }),
                    );
                }
                Err(g) => {
                    map.insert(
                        kind.as_str().into(),
                        serde_json::json!({"available": false, "gap": g}),
                    );
                }
            }
        }
        serde_json::Value::Object(map)
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}
