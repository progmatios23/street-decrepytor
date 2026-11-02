use std::collections::HashMap;
use street_core::{classify_bytes, ArtifactProfile};
use street_decompile::Registry;
use street_disasm::{func, DisasmResult, RecoveredFn};

pub struct OpenSession {
    pub id: u32,
    pub path: String,
    pub data: Vec<u8>,
    pub profile: ArtifactProfile,
    pub image_base: u64,
    pub functions: Vec<RecoveredFn>,
    pub disasm: Option<DisasmResult>,
}

pub struct SessionStore {
    next: u32,
    pub sessions: HashMap<u32, OpenSession>,
    pub registry: Registry,
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            next: 1,
            sessions: HashMap::new(),
            registry: Registry::new(),
        }
    }

    pub fn open_bytes(&mut self, path: &str, data: Vec<u8>) -> Result<u32, String> {
        let profile = classify_bytes(&data, None).map_err(|e| e.to_string())?;
        let (image_base, functions, disasm) = if profile.format == "pe" {
            match func::recover_pe(&data, 80_000) {
                Ok((b, f, d)) => (b, f, Some(d)),
                Err(_) => (0x140000000, vec![], None),
            }
        } else {
            (0, vec![], None)
        };
        let id = self.next;
        self.next += 1;
        self.sessions.insert(
            id,
            OpenSession {
                id,
                path: path.into(),
                data,
                profile,
                image_base,
                functions,
                disasm,
            },
        );
        Ok(id)
    }

    pub fn open_path(&mut self, path: &str) -> Result<u32, String> {
        let data = std::fs::read(path).map_err(|e| e.to_string())?;
        self.open_bytes(path, data)
    }

    pub fn get(&self, id: u32) -> Result<&OpenSession, String> {
        self.sessions.get(&id).ok_or_else(|| format!("no session {id}"))
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}
