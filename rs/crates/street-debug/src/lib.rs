//! One-process debugger. CreateProcess DEBUG_ONLY_THIS_PROCESS, like x64dbg's engine
//! without TitanEngine. Kernel RPM is a fallback, not a requirement.
//!
//! `live` adds x64dbg-shaped memory reconnaissance: enumerate the target's
//! virtual address space, flag and dump injected/downloaded shellcode, and
//! capture the kernel drivers the target loads.

#[cfg(windows)]
pub mod live;

#[cfg(windows)]
pub mod observe;

#[cfg(windows)]
pub mod trace;

#[cfg(windows)]
mod win;

#[cfg(windows)]
pub use win::*;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugSnapshot {
    pub pid: u32,
    pub tid: u32,
    pub running: bool,
    pub image_base: u64,
    pub rip: u64,
    pub rsp: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub last_event: String,
    pub cpu: Vec<String>,
    pub dump: Vec<u8>,
    pub dump_base: u64,
    pub modules: Vec<String>,
    pub log: Vec<String>,
    pub kernel: bool,
}

impl Default for DebugSnapshot {
    fn default() -> Self {
        Self {
            pid: 0,
            tid: 0,
            running: false,
            image_base: 0,
            rip: 0,
            rsp: 0,
            rax: 0,
            rcx: 0,
            rdx: 0,
            rbx: 0,
            rbp: 0,
            rsi: 0,
            rdi: 0,
            r8: 0,
            r9: 0,
            last_event: "idle".into(),
            cpu: vec![],
            dump: vec![],
            dump_base: 0,
            modules: vec![],
            log: vec![],
            kernel: false,
        }
    }
}

#[cfg(not(windows))]
pub struct Debugger;

#[cfg(not(windows))]
impl Debugger {
    pub fn spawn(_path: &str) -> Result<Self, String> {
        Err("windows only".into())
    }
}
