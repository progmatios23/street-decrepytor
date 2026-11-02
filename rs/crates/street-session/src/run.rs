use crate::emu::emulate_entry;
use crate::flow::build_encryption_flows;
use crate::modules::build_modules;
use serde::{Deserialize, Serialize};
use std::path::Path;
use street_core::inventory::inventory_bytes;
use street_crypto::run_static_bytes;

#[derive(Debug, Clone)]
pub struct SessionOptions {
    pub max_emu_insns: u64,
}

impl Default for SessionOptions {
    fn default() -> Self {
        Self { max_emu_insns: 2048 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionReport {
    pub schema_version: u32,
    pub path: String,
    pub out_dir: String,
    pub modules: usize,
    pub dll_modules: usize,
    pub functions_lifted: usize,
    pub encryption_flows: usize,
    pub emu_insns: u64,
    pub emu_stop: String,
    pub decrypted: bool,
    pub role: String,
    pub notes: Vec<String>,
    pub tree: Vec<String>,
}

pub fn run_session(path: &Path, out_dir: &Path, opt: &SessionOptions) -> SessionReport {
    let _ = std::fs::create_dir_all(out_dir);
    let mut notes = Vec::new();
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            let r = SessionReport {
                schema_version: 1,
                path: path.display().to_string(),
                out_dir: out_dir.display().to_string(),
                modules: 0,
                dll_modules: 0,
                functions_lifted: 0,
                encryption_flows: 0,
                emu_insns: 0,
                emu_stop: "read_fail".into(),
                decrypted: false,
                role: "unknown".into(),
                notes: vec![format!("read gap: {e}")],
                tree: vec![],
            };
            let _ = std::fs::write(
                out_dir.join("SESSION.json"),
                serde_json::to_vec_pretty(&r).unwrap_or_default(),
            );
            return r;
        }
    };

    // 0) full PE weight
    let _ = street_core::dump_full(path, &out_dir.join("pe"));

    // 1) inventory
    let inv = inventory_bytes(path, &data);
    let _ = std::fs::write(
        out_dir.join("HOST_INVENTORY.json"),
        serde_json::to_vec_pretty(&inv).unwrap_or_default(),
    );

    // 2) modules (main + DLLs)
    let modules = build_modules(path, &data, out_dir);
    let dll_n = modules.iter().filter(|m| m.info.kind != "main").count();
    let fns = modules
        .iter()
        .filter(|m| m.info.kind == "main")
        .map(|m| m.functions.len())
        .sum::<usize>();
    let mods_json: Vec<_> = modules.iter().map(|m| &m.info).collect();
    let _ = std::fs::write(
        out_dir.join("MODULES.json"),
        serde_json::to_vec_pretty(&mods_json).unwrap_or_default(),
    );

    // 3) encryption flows + stub C
    let flows = build_encryption_flows(path, &data, out_dir);

    // 4) crypto ranking (same engine, gaps ok)
    let crypto = run_static_bytes(path, &data);
    let decrypted = crypto.as_ref().map(|c| c.decrypted).unwrap_or(false);
    if let Ok(c) = &crypto {
        let _ = street_crypto::write_report(c, &out_dir.join("crypto"));
    } else {
        notes.push("crypto engine gap — flows still written".into());
    }

    // 5) string deobfuscation
    let strings = street_crypto::deobfuscate_strings(&data);
    let _ = std::fs::create_dir_all(out_dir.join("strings"));
    let _ = std::fs::write(
        out_dir.join("strings").join("STRINGS_DEOBF.json"),
        serde_json::to_vec_pretty(&strings).unwrap_or_default(),
    );
    let mut clear = String::new();
    clear.push_str("# deobfuscated\n");
    for s in &strings.deobfuscated {
        clear.push_str(&format!("[{}] {}\n", s.origin, s.value));
    }
    clear.push_str("\n# plaintext interesting\n");
    for s in strings.plaintext.iter().filter(|s| s.score >= 50).take(200) {
        clear.push_str(&format!("{}\n", s.value));
    }
    let _ = std::fs::write(out_dir.join("strings").join("STRINGS_CLEAR.txt"), clear);

    // 6) entry emu
    let emu = emulate_entry(&data, opt.max_emu_insns);
    let _ = std::fs::write(
        out_dir.join("ENTRY_EMU.json"),
        serde_json::to_vec_pretty(&emu).unwrap_or_default(),
    );

    notes.extend(inv.notes.iter().cloned());
    notes.push(format!(
        "IDA-like tree: {} modules ({} dlls), {} funcs lifted, {} enc flows, emu {} insns stop={}",
        modules.len(),
        dll_n,
        fns,
        flows.len(),
        emu.instructions_run,
        emu.stop_reason
    ));

    let tree = collect_tree(out_dir, 0, 3);
    let r = SessionReport {
        schema_version: 1,
        path: path.display().to_string(),
        out_dir: out_dir.display().to_string(),
        modules: modules.len(),
        dll_modules: dll_n,
        functions_lifted: fns,
        encryption_flows: flows.len(),
        emu_insns: emu.instructions_run,
        emu_stop: emu.stop_reason,
        decrypted,
        role: inv.role_guess,
        notes,
        tree,
    };
    let _ = std::fs::write(
        out_dir.join("SESSION.json"),
        serde_json::to_vec_pretty(&r).unwrap_or_default(),
    );
    let _ = std::fs::write(out_dir.join("SESSION.md"), render_md(&r));
    r
}

fn collect_tree(dir: &Path, depth: usize, max: usize) -> Vec<String> {
    if depth > max {
        return vec![];
    }
    let mut rows = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return rows;
    };
    let mut ents: Vec<_> = rd.flatten().collect();
    ents.sort_by_key(|e| e.file_name());
    for e in ents.into_iter().take(80) {
        let name = e.file_name().to_string_lossy().into_owned();
        let pad = "  ".repeat(depth);
        if e.path().is_dir() {
            rows.push(format!("{pad}{name}/"));
            rows.extend(collect_tree(&e.path(), depth + 1, max));
        } else {
            rows.push(format!("{pad}{name}"));
        }
    }
    rows
}

fn render_md(r: &SessionReport) -> String {
    let mut s = String::new();
    s.push_str("# Street session (IDA-like)\n\n");
    s.push_str(&format!("- path: `{}`\n", r.path));
    s.push_str(&format!("- role: **{}**\n", r.role));
    s.push_str(&format!("- modules: {} (dlls {})\n", r.modules, r.dll_modules));
    s.push_str(&format!("- functions lifted: {}\n", r.functions_lifted));
    s.push_str(&format!("- encryption flows: {}\n", r.encryption_flows));
    s.push_str(&format!("- entry emu: {} insns, stop=`{}`\n", r.emu_insns, r.emu_stop));
    s.push_str(&format!("- decrypted: **{}**\n\n", r.decrypted));
    s.push_str("## Tree\n\n```\n");
    for t in r.tree.iter().take(120) {
        s.push_str(t);
        s.push('\n');
    }
    s.push_str("```\n\n## Notes\n\n");
    for n in &r.notes {
        s.push_str(&format!("- {n}\n"));
    }
    s
}
