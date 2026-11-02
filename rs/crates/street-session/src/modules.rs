//! One record per module — main image + each import DLL (IDA-style).

use serde::{Deserialize, Serialize};
use street_core::imports::imports_by_dll;
use street_core::pe::parse_pe;
use street_core::{sha256_bytes, Arch};
use street_disasm::func::recover_pe;
use street_disasm::RecoveredFn;
use street_lift::{lift_bytes, Abi, LiftOptions, LiftResult};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleInfo {
    pub id: String,
    pub name: String,
    pub kind: String, // "main" | "import_dll" | "system_stub"
    pub path: Option<String>,
    pub base: u64,
    pub size: u64,
    pub sha256: Option<String>,
    pub arch: String,
    pub entry_rva: Option<u32>,
    pub function_count: usize,
    pub import_count: usize,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCard {
    pub name: String,
    pub start: u64,
    pub size: u64,
    pub pseudocode_path: String,
    pub ir_path: String,
    pub status: String,
}

pub struct ModuleBuild {
    pub info: ModuleInfo,
    pub functions: Vec<FunctionCard>,
    pub dir: PathBuf,
}

pub fn build_modules(main_path: &Path, data: &[u8], out_root: &Path) -> Vec<ModuleBuild> {
    let mut out = Vec::new();
    let main_name = main_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("main.exe")
        .to_string();

    // --- main module ---
    let main_dir = out_root.join("modules").join(sanitize(&main_name));
    let _ = std::fs::create_dir_all(main_dir.join("pseudocode"));
    let _ = std::fs::create_dir_all(main_dir.join("ir"));
    let _ = std::fs::create_dir_all(main_dir.join("disasm"));

    let (base, fns, disasm) = match recover_pe(data, 60_000) {
        Ok(t) => t,
        Err(e) => {
            let info = ModuleInfo {
                id: "mod_000_main".into(),
                name: main_name.clone(),
                kind: "main".into(),
                path: Some(main_path.display().to_string()),
                base: 0,
                size: data.len() as u64,
                sha256: Some(sha256_bytes(data)),
                arch: "unknown".into(),
                entry_rva: None,
                function_count: 0,
                import_count: 0,
                notes: vec![format!("function recovery gap: {e}")],
            };
            let _ = std::fs::write(
                main_dir.join("MODULE.json"),
                serde_json::to_vec_pretty(&info).unwrap_or_default(),
            );
            out.push(ModuleBuild {
                info,
                functions: vec![],
                dir: main_dir,
            });
            return extend_with_dll_stubs(out, data, out_root);
        }
    };

    let img = parse_pe(data).ok();
    let arch = img.as_ref().map(|i| i.arch).unwrap_or(Arch::X64);
    let entry_rva = img.as_ref().map(|i| i.entry_rva);
    let imports = imports_by_dll(data);

    let mut cards = Vec::new();
    let opt = LiftOptions {
        abi: Abi::Win64,
        asm_comments: true,
        max_insns: 512,
    };
    for (i, f) in fns.iter().take(64).enumerate() {
        let size = f.size.max(16).min(0x800) as usize;
        let (code, va) = street_disasm::func::function_bytes(data, f.start, size)
            .unwrap_or((&[][..], f.start));
        let lift = if code.is_empty() {
            LiftResult {
                schema_version: 1,
                backend: "gap",
                arch: arch.as_str().into(),
                start: f.start,
                name: f.name.clone(),
                signature: format!("void {}(void)", f.name),
                c: format!("/* gap: no bytes for {} @ {:#x} */\nvoid {}(void) {{}}\n", f.name, f.start, f.name),
                insn_count: 0,
                structured: false,
                notes: vec!["empty_code".into()],
            }
        } else {
            lift_bytes(code, va, arch, &f.name, &opt)
        };
        let pc_name = format!("{:04}_{}.c", i, sanitize(&f.name));
        let ir_name = format!("{:04}_{}.json", i, sanitize(&f.name));
        let _ = std::fs::write(main_dir.join("pseudocode").join(&pc_name), &lift.c);
        let ir = street_ir::lift_x86(code, va, if matches!(arch, Arch::X86) { 32 } else { 64 }, &f.name, 256);
        let _ = std::fs::write(
            main_dir.join("ir").join(&ir_name),
            serde_json::to_vec_pretty(&ir).unwrap_or_default(),
        );
        cards.push(FunctionCard {
            name: f.name.clone(),
            start: f.start,
            size: f.size,
            pseudocode_path: format!("pseudocode/{pc_name}"),
            ir_path: format!("ir/{ir_name}"),
            status: if lift.insn_count > 0 { "ok" } else { "gap" }.into(),
        });
    }

    // listing at entry
    if let Some(ep) = entry_rva {
        let listing = street_disasm::listing(&disasm, Some(80));
        let _ = std::fs::write(main_dir.join("disasm").join("entry_window.txt"), listing);
        let _ = ep;
        let _ = base;
    }

    let info = ModuleInfo {
        id: "mod_000_main".into(),
        name: main_name,
        kind: "main".into(),
        path: Some(main_path.display().to_string()),
        base: img.as_ref().map(|i| i.image_base).unwrap_or(base),
        size: data.len() as u64,
        sha256: Some(sha256_bytes(data)),
        arch: arch.as_str().into(),
        entry_rva,
        function_count: cards.len(),
        import_count: imports.iter().map(|d| d.count).sum(),
        notes: vec!["main image — full lift".into()],
    };
    let _ = std::fs::write(
        main_dir.join("MODULE.json"),
        serde_json::to_vec_pretty(&info).unwrap_or_default(),
    );
    let _ = std::fs::write(
        main_dir.join("FUNCTIONS.json"),
        serde_json::to_vec_pretty(&cards).unwrap_or_default(),
    );
    let _ = std::fs::write(
        main_dir.join("IMPORTS.json"),
        serde_json::to_vec_pretty(&imports).unwrap_or_default(),
    );

    out.push(ModuleBuild {
        info,
        functions: cards,
        dir: main_dir,
    });

    extend_with_dll_stubs(out, data, out_root)
}

fn extend_with_dll_stubs(mut out: Vec<ModuleBuild>, data: &[u8], out_root: &Path) -> Vec<ModuleBuild> {
    let imports = imports_by_dll(data);
    for (i, dll) in imports.into_iter().enumerate() {
        let id = format!("mod_{:03}_{}", i + 1, sanitize(&dll.dll));
        let dir = out_root.join("modules").join(sanitize(&dll.dll));
        let _ = std::fs::create_dir_all(&dir);
        let sys = resolve_system_dll(&dll.dll);
        let mut notes = vec![
            "Import DLL — separate IDA-style module card.".into(),
            "Body not lifted unless local copy is found.".into(),
        ];
        let (kind, path, sha, size, fns) = if let Some(ref p) = sys {
            notes.push(format!("resolved on disk: {}", p.display()));
            match std::fs::read(p) {
                Ok(bytes) => {
                    let sha = sha256_bytes(&bytes);
                    let fns = recover_pe(&bytes, 8_000)
                        .map(|(_, f, _)| f)
                        .unwrap_or_default();
                    // write import surface + optional short listing
                    let _ = std::fs::write(
                        dir.join("EXPORTS_USED.json"),
                        serde_json::to_vec_pretty(&dll.funcs).unwrap_or_default(),
                    );
                    (
                        "import_dll".into(),
                        Some(p.display().to_string()),
                        Some(sha),
                        bytes.len() as u64,
                        fns,
                    )
                }
                Err(e) => {
                    notes.push(format!("read gap: {e}"));
                    (
                        "system_stub".into(),
                        Some(p.display().to_string()),
                        None,
                        0,
                        Vec::<RecoveredFn>::new(),
                    )
                }
            }
        } else {
            notes.push("not found under System32/SysWOW64 — stub only".into());
            let _ = std::fs::write(
                dir.join("EXPORTS_USED.json"),
                serde_json::to_vec_pretty(&dll.funcs).unwrap_or_default(),
            );
            ("system_stub".into(), None, None, 0, vec![])
        };

        let _ = std::fs::create_dir_all(dir.join("pseudocode"));
        let mut externs = String::from("/* external DLL surface — Street session */\n#include <stdint.h>\n\n");
        for f in &dll.funcs {
            externs.push_str(&format!("/* import */ uint64_t {}(void);\n", sanitize_c_ident(f)));
        }
        let _ = std::fs::write(dir.join("pseudocode").join("externs.c"), &externs);

        let info = ModuleInfo {
            id: id.clone(),
            name: dll.dll.clone(),
            kind,
            path,
            base: 0,
            size,
            sha256: sha,
            arch: "x64".into(),
            entry_rva: None,
            function_count: fns.len().min(dll.funcs.len()),
            import_count: 0,
            notes,
        };
        let _ = std::fs::write(
            dir.join("MODULE.json"),
            serde_json::to_vec_pretty(&info).unwrap_or_default(),
        );
        let _ = std::fs::write(
            dir.join("IMPORTS_USED.json"),
            serde_json::to_vec_pretty(&dll).unwrap_or_default(),
        );
        out.push(ModuleBuild {
            info,
            functions: dll
                .funcs
                .iter()
                .take(64)
                .map(|f| FunctionCard {
                    name: f.clone(),
                    start: 0,
                    size: 0,
                    pseudocode_path: "pseudocode/externs.c".into(),
                    ir_path: String::new(),
                    status: "extern".into(),
                })
                .collect(),
            dir,
        });
    }
    out
}

fn resolve_system_dll(name: &str) -> Option<PathBuf> {
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    let candidates = [
        std::env::var("SYSTEMROOT").unwrap_or_else(|_| r"C:\Windows".into()) + r"\System32\" + name,
        std::env::var("SYSTEMROOT").unwrap_or_else(|_| r"C:\Windows".into()) + r"\SysWOW64\" + name,
    ];
    for c in candidates {
        let p = PathBuf::from(&c);
        if p.is_file() {
            return Some(p);
        }
    }
    // api-ms-win-* are forwarders — leave stub
    None
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

fn sanitize_c_ident(s: &str) -> String {
    let mut t: String = s
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
        .collect();
    if t.is_empty() {
        t = "sym".into();
    }
    if t.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
        t = format!("f_{t}");
    }
    t
}
