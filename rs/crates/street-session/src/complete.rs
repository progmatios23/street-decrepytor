//! Complete dump pipeline — nothing skipped; every stage writes a file (ok or gap).

use crate::run::{run_session, SessionOptions};
use serde_json::json;
use std::path::Path;
use street_core::{dump_full, inventory_path};
use street_crypto::{
    build_ida_strings, deobfuscate_strings, format_ida_listing, harvest_ac_surface, run_static,
    write_report,
};

#[derive(Debug, Clone, serde::Serialize)]
pub struct CompleteReport {
    pub path: String,
    pub out_dir: String,
    pub stages: Vec<StageResult>,
    pub ok: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct StageResult {
    pub stage: String,
    pub status: String,
    pub detail: String,
}

pub fn dump_complete(path: &Path, out_dir: &Path) -> CompleteReport {
    let _ = std::fs::create_dir_all(out_dir);
    let mut stages = Vec::new();
    let mut ok = true;

    // 1) full PE
    match dump_full(path, &out_dir.join("pe")) {
        Ok(f) => stages.push(StageResult {
            stage: "pe_full".into(),
            status: "ok".into(),
            detail: format!(
                "sections={} dirs={} overlay={} tls_cb={}",
                f.sections.len(),
                f.data_dirs.iter().filter(|d| d.rva != 0).count(),
                f.overlay_size,
                f.tls.as_ref().map(|t| t.callbacks.len()).unwrap_or(0)
            ),
        }),
        Err(e) => {
            ok = false;
            let _ = std::fs::write(out_dir.join("pe").join("GAP.txt"), e.to_string());
            stages.push(StageResult {
                stage: "pe_full".into(),
                status: "gap".into(),
                detail: e.to_string(),
            });
        }
    }

    // 2) inventory
    match inventory_path(path) {
        Ok(inv) => {
            let _ = std::fs::write(
                out_dir.join("HOST_INVENTORY.json"),
                serde_json::to_vec_pretty(&inv).unwrap_or_default(),
            );
            stages.push(StageResult {
                stage: "extract".into(),
                status: "ok".into(),
                detail: format!("role={} imports={}", inv.role_guess, inv.imports.len()),
            });
        }
        Err(e) => {
            ok = false;
            let _ = std::fs::write(out_dir.join("HOST_INVENTORY.GAP.txt"), e.to_string());
            stages.push(StageResult {
                stage: "extract".into(),
                status: "gap".into(),
                detail: e.to_string(),
            });
        }
    }

    // 3) crypto
    match run_static(path) {
        Ok(rep) => {
            let _ = write_report(&rep, &out_dir.join("crypto"));
            stages.push(StageResult {
                stage: "crypto".into(),
                status: "ok".into(),
                detail: format!(
                    "primary={} decrypted={} solved={}",
                    rep.ranking.primary,
                    rep.decrypted,
                    rep.solved.len()
                ),
            });
        }
        Err(e) => {
            let _ = std::fs::write(out_dir.join("crypto").join("GAP.txt"), &e);
            stages.push(StageResult {
                stage: "crypto".into(),
                status: "gap".into(),
                detail: e,
            });
        }
    }

    // 4) IDA strings + deobf
    let data = std::fs::read(path).unwrap_or_default();
    if data.is_empty() {
        ok = false;
        stages.push(StageResult {
            stage: "strings".into(),
            status: "gap".into(),
            detail: "empty read".into(),
        });
    } else {
        let ida = build_ida_strings(&data);
        let _ = std::fs::create_dir_all(out_dir.join("strings"));
        let _ = std::fs::write(
            out_dir.join("strings").join("STRINGS_IDA.json"),
            serde_json::to_vec_pretty(&ida).unwrap_or_default(),
        );
        let _ = std::fs::write(
            out_dir.join("strings").join("STRINGS_IDA.txt"),
            format_ida_listing(&ida),
        );
        // xref-only view
        let mut xref_view = String::from("; strings with code xrefs\n\n");
        for s in ida.strings.iter().filter(|s| s.xref_count > 0) {
            xref_view.push_str(&format!(
                "{:016X}  XREF:{}  {}\n",
                s.ea, s.xref_count, s.display
            ));
        }
        let _ = std::fs::write(out_dir.join("strings").join("STRINGS_XREFS.txt"), xref_view);

        let deob = deobfuscate_strings(&data);
        let _ = std::fs::write(
            out_dir.join("strings").join("STRINGS_DEOBF.json"),
            serde_json::to_vec_pretty(&deob).unwrap_or_default(),
        );
        let ac = harvest_ac_surface(&path.display().to_string(), &data);
        let _ = std::fs::write(
            out_dir.join("AC_SURFACE.json"),
            serde_json::to_vec_pretty(&ac).unwrap_or_default(),
        );
        stages.push(StageResult {
            stage: "strings".into(),
            status: "ok".into(),
            detail: format!(
                "ida={} xrefed={} deob={} ac={}",
                ida.count,
                ida.with_xrefs,
                deob.deobfuscated.len(),
                ac.count
            ),
        });
    }

    // 5) session (modules / flows / emu)
    let sess = run_session(path, &out_dir.join("session"), &SessionOptions { max_emu_insns: 512 });
    stages.push(StageResult {
        stage: "session".into(),
        status: "ok".into(),
        detail: format!(
            "modules={} funcs={} flows={} emu_stop={}",
            sess.modules, sess.functions_lifted, sess.encryption_flows, sess.emu_stop
        ),
    });

    // 6) cleartext credentials — a host that ships its own keys is a finding.
    match std::fs::read(path) {
        Ok(data) => {
            let secrets = street_crypto::scan_secrets(&data, false);
            let _ = std::fs::write(
                out_dir.join("SECRETS.json"),
                serde_json::to_vec_pretty(&secrets).unwrap_or_default(),
            );
            let kinds: Vec<String> = secrets.by_kind.keys().cloned().collect();
            stages.push(StageResult {
                stage: "secrets".into(),
                status: if secrets.hits.is_empty() { "clean".into() } else { "ok".into() },
                detail: if secrets.hits.is_empty() {
                    "no cleartext credentials".into()
                } else {
                    format!("{} hits — {}", secrets.hits.len(), kinds.join(", "))
                },
            });
        }
        Err(e) => stages.push(StageResult {
            stage: "secrets".into(),
            status: "gap".into(),
            detail: e.to_string(),
        }),
    }

    let report = CompleteReport {
        path: path.display().to_string(),
        out_dir: out_dir.display().to_string(),
        stages: stages.clone(),
        ok,
    };
    let _ = std::fs::write(
        out_dir.join("COMPLETE.json"),
        serde_json::to_vec_pretty(&report).unwrap_or_default(),
    );
    let mut md = String::from("# Street complete dump\n\n");
    md.push_str(&format!("- path: `{}`\n- ok: **{}**\n\n## Stages\n\n", report.path, report.ok));
    for s in &stages {
        md.push_str(&format!("- `{}` **{}** — {}\n", s.stage, s.status, s.detail));
    }
    let _ = std::fs::write(out_dir.join("COMPLETE.md"), md);
    report
}

pub fn dump_complete_folder(folder: &Path, out_root: &Path) -> Vec<CompleteReport> {
    let _ = std::fs::create_dir_all(out_root);
    let mut reports = Vec::new();
    let Ok(rd) = std::fs::read_dir(folder) else {
        return reports;
    };
    for e in rd.flatten() {
        let p = e.path();
        let ext = p
            .extension()
            .and_then(|x| x.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if !matches!(ext.as_str(), "exe" | "dll" | "sys" | "bin") {
            continue;
        }
        let name = p.file_stem().and_then(|s| s.to_str()).unwrap_or("bin");
        let out = out_root.join(name);
        reports.push(dump_complete(&p, &out));
    }
    let summary = json!({
        "folder": folder,
        "count": reports.len(),
        "all_ok": reports.iter().all(|r| r.ok),
        "reports": reports.iter().map(|r| json!({
            "path": r.path,
            "ok": r.ok,
            "out": r.out_dir,
            "stages": r.stages,
        })).collect::<Vec<_>>(),
    });
    let _ = std::fs::write(
        out_root.join("FOLDER_COMPLETE.json"),
        serde_json::to_vec_pretty(&summary).unwrap_or_default(),
    );
    reports
}

