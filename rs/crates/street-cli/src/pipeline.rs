//! One target, one order. Static stages always. No-debug observe only with
//! `--observe`. DEBUG_PROCESS is not this path. Auth is a name list, not a rewrite.

use anyhow::{Context, Result};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use street_core::pe::{image_span, parse_pe};
use street_core::{classify_path, write_pdata};
use street_crypto::detect_systems;
use street_session::dump_complete;

#[derive(Debug, Clone)]
pub struct PipelineOpts {
    pub out: PathBuf,
    pub observe: bool,
    pub seconds: u64,
    pub image_base: u64,
    /// `None` picks the largest virtual-only section, else `.text` at `0x1000`.
    pub text_rva: Option<u64>,
    pub text_size: u64,
    pub image_size: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PipelineReport {
    pub path: String,
    pub out: String,
    pub primary: String,
    pub playbook: String,
    pub needs_runtime: bool,
    pub observed: bool,
    pub unpacked: bool,
    pub pdata_disk: usize,
    pub pdata_dump: usize,
    pub decrypted: bool,
    pub note: String,
}

pub fn run_pipeline(path: &Path, opt: &PipelineOpts) -> Result<PipelineReport> {
    fs::create_dir_all(&opt.out).context("pipeline out")?;
    let data = fs::read(path).with_context(|| format!("read {}", path.display()))?;

    let profile = classify_path(path)?;
    fs::write(
        opt.out.join("01-classify.json"),
        serde_json::to_vec_pretty(&profile)?,
    )?;

    let complete = dump_complete(path, &opt.out.join("02-complete"));
    let decrypted = complete.stages.iter().any(|s| {
        s.stage == "crypto" && s.detail.contains("decrypted=true")
    });
    fs::write(
        opt.out.join("02-complete.json"),
        serde_json::to_vec_pretty(&complete)?,
    )?;

    let ranking = detect_systems(&data);
    let needs = needs_runtime(&ranking.primary, &ranking.playbook);
    let pdata = write_pdata(&data, &opt.out.join("06-pdata")).map_err(|e| anyhow::anyhow!(e))?;
    let auth = auth_surface(&data);
    fs::write(opt.out.join("07-AUTH.md"), &auth)?;

    let mut observed = false;
    let mut unpacked = false;
    let mut pdata_dump = 0usize;
    let mut note = if needs {
        "packed or protector on disk. static stops. --observe is the no-debug RPM path. live-dump is not used.".into()
    } else {
        "disk image is the artifact. no observe.".into()
    };

    if opt.observe && needs {
        #[cfg(windows)]
        {
            observed = true;
            let mut o = street_debug::observe::ObserveOptions::default();
            o.out_dir = opt.out.join("04-observe");
            o.seconds = opt.seconds;
            let (base, span) = image_span(&data).unwrap_or((opt.image_base, 0));
            o.image_base = if opt.image_base == 0 { base } else { opt.image_base };
            o.image_size = if opt.image_size == 0 { span as u64 } else { opt.image_size };
            let (rva, sz, why) = probe_for(&data, opt.text_rva, opt.text_size);
            o.text_rva = rva;
            o.text_size = sz;
            fs::write(
                opt.out.join("03-probe.json"),
                serde_json::to_vec_pretty(&serde_json::json!({
                    "image_base": format!("{:#x}", o.image_base),
                    "image_size": format!("{:#x}", o.image_size),
                    "text_rva": format!("{:#x}", rva),
                    "text_size": format!("{:#x}", sz),
                    "why": why,
                }))?,
            )?;
            match street_debug::observe::run_observe(&path.display().to_string(), &o) {
                Ok(rep) => {
                    unpacked = rep.unpacked;
                    fs::write(
                        opt.out.join("04-observe.json"),
                        serde_json::to_vec_pretty(&rep)?,
                    )?;
                    if rep.unpacked {
                        let img = o.out_dir.join("image.bin");
                        let _ = dump_complete(&img, &opt.out.join("05-dump-complete"));
                        if let Ok(bytes) = fs::read(&img) {
                            if let Ok(t) = write_pdata(&bytes, &opt.out.join("06-pdata-dump")) {
                                pdata_dump = t.count;
                            }
                        }
                        note = "observe wrote image.bin with MZ. runtime_dump, not a cipher.".into();
                    } else {
                        note = format!(
                            "observe ran, probe Shannon {:.3} stayed under 4. decrypted stays false.",
                            rep.text_h
                        );
                    }
                }
                Err(e) => {
                    note = format!("observe failed: {e}");
                    fs::write(opt.out.join("04-observe.GAP.txt"), &e)?;
                }
            }
        }
        #[cfg(not(windows))]
        {
            note = "observe is windows-only".into();
        }
    } else if opt.observe && !needs {
        note = "observe skipped — ranking is not a runtime protector.".into();
    }

    let report = PipelineReport {
        path: path.display().to_string(),
        out: opt.out.display().to_string(),
        primary: ranking.primary.clone(),
        playbook: ranking.playbook.clone(),
        needs_runtime: needs,
        observed,
        unpacked,
        pdata_disk: pdata.count,
        pdata_dump,
        decrypted,
        note,
    };
    fs::write(
        opt.out.join("PIPELINE.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    fs::write(opt.out.join("PIPELINE.md"), render_md(&report, &auth))?;
    Ok(report)
}

fn probe_for(data: &[u8], override_rva: Option<u64>, text_size: u64) -> (u64, u64, String) {
    if let Some(rva) = override_rva {
        let sz = if text_size == 0 { 0x10000 } else { text_size };
        return (rva, sz, "cli".into());
    }
    if let Ok(img) = parse_pe(data) {
        if let Some(sec) = img
            .sections
            .iter()
            .filter(|s| s.raw_size == 0 && s.vsize >= 0x1000)
            .max_by_key(|s| s.vsize)
        {
            let name = sec.name.trim_matches(|c: char| c == '\0' || c.is_whitespace());
            let sz = (sec.vsize as u64).min(0x10000);
            return (
                sec.va as u64,
                sz,
                format!("largest virtual-only section `{name}` va={:#x} vsize={:#x}", sec.va, sec.vsize),
            );
        }
    }
    (0x1000, 0x10000, ".text default".into())
}

fn needs_runtime(primary: &str, playbook: &str) -> bool {
    matches!(
        primary,
        "themida" | "vmprotect" | "runtime_section_decryptor"
    ) || playbook.contains("live_dump")
}

fn auth_surface(data: &[u8]) -> String {
    const NEEDLES: &[&[u8]] = &[
        b"KeyAuth",
        b"keyauth",
        b"HttpClient",
        b"WinHttp",
        b"WinHTTP",
        b"BtnLogin",
    ];
    let window = &data[..data.len().min(24 << 20)];
    let mut lines = vec![
        "# auth surface — log only".to_string(),
        "".into(),
        "Names found on disk. No rewrite, no hook, no plaintext patch.".into(),
        "".into(),
    ];
    let mut n = 0usize;
    for needle in NEEDLES {
        let mut start = 0usize;
        let mut hits = 0usize;
        while start + needle.len() <= window.len() {
            if let Some(rel) = window[start..]
                .windows(needle.len())
                .position(|w| w == *needle)
            {
                let at = start + rel;
                if hits < 8 {
                    lines.push(format!("- `{}` @ {:#x}", String::from_utf8_lossy(needle), at));
                }
                hits += 1;
                n += 1;
                start = at + needle.len();
            } else {
                break;
            }
        }
    }
    if n == 0 {
        lines.push("_none on disk_".into());
    }
    lines.push("".into());
    lines.join("\n")
}

fn render_md(r: &PipelineReport, auth: &str) -> String {
    format!(
        "# Street pipeline\n\n\
         - path: `{}`\n\
         - primary: **{}** (`{}`)\n\
         - needs_runtime: {}\n\
         - observed: {} unpacked: {}\n\
         - pdata disk: {}  pdata dump: {}\n\
         - decrypted: **{}**\n\n\
         {}\n\n\
         ## phases\n\n\
         1. `01-classify.json`\n\
         2. `02-complete/` pe, crypto, strings, session\n\
         3. `06-pdata/FUNCS_PDATA.txt`\n\
         4. `07-AUTH.md` log only\n\
         5. `04-observe/` only with `--observe` and a runtime protector\n\n\
         ## auth\n\n\
         {auth}\n",
        r.path,
        r.primary,
        r.playbook,
        r.needs_runtime,
        r.observed,
        r.unpacked,
        r.pdata_disk,
        r.pdata_dump,
        r.decrypted,
        r.note,
    )
}
