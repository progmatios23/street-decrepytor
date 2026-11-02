//! Host inventory — what is *inside* the image on disk (no spawn).

use crate::imports::imports_by_dll;
use crate::pe::{parse_pe, section_bytes};
use crate::{classify_bytes, sha256_bytes};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInventory {
    pub schema_version: u32,
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub family: String,
    pub arch: String,
    pub sections: Vec<SectionRow>,
    pub imports: Vec<crate::imports::ImportDll>,
    pub interesting_imports: Vec<String>,
    pub urls: Vec<String>,
    pub hosts: Vec<String>,
    pub shared_objects: Vec<String>,
    pub paths: Vec<String>,
    pub pdb: Option<String>,
    pub overlay_size: u64,
    pub overlay_sha256: Option<String>,
    pub resource_rva: u32,
    pub resource_size: u32,
    pub role_guess: String,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionRow {
    pub name: String,
    pub va: u32,
    pub vsize: u32,
    pub raw_off: u32,
    pub raw_size: u32,
    pub virtual_only: bool,
}

pub fn inventory_path(path: &Path) -> crate::Result<HostInventory> {
    let data = std::fs::read(path)?;
    Ok(inventory_bytes(path, &data))
}

pub fn inventory_bytes(path: &Path, data: &[u8]) -> HostInventory {
    let profile = classify_bytes(data, Some(path)).unwrap_or_else(|_| crate::ArtifactProfile {
        path: path.display().to_string(),
        size: data.len() as u64,
        sha256: sha256_bytes(data),
        family: crate::LangFamily::Unknown,
        arch: crate::Arch::Unknown,
        format: "unknown".into(),
        confidence: 0.0,
        signals: vec![],
        multi_build_hints: vec![],
        exec_profile: None,
        protector_candidates: vec![],
        pe_info: serde_json::json!({}),
        schema_version: crate::SCHEMA_VERSION,
    });

    let mut sections = Vec::new();
    let mut overlay_size = 0u64;
    let mut overlay_sha = None;
    let mut resource_rva = 0u32;
    let mut resource_size = 0u32;

    if let Ok(img) = parse_pe(data) {
        for s in &img.sections {
            sections.push(SectionRow {
                name: s.name.clone(),
                va: s.va,
                vsize: s.vsize,
                raw_off: s.raw_off,
                raw_size: s.raw_size,
                virtual_only: s.virtual_only(),
            });
        }
        let last = img
            .sections
            .iter()
            .map(|s| s.raw_off as u64 + s.raw_size as u64)
            .max()
            .unwrap_or(0);
        if (data.len() as u64) > last {
            overlay_size = data.len() as u64 - last;
            let ov = &data[last as usize..];
            overlay_sha = Some(sha256_bytes(ov));
        }
        // resource dir
        let e_lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
        let opt = e_lfanew + 0x18;
        let dd = if img.is_64 { opt + 0x70 } else { opt + 0x60 };
        if dd + 24 <= data.len() {
            resource_rva = u32::from_le_bytes(data[dd + 16..dd + 20].try_into().unwrap());
            resource_size = u32::from_le_bytes(data[dd + 20..dd + 24].try_into().unwrap());
        }
        let _ = section_bytes(data, &img.sections[0]);
    }

    let imports = imports_by_dll(data);
    let mut interesting = Vec::new();
    let watch = [
        "VirtualAlloc",
        "VirtualAllocEx",
        "WriteProcessMemory",
        "ReadProcessMemory",
        "CreateRemoteThread",
        "NtMapView",
        "MapViewOfFile",
        "OpenProcess",
        "InternetOpen",
        "InternetOpenUrl",
        "HttpQuery",
        "URLDownload",
        "WinHttp",
        "DeviceIoControl",
        "LoadLibrary",
        "GetProcAddress",
        "OpenFileMapping",
        "CreateFileMapping",
        "CreateProcess",
        "ShellExecute",
    ];
    for dll in &imports {
        for f in &dll.funcs {
            if watch.iter().any(|w| f.contains(w)) {
                interesting.push(format!("{}!{}", dll.dll, f));
            }
        }
    }

    let (urls, hosts, shared, paths, pdb) = scan_strings(data);

    let virt_n = sections.iter().filter(|s| s.virtual_only).count();
    let fat_enc = sections
        .iter()
        .filter(|s| s.raw_size >= 1_000_000)
        .count();
    let bundled = script_marker_count(data);
    let role_guess = guess_role_ex(&interesting, &urls, &shared, virt_n, fat_enc, bundled);
    let mut notes = vec![
        "Static host inventory — no process spawn.".into(),
        "If carved/overlay empty and decrypted=false, payload is likely fetched at runtime.".into(),
    ];
    if bundled >= 2 {
        notes.push(format!(
            "EMBEDDED SCRIPTS: {bundled} script/config markers in the image — the host ships plaintext payloads (scripts/config/persona), not compiled logic."
        ));
    }
    if virt_n >= 3 && fat_enc >= 1 {
        notes.push(format!(
            "PACKED: {virt_n} virtual-only sections + {fat_enc} fat raw section(s) — disk decrypt of .text not available; need live dump or stub invert."
        ));
    }
    if overlay_size == 0 && resource_size < 0x400 && fat_enc == 0 {
        notes.push("No fat overlay / tiny .rsrc — nothing packed behind the PE.".into());
    }
    if !urls.is_empty() {
        notes.push(format!("Runtime download URL(s): {}", urls.join(", ")));
    }
    if path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("dll"))
        .unwrap_or(false)
    {
        if let Ok(img) = parse_pe(data) {
            let e_lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
            let opt = e_lfanew + 0x18;
            let dd = if img.is_64 { opt + 0x70 } else { opt + 0x60 };
            if dd + 8 <= data.len() {
                let exp_rva = u32::from_le_bytes(data[dd..dd + 4].try_into().unwrap());
                if exp_rva == 0 {
                    notes.push(
                        "DLL export RVA=0 — manual-map / reflective load candidate (no LoadLibrary exports)."
                            .into(),
                    );
                }
            }
        }
    }

    HostInventory {
        schema_version: 1,
        path: path.display().to_string(),
        sha256: profile.sha256,
        size: profile.size,
        family: profile.family.as_str().into(),
        arch: profile.arch.as_str().into(),
        sections,
        imports,
        interesting_imports: interesting,
        urls,
        hosts,
        shared_objects: shared,
        paths,
        pdb,
        overlay_size,
        overlay_sha256: overlay_sha,
        resource_rva,
        resource_size,
        role_guess,
        notes,
    }
}

fn scan_strings(data: &[u8]) -> (Vec<String>, Vec<String>, Vec<String>, Vec<String>, Option<String>) {
    let mut urls = Vec::new();
    let mut hosts = Vec::new();
    let mut shared = Vec::new();
    let mut paths = Vec::new();
    let mut pdb = None;
    let mut cur = Vec::new();
    for &b in data {
        if (32..127).contains(&b) {
            cur.push(b);
        } else {
            if cur.len() >= 6 {
                let s = String::from_utf8_lossy(&cur).into_owned();
                if s.starts_with("http://") || s.starts_with("https://") {
                    urls.push(s.clone());
                    if let Some(h) = s.split("://").nth(1).and_then(|r| r.split('/').next()) {
                        hosts.push(h.to_string());
                    }
                } else if s.starts_with(r"Local\") || s.starts_with(r"Global\") || s.starts_with(r"\\.\") {
                    shared.push(s.clone());
                } else if s.ends_with(".pdb") {
                    pdb = Some(s.clone());
                } else if s.len() >= 8
                    && (s.starts_with(r"C:\") || s.starts_with(r"\\") || s.starts_with("/usr/"))
                {
                    paths.push(s);
                }
            }
            cur.clear();
        }
    }
    urls.sort();
    urls.dedup();
    hosts.sort();
    hosts.dedup();
    shared.sort();
    shared.dedup();
    paths.truncate(40);
    (urls, hosts, shared, paths, pdb)
}

#[allow(dead_code)]
fn guess_role(interesting: &[String], urls: &[String], shared: &[String]) -> String {
    guess_role_ex(interesting, urls, shared, 0, 0, 0)
}

/// Count distinct script/config markers in the raw image — a host that *ships*
/// embedded payloads (`.bat`, `.py`, `.ps1`, JSON config, persona text) rather than
/// compiling them in. `onx_cmd.exe` scores 8+; an ordinary native tool scores 0–1.
fn script_marker_count(data: &[u8]) -> usize {
    const MARKERS: &[&[u8]] = &[
        b"@echo off",
        b"REM ",
        b"powershell -NoProfile",
        b"ExecutionPolicy Bypass",
        b"from fastapi",
        b"from pathlib",
        b"async def ",
        b"import ",
        b"\"$schema\"",
        b"$ErrorActionPreference",
        b"goto :",
        b"#!/usr/bin/env",
    ];
    MARKERS
        .iter()
        .filter(|m| contains(data, m))
        .count()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || hay.len() < needle.len() {
        return false;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

pub fn guess_role_ex(
    interesting: &[String],
    urls: &[String],
    shared: &[String],
    virtual_only: usize,
    fat_encrypted: usize,
    bundled_scripts: usize,
) -> String {
    if virtual_only >= 3 && fat_encrypted >= 1 {
        return "packed_injector_host (empty .text — runtime decrypt then inject)".into();
    }
    let inj = interesting.iter().any(|s| {
        s.contains("WriteProcessMemory")
            || s.contains("CreateRemoteThread")
            || s.contains("VirtualAllocEx")
    });
    let spawns = interesting
        .iter()
        .any(|s| s.contains("CreateProcess") || s.contains("ShellExecute"));
    // Embedded scripts + a child-process launch = a launcher/bundler, not a plain tool.
    if bundled_scripts >= 2 && spawns && !inj {
        return "launcher_bundler (embedded scripts/config + child process)".into();
    }
    let net = interesting.iter().any(|s| s.contains("Internet") || s.contains("Http") || s.contains("WinHttp"))
        || urls.iter().any(|u| u.len() > 8);
    let shm = !shared.is_empty() || interesting.iter().any(|s| s.contains("MapViewOfFile"));
    let overlay = interesting.iter().any(|s| s.contains("D3D") || s.contains("Present"));
    match (inj, net, shm, overlay) {
        (true, true, _, _) => "network_fetch_then_inject (downloader/dumper host)".into(),
        (true, false, _, _) => "local_injector".into(),
        (false, true, true, _) => "network_to_shared_memory".into(),
        (false, true, false, true) => "overlay_client (imgui/dx + http)".into(),
        (false, true, false, false) => "network_client".into(),
        _ => "native_tool".into(),
    }
}
