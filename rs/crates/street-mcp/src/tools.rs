use crate::budget::{bounded_json, cap_str};
use crate::packet::{evidence_packet, function_card};
use crate::protocol::{json_result, JsonRpcReq, JsonRpcRes};
use crate::session::SessionStore;
use serde_json::json;
use std::sync::Mutex;
use street_decompile::backend::{BackendKind, DecompileRequest};
use street_disasm::func::function_bytes;
use street_lift::Abi;

pub fn list_tools(req: &JsonRpcReq) -> JsonRpcRes {
    let tools = json!({"tools": [
        tool("session.open", "Load a binary. Returns tiny profile, not listing.", obj(&[("path", "string")])),
        tool("session.status", "Open sessions: id, path, family, func count.", obj(&[])),
        tool("backends", "Capability flags. Check before calling a backend.", obj(&[])),
        tool("classify", "Classify bytes/path. JSON profile only.", obj(&[("path", "string")])),
        tool("funcs.list", "Compact function table. limit default 40.", obj(&[("session", "number"), ("limit", "number"), ("offset", "number")])),
        tool("func.card", "Name/size/calls. NO body. Prefer this over decompile.", obj(&[("session", "number"), ("addr", "string")])),
        tool("evidence.packet", "Bounded packet: 8 insn + 3 xrefs + 3 strings + 600-char C sketch.", obj(&[("session", "number"), ("addr", "string")])),
        tool("decompile", "C-like pseudocode for ONE function. max_chars default 4000. backend=native|ghidra|ida|binja.", obj(&[("session", "number"), ("addr", "string"), ("backend", "string"), ("max_chars", "number")])),
        tool("disasm", "Bounded listing. count default 32.", obj(&[("session", "number"), ("addr", "string"), ("count", "number")])),
        tool("xrefs", "Xrefs to/from addr. limit 20.", obj(&[("session", "number"), ("addr", "string")])),
        tool("cfg", "Compact CFG edges for a function.", obj(&[("session", "number"), ("addr", "string")])),
        tool("strings.search", "Filtered strings. limit 20.", obj(&[("session", "number"), ("query", "string"), ("limit", "number")])),
        tool("graph.neighbors", "1-hop call neighbors.", obj(&[("session", "number"), ("addr", "string")])),
        tool("compare.backends", "Native vs other backends, each body capped.", obj(&[("session", "number"), ("addr", "string")])),
        tool("links", "Auto URLs/hosts/imports/xrefs. Compact counts + first 20.", obj(&[("session", "number")])),
        tool("ir", "ISA-neutral IR for one function. max 80 ops.", obj(&[("session", "number"), ("addr", "string")])),
        tool("kernel.status", "StreetKernel.sys present?", obj(&[])),
        tool("crypto.rank", "Static crypto ranking + auto-solve summary (no spawn).", obj(&[("session", "number")])),
    ]});
    JsonRpcRes::ok(req.id.clone(), tools)
}

fn tool(name: &str, desc: &str, schema: serde_json::Value) -> serde_json::Value {
    json!({
        "name": name,
        "description": desc,
        "inputSchema": schema
    })
}

fn obj(fields: &[(&str, &str)]) -> serde_json::Value {
    let mut props = serde_json::Map::new();
    let mut required = Vec::new();
    for (k, t) in fields {
        props.insert((*k).into(), json!({"type": t}));
        if *k != "limit" && *k != "offset" && *k != "backend" && *k != "max_chars" && *k != "count" && *k != "query" {
            required.push(*k);
        }
    }
    json!({"type": "object", "properties": props, "required": required})
}

pub fn call_tool(store: &Mutex<SessionStore>, req: &JsonRpcReq) -> JsonRpcRes {
    let args = req.params.get("arguments").cloned().unwrap_or_else(|| req.params.clone());
    let name = req
        .params
        .get("name")
        .and_then(|x| x.as_str())
        .unwrap_or("");
    let out = match name {
        "session.open" => t_open(store, &args),
        "session.status" => t_status(store),
        "backends" => t_backends(store),
        "classify" => t_classify(&args),
        "funcs.list" => t_funcs(store, &args),
        "func.card" => t_card(store, &args),
        "evidence.packet" => t_packet(store, &args),
        "decompile" => t_decompile(store, &args),
        "disasm" => t_disasm(store, &args),
        "xrefs" => t_xrefs(store, &args),
        "cfg" => t_cfg(store, &args),
        "strings.search" => t_strings(store, &args),
        "graph.neighbors" => t_graph(store, &args),
        "compare.backends" => t_compare(store, &args),
        "links" => t_links(store, &args),
        "ir" => t_ir(store, &args),
        "kernel.status" => Ok(serde_json::to_value(street_kernel::KernelClient::open().status()).unwrap()),
        "crypto.rank" => t_crypto(store, &args),
        _ => Err(format!("unknown tool {name}")),
    };
    match out {
        Ok(v) => json_result(req.id.clone(), bounded_json(v, 12_000)),
        Err(e) => json_result(req.id.clone(), json!({"error": e})),
    }
}

fn sid(args: &serde_json::Value) -> Result<u32, String> {
    args.get("session")
        .and_then(|x| x.as_u64())
        .map(|x| x as u32)
        .ok_or_else(|| "session id required".into())
}

fn addr_of(args: &serde_json::Value) -> Result<u64, String> {
    let s = args
        .get("addr")
        .and_then(|x| x.as_str())
        .ok_or("addr required")?;
    let t = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(t, 16).map_err(|e| e.to_string())
}

fn t_open(store: &Mutex<SessionStore>, args: &serde_json::Value) -> Result<serde_json::Value, String> {
    let path = args.get("path").and_then(|x| x.as_str()).ok_or("path required")?;
    let mut st = store.lock().map_err(|e| e.to_string())?;
    let id = st.open_path(path)?;
    let s = st.get(id)?;
    Ok(json!({
        "session": id,
        "family": s.profile.family,
        "arch": s.profile.arch,
        "format": s.profile.format,
        "size": s.profile.size,
        "sha256": &s.profile.sha256[..16],
        "funcs": s.functions.len(),
        "signals": s.profile.signals.iter().take(8).cloned().collect::<Vec<_>>(),
    }))
}

fn t_status(store: &Mutex<SessionStore>) -> Result<serde_json::Value, String> {
    let st = store.lock().map_err(|e| e.to_string())?;
    let rows: Vec<_> = st
        .sessions
        .values()
        .map(|s| {
            json!({
                "session": s.id,
                "path": s.path,
                "family": s.profile.family,
                "funcs": s.functions.len()
            })
        })
        .collect();
    Ok(json!({"sessions": rows}))
}

fn t_backends(store: &Mutex<SessionStore>) -> Result<serde_json::Value, String> {
    let st = store.lock().map_err(|e| e.to_string())?;
    let list: Vec<_> = st
        .registry
        .list()
        .into_iter()
        .map(|(k, c)| json!({"backend": k.as_str(), "caps": c}))
        .collect();
    Ok(json!({"backends": list}))
}

fn t_classify(args: &serde_json::Value) -> Result<serde_json::Value, String> {
    let path = args.get("path").and_then(|x| x.as_str()).ok_or("path")?;
    let p = street_core::classify_path(std::path::Path::new(path)).map_err(|e| e.to_string())?;
    Ok(serde_json::to_value(p).unwrap())
}

fn t_funcs(store: &Mutex<SessionStore>, args: &serde_json::Value) -> Result<serde_json::Value, String> {
    let id = sid(args)?;
    let st = store.lock().map_err(|e| e.to_string())?;
    let s = st.get(id)?;
    let limit = args.get("limit").and_then(|x| x.as_u64()).unwrap_or(40) as usize;
    let offset = args.get("offset").and_then(|x| x.as_u64()).unwrap_or(0) as usize;
    let rows: Vec<_> = s
        .functions
        .iter()
        .skip(offset)
        .take(limit)
        .map(|f| json!({"a": format!("0x{:x}", f.start), "n": f.name, "s": f.size}))
        .collect();
    Ok(json!({"total": s.functions.len(), "rows": rows}))
}

fn t_card(store: &Mutex<SessionStore>, args: &serde_json::Value) -> Result<serde_json::Value, String> {
    let id = sid(args)?;
    let addr = addr_of(args)?;
    let st = store.lock().map_err(|e| e.to_string())?;
    Ok(function_card(st.get(id)?, addr))
}

fn t_packet(store: &Mutex<SessionStore>, args: &serde_json::Value) -> Result<serde_json::Value, String> {
    let id = sid(args)?;
    let addr = addr_of(args)?;
    let st = store.lock().map_err(|e| e.to_string())?;
    Ok(evidence_packet(st.get(id)?, addr))
}

fn t_decompile(store: &Mutex<SessionStore>, args: &serde_json::Value) -> Result<serde_json::Value, String> {
    let id = sid(args)?;
    let addr = addr_of(args)?;
    let backend = args
        .get("backend")
        .and_then(|x| x.as_str())
        .and_then(BackendKind::parse)
        .unwrap_or(BackendKind::Native);
    let max_chars = args.get("max_chars").and_then(|x| x.as_u64()).unwrap_or(4000) as usize;
    let st = store.lock().map_err(|e| e.to_string())?;
    let s = st.get(id)?;
    let f = s.functions.iter().find(|f| addr >= f.start && addr < f.end);
    let (start, size, name) = match f {
        Some(f) => (f.start, f.size as usize, f.name.clone()),
        None => (addr, 0x100, format!("sub_{addr:x}")),
    };
    let (code, va) = function_bytes(&s.data, start, size.max(16)).unwrap_or((&[][..], start));
    let req = DecompileRequest {
        addr: va,
        name,
        arch: s.profile.arch,
        code: code.to_vec(),
        abi: Abi::Win64,
        max_chars,
        asm_comments: false,
    };
    match st.registry.decompile(backend, &req) {
        Ok(t) => Ok(serde_json::to_value(t).unwrap()),
        Err(g) => Ok(json!({"gap": g})),
    }
}

fn t_disasm(store: &Mutex<SessionStore>, args: &serde_json::Value) -> Result<serde_json::Value, String> {
    let id = sid(args)?;
    let addr = addr_of(args)?;
    let count = args.get("count").and_then(|x| x.as_u64()).unwrap_or(32) as usize;
    let st = store.lock().map_err(|e| e.to_string())?;
    let s = st.get(id)?;
    let d = s.disasm.as_ref().ok_or("no disasm")?;
    let rows: Vec<_> = d
        .instructions
        .iter()
        .filter(|i| i.addr >= addr)
        .take(count)
        .map(|i| format!("{:x}: {} {}", i.addr, i.mnemonic, i.op_str))
        .collect();
    let text = rows.join("\n");
    let (text, truncated) = cap_str(&text, 4000);
    Ok(json!({"text": text, "truncated": truncated, "n": rows.len()}))
}

fn t_xrefs(store: &Mutex<SessionStore>, args: &serde_json::Value) -> Result<serde_json::Value, String> {
    let id = sid(args)?;
    let addr = addr_of(args)?;
    let st = store.lock().map_err(|e| e.to_string())?;
    let s = st.get(id)?;
    let d = s.disasm.as_ref().ok_or("no disasm")?;
    let rows: Vec<_> = d
        .xrefs
        .iter()
        .filter(|x| x.from == addr || x.to == addr)
        .take(20)
        .map(|x| json!({"from": format!("0x{:x}", x.from), "to": format!("0x{:x}", x.to), "k": x.kind}))
        .collect();
    Ok(json!({"xrefs": rows}))
}

fn t_cfg(store: &Mutex<SessionStore>, args: &serde_json::Value) -> Result<serde_json::Value, String> {
    let id = sid(args)?;
    let addr = addr_of(args)?;
    let st = store.lock().map_err(|e| e.to_string())?;
    let s = st.get(id)?;
    let f = s.functions.iter().find(|f| addr >= f.start && addr < f.end);
    let (start, end) = match f {
        Some(f) => (f.start, f.end),
        None => (addr, addr + 0x100),
    };
    let d = s.disasm.as_ref().ok_or("no disasm")?;
    let edges: Vec<_> = d
        .cfg_edges
        .iter()
        .filter(|e| e.from >= start && e.from < end)
        .take(80)
        .map(|e| json!({"f": format!("0x{:x}", e.from), "t": format!("0x{:x}", e.to), "k": e.kind}))
        .collect();
    Ok(json!({"edges": edges}))
}

fn t_strings(store: &Mutex<SessionStore>, args: &serde_json::Value) -> Result<serde_json::Value, String> {
    let id = sid(args)?;
    let q = args.get("query").and_then(|x| x.as_str()).unwrap_or("").to_ascii_lowercase();
    let limit = args.get("limit").and_then(|x| x.as_u64()).unwrap_or(20) as usize;
    let st = store.lock().map_err(|e| e.to_string())?;
    let s = st.get(id)?;
    let mut hits = Vec::new();
    let mut cur = Vec::new();
    for &b in &s.data {
        if (32..127).contains(&b) {
            cur.push(b);
        } else {
            if cur.len() >= 5 {
                let t = String::from_utf8_lossy(&cur).into_owned();
                if q.is_empty() || t.to_ascii_lowercase().contains(&q) {
                    hits.push(t);
                    if hits.len() >= limit {
                        break;
                    }
                }
            }
            cur.clear();
        }
    }
    Ok(json!({"strings": hits}))
}

fn t_graph(store: &Mutex<SessionStore>, args: &serde_json::Value) -> Result<serde_json::Value, String> {
    let id = sid(args)?;
    let addr = addr_of(args)?;
    let st = store.lock().map_err(|e| e.to_string())?;
    let s = st.get(id)?;
    let d = s.disasm.as_ref().ok_or("no disasm")?;
    let callees: Vec<_> = d
        .xrefs
        .iter()
        .filter(|x| x.kind == "call" && x.from == addr)
        .take(16)
        .map(|x| format!("0x{:x}", x.to))
        .collect();
    let callers: Vec<_> = d
        .xrefs
        .iter()
        .filter(|x| x.kind == "call" && x.to == addr)
        .take(16)
        .map(|x| format!("0x{:x}", x.from))
        .collect();
    Ok(json!({"addr": format!("0x{addr:x}"), "callers": callers, "callees": callees}))
}

fn t_compare(store: &Mutex<SessionStore>, args: &serde_json::Value) -> Result<serde_json::Value, String> {
    let id = sid(args)?;
    let addr = addr_of(args)?;
    let st = store.lock().map_err(|e| e.to_string())?;
    let s = st.get(id)?;
    let (code, va) = function_bytes(&s.data, addr, 0x200).unwrap_or((&[][..], addr));
    let req = DecompileRequest {
        addr: va,
        name: format!("sub_{addr:x}"),
        arch: s.profile.arch,
        code: code.to_vec(),
        abi: Abi::Win64,
        max_chars: 1200,
        asm_comments: false,
    };
    Ok(st.registry.compare(&req, 1200))
}

fn t_links(store: &Mutex<SessionStore>, args: &serde_json::Value) -> Result<serde_json::Value, String> {
    let id = sid(args)?;
    let st = store.lock().map_err(|e| e.to_string())?;
    let s = st.get(id)?;
    let rep = street_links::identify(&s.data, s.image_base, s.disasm.as_ref());
    Ok(json!({
        "urls": rep.urls.iter().take(20).map(|l| &l.value).collect::<Vec<_>>(),
        "hosts": rep.hosts.iter().take(20).map(|l| &l.value).collect::<Vec<_>>(),
        "imports_n": rep.imports.len(),
        "xrefs_n": rep.xrefs.len(),
        "url_n": rep.urls.len(),
    }))
}

fn t_crypto(store: &Mutex<SessionStore>, args: &serde_json::Value) -> Result<serde_json::Value, String> {
    let id = sid(args)?;
    let st = store.lock().map_err(|e| e.to_string())?;
    let s = st.get(id)?;
    let rep = street_crypto::run_static_bytes(std::path::Path::new(&s.path), &s.data)?;
    Ok(json!({
        "primary": rep.ranking.primary,
        "playbook": rep.ranking.playbook,
        "decrypted": rep.decrypted,
        "top": rep.ranking.hits.iter().take(6).map(|h| json!({
            "system": h.system, "confidence": h.confidence, "evidence": h.evidence
        })).collect::<Vec<_>>(),
        "solved_n": rep.solved.len(),
        "solved": rep.solved.iter().take(8).map(|x| json!({
            "cipher": x.cipher, "score": x.score, "decrypted": x.decrypted, "note": x.note
        })).collect::<Vec<_>>(),
        "steps": rep.playbook_steps,
    }))
}

fn t_ir(store: &Mutex<SessionStore>, args: &serde_json::Value) -> Result<serde_json::Value, String> {
    let id = sid(args)?;
    let addr = addr_of(args)?;
    let st = store.lock().map_err(|e| e.to_string())?;
    let s = st.get(id)?;
    let (code, va) = function_bytes(&s.data, addr, 0x200).unwrap_or((&[][..], addr));
    let ir = street_ir::lift_x86(code, va, 64, &format!("sub_{addr:x}"), 80);
    Ok(serde_json::to_value(ir).unwrap())
}
