//! Reagent-style evidence packet: card + 8 insn + 3 xrefs + 3 strings. ~few hundred tokens.

use crate::session::OpenSession;
use serde_json::json;
use street_core::sha256_bytes;
use street_disasm::func::function_bytes;
use street_lift::{lift_bytes, LiftOptions};

pub fn evidence_packet(sess: &OpenSession, addr: u64) -> serde_json::Value {
    let f = sess
        .functions
        .iter()
        .find(|f| addr >= f.start && addr < f.end)
        .cloned();
    let start = f.as_ref().map(|x| x.start).unwrap_or(addr);
    let size = f.as_ref().map(|x| x.size as usize).unwrap_or(0x80);
    let name = f.as_ref().map(|x| x.name.clone()).unwrap_or_else(|| format!("sub_{start:x}"));

    let mut listing = Vec::new();
    let mut xrefs = Vec::new();
    if let Some(d) = &sess.disasm {
        for insn in d.instructions.iter().filter(|i| i.addr >= start).take(8) {
            listing.push(json!({
                "a": format!("0x{:x}", insn.addr),
                "m": insn.mnemonic,
                "o": insn.op_str,
            }));
        }
        for x in d.xrefs.iter().filter(|x| x.from == start || x.to == start).take(3) {
            xrefs.push(json!({"from": format!("0x{:x}", x.from), "to": format!("0x{:x}", x.to), "k": x.kind}));
        }
    }

    let mut strings = Vec::new();
    if let Some((bytes, _)) = function_bytes(&sess.data, start, size.min(0x400)) {
        strings.extend(extract_ascii(bytes, 3));
    }

    let sketch = if let Some((bytes, va)) = function_bytes(&sess.data, start, size.min(0x200)) {
        let r = lift_bytes(bytes, va, sess.profile.arch, &name, &LiftOptions::default());
        let mut c = r.c;
        if c.len() > 600 {
            c.truncate(600);
            c.push_str("\n/* truncated sketch */");
        }
        c
    } else {
        String::new()
    };

    let raw = json!({
        "schema_version": 1,
        "kind": "evidence-packet",
        "addr": format!("0x{start:x}"),
        "name": name,
        "size": size,
        "arch": sess.profile.arch,
        "family": sess.profile.family,
        "calls_out": xrefs.len(),
        "listing8": listing,
        "xrefs3": xrefs,
        "strings3": strings,
        "sketch": sketch,
    });
    let fp = sha256_bytes(serde_json::to_string(&raw).unwrap_or_default().as_bytes());
    json!({
        "schema_version": 1,
        "kind": "evidence-packet",
        "addr": format!("0x{start:x}"),
        "name": name,
        "size": size,
        "arch": sess.profile.arch,
        "family": sess.profile.family,
        "listing8": listing,
        "xrefs3": xrefs,
        "strings3": strings,
        "sketch": sketch,
        "fingerprint": &fp[..16],
        "budget": { "target_tokens": 400 }
    })
}

pub fn function_card(sess: &OpenSession, addr: u64) -> serde_json::Value {
    let f = sess.functions.iter().find(|f| addr >= f.start && addr < f.end);
    let (start, size, name) = match f {
        Some(f) => (f.start, f.size, f.name.clone()),
        None => (addr, 0, format!("sub_{addr:x}")),
    };
    let mut calls_in = 0u32;
    let mut calls_out = 0u32;
    if let Some(d) = &sess.disasm {
        for x in &d.xrefs {
            if x.kind == "call" && x.to == start {
                calls_in += 1;
            }
            if x.kind == "call" && x.from >= start && x.from < start + size {
                calls_out += 1;
            }
        }
    }
    json!({
        "schema_version": 1,
        "kind": "function-card",
        "addr": format!("0x{start:x}"),
        "name": name,
        "size": size,
        "calls_in": calls_in,
        "calls_out": calls_out,
        "arch": sess.profile.arch,
        "note": "no body; call decompile only if you need C"
    })
}

fn extract_ascii(data: &[u8], limit: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    for &b in data {
        if (32..127).contains(&b) {
            cur.push(b);
        } else {
            if cur.len() >= 4 {
                out.push(String::from_utf8_lossy(&cur).into_owned());
                if out.len() >= limit {
                    break;
                }
            }
            cur.clear();
        }
    }
    out
}
