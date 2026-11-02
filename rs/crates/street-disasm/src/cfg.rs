use crate::{CfgEdge, DisasmResult};

pub fn build_cfg(out: &mut DisasmResult) {
    out.cfg_edges.clear();
    for insn in &out.instructions {
        if let Some(t) = insn.target {
            let kind = if insn.is_call {
                "call"
            } else if insn.is_jcc {
                "jcc"
            } else {
                "jmp"
            };
            out.cfg_edges.push(CfgEdge {
                from: insn.addr,
                to: t,
                kind: kind.into(),
            });
        }
        if !insn.is_jmp && !insn.is_ret {
            out.cfg_edges.push(CfgEdge {
                from: insn.addr,
                to: insn.addr + insn.size as u64,
                kind: "fall".into(),
            });
        }
    }
}

pub fn leaders(result: &DisasmResult) -> Vec<u64> {
    use std::collections::BTreeSet;
    let mut l = BTreeSet::new();
    if let Some(first) = result.instructions.first() {
        l.insert(first.addr);
    }
    for e in &result.cfg_edges {
        if e.kind != "fall" && e.kind != "call" {
            l.insert(e.to);
        }
        if e.kind == "jcc" || e.kind == "jmp" {
            // fallthrough of jcc is also a leader
        }
    }
    for insn in &result.instructions {
        if insn.is_jcc {
            l.insert(insn.addr + insn.size as u64);
            if let Some(t) = insn.target {
                l.insert(t);
            }
        }
        if insn.is_jmp {
            if let Some(t) = insn.target {
                l.insert(t);
            }
        }
        if insn.is_call {
            l.insert(insn.addr + insn.size as u64);
        }
    }
    l.into_iter().collect()
}
