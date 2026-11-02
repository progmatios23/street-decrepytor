use crate::ir::Stmt;
use std::collections::BTreeMap;

pub fn render_function(
    name: &str,
    start: u64,
    n_args: usize,
    stmts: &[Stmt],
    locals: &BTreeMap<i64, String>,
) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "/* street-lift native | start=0x{start:x} | readable C-like pseudocode */\n"
    ));
    out.push_str("#include <stdint.h>\n\n");
    let args: Vec<String> = (0..n_args.max(1))
        .map(|i| format!("uint64_t arg{i}"))
        .collect();
    out.push_str(&format!("uint64_t {name}({})\n{{\n", args.join(", ")));

    // declare locals + v_ret
    out.push_str("    uint64_t v_ret = 0;\n");
    let mut declared = std::collections::BTreeSet::new();
    declared.insert("v_ret".into());
    for n in locals.values() {
        if declared.insert(n.clone()) {
            out.push_str(&format!("    uint64_t {n} = 0;\n"));
        }
    }
    collect_idents(stmts, &mut declared, &mut out);

    out.push('\n');
    for s in stmts {
        s.indent_render(1, &mut out);
    }
    // ensure a return
    if !matches!(stmts.last(), Some(Stmt::Return { .. })) {
        out.push_str("    return v_ret;\n");
    }
    out.push_str("}\n");
    out
}

fn collect_idents(stmts: &[Stmt], declared: &mut std::collections::BTreeSet<String>, out: &mut String) {
    for s in stmts {
        match s {
            Stmt::Assign { dst, .. } | Stmt::Store { dst, .. } => {
                maybe_decl(dst, declared, out);
            }
            Stmt::Call { dst, .. } => {
                if let Some(d) = dst {
                    maybe_decl(d, declared, out);
                }
            }
            Stmt::If { then, els, .. } => {
                collect_idents(then, declared, out);
                collect_idents(els, declared, out);
            }
            Stmt::While { body, .. } => collect_idents(body, declared, out),
            _ => {}
        }
    }
}

fn maybe_decl(dst: &str, declared: &mut std::collections::BTreeSet<String>, out: &mut String) {
    let id = dst.trim();
    if id.contains('(') || id.contains('*') || id.contains('[') || id.contains(' ') {
        return;
    }
    if id.starts_with("arg") || id == "v_ret" {
        return;
    }
    if declared.insert(id.to_string()) {
        out.push_str(&format!("    uint64_t {id} = 0;\n"));
    }
}
