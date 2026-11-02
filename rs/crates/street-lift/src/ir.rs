//! Tiny statement IR. Values are C-ish strings already lowered.

#[derive(Debug, Clone)]
pub enum Stmt {
    Comment(String),
    Raw(String),
    Assign { dst: String, src: String },
    Store { dst: String, src: String },
    Call { dst: Option<String>, target: String, args: Vec<String> },
    Return { value: Option<String> },
    If { cond: String, then: Vec<Stmt>, els: Vec<Stmt> },
    While { cond: String, body: Vec<Stmt> },
    Goto { label: String },
    Label { name: String },
}

impl Stmt {
    pub fn indent_render(&self, indent: usize, out: &mut String) {
        let pad = "    ".repeat(indent);
        match self {
            Stmt::Comment(c) => out.push_str(&format!("{pad}/* {c} */\n")),
            Stmt::Raw(s) => out.push_str(&format!("{pad}{s}\n")),
            Stmt::Assign { dst, src } => out.push_str(&format!("{pad}{dst} = {src};\n")),
            Stmt::Store { dst, src } => out.push_str(&format!("{pad}{dst} = {src};\n")),
            Stmt::Call { dst, target, args } => {
                let a = args.join(", ");
                if let Some(d) = dst {
                    out.push_str(&format!("{pad}{d} = {target}({a});\n"));
                } else {
                    out.push_str(&format!("{pad}{target}({a});\n"));
                }
            }
            Stmt::Return { value } => {
                if let Some(v) = value {
                    out.push_str(&format!("{pad}return {v};\n"));
                } else {
                    out.push_str(&format!("{pad}return;\n"));
                }
            }
            Stmt::If { cond, then, els } => {
                out.push_str(&format!("{pad}if ({cond}) {{\n"));
                for s in then {
                    s.indent_render(indent + 1, out);
                }
                if els.is_empty() {
                    out.push_str(&format!("{pad}}}\n"));
                } else {
                    out.push_str(&format!("{pad}}} else {{\n"));
                    for s in els {
                        s.indent_render(indent + 1, out);
                    }
                    out.push_str(&format!("{pad}}}\n"));
                }
            }
            Stmt::While { cond, body } => {
                out.push_str(&format!("{pad}while ({cond}) {{\n"));
                for s in body {
                    s.indent_render(indent + 1, out);
                }
                out.push_str(&format!("{pad}}}\n"));
            }
            Stmt::Goto { label } => out.push_str(&format!("{pad}goto {label};\n")),
            Stmt::Label { name } => out.push_str(&format!("{name}:\n")),
        }
    }
}

pub fn c_type_for_size(bytes: u32) -> &'static str {
    match bytes {
        1 => "uint8_t",
        2 => "uint16_t",
        4 => "uint32_t",
        8 => "uint64_t",
        _ => "uint64_t",
    }
}

pub fn mem_deref(addr: &str, size: u32) -> String {
    format!("*({} *)({})", c_type_for_size(size), addr)
}
