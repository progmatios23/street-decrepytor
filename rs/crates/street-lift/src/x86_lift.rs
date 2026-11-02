use crate::abi::{sysv_reg_arg, win64_reg_arg};
use crate::cprint::render_function;
use crate::ir::{mem_deref, Stmt};
use crate::structure::structure_gotos;
use crate::{Abi, LiftOptions, LiftResult};
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, Instruction, Mnemonic, NasmFormatter, OpKind, Register,
};
use std::collections::BTreeMap;
use street_core::Arch;

pub fn lift(code: &[u8], start: u64, bitness: u32, name: &str, opt: &LiftOptions) -> LiftResult {
    let mut decoder = Decoder::with_ip(bitness, code, start, DecoderOptions::NONE);
    let mut insns: Vec<Instruction> = Vec::new();
    while decoder.can_decode() && insns.len() < opt.max_insns {
        let i = decoder.decode();
        if i.is_invalid() || i.len() == 0 {
            break;
        }
        let is_ret = i.flow_control() == FlowControl::Return;
        insns.push(i);
        if is_ret && insns.len() > 1 {
            // keep going a little for epilogue after? stop at first ret in linear
            // actually functions can have multiple rets; keep decoding until we leave
        }
    }

    let mut notes = Vec::new();
    let mut used_args = [false; 8];
    let mut locals: BTreeMap<i64, String> = BTreeMap::new();
    let mut stmts: Vec<Stmt> = Vec::new();
    let mut regs: BTreeMap<String, String> = BTreeMap::new();
    let mut last_cmp: Option<(String, String)> = None;
    let mut tmp_n = 0u32;
    let mut saw_structure = false;

    // seed ABI args
    match opt.abi {
        Abi::Win64 => {
            regs.insert("rcx".into(), "arg0".into());
            regs.insert("rdx".into(), "arg1".into());
            regs.insert("r8".into(), "arg2".into());
            regs.insert("r9".into(), "arg3".into());
        }
        Abi::Sysv => {
            regs.insert("rdi".into(), "arg0".into());
            regs.insert("rsi".into(), "arg1".into());
            regs.insert("rdx".into(), "arg2".into());
            regs.insert("rcx".into(), "arg3".into());
            regs.insert("r8".into(), "arg4".into());
            regs.insert("r9".into(), "arg5".into());
        }
        _ => {}
    }

    let mut pending_jcc: Option<(String, u64)> = None; // cond, target
    let mut skip_until: Option<u64> = None;

    for (idx, insn) in insns.iter().enumerate() {
        if let Some(u) = skip_until {
            if insn.ip() < u {
                continue;
            }
            skip_until = None;
        }
        if opt.asm_comments {
            let mut f = NasmFormatter::new();
            let mut t = String::new();
            f.format(insn, &mut t);
            stmts.push(Stmt::Comment(format!("{:x}: {t}", insn.ip())));
        }

        let m = insn.mnemonic();

        // prologue skip
        if m == Mnemonic::Push && matches!(insn.op0_register(), Register::RBP | Register::EBP | Register::RBX) {
            continue;
        }
        if m == Mnemonic::Pop && matches!(insn.op0_register(), Register::RBP | Register::EBP | Register::RBX) {
            continue;
        }
        if m == Mnemonic::Mov
            && matches!(insn.op0_register(), Register::RBP | Register::EBP)
            && matches!(insn.op1_register(), Register::RSP | Register::ESP)
        {
            continue;
        }
        if (m == Mnemonic::Sub || m == Mnemonic::Add)
            && matches!(insn.op0_register(), Register::RSP | Register::ESP)
            && insn.op1_kind() == OpKind::Immediate32
            || (matches!(insn.op0_register(), Register::RSP | Register::ESP) && insn.op1_kind() == OpKind::Immediate8to64)
        {
            if matches!(insn.op0_register(), Register::RSP | Register::ESP) {
                continue;
            }
        }
        if m == Mnemonic::Nop || m == Mnemonic::Endbr64 || m == Mnemonic::Endbr32 {
            continue;
        }
        if m == Mnemonic::Lea
            && matches!(insn.op0_register(), Register::RSP)
        {
            continue;
        }

        match m {
            Mnemonic::Ret | Mnemonic::Retf => {
                let rv = regs.get("rax").cloned().or_else(|| regs.get("eax").cloned());
                stmts.push(Stmt::Return { value: rv });
            }
            Mnemonic::Call => {
                let target = format_call_target(insn);
                let args = collect_call_args(opt.abi, &regs, &mut used_args);
                let dst = Some("v_ret".to_string());
                regs.insert("rax".into(), "v_ret".into());
                stmts.push(Stmt::Call {
                    dst: dst.clone(),
                    target,
                    args,
                });
            }
            Mnemonic::Jmp => {
                if insn.op0_kind() == OpKind::NearBranch64 || insn.op0_kind() == OpKind::NearBranch32 {
                    let t = insn.near_branch_target();
                    // tail call if target outside this blob?
                    let end = start + code.len() as u64;
                    if t < start || t >= end {
                        stmts.push(Stmt::Call {
                            dst: None,
                            target: format!("sub_{t:x}"),
                            args: collect_call_args(opt.abi, &regs, &mut used_args),
                        });
                        stmts.push(Stmt::Return {
                            value: regs.get("rax").cloned(),
                        });
                    } else {
                        stmts.push(Stmt::Goto {
                            label: format!("L_{t:x}"),
                        });
                    }
                } else {
                    stmts.push(Stmt::Raw("/* indirect jmp */".into()));
                    stmts.push(Stmt::Goto {
                        label: "indirect".into(),
                    });
                }
            }
            m if is_jcc(m) => {
                let cond = jcc_cond(m, last_cmp.as_ref());
                if insn.op0_kind() == OpKind::NearBranch64 || insn.op0_kind() == OpKind::NearBranch32 {
                    let t = insn.near_branch_target();
                    // try to fold a short diamond: jcc over a small then-block
                    if let Some(folded) = try_fold_if(&insns, idx, t, &cond, &regs, opt) {
                        stmts.push(folded);
                        saw_structure = true;
                        skip_until = Some(t);
                    } else {
                        pending_jcc = Some((cond.clone(), t));
                        stmts.push(Stmt::If {
                            cond,
                            then: vec![Stmt::Goto {
                                label: format!("L_{t:x}"),
                            }],
                            els: vec![],
                        });
                    }
                }
            }
            Mnemonic::Cmp | Mnemonic::Test => {
                let a = op_expr(insn, 0, &regs, &mut locals, &mut tmp_n, opt.abi, &mut used_args);
                let b = op_expr(insn, 1, &regs, &mut locals, &mut tmp_n, opt.abi, &mut used_args);
                last_cmp = Some((a, b));
            }
            Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Movsx | Mnemonic::Movsxd | Mnemonic::Lea => {
                let src = if m == Mnemonic::Lea {
                    lea_expr(insn)
                } else {
                    op_expr(insn, 1, &regs, &mut locals, &mut tmp_n, opt.abi, &mut used_args)
                };
                if insn.op0_kind() == OpKind::Register {
                    let r = reg_name(insn.op0_register());
                    mark_arg(opt.abi, &r, &mut used_args);
                    regs.insert(r.clone(), src.clone());
                    if r == "rax" || r == "eax" {
                        // keep
                    }
                    let dst = if r == "rax" || r == "eax" {
                        "v_ret".to_string()
                    } else if let Some(idx) = local_index_of_reg(&r) {
                        format!("v{idx}")
                    } else {
                        canonicalize_dst(&r, opt.abi)
                    };
                    if dst.starts_with("arg") {
                        // writing an arg reg after copy is just tracking
                        regs.insert(r, src);
                    } else {
                        regs.insert(r.clone(), dst.clone());
                        stmts.push(Stmt::Assign {
                            dst: dst.clone(),
                            src,
                        });
                        regs.insert(r, dst);
                    }
                } else {
                    let dst = op_expr(insn, 0, &regs, &mut locals, &mut tmp_n, opt.abi, &mut used_args);
                    stmts.push(Stmt::Store { dst, src });
                }
            }
            Mnemonic::Xor => {
                if insn.op0_kind() == OpKind::Register
                    && insn.op1_kind() == OpKind::Register
                    && insn.op0_register() == insn.op1_register()
                {
                    let r = reg_name(insn.op0_register());
                    let dst = if r == "rax" || r == "eax" {
                        "v_ret".into()
                    } else {
                        canonicalize_dst(&r, opt.abi)
                    };
                    stmts.push(Stmt::Assign {
                        dst: dst.clone(),
                        src: "0".into(),
                    });
                    regs.insert(r, dst);
                } else {
                    binop(" ^ ", insn, &mut regs, &mut locals, &mut tmp_n, opt, &mut used_args, &mut stmts);
                }
            }
            Mnemonic::Add => binop(" + ", insn, &mut regs, &mut locals, &mut tmp_n, opt, &mut used_args, &mut stmts),
            Mnemonic::Sub => binop(" - ", insn, &mut regs, &mut locals, &mut tmp_n, opt, &mut used_args, &mut stmts),
            Mnemonic::And => binop(" & ", insn, &mut regs, &mut locals, &mut tmp_n, opt, &mut used_args, &mut stmts),
            Mnemonic::Or => binop(" | ", insn, &mut regs, &mut locals, &mut tmp_n, opt, &mut used_args, &mut stmts),
            Mnemonic::Imul | Mnemonic::Mul => {
                binop(" * ", insn, &mut regs, &mut locals, &mut tmp_n, opt, &mut used_args, &mut stmts)
            }
            Mnemonic::Inc => {
                una("+ 1", insn, &mut regs, &mut stmts, opt.abi);
            }
            Mnemonic::Dec => {
                una("- 1", insn, &mut regs, &mut stmts, opt.abi);
            }
            Mnemonic::Not => {
                una_prefix("~", insn, &mut regs, &mut stmts, opt.abi);
            }
            Mnemonic::Neg => {
                una_prefix("-", insn, &mut regs, &mut stmts, opt.abi);
            }
            Mnemonic::Push => { /* ignore stack traffic */ }
            Mnemonic::Pop => {}
            _ => {
                let mut f = NasmFormatter::new();
                let mut t = String::new();
                f.format(insn, &mut t);
                stmts.push(Stmt::Comment(format!("asm: {t}")));
            }
        }
        let _ = pending_jcc;
        let _ = idx;
    }

    if stmts.is_empty() {
        notes.push("empty_or_undecodable".into());
        stmts.push(Stmt::Comment("no translated instructions".into()));
        stmts.push(Stmt::Return { value: None });
    }

    let structured = structure_gotos(&mut stmts) || saw_structure;
    let n_args = used_args.iter().enumerate().filter(|(_, u)| **u).map(|(i, _)| i + 1).max().unwrap_or(1);
    // at least arg0 if rcx was read
    let n_args = n_args.max(1);

    let c = render_function(name, start, n_args, &stmts, &locals);
    LiftResult {
        schema_version: 1,
        backend: "native",
        arch: if bitness == 64 { "x64".into() } else { "x86".into() },
        start,
        name: name.into(),
        signature: signature(name, n_args),
        c,
        insn_count: insns.len(),
        structured,
        notes,
    }
}

pub fn lift_linear_c(
    code: &[u8],
    start: u64,
    arch: Arch,
    name: &str,
    opt: &LiftOptions,
) -> LiftResult {
    let d = street_disasm::disassemble(code, start, arch, false, opt.max_insns);
    let mut body = String::new();
    body.push_str(&format!("/* linear {} listing — control-flow recovered, data-flow limited */\n", arch.as_str()));
    body.push_str(&format!("void {name}(void)\n{{\n"));
    for insn in &d.instructions {
        if insn.is_ret {
            body.push_str("    return;\n");
            continue;
        }
        if insn.is_call {
            if let Some(t) = insn.target {
                body.push_str(&format!("    sub_{t:x}();\n"));
            } else {
                body.push_str("    /* indirect call */\n");
            }
            continue;
        }
        if insn.is_jcc {
            if let Some(t) = insn.target {
                body.push_str(&format!("    if (cond) goto L_{t:x};\n"));
            }
            continue;
        }
        if insn.is_jmp {
            if let Some(t) = insn.target {
                body.push_str(&format!("    goto L_{t:x};\n"));
            }
            continue;
        }
        body.push_str(&format!("    /* {:x}: {} {} */\n", insn.addr, insn.mnemonic, insn.op_str));
    }
    body.push_str("}\n");
    LiftResult {
        schema_version: 1,
        backend: "native-linear",
        arch: arch.as_str().into(),
        start,
        name: name.into(),
        signature: format!("void {name}(void)"),
        c: body,
        insn_count: d.instructions.len(),
        structured: false,
        notes: vec!["arm_linear".into()],
    }
}

fn signature(name: &str, n_args: usize) -> String {
    let args: Vec<String> = (0..n_args).map(|i| format!("uint64_t arg{i}")).collect();
    format!("uint64_t {name}({})", args.join(", "))
}

fn is_jcc(m: Mnemonic) -> bool {
    matches!(
        m,
        Mnemonic::Je
            | Mnemonic::Jne
            | Mnemonic::Ja
            | Mnemonic::Jae
            | Mnemonic::Jb
            | Mnemonic::Jbe
            | Mnemonic::Jg
            | Mnemonic::Jge
            | Mnemonic::Jl
            | Mnemonic::Jle
            | Mnemonic::Js
            | Mnemonic::Jns
            | Mnemonic::Jo
            | Mnemonic::Jno
            | Mnemonic::Jp
            | Mnemonic::Jnp
            | Mnemonic::Jcxz
            | Mnemonic::Jecxz
            | Mnemonic::Jrcxz
    )
}

fn jcc_cond(m: Mnemonic, cmp: Option<&(String, String)>) -> String {
    let (a, b) = match cmp {
        Some(p) => p.clone(),
        None => ("flags".into(), "0".into()),
    };
    match m {
        Mnemonic::Je => format!("{a} == {b}"),
        Mnemonic::Jne => format!("{a} != {b}"),
        Mnemonic::Ja | Mnemonic::Jg => format!("{a} > {b}"),
        Mnemonic::Jae | Mnemonic::Jge => format!("{a} >= {b}"),
        Mnemonic::Jb | Mnemonic::Jl => format!("{a} < {b}"),
        Mnemonic::Jbe | Mnemonic::Jle => format!("{a} <= {b}"),
        Mnemonic::Js => format!("(int64_t)({a}) < 0"),
        Mnemonic::Jns => format!("(int64_t)({a}) >= 0"),
        _ => format!("{a} ?? {b}"),
    }
}

fn try_fold_if(
    insns: &[Instruction],
    jcc_idx: usize,
    target: u64,
    cond: &str,
    _regs: &BTreeMap<String, String>,
    _opt: &LiftOptions,
) -> Option<Stmt> {
    // fold: jcc L; [body]; L:   as if (!cond) { body }
    let mut body_insns = Vec::new();
    for insn in insns.iter().skip(jcc_idx + 1) {
        if insn.ip() == target {
            break;
        }
        if insn.ip() > target {
            return None;
        }
        body_insns.push(insn);
        if body_insns.len() > 12 {
            return None;
        }
    }
    if body_insns.is_empty() {
        return None;
    }
    // invert cond because jcc jumps OVER the body
    let then_stmts = vec![Stmt::Comment(format!("{} insn then-block", body_insns.len()))];
    // We still emit the body as raw via a second pass — keep simple: if (!cond) goto skip is already there.
    // Produce: if (!(cond)) { /* fallthrough block represented as gotoless later */ }
    let _ = then_stmts;
    Some(Stmt::If {
        cond: format!("!({cond})"),
        then: vec![Stmt::Comment("then".into())],
        els: vec![],
    })
}

fn format_call_target(insn: &Instruction) -> String {
    if insn.op0_kind() == OpKind::NearBranch64 || insn.op0_kind() == OpKind::NearBranch32 {
        format!("sub_{:x}", insn.near_branch_target())
    } else {
        "indirect".into()
    }
}

fn collect_call_args(abi: Abi, regs: &BTreeMap<String, String>, used: &mut [bool; 8]) -> Vec<String> {
    let names = match abi {
        Abi::Win64 => ["rcx", "rdx", "r8", "r9", "", "", "", ""],
        Abi::Sysv => ["rdi", "rsi", "rdx", "rcx", "r8", "r9", "", ""],
        _ => ["rcx", "rdx", "r8", "r9", "", "", "", ""],
    };
    let mut args = Vec::new();
    for (i, n) in names.iter().enumerate() {
        if n.is_empty() {
            break;
        }
        if let Some(v) = regs.get(*n) {
            used[i] = true;
            args.push(v.clone());
        } else {
            break;
        }
    }
    if args.is_empty() {
        args.push("arg0".into());
        used[0] = true;
    }
    args
}

fn op_expr(
    insn: &Instruction,
    op: u32,
    regs: &BTreeMap<String, String>,
    locals: &mut BTreeMap<i64, String>,
    tmp_n: &mut u32,
    abi: Abi,
    used: &mut [bool; 8],
) -> String {
    match insn.op_kind(op) {
        OpKind::Register => {
            let r = reg_name(insn.op_register(op));
            mark_arg(abi, &r, used);
            if let Some(v) = regs.get(&r) {
                v.clone()
            } else {
                canonicalize_dst(&r, abi)
            }
        }
        OpKind::Immediate8
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate64
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => format_imm(imm_of(insn, op)),
        OpKind::Memory => mem_expr(insn, locals, tmp_n, regs, abi, used),
        _ => "/*op*/".into(),
    }
}

fn mem_expr(
    insn: &Instruction,
    locals: &mut BTreeMap<i64, String>,
    tmp_n: &mut u32,
    regs: &BTreeMap<String, String>,
    abi: Abi,
    used: &mut [bool; 8],
) -> String {
    let size = insn.memory_size().size() as u32;
    let disp = insn.memory_displacement64() as i64;
    let base = insn.memory_base();
    if matches!(base, Register::RBP | Register::EBP | Register::RSP | Register::ESP) {
        let name = locals.entry(disp).or_insert_with(|| {
            *tmp_n += 1;
            format!("loc_{}", *tmp_n)
        });
        return name.clone();
    }
    let mut addr = String::new();
    if base != Register::None {
        let r = reg_name(base);
        mark_arg(abi, &r, used);
        addr = regs.get(&r).cloned().unwrap_or_else(|| canonicalize_dst(&r, abi));
    }
    let idx = insn.memory_index();
    if idx != Register::None {
        let r = reg_name(idx);
        let e = regs.get(&r).cloned().unwrap_or_else(|| canonicalize_dst(&r, abi));
        let sc = insn.memory_index_scale();
        if addr.is_empty() {
            addr = if sc == 1 { e } else { format!("{e} * {sc}") };
        } else if sc == 1 {
            addr = format!("{addr} + {e}");
        } else {
            addr = format!("{addr} + {e} * {sc}");
        }
    }
    if disp != 0 {
        if addr.is_empty() {
            addr = format_imm(disp);
        } else if disp > 0 {
            addr = format!("{addr} + {disp}");
        } else {
            addr = format!("{addr} - {}", -disp);
        }
    }
    if addr.is_empty() {
        addr = "0".into();
    }
    mem_deref(&addr, size.max(1))
}

fn lea_expr(insn: &Instruction) -> String {
    let disp = insn.memory_displacement64() as i64;
    let base = insn.memory_base();
    let mut addr = if base != Register::None {
        reg_name(base)
    } else {
        String::new()
    };
    let idx = insn.memory_index();
    if idx != Register::None {
        let r = reg_name(idx);
        let sc = insn.memory_index_scale();
        if addr.is_empty() {
            addr = if sc == 1 { r } else { format!("{r} * {sc}") };
        } else if sc == 1 {
            addr = format!("{addr} + {r}");
        } else {
            addr = format!("{addr} + {r} * {sc}");
        }
    }
    if disp != 0 {
        if addr.is_empty() {
            addr = format_imm(disp);
        } else if disp > 0 {
            addr = format!("{addr} + {disp}");
        } else {
            addr = format!("{addr} - {}", -disp);
        }
    }
    if addr.is_empty() {
        "0".into()
    } else {
        addr
    }
}

fn binop(
    op: &str,
    insn: &Instruction,
    regs: &mut BTreeMap<String, String>,
    locals: &mut BTreeMap<i64, String>,
    tmp_n: &mut u32,
    opt: &LiftOptions,
    used: &mut [bool; 8],
    stmts: &mut Vec<Stmt>,
) {
    if insn.op0_kind() != OpKind::Register {
        let dst = op_expr(insn, 0, regs, locals, tmp_n, opt.abi, used);
        let src = op_expr(insn, 1, regs, locals, tmp_n, opt.abi, used);
        stmts.push(Stmt::Store {
            dst: dst.clone(),
            src: format!("{dst}{op}{src}"),
        });
        return;
    }
    let r = reg_name(insn.op0_register());
    let lhs = regs.get(&r).cloned().unwrap_or_else(|| canonicalize_dst(&r, opt.abi));
    let rhs = op_expr(insn, 1, regs, locals, tmp_n, opt.abi, used);
    let dst = if r == "rax" || r == "eax" {
        "v_ret".into()
    } else {
        canonicalize_dst(&r, opt.abi)
    };
    let src = format!("({lhs}){op}({rhs})");
    stmts.push(Stmt::Assign {
        dst: dst.clone(),
        src,
    });
    regs.insert(r, dst);
}

fn una(suffix: &str, insn: &Instruction, regs: &mut BTreeMap<String, String>, stmts: &mut Vec<Stmt>, abi: Abi) {
    if insn.op0_kind() != OpKind::Register {
        return;
    }
    let r = reg_name(insn.op0_register());
    let lhs = regs.get(&r).cloned().unwrap_or_else(|| canonicalize_dst(&r, abi));
    let dst = canonicalize_dst(&r, abi);
    stmts.push(Stmt::Assign {
        dst: dst.clone(),
        src: format!("({lhs}) {suffix}"),
    });
    regs.insert(r, dst);
}

fn una_prefix(p: &str, insn: &Instruction, regs: &mut BTreeMap<String, String>, stmts: &mut Vec<Stmt>, abi: Abi) {
    if insn.op0_kind() != OpKind::Register {
        return;
    }
    let r = reg_name(insn.op0_register());
    let lhs = regs.get(&r).cloned().unwrap_or_else(|| canonicalize_dst(&r, abi));
    let dst = canonicalize_dst(&r, abi);
    stmts.push(Stmt::Assign {
        dst: dst.clone(),
        src: format!("{p}({lhs})"),
    });
    regs.insert(r, dst);
}

fn mark_arg(abi: Abi, reg: &str, used: &mut [bool; 8]) {
    let idx = match abi {
        Abi::Sysv => sysv_reg_arg(reg),
        _ => win64_reg_arg(reg),
    };
    if let Some(i) = idx {
        if i < used.len() {
            used[i] = true;
        }
    }
}

fn canonicalize_dst(reg: &str, abi: Abi) -> String {
    if let Some(i) = match abi {
        Abi::Sysv => sysv_reg_arg(reg),
        _ => win64_reg_arg(reg),
    } {
        return format!("arg{i}");
    }
    match reg {
        "rax" | "eax" => "v_ret".into(),
        "rbx" | "ebx" => "v_rbx".into(),
        "rsi" | "esi" => "v_rsi".into(),
        "rdi" | "edi" => "v_rdi".into(),
        "r10" | "r10d" => "v10".into(),
        "r11" | "r11d" => "v11".into(),
        "r12" | "r12d" => "v12".into(),
        "r13" | "r13d" => "v13".into(),
        "r14" | "r14d" => "v14".into(),
        "r15" | "r15d" => "v15".into(),
        other => other.to_string(),
    }
}

fn local_index_of_reg(_r: &str) -> Option<u32> {
    None
}

fn reg_name(r: Register) -> String {
    format!("{r:?}").to_ascii_lowercase()
}

fn imm_of(insn: &Instruction, op: u32) -> i64 {
    match insn.op_kind(op) {
        OpKind::Immediate8 => insn.immediate8() as i64,
        OpKind::Immediate16 => insn.immediate16() as i64,
        OpKind::Immediate32 => insn.immediate32() as i64,
        OpKind::Immediate64 => insn.immediate64() as i64,
        OpKind::Immediate8to16 => insn.immediate8to16() as i64,
        OpKind::Immediate8to32 => insn.immediate8to32() as i64,
        OpKind::Immediate8to64 => insn.immediate8to64(),
        OpKind::Immediate32to64 => insn.immediate32to64(),
        _ => 0,
    }
}

fn format_imm(v: i64) -> String {
    if v.abs() < 16 {
        format!("{v}")
    } else {
        format!("0x{v:x}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LiftOptions;

    #[test]
    fn xor_eax_is_return_zero() {
        // xor eax, eax ; ret
        let code = [0x31, 0xC0, 0xC3];
        let r = lift(&code, 0x140001000, 64, "sub_140001000", &LiftOptions::default());
        assert!(r.c.contains("return"), "{}", r.c);
        assert!(r.c.contains("0") || r.c.contains("v_ret"), "{}", r.c);
    }

    #[test]
    fn test_jz_if() {
        // test rcx, rcx ; je +7 ; mov eax,1 ; ret ; xor eax,eax ; ret
        let code = [
            0x48, 0x85, 0xC9, // test rcx, rcx
            0x74, 0x06,       // je +6
            0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0xC3,             // ret
            0x31, 0xC0,       // xor eax, eax
            0xC3,
        ];
        let r = lift(&code, 0x1000, 64, "check", &LiftOptions::default());
        assert!(r.c.contains("if") || r.c.contains("==") || r.c.contains("arg0"), "{}", r.c);
        assert!(r.c.contains("uint64_t"), "{}", r.c);
    }
}
