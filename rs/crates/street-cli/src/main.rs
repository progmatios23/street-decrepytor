mod elevate;
mod host;
mod netwatch;
mod pipeline;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use street_core::{classify_path, pe::parse_pe, VERSION};
use street_decompile::backend::{BackendKind, DecompileRequest};
use street_decompile::Registry;
use street_disasm::func::{function_bytes, recover_pe};
use street_lift::{lift_bytes, Abi, LiftOptions};
use street_x64dbg::{commands, menus};

#[derive(Parser)]
#[command(name = "street", version = VERSION, about = "Street — static crypto rank/solve + C motor + optional debug")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Classify an artifact (JSON)
    Classify { path: PathBuf },
    /// Watch a running process's network peers, from outside it.
    Net {
        #[arg(long)]
        pid: u32,
        #[arg(long, default_value_t = 30)]
        seconds: u64,
    },
    /// Launch the target WITHOUT attaching a debugger.
    ///
    /// This is the control case for `trace`. If a target behaves the same way
    /// with and without the tracer — same exit code, same lifetime — then
    /// whatever it does is not a reaction to being traced, and no amount of
    /// instrumentation will change it.
    Run {
        path: PathBuf,
        /// How long to watch before leaving it running.
        #[arg(long, default_value_t = 30)]
        seconds: u64,
        /// Force elevation even if the manifest does not ask for it.
        #[arg(long)]
        elevate: bool,
        /// Watch the target's network peers from outside the process.
        ///
        /// Works on a target that refuses to be debugged, because it puts
        /// nothing inside the target.
        #[arg(long)]
        watch_net: bool,
    },
    /// Recover functions
    Funcs { path: PathBuf },
    /// Disassemble .text (listing)
    Disasm {
        path: PathBuf,
        #[arg(long, default_value_t = 80)]
        max: usize,
    },
    /// Disassemble a raw region — a carved section, an unpacked image, or a
    /// captured memory blob — at the virtual address it was mapped at.
    DisasmRaw {
        path: PathBuf,
        /// Virtual address the region starts at
        #[arg(long, default_value = "0")]
        base: String,
        /// Address to start decoding at (defaults to `base`)
        #[arg(long)]
        at: Option<String>,
        /// Maximum instructions
        #[arg(long, default_value_t = 200)]
        max: usize,
    },
    /// Walk a packer's stub chain: from a start address inside a raw region,
    /// decode forward to the first *unconditional* branch and follow it, hop by
    /// hop. Reports the route, not the semantics — the instruction stream in a
    /// commercial protector is mutated, so this gives control flow only.
    FollowCalls {
        path: PathBuf,
        /// Absolute virtual address the region's first byte is loaded at
        #[arg(long)]
        base: String,
        /// Address to start following from (defaults to `base`)
        #[arg(long)]
        at: Option<String>,
        /// Maximum hops
        #[arg(long, default_value_t = 16)]
        hops: usize,
        /// Instructions decoded per hop while searching for the first branch
        #[arg(long, default_value_t = 24)]
        window: usize,
    },
    /// Native C-like pseudocode for one function
    Lift {
        path: PathBuf,
        #[arg(long)]
        addr: Option<String>,
        #[arg(long, default_value = "win64")]
        abi: String,
        #[arg(long)]
        asm_comments: bool,
    },
    /// Decompile via a backend (native|ghidra|ida|binja)
    Decompile {
        path: PathBuf,
        #[arg(long)]
        addr: Option<String>,
        #[arg(long, default_value = "native")]
        backend: String,
    },
    /// List backend capability flags
    Backends,
    /// Dump x64dbg menu + command set
    X64dbg,
    /// Run MCP stdio server (token-first tools)
    Mcp,
    /// Invert dword stub (Cs2-External class)
    StubDecrypt {
        path: PathBuf,
        #[arg(long)]
        rva: Option<String>,
    },
    /// Honesty: XOR magic-anchored decrypt probe
    Decrypt { path: PathBuf },
    /// Static crypto ranking + auto-solve (disk only, no spawn)
    Crypto {
        path: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Alias: crypto rank + solve + write CRYPTO_RANKING.*
    Crack {
        path: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Optional live host (not required for crypto/crack)
    Debug { path: PathBuf },
    /// Auto-identify URLs, hosts, imports, xrefs
    Links { path: PathBuf },
    /// Full static: classify + links + IR + C + project JSON
    Analyze {
        path: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// StreetKernel.sys status
    Kernel,
    /// Lift to ISA-neutral IR (JSON)
    Ir {
        path: PathBuf,
        #[arg(long)]
        addr: Option<String>,
    },
    /// Extract what is *inside* the host on disk (imports, URLs, shm, overlay)
    Extract {
        path: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Auto string deobfuscation (stack / xor / lea-loop / plaintext)
    Strings {
        path: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Cleartext credential scan (API keys, tokens, PEM, URL creds)
    Secrets {
        path: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
        /// Include the raw secret values in the output (off by default)
        #[arg(long)]
        reveal: bool,
    },
    /// Junk-jump obfuscation scan, with an offset-preserving collapse.
    ///
    /// One protector family rewrites every unconditional jump into `je T; jne T`
    /// — a pair of opposite conditionals resolving to the same target. One of
    /// them always fires, so the pair is an unconditional jump in 12 bytes where
    /// 5 would do. This finds the pairs, reports where they cluster, and can
    /// emit a collapsed copy of the region whose byte offsets do not move.
    Deobf {
        /// A carved region, an unpacked image, or a whole file
        path: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
        /// Write the collapsed bytes alongside the report
        #[arg(long)]
        write: bool,
    },
    /// Dump the full PE weight: dirs, sections, resources, exports, TLS, debug, overlay
    Full {
        path: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// IDA-like session: modules/DLLs split, encryption flows, entry emu, C pseudocode
    Session {
        path: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long, default_value_t = 2048)]
        emu: u64,
    },
    /// Static pipeline, then optional no-debug observe. Never DEBUG_PROCESS.
    Pipeline {
        path: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
        /// Spawn without a debugger and RPM when the probe Shannon reaches 4.
        #[arg(long)]
        observe: bool,
        #[arg(long, default_value_t = 40)]
        seconds: u64,
        /// `0` reads ImageBase from the PE.
        #[arg(long, default_value_t = 0)]
        image_base: u64,
        /// `0` reads SizeOfImage from the PE.
        #[arg(long, default_value_t = 0)]
        image_size: u64,
        /// Probe RVA. Omit to use the largest virtual-only section.
        #[arg(long)]
        text_rva: Option<String>,
        #[arg(long, default_value_t = 0)]
        text_size: u64,
        #[arg(long)]
        elevate: bool,
    },
    /// RUNTIME_FUNCTION list. Raw PE, or a VA-linear image.bin from observe.
    Pdata {
        path: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Complete dump — pe+extract+crypto+IDA strings+session; nothing skipped
    Complete {
        /// File or folder of .exe/.dll
        path: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Rebuild a PE image from a `full` dump — sections + PE_FULL.json back into
    /// a runnable file. `--crack` sweeps the linker-default header fields
    /// against the recorded whole-file hash and stops at the first that matches
    RebuildPe {
        /// Directory holding PE_FULL.json and sections/ (as written by `full`)
        dump: PathBuf,
        #[arg(long)]
        out: PathBuf,
        /// Sweep the synthesised header fields until the image hashes to the original
        #[arg(long)]
        crack: bool,
        /// Cap how many header candidates `--crack` tries (each costs a full
        /// pass over the image; the sweep is ordered most-likely-first)
        #[arg(long, default_value_t = 6000)]
        crack_budget: u64,
    },
    /// No-debugger observe: spawn, wait until .text fills, RPM the image.
    /// Does not attach DEBUG_PROCESS. Themida and similar packers stay alive.
    Observe {
        path: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long, default_value_t = 40)]
        seconds: u64,
        #[arg(long, default_value_t = 0x140000000)]
        image_base: u64,
        #[arg(long)]
        elevate: bool,
    },
    /// Live dump — run the target under the debugger and capture the private
    /// executable memory it creates at runtime (injected shellcode, manual maps),
    /// plus the kernel drivers it loads. Network traffic and file-system writes
    /// are NOT instrumented — see docs/LIVE_DUMP.md for the coverage boundary
    LiveDump {
        /// Target .exe to run under the debugger
        path: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
        /// How long to observe the target, in seconds
        #[arg(long, default_value_t = 20)]
        seconds: u64,
        /// Memory scan interval, in milliseconds
        #[arg(long, default_value_t = 500)]
        interval: u64,
        /// Ignore executable regions smaller than this many bytes
        #[arg(long, default_value_t = 64)]
        min_region: usize,
        /// Force a UAC elevation prompt. Elevation also happens automatically
        /// when the target's manifest demands it — but the manifest cannot be
        /// read while the file is blocked by on-access AV, so pass this
        /// explicitly for a protected sample.
        #[arg(long)]
        elevate: bool,
    },
    /// Live trace — run the target under the debugger and record the API calls
    /// it makes (memory, module, process, file, network, registry, crypto) with
    /// timestamps, arguments and callers, from load through shellcode execution.
    /// Syscalls are not directly visible from user mode.
    Trace {
        /// Target .exe to run under the debugger
        path: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
        /// How long to observe the target, in seconds
        #[arg(long, default_value_t = 30)]
        seconds: u64,
        /// Hard cap on recorded events
        #[arg(long, default_value_t = 20000)]
        max_events: usize,
        /// Cap on breakpoints armed
        #[arg(long, default_value_t = 512)]
        max_armed: usize,
        /// Comma-separated categories to trace:
        /// memory,module,process,file,network,registry,crypto,sync,ui,anti_debug,other
        #[arg(long)]
        categories: Option<String>,
        /// Do not hide the debugger from the target. Use this to measure what
        /// the target does when it can see that it is being traced — which is
        /// itself a useful observation.
        #[arg(long)]
        no_stealth: bool,
        /// Entry breakpoint mode: `hw` (DR0, writes nothing to the target),
        /// `sw` (int3, writes one byte), or `none` (attach with no breakpoint
        /// there at all — the pure control for "does merely being debugged
        /// change the target's behaviour?").
        #[arg(long, default_value = "hw")]
        entry_bp: String,
        /// Force a UAC elevation prompt. Elevation also happens automatically
        /// when the target's manifest demands it.
        #[arg(long)]
        elevate: bool,
    },
}

fn parse_addr(s: &str) -> Result<u64> {
    let t = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    Ok(u64::from_str_radix(t, 16)?)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Classify { path } => {
            let p = classify_path(&path)?;
            println!("{}", serde_json::to_string_pretty(&p)?);
        }
        Cmd::Funcs { path } => {
            let data = std::fs::read(&path)?;
            let (_, fns, _) = recover_pe(&data, 80_000).map_err(|e| anyhow::anyhow!(e))?;
            println!("{}", serde_json::to_string_pretty(&fns)?);
        }
        Cmd::Disasm { path, max } => {
            let data = std::fs::read(&path)?;
            let (_, _, d) = recover_pe(&data, 80_000).map_err(|e| anyhow::anyhow!(e))?;
            println!("{}", street_disasm::listing(&d, Some(max)));
        }
        Cmd::DisasmRaw { path, base, at, max } => {
            let data = std::fs::read(&path)?;
            let base = parse_addr(&base)?;
            let start = match at {
                Some(a) => parse_addr(&a)?,
                None => base,
            };
            let end = base.saturating_add(data.len() as u64);
            if start < base || start >= end {
                anyhow::bail!("--at 0x{start:x} is outside the region 0x{base:x}..0x{end:x}");
            }
            let off = (start - base) as usize;
            // A raw region inside a PE is addressed by *file offset* here, but the
            // CPU resolves rip-relative branches against RVAs. In .text the two
            // differ by a constant, so every target printed below is off by that
            // delta if read as an RVA — which is exactly how a `call` to the
            // `.reloc` stub got misread during this engagement. Say the mapping.
            if let Ok(img) = street_core::pe::parse_pe(&data) {
                if let Some(s) = img.sections.iter().find(|s| {
                    let a = s.raw_off as usize;
                    off >= a && off < a + s.raw_size as usize
                }) {
                    let rva = s.va as i64 + (off as i64 - s.raw_off as i64);
                    println!(
                        "# {} region — addresses below are FILE OFFSETS.\n\
                         # RVA = address + {:#x}  (--at {:#x} is RVA {:#x})",
                        s.name,
                        rva - start as i64,
                        start,
                        rva
                    );
                }
            }
            let d = street_disasm::disassemble(
                &data[off..],
                start,
                street_core::Arch::X64,
                false,
                max,
            );
            println!("{}", street_disasm::listing(&d, Some(max)));
        }
        Cmd::FollowCalls { path, base, at, hops, window } => {
            let data = std::fs::read(&path)?;
            let base = parse_addr(&base)?;
            let end = base.saturating_add(data.len() as u64);
            let mut va = match at {
                Some(a) => parse_addr(&a)?,
                None => base,
            };
            let mut seen = std::collections::HashSet::new();
            println!(
                "# follow-calls  region 0x{base:x}..0x{end:x} ({} bytes)",
                data.len()
            );
            for hop in 0..hops {
                if va < base || va >= end {
                    println!("{hop:>3}  0x{va:x}  OUT OF REGION — the chain leaves this blob");
                    break;
                }
                if !seen.insert(va) {
                    println!("{hop:>3}  0x{va:x}  LOOP — already visited");
                    break;
                }
                let off = (va - base) as usize;
                let d = street_disasm::disassemble(
                    &data[off..],
                    va,
                    street_core::Arch::X64,
                    false,
                    window,
                );
                // Unconditional branches only: `is_call` covers Call/IndirectCall
                // and `is_jmp` is Mnemonic::Jmp. A conditional branch is ambiguous
                // and is deliberately not followed.
                match d
                    .instructions
                    .iter()
                    .find(|i| (i.is_call || i.is_jmp) && i.target.is_some())
                {
                    Some(i) => {
                        let t = i.target.unwrap_or(0);
                        println!(
                            "{hop:>3}  0x{va:x}  {:<6} 0x{:x}  ->  0x{t:x}",
                            i.mnemonic, i.addr
                        );
                        va = t;
                    }
                    None => {
                        println!(
                            "{hop:>3}  0x{va:x}  no unconditional branch within {window} instructions — chain ends"
                        );
                        for l in d.instructions.iter().take(6) {
                            println!("       0x{:x}  {} {}", l.addr, l.mnemonic, l.op_str);
                        }
                        break;
                    }
                }
            }
        }
        Cmd::Lift { path, addr, abi, asm_comments } => {
            let data = std::fs::read(&path)?;
            let img = parse_pe(&data)?;
            let (base, fns, _) = recover_pe(&data, 80_000).map_err(|e| anyhow::anyhow!(e))?;
            let start = if let Some(a) = addr {
                parse_addr(&a)?
            } else {
                fns.first().map(|f| f.start).unwrap_or(img.va(img.entry_rva))
            };
            let size = fns
                .iter()
                .find(|f| f.start == start)
                .map(|f| f.size as usize)
                .unwrap_or(0x200);
            let (code, va) = function_bytes(&data, start, size).ok_or_else(|| anyhow::anyhow!("no bytes"))?;
            let abi = match abi.as_str() {
                "sysv" => Abi::Sysv,
                "cdecl" => Abi::Cdecl,
                _ => Abi::Win64,
            };
            let r = lift_bytes(
                code,
                va,
                img.arch,
                &format!("sub_{start:x}"),
                &LiftOptions { abi, asm_comments, max_insns: 4096 },
            );
            print!("{}", r.c);
            let _ = base;
        }
        Cmd::Decompile { path, addr, backend } => {
            let data = std::fs::read(&path)?;
            let img = parse_pe(&data)?;
            let (_, fns, _) = recover_pe(&data, 80_000).map_err(|e| anyhow::anyhow!(e))?;
            let start = if let Some(a) = addr {
                parse_addr(&a)?
            } else {
                fns.first().map(|f| f.start).unwrap_or(img.va(img.entry_rva))
            };
            let size = fns.iter().find(|f| f.start == start).map(|f| f.size as usize).unwrap_or(0x200);
            let (code, va) = function_bytes(&data, start, size).unwrap_or((&[][..], start));
            let kind = BackendKind::parse(&backend).ok_or_else(|| anyhow::anyhow!("backend"))?;
            let reg = Registry::new();
            let req = DecompileRequest {
                addr: va,
                name: format!("sub_{start:x}"),
                arch: img.arch,
                code: code.to_vec(),
                abi: Abi::Win64,
                max_chars: 8000,
                asm_comments: false,
            };
            match reg.decompile(kind, &req) {
                Ok(t) => print!("{}", t.c),
                Err(g) => println!("{}", serde_json::to_string_pretty(&g)?),
            }
        }
        Cmd::Backends => {
            let reg = Registry::new();
            println!("{}", serde_json::to_string_pretty(&reg.list())?);
        }
        Cmd::X64dbg => {
            print!("{}", menus::plugin_menus());
            println!();
            print!("{}", commands::command_help());
        }
        Cmd::Mcp => street_mcp::serve_stdio()?,
        Cmd::StubDecrypt { path, rva } => {
            let data = std::fs::read(&path)?;
            let rva = rva.map(|s| parse_addr(&s).unwrap_or(0)).unwrap_or(0);
            let ops = street_crypto::extract_dw_ops(&data, rva);
            println!("{}", serde_json::to_string_pretty(&ops)?);
        }
        Cmd::Decrypt { path } => {
            let data = std::fs::read(&path)?;
            match street_crypto::decrypt_blob(&data) {
                Some(h) => println!("{}", serde_json::to_string_pretty(&h)?),
                None => println!("{{\"decrypted\":false,\"note\":\"no_magic_hit\"}}"),
            }
        }
        Cmd::Crypto { path, out } | Cmd::Crack { path, out } => {
            let report = street_crypto::run_static(&path).map_err(|e| anyhow::anyhow!(e))?;
            let out_dir = out.unwrap_or_else(|| {
                PathBuf::from("output").join("crypto").join(
                    path.file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("target"),
                )
            });
            let written = street_crypto::write_report(&report, &out_dir).map_err(|e| anyhow::anyhow!(e))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "primary": report.ranking.primary,
                    "playbook": report.ranking.playbook,
                    "decrypted": report.decrypted,
                    "anti_debug": report.protect.anti_debug.len(),
                    "tamper": report.protect.tamper.len(),
                    "crypto_api": report.protect.crypto_api.len(),
                    "hits_ranked": report.ranking.hits.iter().take(8).map(|h| serde_json::json!({
                        "system": h.system,
                        "confidence": h.confidence,
                        "rank_score": h.rank_score,
                        "evidence": h.evidence,
                    })).collect::<Vec<_>>(),
                    "solved": report.solved.iter().take(12).map(|s| serde_json::json!({
                        "cipher": s.cipher,
                        "magic": s.magic,
                        "score": s.score,
                        "offset": format!("{:#x}", s.offset),
                        "decrypted": s.decrypted,
                        "note": s.note,
                    })).collect::<Vec<_>>(),
                    "carved": report.carved.iter().take(16).map(|c| serde_json::json!({
                        "offset": format!("{:#x}", c.offset),
                        "size": c.size,
                        "sha256": &c.sha256[..16.min(c.sha256.len())],
                        "machine": c.machine,
                        "sections": c.sections,
                    })).collect::<Vec<_>>(),
                    "playbook_steps": report.playbook_steps,
                    "report": written,
                }))?
            );
        }
        Cmd::Debug { path } => host::run_debug(&path.display().to_string())?,
        Cmd::Observe {
            path,
            out,
            seconds,
            image_base,
            elevate,
        } => {
            if elevate {
                if elevate::ensure_elevated("observe --elevate").map_err(|e| anyhow::anyhow!(e))? {
                    return Ok(());
                }
            }
            let mut opts = street_debug::observe::ObserveOptions::default();
            opts.seconds = seconds;
            opts.image_base = image_base;
            if let Some(o) = out {
                opts.out_dir = o;
            }
            let rep = street_debug::observe::run_observe(&path.display().to_string(), &opts)
                .map_err(|e| anyhow::anyhow!(e))?;
            println!("{}", serde_json::to_string_pretty(&rep)?);
        }
        Cmd::LiveDump {
            path,
            out,
            seconds,
            interval,
            min_region,
            elevate,
        } => {
            // A debugger must be at least as privileged as its target. The
            // manifest check cannot see through an on-access AV block, so
            // `--elevate` exists for exactly that case.
            let requires_elevation = std::fs::read(&path)
                .ok()
                .map(|d| street_core::exec_profile::analyze(&d).requires_elevation)
                .unwrap_or(false);
            if elevate || requires_elevation {
                let why = if requires_elevation {
                    "target manifest requires administrator — a debugger cannot be \
                     less privileged than its target"
                } else {
                    "--elevate was requested"
                };
                if elevate::ensure_elevated(why).map_err(|e| anyhow::anyhow!(e))? {
                    // An elevated child was started and will do the work.
                    return Ok(());
                }
            }
            let mut opts = street_debug::live::LiveDumpOptions::default();
            if let Some(o) = out {
                opts.out_dir = o;
            }
            opts.seconds = seconds;
            opts.scan_interval_ms = interval;
            opts.min_shellcode = min_region;
            let exe = path.display().to_string();
            let rep = street_debug::live::run_live_dump(&exe, &opts)
                .map_err(|e| anyhow::anyhow!(e))?;
            // Refuse to emit a report that could read as a clean result without
            // declaring what was never instrumented.
            street_debug::live::check_honesty(&rep).map_err(|e| anyhow::anyhow!(e))?;
            let root = opts.out_dir.join(rep.pid.to_string());
            std::fs::create_dir_all(&root)?;
            std::fs::write(root.join("LIVEDUMP.json"), serde_json::to_string_pretty(&rep)?)?;
            std::fs::write(root.join("LIVEDUMP.md"), street_debug::live::report_md(&rep))?;
            println!("{}", street_debug::live::summary_md(&rep));
            println!("\nfull report: {}", root.join("LIVEDUMP.md").display());
        }
        Cmd::Net { pid, seconds } => {
            println!("street: watching pid {pid} for {seconds}s (external observation)");
            let peers = netwatch::watch(pid, seconds);
            if peers.is_empty() {
                println!("street: no remote peers observed");
            } else {
                println!("street: {} remote peer(s):", peers.len());
                for p in &peers {
                    println!("  {}:{}", p.address, p.port);
                }
            }
            let _ = std::fs::create_dir_all("output");
            let _ = std::fs::write(
                "output/net-watch.txt",
                peers
                    .iter()
                    .map(|p| format!("{}:{}", p.address, p.port))
                    .collect::<Vec<_>>()
                    .join("
"),
            );
        }
        Cmd::Run {
            path,
            seconds,
            elevate,
            watch_net,
        } => {
            // Same elevation rule as `trace`: a target whose manifest demands
            // administrator cannot be launched from a plain prompt, and the
            // requirement is known statically.
            let requires_elevation = std::fs::read(&path)
                .ok()
                .map(|d| street_core::exec_profile::analyze(&d).requires_elevation)
                .unwrap_or(false);
            if elevate || requires_elevation {
                let why = if requires_elevation {
                    "the target's manifest requests requireAdministrator"
                } else {
                    "--elevate was requested"
                };
                if elevate::ensure_elevated(why).map_err(|e| anyhow::anyhow!(e))? {
                    // An elevated child was started and will do the work.
                    return Ok(());
                }
            }

            let started = std::time::Instant::now();
            let mut child = std::process::Command::new(&path).spawn()?;
            println!(
                "street: launched {} WITHOUT a debugger (pid {})",
                path.display(),
                child.id()
            );
            // Publish the pid immediately: an external observer needs it while
            // the target is still running, not after it exits. For a target that
            // refuses to be traced, watching it from outside is the only
            // observation available.
            let _ = std::fs::create_dir_all("output");
            let _ = std::fs::write("output/run-pid.txt", format!("{}", child.id()));
            // The elevated child gets its own console, so its stdout is not
            // visible to whoever launched it. Mirror the outcome to a file.
            let log_path = std::path::PathBuf::from("output").join("run-result.txt");
            // Assigned on every path out of the loop below, so it needs no
            // placeholder — and a placeholder would only be dead code.
            let mut verdict: String;
            let mut peers: std::collections::BTreeMap<netwatch::Peer, ()> =
                std::collections::BTreeMap::new();
            let deadline = started + std::time::Duration::from_secs(seconds);
            loop {
                if let Some(st) = child.try_wait()? {
                    let dt = started.elapsed().as_secs_f64();
                    verdict = match st.code() {
                        Some(c) => format!(
                            "exited after {dt:.1}s with code {c} (0x{:x})",
                            c as u32
                        ),
                        None => format!("exited after {dt:.1}s (terminated by signal)"),
                    };
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    // Dropping a Child does not kill it, so the target is left
                    // running rather than torn down.
                    verdict = format!("still running after {seconds}s — left alive");
                    break;
                }
                if watch_net {
                    for p in netwatch::tcp_peers_of(child.id()) {
                        peers.insert(p, ());
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            if watch_net {
                let mut list: Vec<_> = peers.into_keys().collect();
                list.sort();
                if list.is_empty() {
                    println!("street: network — no remote peers observed");
                } else {
                    println!("street: network — {} remote peer(s):", list.len());
                    for p in &list {
                        println!("  {}:{}", p.address, p.port);
                    }
                }
                verdict.push_str(&format!(
                    " | peers: {}",
                    list.iter()
                        .map(|p| format!("{}:{}", p.address, p.port))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            println!("street: {verdict}");
            let _ = std::fs::create_dir_all("output");
            let _ = std::fs::write(&log_path, format!("{}\n{}\n", path.display(), verdict));
            println!("street: result written to {}", log_path.display());
        }
        Cmd::Trace {
            path,
            out,
            seconds,
            max_events,
            max_armed,
            categories,
            no_stealth,
            entry_bp,
            elevate,
        } => {
            // Elevation. A debugger must be at least as privileged as its
            // target, and a target whose manifest says `requireAdministrator`
            // cannot be spawned from a non-elevated parent. The requirement is
            // detected statically here rather than discovered as a spawn
            // failure, and elevation is requested only when it is needed.
            let requires_elevation = std::fs::read(&path)
                .ok()
                .map(|d| street_core::exec_profile::analyze(&d).requires_elevation)
                .unwrap_or(false);
            if elevate || requires_elevation {
                let why = if requires_elevation {
                    "the target's manifest requests requireAdministrator"
                } else {
                    "--elevate was requested"
                };
                if elevate::ensure_elevated(why).map_err(|e| anyhow::anyhow!(e))? {
                    // An elevated child was started and will do the work.
                    return Ok(());
                }
            }

            let mut opts = street_debug::trace::TraceOptions::default();
            if let Some(o) = out {
                opts.out_dir = o;
            }
            opts.seconds = seconds;
            opts.max_events = max_events;
            opts.max_armed = max_armed;
            opts.stealth = !no_stealth;
            let eb = entry_bp.trim().to_ascii_lowercase();
            opts.entry_bp = eb != "none";
            opts.hw_entry = eb != "sw" && eb != "none";
            if let Some(c) = categories {
                for part in c.split(',') {
                    let p = part.trim().to_ascii_lowercase();
                    let cat = match p.as_str() {
                        "memory" => street_debug::trace::ApiCategory::Memory,
                        "module" => street_debug::trace::ApiCategory::Module,
                        "process" => street_debug::trace::ApiCategory::Process,
                        "file" => street_debug::trace::ApiCategory::File,
                        "network" => street_debug::trace::ApiCategory::Network,
                        "registry" => street_debug::trace::ApiCategory::Registry,
                        "crypto" => street_debug::trace::ApiCategory::Crypto,
                        "sync" => street_debug::trace::ApiCategory::Sync,
                        "ui" | "user32" | "dialog" => street_debug::trace::ApiCategory::Ui,
                        "anti_debug" | "antidebug" | "anti-debug" => {
                            street_debug::trace::ApiCategory::AntiDebug
                        }
                        "other" => street_debug::trace::ApiCategory::Other,
                        "" => continue,
                        other => anyhow::bail!(
                            "unknown category '{other}' — use memory,module,process,file,network,\
                             registry,crypto,sync,ui,anti_debug,other"
                        ),
                    };
                    opts.categories.push(cat);
                }
            }
            let exe = path.display().to_string();
            let rep = match street_debug::trace::run_trace(&exe, &opts) {
                Ok(r) => r,
                Err(e) => {
                    // A pre-run failure is not a trace result. Report it as its
                    // own verdict and exit distinctly, so a script cannot read a
                    // spawn failure as an inconclusive or anti-tamper run.
                    eprintln!("trace could not start: {e}");
                    eprintln!(
                        "verdict: spawn_failed — the target never executed, so this is NOT an \
                         anti-tamper or 'no activity' result"
                    );
                    std::process::exit(4);
                }
            };
            let root = opts.out_dir.join(rep.pid.to_string());
            std::fs::create_dir_all(&root)?;
            std::fs::write(root.join("TRACE.json"), serde_json::to_string_pretty(&rep)?)?;
            std::fs::write(root.join("TRACE.md"), street_debug::trace::report_md(&rep))?;
            println!("{}", street_debug::trace::summary_md(&rep));
            println!("\nevents: {}", root.join("EVENTS.jsonl").display());
            println!("report: {}", root.join("TRACE.md").display());
            if !rep.succeeded() {
                // Non-zero exit so a scripted run cannot read an incomplete
                // trace as a clean one.
                std::process::exit(3);
            }
        }
        Cmd::Links { path } => {
            let data = std::fs::read(&path)?;
            let img = parse_pe(&data).ok();
            let base = img.as_ref().map(|i| i.image_base).unwrap_or(0);
            let d = recover_pe(&data, 40_000).ok().map(|t| t.2);
            let rep = street_links::identify(&data, base, d.as_ref());
            println!("{}", serde_json::to_string_pretty(&rep)?);
        }
        Cmd::Analyze { path, out } => {
            let data = std::fs::read(&path)?;
            let prof = classify_path(&path)?;
            let img = parse_pe(&data)?;
            let (_, fns, d) = recover_pe(&data, 80_000).map_err(|e| anyhow::anyhow!(e))?;
            let links = street_links::identify(&data, img.image_base, Some(&d));
            let start = fns.first().map(|f| f.start).unwrap_or(img.va(img.entry_rva));
            let size = fns.iter().find(|f| f.start == start).map(|f| f.size as usize).unwrap_or(0x100);
            let (code, va) = function_bytes(&data, start, size).unwrap_or((&[][..], start));
            let ir = street_ir::lift_x86(code, va, if img.is_64 { 64 } else { 32 }, &format!("sub_{start:x}"), 256);
            let c = lift_bytes(code, va, img.arch, &format!("sub_{start:x}"), &LiftOptions::default());
            let mut proj = street_project::Project::new(&path, &data);
            proj.links = Some(links.clone());
            let outp = out.unwrap_or_else(|| street_project::Project::default_path(&path));
            proj.save(&outp)?;
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "profile": prof,
                "funcs": fns.len(),
                "links": {
                    "urls": links.urls.len(),
                    "hosts": links.hosts.len(),
                    "imports": links.imports.len(),
                    "xrefs": links.xrefs.len(),
                },
                "ir_ops": ir.ops.len(),
                "c_preview": c.c.chars().take(800).collect::<String>(),
                "project": outp,
                "kernel": street_kernel::KernelClient::open().status(),
            }))?);
        }
        Cmd::Kernel => {
            println!("{}", serde_json::to_string_pretty(&street_kernel::KernelClient::open().status())?);
        }
        Cmd::Ir { path, addr } => {
            let data = std::fs::read(&path)?;
            let img = parse_pe(&data)?;
            let (_, fns, _) = recover_pe(&data, 40_000).map_err(|e| anyhow::anyhow!(e))?;
            let start = if let Some(a) = addr {
                parse_addr(&a)?
            } else {
                fns.first().map(|f| f.start).unwrap_or(img.va(img.entry_rva))
            };
            let size = fns.iter().find(|f| f.start == start).map(|f| f.size as usize).unwrap_or(0x200);
            let (code, va) = function_bytes(&data, start, size).unwrap_or((&[][..], start));
            let ir = street_ir::lift_x86(code, va, if img.is_64 { 64 } else { 32 }, &format!("sub_{start:x}"), 512);
            println!("{}", serde_json::to_string_pretty(&ir)?);
        }
        Cmd::Extract { path, out } => {
            let inv = street_core::inventory_path(&path)?;
            if let Some(dir) = out {
                std::fs::create_dir_all(&dir)?;
                let p = dir.join("HOST_INVENTORY.json");
                std::fs::write(&p, serde_json::to_vec_pretty(&inv)?)?;
                // also dump interesting import list as text
                let mut txt = String::new();
                txt.push_str(&format!("role: {}\n", inv.role_guess));
                txt.push_str(&format!("urls: {}\n", inv.urls.join(", ")));
                txt.push_str(&format!("shm: {}\n", inv.shared_objects.join(", ")));
                txt.push_str("interesting imports:\n");
                for i in &inv.interesting_imports {
                    txt.push_str(&format!("  {i}\n"));
                }
                std::fs::write(dir.join("HOST_INVENTORY.txt"), txt)?;
                println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                    "role": inv.role_guess,
                    "urls": inv.urls,
                    "shared": inv.shared_objects,
                    "pdb": inv.pdb,
                    "overlay_size": inv.overlay_size,
                    "interesting_imports": inv.interesting_imports,
                    "import_dlls": inv.imports.iter().map(|d| serde_json::json!({
                        "dll": d.dll, "count": d.count
                    })).collect::<Vec<_>>(),
                    "notes": inv.notes,
                    "written": p,
                }))?);
            } else {
                println!("{}", serde_json::to_string_pretty(&inv)?);
            }
        }
        Cmd::Strings { path, out } => {
            let data = std::fs::read(&path)?;
            let ida = street_crypto::build_ida_strings(&data);
            let rep = street_crypto::deobfuscate_strings(&data);
            if let Some(dir) = out {
                std::fs::create_dir_all(&dir)?;
                std::fs::write(dir.join("STRINGS_IDA.json"), serde_json::to_vec_pretty(&ida)?)?;
                std::fs::write(dir.join("STRINGS_IDA.txt"), street_crypto::format_ida_listing(&ida))?;
                let mut xref = String::from("; strings with xrefs\n\n");
                for s in ida.strings.iter().filter(|s| s.xref_count > 0) {
                    xref.push_str(&format!("{:016X}  XREF:{}  {}\n", s.ea, s.xref_count, s.display));
                }
                std::fs::write(dir.join("STRINGS_XREFS.txt"), xref)?;
                std::fs::write(dir.join("STRINGS_DEOBF.json"), serde_json::to_vec_pretty(&rep)?)?;
                let mut t = String::new();
                t.push_str(&format!("ida: {}  xrefed: {}  deob: {}\n\n", ida.count, ida.with_xrefs, rep.deobfuscated.len()));
                for s in &rep.deobfuscated {
                    t.push_str(&format!("[{} k={:?} off={:#x}] {}\n", s.origin, s.key_hex, s.offset, s.value));
                }
                std::fs::write(dir.join("STRINGS_CLEAR.txt"), t)?;
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "ida": { "count": ida.count, "with_xrefs": ida.with_xrefs },
                    "stats": rep.stats,
                    "ida_sample": ida.strings.iter().filter(|s| s.xref_count>0).take(20).collect::<Vec<_>>(),
                    "deobfuscated": rep.deobfuscated.iter().take(30).collect::<Vec<_>>(),
                    "plaintext_top": rep.plaintext.iter().filter(|s| s.score>=50).take(20).collect::<Vec<_>>(),
                }))?
            );
        }
        Cmd::Secrets { path, out, reveal } => {
            let data = std::fs::read(&path)?;
            let rep = street_crypto::scan_secrets(&data, reveal);
            if let Some(dir) = out {
                std::fs::create_dir_all(&dir)?;
                std::fs::write(dir.join("SECRETS.json"), serde_json::to_vec_pretty(&rep)?)?;
                let mut t = String::from("# cleartext credentials\n\n");
                for h in &rep.hits {
                    t.push_str(&format!(
                        "0x{:08X}  {:<18} {:<8} {}\n",
                        h.offset, h.kind, h.encoding, h.masked
                    ));
                }
                std::fs::write(dir.join("SECRETS.txt"), t)?;
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "hits": rep.hits.len(),
                    "by_kind": rep.by_kind,
                    "findings": rep.hits,
                }))?
            );
        }
        Cmd::Deobf { path, out, write } => {
            let data = std::fs::read(&path)?;
            let (collapsed, rep) = street_core::deobfuscate(&data);
            if let Some(dir) = out.as_ref() {
                std::fs::create_dir_all(dir)?;
                std::fs::write(dir.join("DEOBF.json"), serde_json::to_vec_pretty(&rep)?)?;
                std::fs::write(dir.join("DEOBF.txt"), rep.render())?;
                if write {
                    let stem = path
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("region");
                    std::fs::write(dir.join(format!("{stem}.deobf.bin")), &collapsed)?;
                }
            }
            println!("{}", rep.render());
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "path": path.display().to_string(),
                    "pairs": rep.pairs,
                    "near_pairs": rep.near_pairs,
                    "short_pairs": rep.short_pairs,
                    "wasted_bytes": rep.wasted_bytes,
                    "flattened": rep.flattened,
                    "zero_filler_run": rep.zero_filler_run,
                    "clusters": rep.clusters,
                    "density": rep.density,
                    "wrote": if write { "collapsed image" } else { "report only" },
                }))?
            );
        }
        Cmd::RebuildPe { dump, out, crack, crack_budget } => {
            let mut guess = street_core::HeaderGuess::default();
            if crack {
                println!("# sweeping linker defaults against the recorded hash…");
                let rep = street_core::crack_header(&dump, Some(crack_budget))?;
                println!("{}", rep.render());
                if let Some(g) = rep.found {
                    guess = g;
                }
            }
            let rep = street_core::rebuild_from_dump(&dump, &out, guess)?;
            println!("{}", rep.render());
            if !rep.sections_ok {
                return Err(anyhow::anyhow!(
                    "rebuilt image has sections that do not match the dump — refusing to call it done"
                ));
            }
        }
        Cmd::Full { path, out } => {
            let out_dir = out.unwrap_or_else(|| {
                PathBuf::from("output").join("full").join(
                    path.file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("target"),
                )
            });
            let full = street_core::dump_full(&path, &out_dir)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "path": full.path,
                    "size": full.size,
                    "sha256": full.sha256,
                    "arch": if full.is_64 { "x64" } else { "x86" },
                    "entry_va": format!("{:#x}", full.entry_va),
                    "sections": full.sections.iter().map(|s| serde_json::json!({
                        "name": s.name, "raw": s.raw_size, "H": (s.entropy * 1000.0).round() / 1000.0,
                        "exec": s.executable, "virtual_only": s.virtual_only
                    })).collect::<Vec<_>>(),
                    "dirs": full.data_dirs.iter().filter(|d| d.rva != 0).map(|d| serde_json::json!({
                        "name": d.name, "rva": format!("{:#x}", d.rva), "size": d.size
                    })).collect::<Vec<_>>(),
                    "exports": full.exports.len(),
                    "resources": full.resources.len(),
                    "tls_callbacks": full.tls.as_ref().map(|t| t.callbacks.len()).unwrap_or(0),
                    "debug": full.debug,
                    "overlay_size": full.overlay_size,
                    "utf16_n": full.utf16_strings.len(),
                    "out": out_dir,
                }))?
            );
        }
        Cmd::Session { path, out, emu } => {
            let out_dir = out.unwrap_or_else(|| {
                PathBuf::from("output").join("session").join(
                    path.file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("target"),
                )
            });
            let rep = street_session::run_session(
                &path,
                &out_dir,
                &street_session::SessionOptions { max_emu_insns: emu },
            );
            println!("{}", serde_json::to_string_pretty(&rep)?);
        }
        Cmd::Pipeline {
            path,
            out,
            observe,
            seconds,
            image_base,
            image_size,
            text_rva,
            text_size,
            elevate,
        } => {
            if observe && elevate {
                if elevate::ensure_elevated("pipeline --observe --elevate")
                    .map_err(|e| anyhow::anyhow!(e))?
                {
                    return Ok(());
                }
            }
            let out = out.unwrap_or_else(|| {
                PathBuf::from("output").join("pipeline").join(
                    path.file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("target"),
                )
            });
            let text_rva = match text_rva {
                Some(s) => Some(parse_addr(&s)?),
                None => None,
            };
            let rep = pipeline::run_pipeline(
                &path,
                &pipeline::PipelineOpts {
                    out,
                    observe,
                    seconds,
                    image_base,
                    image_size,
                    text_rva,
                    text_size,
                },
            )?;
            println!("{}", serde_json::to_string_pretty(&rep)?);
        }
        Cmd::Pdata { path, out } => {
            let data = std::fs::read(&path)?;
            let out = out.unwrap_or_else(|| {
                PathBuf::from("output").join("pdata").join(
                    path.file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("target"),
                )
            });
            let table = street_core::write_pdata(&data, &out).map_err(|e| anyhow::anyhow!(e))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "count": table.count,
                    "source": table.source,
                    "image_base": format!("{:#x}", table.image_base),
                    "dir_rva": format!("{:#x}", table.dir_rva),
                    "note": table.note,
                    "out": out,
                }))?
            );
        }
        Cmd::Complete { path, out } => {
            let out_dir = out.unwrap_or_else(|| {
                if path.is_dir() {
                    PathBuf::from("output").join("complete")
                } else {
                    PathBuf::from("output").join("complete").join(
                        path.file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("target"),
                    )
                }
            });
            if path.is_dir() {
                let reps = street_session::dump_complete_folder(&path, &out_dir);
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "folder": path,
                        "count": reps.len(),
                        "all_ok": reps.iter().all(|r| r.ok),
                        "items": reps.iter().map(|r| serde_json::json!({
                            "path": r.path, "ok": r.ok, "out": r.out_dir, "stages": r.stages
                        })).collect::<Vec<_>>(),
                    }))?
                );
            } else {
                let rep = street_session::dump_complete(&path, &out_dir);
                println!("{}", serde_json::to_string_pretty(&rep)?);
            }
        }
    }
    Ok(())
}
