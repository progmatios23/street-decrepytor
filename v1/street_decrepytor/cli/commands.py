# language: Python 3, file: cli/main.py
# Street-decrepytor CLI — agent-first, --help complete, .exe friendly
from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from street_decrepytor import __version__


def _print_json(obj: object) -> None:
    click.echo(json.dumps(obj, indent=2, default=str))


class AgentGroup(click.Group):
    """Show full command list + examples on bare --help."""

    def format_help(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        super().format_help(ctx, formatter)
        formatter.write_paragraph()
        formatter.write_text("Quick start (agents & operators):")
        formatter.write_text(
            "  street-decrepytor unpack FarmServices.exe\n"
            "  street-decrepytor unpack \"DFIR (1).exe\"\n"
            "  street-decrepytor dump --spawn DFIR.exe --wait 12 --vad --fix-pe --iat\n"
            "  street-decrepytor pe-dump <pid> --fix-pe --iat --out dumped.exe\n"
            "  street-decrepytor dump --name target.exe --vad\n"
            "  street-decrepytor cdn-pull --download --crack\n"
            "  street-decrepytor recrack Potassium.dll"
        )


@click.group(
    cls=AgentGroup,
    context_settings={"help_option_names": ["-h", "--help"], "max_content_width": 100},
    invoke_without_command=False,
)
@click.version_option(__version__, prog_name="street-decrepytor")
@click.option("--verbose", "-v", is_flag=True, help="Verbose errors to stderr.")
@click.pass_context
def main(ctx: click.Context, verbose: bool) -> None:
    """Street-decrepytor — classify / extract / dump / report (CLI-first).

    Does not decrypt Themida/VMProtect. See CRITICAL.md.
    New unknown PE: unpack then dump --spawn. Potassium gates: recrack.
    """
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose


# ── primary operator verbs ───────────────────────────────────────────


@main.command("crack")
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
@click.option("--out", type=click.Path(), default="output/crack", show_default=True, help="Output root directory.")
@click.option("--dynamic", is_flag=True, help="Enable live process-scan stage.")
@click.option("--no-simd", is_flag=True, help="Skip SIMD string emulator pass.")
@click.option("--gates", is_flag=True, help="Apply Potassium recrack (only if filename contains potassium). Off by default.")
@click.option("--unpack", "do_unpack", is_flag=True, help="Also run honest Themida-class unpack/resource extract.")
@click.option("--json-only", is_flag=True, help="Print full JSON only (no path hint on stderr).")
def cmd_crack(
    target: str,
    out: str,
    dynamic: bool,
    no_simd: bool,
    gates: bool,
    do_unpack: bool,
    json_only: bool,
) -> None:
    """One-shot crack/unpack pipeline for ANY PE/JAR/etc.

    Runs classify + full static stages + deobf routing + optional SIMD + gate patch.
    Writes CRACK_REPORT.md and crack_report.json under --out.
    Add --unpack for Themida-class detect + real resource/PE extraction.
    """
    from street_decrepytor.core.crack import crack_target

    report = crack_target(
        target,
        out=out,
        dynamic=dynamic,
        deep_simd=not no_simd,
        apply_gates=gates,
    )
    unpack_rep = None
    if do_unpack:
        from street_decrepytor.protectors.unpack_engine import unpack_target

        unpack_rep = unpack_target(target, Path(out) / "unpack")
        report["unpack"] = {
            "honest_verdict": unpack_rep.get("honest_verdict"),
            "themida_class": (unpack_rep.get("themida_class_ident") or {}).get("themida_class"),
            "score": (unpack_rep.get("themida_class_ident") or {}).get("score"),
            "layers_removed": unpack_rep.get("layers_removed"),
            "image_transforms": unpack_rep.get("image_transforms"),
            "decrypted": unpack_rep.get("decrypted"),
            "report_md": unpack_rep.get("report_md"),
        }
    if json_only:
        _print_json(report)
    else:
        _print_json({
            "verdict": report.get("verdict"),
            "report_md": report.get("report_md"),
            "pipeline_dir": report.get("pipeline_dir"),
            "errors": report.get("errors"),
            "actions": report.get("actions"),
            "unpack": report.get("unpack"),
        })
        click.echo(f"report: {report.get('report_md')}")
        if unpack_rep:
            click.echo(f"unpack: {unpack_rep.get('report_md')}")


@main.command("unpack")
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
@click.option("--out", type=click.Path(), default=None, help="Default: output/unpack/<stem>")
@click.option("--live", is_flag=True, help="If Themida-class: spawn+dump+OEP (runtime decrypt capture).")
@click.option("--wait", default=12.0, show_default=True, help="Live unpack timeout seconds.")
def cmd_unpack(target: str, out: str | None, live: bool, wait: float) -> None:
    """Static extract + optional --live Themida capture (no fake static decrypt).

    - Detects Themida/VMProtect by markers + virtual sections + EP placement
    - Extracts PE resources (embedded PE/XML) to disk
    - --live: spawn + dump + OEP if themida_class
    """
    from street_decrepytor.protectors.unpack_engine import unpack_target

    rep = unpack_target(target, out)
    payload = {
        "honest_verdict": rep.get("honest_verdict"),
        "themida_class": (rep.get("themida_class_ident") or {}).get("themida_class"),
        "score": (rep.get("themida_class_ident") or {}).get("score"),
        "reasons": (rep.get("themida_class_ident") or {}).get("reasons"),
        "cfg_obfuscation": rep.get("cfg_obfuscation"),
        "layers_removed": rep.get("layers_removed"),
        "copied": rep.get("copied"),
        "inventoried": rep.get("inventoried"),
        "image_transforms": rep.get("image_transforms"),
        "decrypted": rep.get("decrypted"),
        "layers_not_present": rep.get("layers_not_present"),
        "packed_sections": rep.get("packed_sections_dumped"),
        "dump_kit": rep.get("dump_kit"),
        "resources": [
            {"type": r["type"], "id": r["id"], "kind": r["kind"], "size": r["size"], "path": r["path"]}
            for r in (rep.get("resources_extracted") or [])
        ],
        "nested": rep.get("nested_pe_cracks"),
        "report_md": rep.get("report_md"),
        "out_dir": rep.get("out_dir"),
    }
    if live and (rep.get("themida_class_ident") or {}).get("themida_class"):
        from street_decrepytor.protectors.themida_unpack import unpack_themida_live

        live_out = Path(rep.get("out_dir") or out or "output/unpack") / "themida_live"
        live_rep = unpack_themida_live(target, live_out, wait_sec=wait)
        payload["live"] = {
            "ok": live_rep.get("ok"),
            "decrypted": live_rep.get("decrypted"),
            "unpacked_pe": live_rep.get("unpacked_pe"),
            "honest_verdict": live_rep.get("honest_verdict"),
            "oep_applied": live_rep.get("oep_applied"),
            "report_md": live_rep.get("report_md"),
        }
        if live_rep.get("decrypted"):
            payload["decrypted"] = True
    _print_json(payload)


@main.command("themida-unpack")
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
@click.option("--out", type=click.Path(), default=None, help="Default: output/themida/<stem>")
@click.option("--wait", default=12.0, show_default=True)
@click.option("--wait-mode", type=click.Choice(["text", "sleep"]), default="text", show_default=True)
@click.option("--force", is_flag=True, help="Dump even if themida_class score is below threshold.")
@click.option("--no-oep", is_flag=True, help="Do not patch AddressOfEntryPoint.")
@click.option("--vad/--no-vad", default=True, show_default=True)
def cmd_themida_unpack(
    target: str,
    out: str | None,
    wait: float,
    wait_mode: str,
    force: bool,
    no_oep: bool,
    vad: bool,
) -> None:
    """Live Themida unpack: spawn, PEB patch, wait for .text, dump, fix PE, hunt OEP.

    The packer decrypts itself in RAM. Street copies that image.
    decrypted=true only if .text raw size grows (disk 0 → dump >0).
    Does not lift the Oreans VM.
    """
    from street_decrepytor.protectors.themida_unpack import unpack_themida_live

    rep = unpack_themida_live(
        target,
        out,
        wait_sec=wait,
        wait_mode=wait_mode,
        vad=vad,
        apply_oep=not no_oep,
        force=force,
    )
    _print_json({
        "ok": rep.get("ok"),
        "decrypted": rep.get("decrypted"),
        "themida_class": rep.get("themida_class"),
        "honest_verdict": rep.get("honest_verdict"),
        "unpacked_pe": rep.get("unpacked_pe"),
        "oep_applied": rep.get("oep_applied"),
        "section_delta": rep.get("section_delta"),
        "iat_quality": rep.get("iat_quality"),
        "error": rep.get("error"),
        "report_md": rep.get("report_md"),
        "out_dir": rep.get("out_dir"),
    })


@main.command("recover")
@click.argument("target", required=False, default=None)
@click.option("--out", type=click.Path(), default="output/recover", show_default=True)
@click.option("--umi", is_flag=True, help="Identify UMI UI + recover injector dump / live if present.")
@click.option("--farm", is_flag=True, help="FarmServices full extract (XML + nested PE).")
@click.option("--live/--no-live", default=True, show_default=True)
@click.option("--wait", default=6.0, show_default=True, help="Live dump timeout (faster default).")
def cmd_recover(target: str | None, out: str, umi: bool, farm: bool, live: bool, wait: float) -> None:
    """Fast recover: extractable layers out. Farm + UMI + Themida dump rebuild.

    recovered_complete ≠ Oreans VM lift. See RECOVER.md.
    """
    from street_decrepytor.core.recover import recover_target

    if not target and not umi and not farm:
        farm = True
        umi = True
    r = recover_target(target, out=out, live=live, wait_sec=wait, umi=umi, farm=farm)
    _print_json({
        "elapsed_sec": r.get("elapsed_sec"),
        "decrypted": r.get("decrypted"),
        "recovered_complete": r.get("recovered_complete"),
        "jobs": [
            {k: j.get(k) for k in ("name", "ok", "recovered_complete", "honest", "stripped", "nested_pe", "tauri", "error", "injector_on_disk", "impossible_part")}
            for j in (r.get("jobs") or [])
        ],
        "report_md": r.get("report_md"),
        "note": r.get("note"),
    })


@main.command("themida-rebuild")
@click.argument("dump", type=click.Path(exists=True, dir_okay=False))
@click.option("--out", type=click.Path(), default=None, help="Default: <dump>_stripped.exe")
def cmd_themida_rebuild(dump: str, out: str | None) -> None:
    """From an already-dumped Themida image: drop Oreans VM sections, compact PE, set OEP.

    Input must be a *runtime dump* (filled .text). Does not decrypt from disk packer.
    """
    from pathlib import Path as P
    from street_decrepytor.protectors.themida_rebuild import strip_packer_sections

    data = P(dump).read_bytes()
    r = strip_packer_sections(data)
    pe = r.pop("pe", None)
    dest = P(out) if out else P(dump).with_name(P(dump).stem + "_stripped.exe")
    if r.get("ok") and pe:
        dest.write_bytes(pe)
        r["written"] = str(dest)
        r["out_size"] = len(pe)
    _print_json(r)


@main.command("batch")
@click.argument("directory", type=click.Path(exists=True, file_okay=False))
@click.option("--out", type=click.Path(), default="output/batch", show_default=True)
@click.option("--glob", "pattern", default="*.exe", show_default=True, help="Glob under directory (also tries .dll).")
def cmd_batch(directory: str, out: str, pattern: str) -> None:
    """Crack every matching binary in a folder (e.g. ANALISTAR dumps)."""
    from street_decrepytor.core.crack import crack_batch

    _print_json(crack_batch(directory, out=out, glob=pattern))


@main.command("cdn-pull")
@click.option("--out", type=click.Path(), default="output/cdn/potassium", show_default=True, help="Where to store CDN JSON + bin/.")
@click.option("--token", default=None, help="Session JWT (Authorization: Bearer). Required for private binary bodies on some builds.")
@click.option("--download/--meta-only", default=False, help="Download MZ binaries after hashes/resource (default: meta-only).")
@click.option("--crack", "auto_crack", is_flag=True, help="After download, run crack (incl. gate re-derive) on bins.")
@click.option("--ip", default=None, help="Force dial IP (skip DoH). SNI still files.potassium.pro.")
@click.option("--files-host", default="files.potassium.pro", show_default=True)
@click.option("--api-host", default="api.potassium.pro", show_default=True)
def cmd_cdn(
    out: str,
    token: str | None,
    download: bool,
    auto_crack: bool,
    ip: str | None,
    files_host: str,
    api_host: str,
) -> None:
    """Pull Potassium product CDN (version/hashes/resource[/binaries]).

    Product-specific: trailing-slash path variants, Bearer auth, DoH resolve
    so Windows hosts pins (127.0.0.1 api/files.potassium.pro) cannot hijack.

    Agent loop:  cdn-pull --download --crack
    """
    from street_decrepytor.potassium.cdn import pull_product_stack

    if auto_crack and not download:
        download = True  # crack implies download
    report = pull_product_stack(
        out,
        token=token,
        files_host=files_host,
        api_host=api_host,
        ip=ip,
        skip_binaries=not download,
        auto_crack=auto_crack,
    )
    _print_json(report)
    if report.get("errors") and not report.get("files"):
        sys.exit(2)


@main.command("classify")
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
def cmd_classify(target: str) -> None:
    """Classify artifact family / arch / protector candidates (fast)."""
    from street_decrepytor.core.artifact import classify_artifact

    _print_json(classify_artifact(target).to_dict())


@main.command("analyze")
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
@click.option("--out", type=click.Path(), default="output", show_default=True)
@click.option("--dynamic", is_flag=True, help="Enable dynamic stages (process scan).")
def cmd_analyze(target: str, out: str, dynamic: bool) -> None:
    """Full static pipeline (+ optional dynamic). Prefer 'crack' for one-shot reports."""
    from street_decrepytor.core.engine import StreetEngine

    eng = StreetEngine(out)
    result = eng.analyze(target, dynamic=dynamic)
    _print_json(result.summary)
    click.echo(f"report: {result.output_dir}/pipeline_result.json")


@main.command("protectors")
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
def cmd_protectors(target: str) -> None:
    """Detect Themida / VMProtect / UPX / .NET obfuscators (behavioral + markers)."""
    from street_decrepytor.core.artifact import classify_artifact
    from street_decrepytor.protectors.detect import detect_protectors

    profile = classify_artifact(target)
    data = Path(target).read_bytes()[: 20 << 20]
    _print_json({"profile": profile.to_dict(), "hits": detect_protectors(data, profile)})


@main.command("junk")
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
def cmd_junk(target: str) -> None:
    """Junk / opaque-predicate / timing density scan (Capstone)."""
    from street_decrepytor.core.artifact import classify_artifact
    from street_decrepytor.static.junk import stage_junk_scan

    profile = classify_artifact(target)
    out = Path("output") / "_junk"
    out.mkdir(parents=True, exist_ok=True)
    _print_json(stage_junk_scan(profile, out))


@main.command("strings")
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
def cmd_strings(target: str) -> None:
    """Interesting strings (URLs, auth, crypto, anti-debug) — noise-filtered."""
    from street_decrepytor.core.artifact import classify_artifact
    from street_decrepytor.static.strings import stage_string_scan

    profile = classify_artifact(target)
    out = Path("output") / "_strings"
    out.mkdir(parents=True, exist_ok=True)
    _print_json(stage_string_scan(profile, out)["interesting"])


@main.command("deobf")
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
@click.option("--out", type=click.Path(), default="output", show_default=True)
def cmd_deobf(target: str, out: str) -> None:
    """Route to language-specific deobf engine (C#/Java/Python/Go/Rust/native)."""
    from street_decrepytor.core.artifact import classify_artifact
    from street_decrepytor.deobf.router import stage_deobf_route

    profile = classify_artifact(target)
    o = Path(out) / "deobf"
    o.mkdir(parents=True, exist_ok=True)
    _print_json(stage_deobf_route(profile, o))


@main.command("frida-script")
@click.option("--family", default="native_pe", show_default=True, help="native_pe|dotnet|python|…")
@click.option("-o", "--output", type=click.Path(), default=None, help="Write JS to file.")
def cmd_frida(family: str, output: str | None) -> None:
    """Emit Frida API-intercept script (no attach)."""
    from street_decrepytor.dynamic.api_intercept import intercept_plan

    plan = intercept_plan(family)
    js = plan["frida_js"]
    if output:
        Path(output).write_text(js, encoding="utf-8")
        click.echo(output)
    else:
        click.echo(js)


@main.command("frida-run")
@click.argument("target")
@click.option("--family", default="native_pe", show_default=True)
@click.option("--spawn", is_flag=True, help="Spawn executable path instead of attach.")
@click.option("--out", type=click.Path(), default="output/frida", show_default=True)
@click.option("--timeout", default=60, show_default=True, help="Seconds before kill.")
def cmd_frida_run(target: str, family: str, spawn: bool, out: str, timeout: int) -> None:
    """Generate hooks and run frida CLI if installed (pid | name | path)."""
    from street_decrepytor.dynamic.frida_run import write_script, run_frida

    out_dir = Path(out)
    script = write_script(family, out_dir / "hooks.js")
    result = run_frida(target, script, spawn=spawn, output_log=out_dir / "frida_run.json", timeout_sec=timeout)
    _print_json({"script": str(script), "run": result})


@main.command("memscan")
@click.argument("pid", type=int)
@click.option("--needle", multiple=True, help="Hex or ascii needle; repeatable.")
def cmd_memscan(pid: int, needle: tuple[str, ...]) -> None:
    """Scan live process memory for needles (Windows)."""
    from street_decrepytor.dynamic.memory import scan_process_memory

    needles: list[bytes] = []
    for n in needle or ("MZ",):
        try:
            needles.append(bytes.fromhex(n))
        except ValueError:
            needles.append(n.encode("utf-8"))
    _print_json(scan_process_memory(pid, needles))


@main.command("peb-patch")
@click.argument("pid", type=int)
def cmd_peb(pid: int) -> None:
    """Clear PEB.BeingDebugged in target process (Windows, best-effort)."""
    from street_decrepytor.dynamic.antidebug import patch_peb_being_debugged

    _print_json(patch_peb_being_debugged(pid))


@main.command("pe-dump")
@click.argument("pid", type=int)
@click.option("--module", default=None, help="Module name (default: main EXE).")
@click.option("--out", type=click.Path(), default="output/dumps/module.bin", show_default=True)
@click.option("--fix-pe/--no-fix-pe", default=True, show_default=True, help="Rewrite section raw=VA for loadable PE.")
@click.option("--iat/--no-iat", default=True, show_default=True, help="Live IAT resolve against process modules.")
@click.option("--all-modules", is_flag=True, help="Dump every loaded module into out dir.")
def cmd_pe_dump(
    pid: int,
    module: str | None,
    out: str,
    fix_pe: bool,
    iat: bool,
    all_modules: bool,
) -> None:
    """Dump live process module(s) — Themida post-unpack primary tool.

    After packer decrypts in memory: pe-dump <pid> --fix-pe --iat
    """
    from street_decrepytor.dynamic.pe_dump import dump_process_module, dump_all_modules

    if all_modules:
        _print_json(dump_all_modules(pid, Path(out), fix_pe=fix_pe))
    else:
        _print_json(dump_process_module(pid, module, Path(out), fix_pe=fix_pe, rebuild_iat=iat))


@main.command("dump")
@click.option("--pid", type=int, default=None, help="Existing process id.")
@click.option("--name", "proc_name", default=None, help="Find process by image name (e.g. DFIR.exe).")
@click.option("--spawn", "spawn_path", type=click.Path(exists=True, dir_okay=False), default=None, help="Spawn EXE then dump after wait.")
@click.option("--wait", default=8.0, show_default=True, help="Timeout seconds after spawn.")
@click.option("--wait-mode", type=click.Choice(["text", "sleep"]), default="text", show_default=True, help="text=poll .text RPM; sleep=timer only.")
@click.option("--out", type=click.Path(), default="output/dumps", show_default=True)
@click.option("--vad", is_flag=True, help="Also dump committed VAD regions.")
@click.option("--all-modules", is_flag=True, help="Dump all modules.")
@click.option("--fix-pe/--no-fix-pe", default=True, show_default=True)
@click.option("--iat/--no-iat", default=True, show_default=True)
@click.option("--kill/--no-kill", default=True, show_default=True, help="Terminate spawned process after dump.")
@click.option("--frida-script", "write_frida", is_flag=True, help="Write Frida dump-on-VirtualProtect script to out.")
def cmd_dump(
    pid: int | None,
    proc_name: str | None,
    spawn_path: str | None,
    wait: float,
    wait_mode: str,
    out: str,
    vad: bool,
    all_modules: bool,
    fix_pe: bool,
    iat: bool,
    kill: bool,
    write_frida: bool,
) -> None:
    """Unified memory dump for packers (Themida-class) and live analysis.

    Modes:
      dump --spawn target.exe --wait 10 --vad
      dump --name FarmServices.exe --vad
      dump --pid 1234 --fix-pe --iat
      dump --spawn target.exe --frida-script
    """
    from street_decrepytor.dynamic.pe_dump import (
        dump_process_module,
        dump_all_modules,
        dump_vad_regions,
        spawn_wait_dump,
        find_pids_by_name,
        frida_dump_on_oep_script,
        list_process_modules,
    )

    outp = Path(out)
    outp.mkdir(parents=True, exist_ok=True)
    report: dict = {"out": str(outp)}

    if write_frida:
        js_path = outp / "dump_on_vp.js"
        js_path.write_text(frida_dump_on_oep_script(), encoding="utf-8")
        report["frida_script"] = str(js_path)

    if spawn_path:
        r = spawn_wait_dump(
            spawn_path,
            outp / "spawn",
            wait_sec=wait,
            fix_pe=fix_pe,
            vad=vad or all_modules,
            kill_after=kill,
            wait_mode=wait_mode,
        )
        report["spawn"] = r
        _print_json(report)
        return

    if proc_name and pid is None:
        pids = find_pids_by_name(proc_name)
        if not pids:
            _print_json({"ok": False, "error": f"no process matching {proc_name}"})
            sys.exit(2)
        pid = pids[0]
        report["matched_pids"] = pids
        report["using_pid"] = pid

    if pid is None:
        raise click.UsageError("provide --pid, --name, or --spawn")

    report["modules"] = list_process_modules(pid)[:30]
    report["main"] = dump_process_module(
        pid,
        None,
        outp / "main_module.exe",
        fix_pe=fix_pe,
        rebuild_iat=iat,
    )
    if all_modules:
        report["all_modules"] = dump_all_modules(pid, outp / "modules", fix_pe=False)
    if vad:
        report["vad"] = dump_vad_regions(pid, outp / "vad")
    _print_json(report)


@main.command("syscall-map")
@click.option("--ntdll", type=click.Path(exists=True), default=None, help="Path to ntdll.dll.")
@click.option("--out", type=click.Path(), default="output/syscalls", show_default=True)
def cmd_syscall(ntdll: str | None, out: str) -> None:
    """Harvest ntdll Nt/Zw syscall numbers for THIS Windows build."""
    from street_decrepytor.dynamic.syscall_trace import harvest_ntdll_syscalls, frida_syscall_script

    report = harvest_ntdll_syscalls(ntdll)
    outp = Path(out)
    outp.mkdir(parents=True, exist_ok=True)
    (outp / "syscall_map.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    if report.get("interesting"):
        (outp / "nt_hooks.js").write_text(frida_syscall_script(report["interesting"]), encoding="utf-8")
    _print_json({"ok": report.get("ok"), "count": report.get("syscall_count"), "out": str(outp)})


@main.command("cfg")
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
@click.option("--out", type=click.Path(), default=None)
def cmd_cfg(target: str, out: str | None) -> None:
    """Inventory CFG/trampoline obfuscation (lea+jmp → dispatcher) and recover lea targets."""
    from street_decrepytor.deobf.cfg_obfuscation import analyze_cfg

    info = analyze_cfg(target)
    if out:
        Path(out).mkdir(parents=True, exist_ok=True)
        (Path(out) / "cfg_obfuscation.json").write_text(json.dumps(info, indent=2), encoding="utf-8")
        info["written"] = str(Path(out) / "cfg_obfuscation.json")
    _print_json(info)


@main.command("stub-db")
@click.option("--out", type=click.Path(), default=None, help="Default: data/stub_db/")
def cmd_stub_db(out: str | None) -> None:
    """R2.1 — build pristine Nt* stub hash DB for this Windows build."""
    from street_decrepytor.runtime.stub_integrity import build_stub_db

    _print_json(build_stub_db(out))


@main.command("stub-integrity")
@click.option("--pid", type=int, required=True)
@click.option("--shots", default=3, show_default=True)
@click.option("--db", type=click.Path(exists=True), default=None)
def cmd_stub_integrity(pid: int, shots: int, db: str | None) -> None:
    """R2 — multi-shot live stub hash validate vs pristine DB."""
    from street_decrepytor.runtime.stub_integrity import validate_stubs_live

    _print_json(validate_stubs_live(pid, shots=shots, db_path=db))


@main.command("observe-syscalls")
@click.option("--pid", type=int, required=True)
def cmd_observe_syscalls(pid: int) -> None:
    """R1 — syscall observatory: live ntdll stubs vs disk + hook destinations."""
    from street_decrepytor.runtime.syscall_observatory import observe_syscalls

    _print_json(observe_syscalls(pid))


@main.command("peb-probe")
@click.option("--pid", type=int, required=True)
def cmd_peb_probe(pid: int) -> None:
    """R3 — PEB deception dual-read (API vs raw RPM). Clean ≠ safe."""
    from street_decrepytor.runtime.peb_deception import probe_peb

    _print_json(probe_peb(pid))


@main.command("themida-phylo")
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
@click.option("--pid", type=int, default=None, help="Optional live PID for RWX VAD sample.")
def cmd_themida_phylo(target: str, pid: int | None) -> None:
    """R4 — phylogenetic / structural Themida signals (probabilistic)."""
    from street_decrepytor.runtime.themida_phylo import themida_phylo

    _print_json(themida_phylo(target, pid=pid))


@main.command("validate")
@click.argument("target", type=click.Path(exists=True, dir_okay=False), required=False, default=None)
@click.option("--pid", type=int, default=None, help="Live process for R1/R2/R3.")
@click.option("--spawn", is_flag=True, help="Spawn target, probe live, dump, kill.")
@click.option("--wait", default=8.0, show_default=True, help="Unpack wait when --spawn.")
@click.option("--out", type=click.Path(), default="output/runtime/validate", show_default=True)
@click.option("--skip-hooks", is_flag=True, help="Skip R1/R2 (faster).")
def cmd_validate(
    target: str | None,
    pid: int | None,
    spawn: bool,
    wait: float,
    out: str,
    skip_hooks: bool,
) -> None:
    """R5 — composite runtime validate (S0/S1/S2 + pillars). Always probabilistic."""
    from street_decrepytor.runtime.composite import validate_target

    if not target and not pid:
        raise click.UsageError("provide TARGET and/or --pid (use --spawn with TARGET)")
    rep = validate_target(
        target,
        pid=pid,
        spawn=spawn,
        wait_sec=wait,
        out_dir=out,
        skip_hooks=skip_hooks,
    )
    _print_json({
        "composite_score": rep.get("composite_score"),
        "confidence": rep.get("confidence"),
        "layers": rep.get("layers"),
        "pillars": {
            k: {"score": v.get("score"), "confidence": v.get("confidence"),
                "flags": [f.get("flag") for f in (v.get("findings") or [])],
                "skipped": v.get("skipped")}
            for k, v in (rep.get("pillars") or {}).items()
        },
        "error_margins_head": (rep.get("error_margins") or [])[:12],
        "disclaimer": rep.get("disclaimer"),
        "manual_cross_check_required": rep.get("manual_cross_check_required"),
        "report_md": rep.get("report_md"),
        "out_dir": rep.get("out_dir"),
        "states": {k: {sk: sv for sk, sv in (v.items() if isinstance(v, dict) else []) if sk != "profile"}
                   for k, v in (rep.get("states") or {}).items()},
    })


@main.command("disasm")
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
@click.option("--out", type=click.Path(), default=None, help="Write listing.txt + disasm.json")
@click.option("--rva", default=None, help="Start RVA (hex), default=.text")
@click.option("--size", type=int, default=None, help="Byte length when using --rva")
@click.option("--max-insns", default=50000, show_default=True)
@click.option("--linear", is_flag=True, help="Linear sweep only (no recursive descent)")
@click.option("--listing-only", is_flag=True, help="Print text listing to stdout")
def cmd_disasm(
    target: str,
    out: str | None,
    rva: str | None,
    size: int | None,
    max_insns: int,
    linear: bool,
    listing_only: bool,
) -> None:
    """Capstone disassembler — recursive CFG + functions + xrefs (StreetDbg backend)."""
    from street_decrepytor.disasm.engine import disassemble_pe

    rva_i = int(rva, 0) if rva else None
    result = disassemble_pe(
        target,
        recursive=not linear,
        max_insns=max_insns,
        rva=rva_i,
        size=size,
    )
    if listing_only:
        click.echo(result.to_listing(max_insns=min(max_insns, 5000)))
        return
    payload = result.to_dict()
    # trim huge instruction arrays in stdout summary
    summary = {
        "arch": payload["arch"],
        "mode": payload["mode"],
        "base": payload["base"],
        "insn_count": payload["insn_count"],
        "functions": len(payload["functions"]),
        "xrefs": len(payload["xrefs"]),
        "errors": payload["errors"],
        "listing_head": result.to_listing(max_insns=40).splitlines(),
    }
    if out:
        outp = Path(out)
        outp.mkdir(parents=True, exist_ok=True)
        (outp / "disasm.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
        (outp / "listing.txt").write_text(result.to_listing(), encoding="utf-8")
        (outp / "functions.json").write_text(json.dumps(payload["functions"], indent=2), encoding="utf-8")
        summary["out"] = str(outp)
    _print_json(summary)


@main.command("dbg-server")
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=39847, show_default=True)
def cmd_dbg_server(host: str, port: int) -> None:
    """JSON disasm API for StreetDbg.exe (x64dbg-style UI). Blocking."""
    from street_decrepytor.disasm.server import main_blocking

    main_blocking(host, port)


@main.command("scyllahide-export")
@click.option("--out", type=click.Path(), default="output/scyllahide", show_default=True)
def cmd_scylla(out: str) -> None:
    """Write ScyllaHide INI profile + usage notes."""
    from street_decrepytor.dynamic.scyllahide_profile import export_scyllahide_profile

    _print_json(export_scyllahide_profile(out))


@main.command("simd-emu")
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
@click.option("--max-funcs", default=40, show_default=True)
@click.option("--funcs-list", type=click.Path(exists=True, dir_okay=False), default=None)
@click.option("--out", type=click.Path(), default="output/simd", show_default=True)
def cmd_simd(target: str, max_funcs: int, funcs_list: str | None, out: str) -> None:
    """SIMD-XOR string emulator (Potassium-class native decryptors)."""
    from street_decrepytor.crypto.simd_emu import run_simd_emu_on_pe

    report = run_simd_emu_on_pe(target, max_funcs=max_funcs, funcs_list=funcs_list)
    outp = Path(out)
    outp.mkdir(parents=True, exist_ok=True)
    (outp / "simd_emu.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    _print_json({
        "unique_strings": report.get("unique_strings"),
        "functions_emulated": report.get("functions_emulated"),
        "sample": [s["str"] for s in report.get("strings_sample", [])[:20]],
        "out": str(outp / "simd_emu.json"),
    })


@main.command("stub-decrypt")
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
@click.option("--stub-file-off", type=lambda v: int(v, 0), required=True,
              help="File-Offset des dw-Stub (.rsrc-Bereich). Aus rsrc_stub_decryptor-Hit ableitbar.")
@click.option("--stub-rva", type=lambda v: int(v, 0), required=True,
              help="RVA des Stub (fuer lea-ziel-berechnung).")
@click.option("--out", type=click.Path(), default=None,
              help="Output-Blob (default: output/stub_decrypt/<stem>_decrypted.bin)")
def cmd_stub_decrypt(target: str, stub_file_off: int, stub_rva: int, out: str | None) -> None:
    """Offline-dw-Stub-Entschluessler (Cs2-External-Klasse).

    Extrahiert die polymorphe add/sub/xor/not dword-Transform-Sequenz aus
    dem .rsrc-Stub, liest die Loop-Geometrie (lea-ziel, blocksize, limit)
    und entschluesselt die Region offline — ohne Prozessstart.
    Verifiziert am target-v2 (448 KB Container, RAM-Vergleich bestanden).
    """
    from street_decrepytor.crypto.stub_decrypt import find_and_decrypt

    data = Path(target).read_bytes()
    try:
        layout, decrypted = find_and_decrypt(data, stub_file_off, stub_rva)
    except ValueError as e:
        _print_json({"error": str(e)})
        return

    if out is None:
        stem = Path(target).stem.replace(" ", "_")
        outp = Path("output/stub_decrypt")
        outp.mkdir(parents=True, exist_ok=True)
        out = str(outp / f"{stem}_decrypted.bin")

    Path(out).write_bytes(decrypted)
    _print_json({
        "ops_extracted": len(layout.ops),
        "key_region_file_off": hex(layout.key_region_file_off),
        "lea_rip_displacement": hex(layout.lea_rip_displacement),
        "block_size": hex(layout.block_size),
        "total_size": hex(layout.total_size),
        "decrypted_size": len(decrypted),
        "out": out,
        "note": "dw-arithmetische offline-entschluesselung — kein prozessstart, "
                "kein cipher-claim (L2: transform = invers anwendbar)",
    })


@main.command("hash-crack")
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
@click.option("--scan", is_flag=True, default=False,
              help="Scan the whole file for imm32 compare constants and crack each (slow).")
@click.option("--hex", "hexvals", multiple=True, default=None,
              help="Explicit hash values to crack, e.g. --hex 0x6e2bca17.")
@click.option("--extra-names", type=click.Path(exists=True, dir_okay=False), default=None,
              help="File with one candidate name per line.")
def cmd_hash_crack(target: str, scan: bool, hexvals: tuple[str, ...], extra_names: str | None) -> None:
    """ROL-19 additive hash cracker (Cs2-External class PEB walkers).

    Cracks PEB->Ldr API hashes of the form  h = rol(h,19) + c  against a
    database of common DLL/API names (utf16 / ascii / ascii-lower forms).
    Discovered on target-v2 Cs2-External (a94f6513...): 0x6E2BCA17 =
    KERNEL32.DLL, 0x8A8B4676 = LoadLibraryA.
    """
    from street_decrepytor.crypto.api_hash import crack, crack_many

    extra: list[str] | None = None
    if extra_names:
        extra = [l.strip() for l in Path(extra_names).read_text(encoding="utf-8").splitlines() if l.strip()]

    results: dict[int, list] = {}
    if hexvals:
        targets = []
        for h in hexvals:
            try:
                targets.append(int(h, 0))
            except ValueError:
                continue
        results = crack_many(targets, extra)
    elif scan:
        data = Path(target).read_bytes()
        consts: set[int] = set()
        i = 0
        n = len(data)
        while i < n - 6:
            b = data[i]
            if b == 0x3D:
                v = int.from_bytes(data[i+1:i+5], "little")
                if 0x10000 < v < 0xFFFFFFFF:
                    consts.add(v)
                i += 5
            elif b == 0x81 and 0xF8 <= data[i+1] <= 0xFF:
                v = int.from_bytes(data[i+2:i+6], "little")
                if 0x10000 < v < 0xFFFFFFFF:
                    consts.add(v)
                i += 6
            else:
                i += 1
        results = crack_many(sorted(consts), extra)
    else:
        _print_json({"error": "provide --scan or --hex VALUES"})
        return

    out = {f"{k:#010x}": v for k, v in results.items()}
    cracked = {k: v for k, v in out.items() if v}
    _print_json({
        "targets_tested": len(out),
        "cracked": cracked,
        "note": "rol19-additive hash (utf16/ascii/ascii-lower) — Cs2-External class",
    })


@main.command("dotnet-analyze")
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
def cmd_dotnet(target: str) -> None:
    """CLR / ConfuserEx-class bridge + Module.cctor dump recipe."""
    from street_decrepytor.deobf.csharp.dnfile_bridge import analyze_dotnet_assembly

    _print_json(analyze_dotnet_assembly(target))


@main.command("potassium")
@click.option("--root", type=click.Path(), default=None, help="Override search root.")
@click.option("--out", type=click.Path(), default="output/potassium", show_default=True)
def cmd_potassium(root: str | None, out: str) -> None:
    """Official Potassium multi-artifact case study + scorecard B1–B6."""
    from street_decrepytor.potassium.case import run_potassium_case

    _print_json(run_potassium_case(root=root, out_dir=out))


@main.command("capture-child")
@click.option("--out", type=click.Path(), default="output/potassium/child", show_default=True)
def cmd_capture_child(out: str) -> None:
    """Scan disk for official Potassium child PE; write capture procedure if missing."""
    from street_decrepytor.potassium.capture_child import write_capture_status

    _print_json(write_capture_status(out))


@main.command("pipeline")
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
@click.option("--out", type=click.Path(), default="output", show_default=True)
@click.option("--dynamic", is_flag=True)
def cmd_pipeline(target: str, out: str, dynamic: bool) -> None:
    """Alias of analyze."""
    ctx = click.get_current_context()
    ctx.invoke(cmd_analyze, target=target, out=out, dynamic=dynamic)


@main.command("gates-apply")
@click.argument("dll", type=click.Path(exists=True, dir_okay=False))
@click.option("--out", type=click.Path(), required=True, help="Output cracked DLL path.")
@click.option("--table", type=click.Path(exists=True), default=None, help="dll_gates_sigs.json path.")
@click.option("--legacy", is_flag=True, help="Exact file-offset apply only (old build).")
def cmd_gates(dll: str, out: str, table: str | None, legacy: bool) -> None:
    """Re-derive + apply Potassium gate table on a DLL (new builds use wildcard context)."""
    if legacy:
        from street_decrepytor.potassium.gates import apply_gate_table

        _print_json(apply_gate_table(dll, out, table))
    else:
        from street_decrepytor.potassium.recrack import recrack_dll

        _print_json(recrack_dll(dll, out=out, table_path=table))


@main.command("recrack")
@click.argument("dll", type=click.Path(exists=True, dir_okay=False))
@click.option("--out", type=click.Path(), default=None, help="Default: <dll>_recracked.dll")
@click.option("--table", type=click.Path(exists=True), default=None)
@click.option("--dry", is_flag=True, help="Scan only, do not write.")
def cmd_recrack(dll: str, out: str | None, table: str | None, dry: bool) -> None:
    """Re-derive 52-gate patches on a NEW Potassium.dll build (cross-version)."""
    from street_decrepytor.potassium.recrack import recrack_dll

    _print_json(recrack_dll(dll, out=out, table_path=table, dry=dry))


@main.command("agent")
@click.argument("target", required=False, default=None)
@click.option("--cdn", is_flag=True, help="Also pull Potassium CDN + crack downloads.")
@click.option("--batch-dir", type=click.Path(exists=True, file_okay=False), default=None)
@click.option("--out", type=click.Path(), default="output/agent", show_default=True)
@click.option("--token", default=None, help="CDN JWT if needed.")
def cmd_agent(target: str | None, cdn: bool, batch_dir: str | None, out: str, token: str | None) -> None:
    """One entry for AI agents: crack target and/or CDN and/or batch folder.

    Examples:
      street-decrepytor agent sample.exe
      street-decrepytor agent --cdn --out output\\agent
      street-decrepytor agent --batch-dir C:\\Users\\ggles\\Downloads\\ANALISTAR
      street-decrepytor agent FarmServices.exe --cdn
    """
    from street_decrepytor.core.crack import crack_target, crack_batch

    summary: dict = {"out": out, "steps": []}
    outp = Path(out)
    outp.mkdir(parents=True, exist_ok=True)

    if target:
        r = crack_target(target, out=outp / "target")
        summary["steps"].append({"crack": target, "verdict": r.get("verdict"), "report": r.get("report_md")})

    if batch_dir:
        b = crack_batch(batch_dir, out=outp / "batch", glob="*.exe")
        summary["steps"].append({"batch": b})

    if cdn:
        from street_decrepytor.potassium.cdn import pull_product_stack

        c = pull_product_stack(
            outp / "cdn",
            token=token,
            skip_binaries=False,
            auto_crack=True,
        )
        summary["steps"].append({
            "cdn": {
                "version": c.get("version_name"),
                "files": list((c.get("files") or {}).keys()),
                "errors": c.get("errors"),
                "auto_crack": [
                    {"t": x.get("target"), "v": (x.get("verdict") or {}).get("family"), "err": x.get("errors")}
                    for x in (c.get("auto_crack") or [])
                ],
            }
        })

    if not target and not batch_dir and not cdn:
        raise click.UsageError("pass TARGET and/or --cdn and/or --batch-dir")

    (outp / "agent_summary.json").write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    _print_json(summary)


if __name__ == "__main__":
    from street_decrepytor.cli.cmd_groups import register_groups

    if "static" not in main.commands:
        register_groups(main)
    main()
