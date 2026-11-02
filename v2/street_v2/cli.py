# language: Python 3.11+, file: cli.py
# street-v2 CLI — full v1 verb surface + better analyze/crack/live/IDA/entropy
from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from street_v2.compat import import_v1


def _out(obj: object) -> None:
    click.echo(json.dumps(obj, indent=2, default=str))


class AgentGroup(click.Group):
    def format_help(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        super().format_help(ctx, formatter)
        formatter.write_paragraph()
        formatter.write_text("v2 adds live IDA-like views, entropy islands, crypto-system reports, Unicorn.")
        formatter.write_text("All v1 verbs (unpack/dump/recrack/…) are forwarded. CRITICAL.md still applies.")
        formatter.write_text(
            "  python -m street_v2 analyze TARGET.exe --out output\\run --unpack\n"
            "  python -m street_v2 crack TARGET.exe --unpack\n"
            "  python -m street_v2 live TARGET.exe --interval 2\n"
            "  python -m street_v2 serve --open TARGET.exe\n"
            "  python -m street_v2 unpack TARGET.exe --live\n"
            "  python -m street_v2 dump --spawn TARGET.exe --wait 12 --vad --fix-pe --iat"
        )


@click.group(
    cls=AgentGroup,
    context_settings={"help_option_names": ["-h", "--help"], "max_content_width": 110},
)
@click.version_option("2.2.0", prog_name="street-v2")
@click.option("--verbose", "-v", is_flag=True, help="Verbose errors to stderr.")
@click.pass_context
def main(ctx: click.Context, verbose: bool) -> None:
    """Street-decrepytor v2 — v1 pipeline + live IDA / entropy / crypto reports / Unicorn.

    Does not decrypt Themida/VMProtect. See parent CRITICAL.md.
    """
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    import_v1()


@main.command("analyze")
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
@click.option("--out", "out_dir", default=None, help="Default: output/<stem>_v2")
@click.option("--dynamic", is_flag=True, help="Enable v1 live process-scan stage.")
@click.option("--unpack", "do_unpack", is_flag=True, help="Also run honest unpack/resource extract.")
@click.option("--emu/--no-emu", default=True, show_default=True)
@click.option("--disasm/--no-disasm", default=True, show_default=True)
@click.option("--harvest/--no-harvest", default=True, show_default=True, help="Dump every section/overlay/resource/carve + decrypt pass.")
@click.option("--max-disasm", default=60000, show_default=True)
@click.option("--max-emu", default=20000, show_default=True)
def analyze_cmd(
    target: str,
    out_dir: str | None,
    dynamic: bool,
    do_unpack: bool,
    emu: bool,
    disasm: bool,
    harvest: bool,
    max_disasm: int,
    max_emu: int,
) -> None:
    """Full v1 pipeline + harvest everything + XOR/RC4/zlib decrypt + IDA/Unicorn."""
    from street_v2.engine import StreetEngineV2

    eng = StreetEngineV2(Path(out_dir).parent if out_dir else "output")
    r = eng.analyze(
        target,
        dynamic=dynamic,
        unpack=do_unpack,
        emu=emu,
        disasm=disasm,
        harvest=harvest,
        max_insns_disasm=max_disasm,
        max_insns_emu=max_emu,
        out=out_dir,
    )
    _out({
        "ok": True,
        "family": (r.get("profile") or {}).get("family"),
        "arch": (r.get("profile") or {}).get("arch"),
        "v1_stages": (r.get("v1") or {}).get("summary"),
        "primary": (r.get("crypto") or {}).get("primary"),
        "playbook": (r.get("crypto") or {}).get("playbook"),
        "high_entropy_ratio": (r.get("entropy") or {}).get("high_ratio"),
        "harvest": r.get("harvest"),
        "decrypt": r.get("decrypt"),
        "ida": r.get("ida"),
        "emu_ok": (r.get("emu") or {}).get("ok") if r.get("emu") else None,
        "decrypted": r.get("decrypted"),
        "image_transforms": r.get("image_transforms"),
        "elapsed_sec": r.get("elapsed_sec"),
        "report_md": r.get("report_md"),
        "out_dir": r.get("out_dir"),
    })
    click.echo(f"report: {r.get('report_md')}", err=True)


@main.command("pipeline")
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
@click.option("--out", "out_dir", default=None)
@click.option("--dynamic", is_flag=True)
@click.option("--unpack", "do_unpack", is_flag=True)
def pipeline_cmd(target: str, out_dir: str | None, dynamic: bool, do_unpack: bool) -> None:
    """Alias of analyze (v2 full pass)."""
    ctx = click.get_current_context()
    ctx.invoke(
        analyze_cmd,
        target=target,
        out_dir=out_dir,
        dynamic=dynamic,
        do_unpack=do_unpack,
        emu=True,
        disasm=True,
        harvest=True,
        max_disasm=60000,
        max_emu=20000,
    )


@main.command("crack")
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
@click.option("--out", type=click.Path(), default="output/crack", show_default=True)
@click.option("--dynamic", is_flag=True)
@click.option("--no-simd", is_flag=True)
@click.option("--gates", is_flag=True, help="Potassium recrack only if filename contains potassium.")
@click.option("--unpack/--no-unpack", "do_unpack", default=True, show_default=True)
@click.option("--emu/--no-emu", default=True, show_default=True)
def crack_cmd(
    target: str,
    out: str,
    dynamic: bool,
    no_simd: bool,
    gates: bool,
    do_unpack: bool,
    emu: bool,
) -> None:
    """v1 crack report + v2 ALL_ANALYSIS (entropy / crypto playbook / IDA / emu)."""
    from street_v2.engine import StreetEngineV2

    eng = StreetEngineV2(out)
    r = eng.crack(
        target,
        out=Path(out) / Path(target).stem,
        dynamic=dynamic,
        unpack=do_unpack,
        emu=emu,
        no_simd=no_simd,
        gates=gates,
    )
    _out({
        "verdict": (r.get("v1_crack") or {}).get("verdict"),
        "crypto": (r.get("v2") or {}).get("crypto"),
        "ida": (r.get("v2") or {}).get("ida"),
        "decrypted": r.get("decrypted"),
        "report_md": r.get("report_md"),
        "v1_report_md": (r.get("v1_crack") or {}).get("report_md"),
        "out_dir": r.get("out_dir"),
    })
    click.echo(f"report: {r.get('report_md')}", err=True)


@main.command("live")
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
@click.option("--out", "out_dir", default=None)
@click.option("--interval", default=2.0, show_default=True)
@click.option("--emu/--no-emu", default=True)
@click.option("--full/--fast", default=False, help="full=re-run v1 pipeline each refresh (slow).")
@click.option("--seconds", default=0, help="run N seconds then exit (0=until Ctrl+C)")
def live_cmd(
    target: str,
    out_dir: str | None,
    interval: float,
    emu: bool,
    full: bool,
    seconds: float,
) -> None:
    """Watch file + re-analyze (IDA-like frequent updates). Default: fast v2 layers only."""
    import time

    from street_v2.live.session import LiveSession

    out = out_dir or str(Path("output") / (Path(target).stem + "_v2_live"))
    sess = LiveSession(target, out_dir=out, interval_sec=interval, run_emu=emu, run_v1=full)

    def on_snap(snap):
        click.echo(
            f"[gen={snap.generation}] family={(snap.v1_profile or {}).get('family')} "
            f"primary={(snap.crypto or {}).get('primary')} "
            f"insns={(snap.ida or {}).get('insn_count')} "
            f"Hratio={(snap.entropy or {}).get('high_ratio')}",
            err=True,
        )

    sess.add_listener(on_snap)
    sess.start_watch()
    _out({"ok": True, "watching": True, "status": sess.status()})
    try:
        if seconds and seconds > 0:
            time.sleep(seconds)
        else:
            while True:
                time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        sess.stop_watch()
        _out({"ok": True, "stopped": True, "status": sess.status()})


@main.command("serve")
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=39848, show_default=True)
@click.option("--open", "open_path", default=None)
@click.option("--interval", default=2.0, show_default=True)
def serve_cmd(host: str, port: int, open_path: str | None, interval: float) -> None:
    """HTTP API — IDA-like listing/functions/xrefs + live refresh (v2)."""
    from street_v2.live.session import LiveSession
    from street_v2.server.api import HUB, main_blocking

    import_v1()
    if open_path:
        HUB.session = LiveSession(open_path, interval_sec=interval)
        HUB.session.refresh(force=True)
        HUB.session.start_watch()
    main_blocking(host, port)


@main.command("harvest")
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
@click.option("--out", "out_dir", default=None)
@click.option("--decrypt/--no-decrypt", default=True, show_default=True)
def harvest_cmd(target: str, out_dir: str | None, decrypt: bool) -> None:
    """Dump every section, overlay, resource, nested PE, magic, island, string — then decrypt pass."""
    from street_v2.crypto.decrypt import decrypt_harvest
    from street_v2.entropy.analyzer import analyze_entropy
    from street_v2.extract.harvest import harvest_file
    from street_v2.pe.loader import load_pe

    out = Path(out_dir or Path("output") / (Path(target).stem + "_harvest"))
    pe = None
    ent = None
    try:
        pe = load_pe(target)
        ent = analyze_entropy(pe)
    except Exception:
        pe = None
    h = harvest_file(target, out, pe=pe, ent=ent)
    d = None
    if decrypt:
        text = pe.text_blob()[0] if pe else b""
        interesting: list[str] = []
        sp = out / "strings" / "strings_interesting.txt"
        if sp.is_file():
            interesting = sp.read_text(encoding="utf-8", errors="replace").splitlines()[:200]
        d = decrypt_harvest(h, out / "decrypt", pe_text=text, strings=interesting)
    _out({
        "ok": True,
        "counts": h.get("counts"),
        "overlay": h.get("overlay"),
        "pyinstaller": h.get("pyinstaller"),
        "decrypt": {
            "hit_count": (d or {}).get("hit_count"),
            "hits": (d or {}).get("hits"),
            "decrypted": (d or {}).get("decrypted"),
        } if d else None,
        "out": str(out),
    })


@main.command("decrypt")
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
@click.option("--out", "out_dir", default=None)
def decrypt_cmd(target: str, out_dir: str | None) -> None:
    """Harvest then XOR/RC4/zlib/magic-anchor decrypt. Writes hits only on real cipher."""
    ctx = click.get_current_context()
    ctx.invoke(harvest_cmd, target=target, out_dir=out_dir, decrypt=True)


@main.command("xref")
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
@click.option("--out", "out_path", default=None)
@click.option("--type", "xtype", default=None, help="code|data|str|xor|crypto")
@click.option("--max-insns", default=40000, show_default=True)
def xref_cmd(target: str, out_path: str | None, xtype: str | None, max_insns: int) -> None:
    """IDA-like xrefs: calls/jmps, data, strings, xor imm, AES-NI/pxor sites."""
    from street_v2.live.ida_like import build_ida_view
    from street_v2.pe.loader import load_pe

    pe = load_pe(target)
    view = build_ida_view(pe, recursive=True, max_insns=max_insns)
    rep = view.xref_report or {}
    if xtype:
        payload = {"type": xtype, "items": (rep.get({"str": "string"}.get(xtype, xtype)) or [])[:400]}
    else:
        payload = {"counts": rep.get("counts"), "xor_keys_hex": rep.get("xor_keys_hex"),
                   "xor_head": (rep.get("xor") or [])[:30],
                   "crypto_head": (rep.get("crypto") or [])[:30],
                   "string_head": (rep.get("string") or [])[:20]}
    if out_path:
        Path(out_path).write_text(json.dumps(rep, indent=2), encoding="utf-8")
        payload["out"] = out_path
    _out(payload)


@main.command("entropy")
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
@click.option("--window", default=4096, show_default=True)
def entropy_cmd(target: str, window: int) -> None:
    """v2 sliding-window Shannon + islands (better than v1 64KB blocks)."""
    from street_v2.entropy.analyzer import analyze_entropy
    from street_v2.pe.loader import load_pe

    pe = load_pe(target)
    _out(analyze_entropy(pe, window=window).to_dict())


@main.command("crypto")
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
@click.option("--out", "out_dir", default=None)
def crypto_cmd(target: str, out_dir: str | None) -> None:
    """Detect crypto/protector system and write automated playbook report."""
    from street_v2.crypto.detector import detect_crypto_system
    from street_v2.crypto.report_gen import generate_crypto_report
    from street_v2.entropy.analyzer import analyze_entropy
    from street_v2.pe.loader import load_pe

    pe = load_pe(target)
    ent = analyze_entropy(pe)
    crypto = detect_crypto_system(pe, ent)
    out = out_dir or str(Path("output") / (Path(target).stem + "_crypto"))
    report = generate_crypto_report(pe, crypto, ent, out)
    _out({"crypto": crypto.to_dict(), "report": report})


@main.command("emu")
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
@click.option("--start", "start_va", default=None)
@click.option("--max-insns", default=20000, show_default=True)
@click.option("--out", "out_dir", default=None)
@click.option("--simd", is_flag=True, help="Also run v1 simd-emu (string XOR) if .text exists.")
def emu_cmd(target: str, start_va: str | None, max_insns: int, out_dir: str | None, simd: bool) -> None:
    """Unicorn trace (v2) + optional v1 SIMD string emu."""
    from street_v2.emu.unicorn_engine import emulate_pe_entry, emulate_range
    from street_v2.pe.loader import load_pe

    pe = load_pe(target)
    if start_va:
        res = emulate_range(pe, int(start_va, 0), max_insns=max_insns)
    else:
        res = emulate_pe_entry(pe, max_insns=max_insns)
    payload = {"unicorn": res.to_dict()}
    if simd:
        import_v1()
        from street_decrepytor.crypto.simd_emu import run_simd_emu_on_pe

        payload["simd"] = run_simd_emu_on_pe(target, max_funcs=40)
    if out_dir:
        p = Path(out_dir)
        p.mkdir(parents=True, exist_ok=True)
        (p / "emu_trace.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
        payload["out"] = str(p / "emu_trace.json")
    _out(payload)


@main.command("disasm")
@click.argument("target", type=click.Path(exists=True, dir_okay=False))
@click.option("--out", "out_path", default=None, help="Write ida_view.json (+ listing.txt if dir)")
@click.option("--rva", default=None, help="Start RVA (hex)")
@click.option("--max-insns", default=60000, show_default=True)
@click.option("--linear", is_flag=True)
@click.option("--listing-only", is_flag=True)
def disasm_cmd(
    target: str,
    out_path: str | None,
    rva: str | None,
    max_insns: int,
    linear: bool,
    listing_only: bool,
) -> None:
    """IDA-like Capstone RD (v2) — functions, xrefs, CFG."""
    from street_v2.live.ida_like import build_ida_view
    from street_v2.pe.loader import load_pe

    pe = load_pe(target)
    seed = int(rva, 0) if rva else None
    view = build_ida_view(pe, recursive=not linear, max_insns=max_insns, seed_rva=seed)
    d = view.to_dict()
    if listing_only:
        lines = []
        for i in view.instructions[:5000]:
            lines.append(f"{i.addr:016x}  {i.bytes_hex:<24}  {i.mnemonic:<8} {i.op_str}")
        click.echo("\n".join(lines))
        return
    if out_path:
        p = Path(out_path)
        if p.suffix.lower() == ".json":
            p.write_text(json.dumps(d, indent=2), encoding="utf-8")
        else:
            p.mkdir(parents=True, exist_ok=True)
            (p / "ida_view.json").write_text(json.dumps(d, indent=2), encoding="utf-8")
            listing = "\n".join(
                f"{i.addr:016x}  {i.bytes_hex:<24}  {i.mnemonic:<8} {i.op_str}"
                for i in view.instructions
            )
            (p / "listing.txt").write_text(listing, encoding="utf-8")
    _out({
        "ok": True,
        "insn_count": d["insn_count"],
        "functions": len(d["functions"]),
        "xrefs": len(d["xrefs"]),
        "base": d["base"],
        "arch": d["arch"],
        "out": out_path,
    })


def _attach_v1_commands(group: click.Group) -> None:
    """Forward every v1 verb that v2 does not override."""
    import_v1()
    from street_decrepytor.cli.commands import main as v1_main

    skip = set(group.commands.keys())
    for name, cmd in list(v1_main.commands.items()):
        if name in skip:
            continue
        if isinstance(cmd, click.Group):
            continue
        group.add_command(cmd, name)

    def _grp(name: str, help_text: str, names: tuple[str, ...]) -> None:
        if name in group.commands:
            return

        @group.group(name, help=help_text)
        def _g() -> None:
            pass

        for n in names:
            cmd = group.commands.get(n)
            if cmd is not None and not isinstance(cmd, click.Group):
                _g.add_command(cmd)

    _grp("static", "Classify / strings / junk / protectors / deobf / cfg / disasm", (
        "classify", "analyze", "pipeline", "protectors", "junk", "strings",
        "deobf", "cfg", "disasm", "dotnet-analyze",
    ))
    _grp("extract", "Honest extract + Themida live unpack", (
        "unpack", "themida-unpack", "themida-rebuild", "recover",
    ))
    # v1 called this `live` — keep dump verbs grouped without clobbering v2 watch
    _grp("dyn", "Dump / validate / hooks (Windows) — v1 live group", (
        "dump", "pe-dump", "themida-unpack", "memscan", "validate", "observe-syscalls",
        "stub-db", "stub-integrity", "peb-probe", "peb-patch", "themida-phylo",
        "frida-script", "frida-run", "syscall-map", "scyllahide-export",
    ))
    _grp("k", "Potassium-only (not universal)", (
        "cdn-pull", "recrack", "gates-apply", "potassium", "capture-child", "simd-emu",
    ))
    _grp("report", "One-shot JSON/MD reports", ("crack", "batch", "agent"))


_attach_v1_commands(main)


if __name__ == "__main__":
    main()
