# language: Python 3.11+, file: report/full.py
# ALL_ANALYSIS.md — one operator report covering v1 pipeline + v2 layers
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def write_all_analysis(out_dir: Path, payload: dict[str, Any]) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    p = payload.get("profile") or {}
    v1 = payload.get("v1") or {}
    crypto = payload.get("crypto") or {}
    ent = payload.get("entropy") or {}
    ida = payload.get("ida") or {}
    emu = payload.get("emu") or {}
    unpack = payload.get("unpack") or {}
    harvest = payload.get("harvest") or {}
    decrypt = payload.get("decrypt") or {}

    lines = [
        f"# ALL_ANALYSIS — `{Path(payload.get('target','')).name}`",
        "",
        f"**tool:** street-decrepytor-v2 `{payload.get('version')}`  ",
        f"**generated:** `{now}`  ",
        f"**target:** `{payload.get('target')}`  ",
        f"**elapsed:** `{payload.get('elapsed_sec')}s`  ",
        f"**decrypted:** `{payload.get('decrypted')}`  ",
        "",
        "## Honesty",
        "",
        "- `decrypted=true` only if a cipher transform recovered a key, or live dump grew `.text` raw from 0.",
        "- v1 pipeline is classify / extract / plan. Commercial VM is **not** lifted.",
        "- Memory dump after packer self-decrypt = `kind: copy`.",
        "",
        "## Classify (v1)",
        "",
        f"- family: `{p.get('family')}`  arch: `{p.get('arch')}`  format: `{p.get('format')}`",
        f"- sha256: `{p.get('sha256')}`  size: `{p.get('size')}`",
        f"- confidence: `{p.get('confidence')}`",
        f"- signals: {', '.join(p.get('signals') or []) or '(none)'}",
        f"- protectors: {', '.join(x.get('name','?') for x in (p.get('protector_candidates') or [])) or '(none strong)'}",
        "",
        "## v1 pipeline stages",
        "",
        f"- output: `{v1.get('output_dir')}`",
        f"- summary: `{v1.get('summary')}`",
        "",
        "| stage | ok | ms | errors |",
        "|-------|----|----|--------|",
    ]
    for s in v1.get("stages") or []:
        err = "; ".join(s.get("errors") or [])[:80]
        lines.append(f"| `{s.get('name')}` | {s.get('ok')} | {s.get('duration_ms')} | {err or ''} |")

    lines += ["", "## Crypto system (v2)", ""]
    if crypto:
        lines.append(f"- primary: **`{crypto.get('primary')}`**")
        lines.append(f"- playbook: `{crypto.get('playbook')}`")
        for h in crypto.get("hits") or []:
            ev = "; ".join(h.get("evidence") or [])[:100]
            lines.append(f"  - `{h.get('system')}` conf={h.get('confidence')} — {ev}")
        for n in crypto.get("notes") or []:
            lines.append(f"- note: {n}")
    else:
        lines.append("_no PE crypto pass (non-PE or load failed)_")

    lines += ["", "## Entropy (v2)", ""]
    if ent:
        lines.append(f"- global_H: **{ent.get('global_H')}**  high_ratio: **{ent.get('high_ratio')}**  islands: **{len(ent.get('islands') or [])}**")
        lines += ["", "| section | H | rawsize | empty_raw |", "|---------|---|---------|-----------|"]
        for s in ent.get("sections") or []:
            lines.append(f"| `{s.get('name')}` | {s.get('H')} | {s.get('rawsize')} | {s.get('empty_raw')} |")
        if ent.get("islands"):
            lines += ["", "### Islands", ""]
            for isl in (ent.get("islands") or [])[:20]:
                lines.append(
                    f"- `{isl.get('start_off')}`–`{isl.get('end_off')}` "
                    f"mean_H={isl.get('mean_H')} hint=`{isl.get('kind_hint')}` sec=`{isl.get('section')}`"
                )
    else:
        lines.append("_skipped_")

    xr = (payload.get("ida") or {}).get("xref_report") or {}
    lines += ["", "## IDA-like view (v2)", ""]
    if ida:
        lines.append(f"- arch `{ida.get('arch')}` base `{ida.get('base')}`")
        lines.append(f"- insns **{ida.get('insn_count')}**  functions **{ida.get('functions')}**")
        xc = xr.get("counts") or (ida.get("xref_report") or {}).get("counts") or {}
        if xc:
            lines.append(
                f"- xrefs code `{xc.get('code')}` data `{xc.get('data')}` "
                f"str `{xc.get('string')}` xor `{xc.get('xor')}` crypto `{xc.get('crypto')}`"
            )
    else:
        lines.append("_skipped_")

    lines += ["", "## Unicorn emu (v2)", ""]
    if emu:
        lines.append(f"- ok `{emu.get('ok')}` reason `{emu.get('stops_reason')}` insns `{emu.get('insn_count')}`")
        lines.append(f"- xor_events {len(emu.get('xor_events') or [])}  aes_events {len(emu.get('aes_events') or [])}")
        lines.append(f"- printable_recoveries {len(emu.get('printable_recoveries') or [])}")
        lines.append(f"- decrypted `{emu.get('decrypted')}` (trace only unless cipher transform)")
    else:
        lines.append("_skipped_")

    lines += ["", "## Harvest (everything from the file)", ""]
    if harvest:
        c = harvest.get("counts") or {}
        lines.append(f"- dir: `{harvest.get('dir')}`")
        lines.append(
            f"- sections `{c.get('sections')}`  resources `{c.get('resources')}`  "
            f"carved_pe `{c.get('carved_pe')}`  magics `{c.get('carved_magic')}`  "
            f"islands `{c.get('islands')}`  zlib `{c.get('zlib_inflated')}`  "
            f"strings `{c.get('strings_ascii')}`"
        )
        lines.append(f"- overlay: `{harvest.get('overlay')}`")
        py = harvest.get("pyinstaller") or {}
        if py:
            lines.append(f"- pyinstaller: ok=`{py.get('ok')}` entries=`{py.get('entry_count')}` reason=`{py.get('reason')}`")
    else:
        lines.append("_skipped_")

    lines += ["", "## Decrypt hits (cipher only)", ""]
    if decrypt:
        lines.append(f"- hit_count: **{decrypt.get('hit_count')}**  keys_tried_imm: `{decrypt.get('keys_tried_imm')}`")
        lines.append(f"- dir: `{decrypt.get('dir')}`")
        for h in (decrypt.get("hits") or [])[:20]:
            lines.append(
                f"  - `{h.get('algo')}` score={h.get('score')} key=`{h.get('key_hex','')[:32]}` "
                f"→ `{h.get('out')}` why={h.get('why')}"
            )
        if not decrypt.get("hits"):
            lines.append("- (no cipher cleared the magic/H-drop threshold — not a fake decrypt)")
    else:
        lines.append("_skipped_")

    lines += ["", "## Image transforms", ""]
    tx = payload.get("image_transforms") or []
    if not tx:
        lines.append("- (none)")
    for t in tx[:40]:
        lines.append(f"- **{t.get('kind')}** `{t.get('layer')}` → `{t.get('path')}`")

    lines += ["", "## Unpack (optional)", ""]
    if unpack:
        lines.append(f"- honest_verdict: `{unpack.get('honest_verdict')}`")
        lines.append(f"- themida_class: `{(unpack.get('themida_class_ident') or {}).get('themida_class')}`")
        lines.append(f"- decrypted: `{unpack.get('decrypted')}`")
        lines.append(f"- report: `{unpack.get('report_md')}`")
    else:
        lines.append("_not requested_")

    cr = payload.get("crypto_report") or {}
    lines += [
        "",
        "## Artifacts",
        "",
        f"- `pipeline_result.json`",
        f"- `v1_pipeline_result.json`",
        f"- crypto md: `{cr.get('md')}`",
        f"- crypto json: `{cr.get('json')}`",
        "",
    ]
    md_path = out_dir / "ALL_ANALYSIS.md"
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return str(md_path)
