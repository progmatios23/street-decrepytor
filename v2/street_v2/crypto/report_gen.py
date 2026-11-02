# language: Python 3.11+, file: crypto/report_gen.py
# Automated Markdown + JSON reports keyed off detected crypto/protector system
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from street_v2.crypto.detector import CryptoSystem
from street_v2.entropy.analyzer import EntropyMap
from street_v2.pe.loader import PeImage

PLAYBOOK_STEPS: dict[str, list[str]] = {
    "themida_live_dump": [
        "Static: confirm .text SizeOfRawData==0 and Oreans markers.",
        "Live: spawn under PEB patch / ScyllaHide profile.",
        "Wait until .text fills in RAM (poll entropy/size, not sleep-only).",
        "dump --fix-pe --iat; rebuild IAT from live pointers.",
        "Hunt OEP near first non-VM transition; do NOT claim VM lift.",
        "Report must set decrypted=true only if dump .text raw grew from 0.",
    ],
    "vmp_live_dump": [
        "Confirm .vmp* sections / VMProtect markers.",
        "Live dump after mutation; IAT fix.",
        "No static VM handler lift in Street v2 — dump only.",
    ],
    "upx_d": [
        "If `upx` on PATH: `upx -d -o <out> <in>`.",
        "If missing: note upx_not_installed; do not set unpacked=true.",
    ],
    "live_dump_wait_text": [
        "Empty on-disk .text → runtime decrypt shell (Themida-class or custom).",
        "Attach / spawn, poll section until raw-equivalent bytes appear.",
        "Copy image; label transform kind=copy (not cipher).",
    ],
    "aes_ni_trace": [
        "Locate AES-NI sites (aesenc/aesdec/aeskeygenassist) via xref type=crypto.",
        "Harvest 16-byte imm keys; try AES-128 ECB on islands.",
        "If key material recovered → kind=cipher; else kind=trace_only.",
    ],
    "chacha_recover": [
        "Constant 'expand 32-byte k' found — ChaCha20.",
        "Try 32-byte keys from imm64 pairs / hex strings on high-H islands.",
    ],
    "tea_recover": [
        "TEA delta 0x9E3779B9 in .text — try TEA/XTEA decode with 16-byte keys.",
    ],
    "simd_emu": [
        "Run simd_emu / Unicorn over pxor string decrypt loops.",
        "Emit simd_strings.txt; image bytes unchanged unless patch stage requested.",
    ],
    "xor_recover": [
        "Collect imm64 candidates near xor windows.",
        "Rolling XOR prefilter on high-entropy islands only.",
        "Promote to cipher transform only on printable decode score≥0.75.",
    ],
    "dotnet_crypto_trace": [
        "dnfile / de4dot for method bodies if available.",
        "Hook System.Security.Cryptography via Frida for live keys.",
    ],
    "rc4_recover": [
        "Find KSA/PRGA loops; emulate key setup.",
        "Decrypt adjacent high-entropy island; verify magic/headers.",
    ],
    "generic": [
        "Classify family/arch.",
        "Entropy map + island list.",
        "Disasm entry + imports.",
        "No decrypt claim without kind=cipher transform.",
    ],
}


def _md(pe: PeImage, crypto: CryptoSystem, ent: EntropyMap | None, extra: dict[str, Any] | None) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    steps = PLAYBOOK_STEPS.get(crypto.playbook, PLAYBOOK_STEPS["generic"])
    lines = [
        f"# Street-decrepytor v2 — Crypto System Report",
        "",
        f"**Generated:** `{now}`  ",
        f"**Target:** `{pe.path}`  ",
        f"**Arch:** `{pe.arch}`  entry `{pe.image_base + pe.entry_rva:#x}`  ",
        f"**Primary system:** `{crypto.primary}`  ",
        f"**Playbook:** `{crypto.playbook}`  ",
        "",
        "## Honesty contract",
        "",
        "- `decrypted` / `kind: cipher` only when bytes were transformed by a recovered key.",
        "- Memory dump after packer self-decrypt = `kind: copy`.",
        "- Commercial VM (Themida/VMProtect) is **not** lifted by this report.",
        "",
        "## Detection hits",
        "",
    ]
    if not crypto.hits:
        lines.append("_no hits_")
    else:
        lines.append("| system | confidence | evidence |")
        lines.append("|--------|------------|----------|")
        for h in crypto.hits:
            ev = "; ".join(h.evidence)[:120].replace("|", "/")
            lines.append(f"| `{h.system}` | {h.confidence:.3f} | {ev} |")

    lines += ["", "## Playbook steps", ""]
    for i, s in enumerate(steps, 1):
        lines.append(f"{i}. {s}")

    if ent:
        lines += [
            "",
            "## Entropy",
            "",
            f"- global_H: **{ent.global_H:.4f}**",
            f"- high_ratio (≥7.2): **{ent.high_ratio:.4f}**",
            f"- islands: **{len(ent.islands)}**",
            "",
            "### Sections",
            "",
            "| name | H | rawsize | empty_raw |",
            "|------|---|---------|-----------|",
        ]
        for s in ent.section_summary:
            lines.append(
                f"| `{s['name']}` | {s['H']:.4f} | {s['rawsize']} | {s.get('empty_raw')} |"
            )
        if ent.islands:
            lines += ["", "### Crypto islands", ""]
            for isl in ent.islands[:20]:
                lines.append(
                    f"- `{isl.start_off:#x}`–`{isl.end_off:#x}` "
                    f"mean_H={isl.mean_H:.3f} hint=`{isl.kind_hint}` sec=`{isl.section}`"
                )

    lines += ["", "## Notes", ""]
    for n in crypto.notes:
        lines.append(f"- {n}")

    if extra:
        lines += ["", "## Extra analysis keys", ""]
        for k in sorted(extra.keys()):
            lines.append(f"- `{k}`")

    lines.append("")
    return "\n".join(lines)


def generate_crypto_report(
    pe: PeImage,
    crypto: CryptoSystem,
    ent: EntropyMap | None,
    out_dir: str | Path,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    payload = {
        "tool": "street-decrepytor-v2",
        "version": "2.0.0",
        "target": pe.to_dict(),
        "crypto": crypto.to_dict(),
        "entropy": ent.to_dict() if ent else None,
        "playbook_steps": PLAYBOOK_STEPS.get(crypto.playbook, PLAYBOOK_STEPS["generic"]),
        "image_transforms": [],
        "decrypted": False,
        "extra": extra or {},
    }
    json_path = out / "CRYPTO_SYSTEM_REPORT.json"
    md_path = out / "CRYPTO_SYSTEM_REPORT.md"
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    md_path.write_text(_md(pe, crypto, ent, extra), encoding="utf-8")
    return {
        "ok": True,
        "json": str(json_path),
        "md": str(md_path),
        "primary": crypto.primary,
        "playbook": crypto.playbook,
        "decrypted": False,
    }
