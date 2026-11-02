# language: Python 3, file: artifact.py
# Adaptive artifact classification — no rigid packer DB as sole signal.
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class LangFamily(str, Enum):
    NATIVE_PE = "native_pe"
    NATIVE_ELF = "native_elf"
    DOTNET = "dotnet"
    JAVA = "java"
    PYTHON = "python"
    GO = "go"
    RUST = "rust"
    CPP_CLI = "cpp_cli"
    MIXED = "mixed"
    CONTAINER = "container"
    ARCHIVE = "archive"
    SCRIPT = "script"
    UNKNOWN = "unknown"


class Arch(str, Enum):
    X86 = "x86"
    X64 = "x64"
    ARM = "arm"
    ARM64 = "arm64"
    UNKNOWN = "unknown"


@dataclass
class ArtifactProfile:
    path: str
    size: int
    sha256: str
    family: LangFamily
    arch: Arch
    format: str
    confidence: float
    signals: list[str] = field(default_factory=list)
    multi_build_hints: list[str] = field(default_factory=list)
    protector_candidates: list[dict[str, Any]] = field(default_factory=list)
    pe_info: dict[str, Any] = field(default_factory=dict)
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "size": self.size,
            "sha256": self.sha256,
            "family": self.family.value,
            "arch": self.arch.value,
            "format": self.format,
            "confidence": self.confidence,
            "signals": self.signals,
            "multi_build_hints": self.multi_build_hints,
            "protector_candidates": self.protector_candidates,
            "pe_info": self.pe_info,
            "extra": self.extra,
        }


def _sha256_file(path: Path, max_read: int | None = None) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        if max_read is None:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        else:
            h.update(f.read(max_read))
    return h.hexdigest()


def _read_head(path: Path, n: int = 1 << 20) -> bytes:
    with path.open("rb") as f:
        return f.read(n)


def _pe_machine_to_arch(machine: int) -> Arch:
    return {
        0x14C: Arch.X86,
        0x8664: Arch.X64,
        0x1C0: Arch.ARM,
        0xAA64: Arch.ARM64,
    }.get(machine, Arch.UNKNOWN)


def _classify_pe(data: bytes, path: Path) -> ArtifactProfile:
    signals: list[str] = []
    family = LangFamily.NATIVE_PE
    conf = 0.55
    pe_info: dict[str, Any] = {}
    arch = Arch.UNKNOWN
    protector_candidates: list[dict[str, Any]] = []
    multi: list[str] = []

    if len(data) < 0x40 or data[:2] != b"MZ":
        return ArtifactProfile(
            str(path), path.stat().st_size, _sha256_file(path),
            LangFamily.UNKNOWN, Arch.UNKNOWN, "unknown", 0.1, ["not_mz"],
        )

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 0x18 >= len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        return ArtifactProfile(
            str(path), path.stat().st_size, _sha256_file(path),
            LangFamily.UNKNOWN, Arch.UNKNOWN, "mz_no_pe", 0.2, ["mz_without_pe"],
        )

    machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
    n_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_magic = struct.unpack_from("<H", data, e_lfanew + 0x18)[0]
    arch = _pe_machine_to_arch(machine)
    pe_info = {
        "machine": hex(machine),
        "sections": n_sections,
        "optional_magic": hex(opt_magic),
        "pe32plus": opt_magic == 0x20B,
    }

    # CLR directory (data directory index 14)
    # PE32: optional header 0xE0, dirs at +0x60; PE32+: 0xF0, dirs at +0x70
    if opt_magic == 0x10B:
        dd_off = e_lfanew + 0x18 + 0x60
    else:
        dd_off = e_lfanew + 0x18 + 0x70
    clr_rva = clr_size = 0
    if dd_off + 15 * 8 <= len(data):
        clr_rva, clr_size = struct.unpack_from("<II", data, dd_off + 14 * 8)
        pe_info["clr_rva"] = clr_rva
        pe_info["clr_size"] = clr_size

    # Section names — behavioral packing signal (raw=0 / high entropy later)
    sec_table = e_lfanew + 0x18 + (0xE0 if opt_magic == 0x10B else 0xF0)
    section_names: list[str] = []
    virtual_only = 0
    for i in range(min(n_sections, 32)):
        off = sec_table + i * 40
        if off + 40 > len(data):
            break
        name = data[off:off + 8].split(b"\0", 1)[0].decode("latin-1", errors="replace")
        vsize, vaddr, rsize, roff = struct.unpack_from("<IIII", data, off + 8)
        section_names.append(name)
        if rsize == 0 and vsize > 0:
            virtual_only += 1
    pe_info["section_names"] = section_names
    if virtual_only:
        signals.append(f"virtual_only_sections={virtual_only}")
        conf += 0.05

    # Language / runtime behavioral probes (content, not hardcoded packer offsets)
    blob = data  # head only; full scan deferred to static module
    full_hint_window = data[: min(len(data), 4 << 20)]

    if clr_rva and clr_size:
        family = LangFamily.DOTNET
        signals.append("clr_directory_present")
        conf = 0.9
        if b"mscoree.dll" in full_hint_window.lower() or b"_CorExeMain" in full_hint_window:
            signals.append("mscoree_bootstrap")

    # Go runtime marker
    if b"runtime.main" in full_hint_window or b"Go build ID:" in full_hint_window or b"runtime.gopanic" in full_hint_window:
        family = LangFamily.GO if family == LangFamily.NATIVE_PE else LangFamily.MIXED
        signals.append("go_runtime_marker")
        conf = max(conf, 0.85)

    # Rust markers
    if b"rustc-version" in full_hint_window or b".llvm." in full_hint_window and b"RUST_BACKTRACE" in full_hint_window:
        signals.append("rust_marker")
        if family == LangFamily.NATIVE_PE:
            family = LangFamily.RUST
            conf = max(conf, 0.8)
    if b"panicked at" in full_hint_window and b"src\\" in full_hint_window:
        signals.append("rust_panic_path")
        if family == LangFamily.NATIVE_PE:
            family = LangFamily.RUST
            conf = max(conf, 0.75)

    # C++/CLI mixed — both CLR and native imports heavy
    if family == LangFamily.DOTNET and (b"KERNEL32.dll" in full_hint_window and b"msvcp" in full_hint_window.lower()):
        family = LangFamily.CPP_CLI
        signals.append("cpp_cli_mixed_hints")

    # Tauri / WebView2 stack (Potassium UI class)
    if b"WebView2" in full_hint_window or b"tauri" in full_hint_window.lower():
        signals.append("tauri_webview2")
        multi.append("desktop_webview_bundle")
        if family == LangFamily.NATIVE_PE:
            family = LangFamily.RUST
            conf = max(conf, 0.78)

    # DFIR / Sysmon-style rule packs (FarmServices, DFIR dumps)
    if b"technique_id=T" in full_hint_window or b"Sysmon" in full_hint_window:
        signals.append("dfir_mitre_rules_embedded")
        conf = max(conf, 0.7)
    if b"EventFiltering" in full_hint_window or b"RuleGroup" in full_hint_window:
        signals.append("sysmon_config_blob")

    # Multi-build: multiple PE magic / nested
    pe_count = full_hint_window.count(b"MZ")
    if pe_count > 3:
        multi.append(f"embedded_mz_count~{pe_count}")
        signals.append("possible_multi_pe_bundle")

    # Protector *candidates* via behavioral section/import shape — refined later
    if virtual_only >= 2:
        protector_candidates.append({
            "name": "runtime_section_decryptor",
            "reason": "multiple zero-raw sections (common Themida/VMProtect/custom)",
            "confidence": 0.45,
        })
    if any(n.lower() in (".themida", ".winlice", ".vmp0", ".vmp1", "themida") for n in section_names):
        protector_candidates.append({
            "name": "named_protector_section",
            "sections": section_names,
            "confidence": 0.7,
        })

    # Entropy proxy: high ratio of non-ascii in first MB of .text-ish payload
    sample = full_hint_window[0x1000:0x1000 + 0x8000] if len(full_hint_window) > 0x9000 else full_hint_window
    if sample:
        printable = sum(1 for b in sample if 32 <= b < 127)
        ratio = printable / len(sample)
        pe_info["printable_ratio_sample"] = round(ratio, 4)
        if ratio < 0.15:
            signals.append("low_printable_ratio_packed_likely")
            conf = min(0.95, conf + 0.05)

    return ArtifactProfile(
        path=str(path.resolve()),
        size=path.stat().st_size,
        sha256=_sha256_file(path),
        family=family,
        arch=arch,
        format="pe",
        confidence=min(conf, 0.99),
        signals=signals,
        multi_build_hints=multi,
        protector_candidates=protector_candidates,
        pe_info=pe_info,
    )


def _classify_other(data: bytes, path: Path) -> ArtifactProfile:
    signals: list[str] = []
    size = path.stat().st_size
    sha = _sha256_file(path)
    name = path.name.lower()

    # ELF
    if data[:4] == b"\x7fELF":
        ei_class = data[4]
        ei_machine = struct.unpack_from("<H", data, 18)[0] if len(data) > 20 else 0
        arch = {3: Arch.X86, 62: Arch.X64, 40: Arch.ARM, 183: Arch.ARM64}.get(ei_machine, Arch.UNKNOWN)
        family = LangFamily.NATIVE_ELF
        if b"Go build ID:" in data[: min(len(data), 1 << 20)]:
            family = LangFamily.GO
            signals.append("go_on_elf")
        return ArtifactProfile(str(path), size, sha, family, arch, "elf", 0.9, signals)

    # JAR / ZIP
    if data[:2] == b"PK":
        signals.append("zip_container")
        family = LangFamily.ARCHIVE
        conf = 0.7
        # scan central-ish names in head
        if b"META-INF/MANIFEST.MF" in data or b".class" in data:
            family = LangFamily.JAVA
            signals.append("java_jar_layout")
            conf = 0.9
        if b"lib/" in data and (b".so" in data or b".dll" in data):
            signals.append("native_libs_in_zip")
        if name.endswith(".apk") or b"AndroidManifest.xml" in data:
            signals.append("android_apk")
        if name.endswith(".nupkg") or b"[Content_Types].xml" in data:
            signals.append("nuget_or_office_pkg")
        return ArtifactProfile(str(path), size, sha, family, Arch.UNKNOWN, "zip", conf, signals,
                               multi_build_hints=["bundled_archive"])

    # Python pyc
    if len(data) >= 16 and data[0] in (0x33, 0x42, 0x55, 0x6F, 0xA7, 0x0A, 0x0D, 0xF3, 0x16, 0x17, 0x61, 0x63, 0x6C, 0xCB, 0xE3):
        # magic number families for various CPython versions
        if name.endswith(".pyc") or data[2:4] in (b"\r\n", b"\n\r"):
            return ArtifactProfile(str(path), size, sha, LangFamily.PYTHON, Arch.UNKNOWN, "pyc", 0.8,
                                   ["pyc_magic_candidate"])

    # PyInstaller archive cookie
    if b"MEI\014\013\012\013\016" in data[: min(len(data), 1 << 20)] or b"PyInstaller" in data[: min(len(data), 1 << 20)]:
        return ArtifactProfile(str(path), size, sha, LangFamily.PYTHON, Arch.UNKNOWN, "pyinstaller", 0.85,
                               ["pyinstaller_cookie"], multi_build_hints=["frozen_python"])

    # Docker / OCI tar hint
    if name.endswith((".tar", ".tar.gz", ".tgz")) or (len(data) > 262 and data[257:262] == b"ustar"):
        return ArtifactProfile(str(path), size, sha, LangFamily.CONTAINER, Arch.UNKNOWN, "tar", 0.75,
                               ["ustar_or_tar_name"], multi_build_hints=["container_fs_layer"])

    # shebang scripts
    if data.startswith(b"#!"):
        return ArtifactProfile(str(path), size, sha, LangFamily.SCRIPT, Arch.UNKNOWN, "script", 0.9,
                               ["shebang"])

    return ArtifactProfile(str(path), size, sha, LangFamily.UNKNOWN, Arch.UNKNOWN, "blob", 0.2, signals)


def classify_artifact(path: str | Path) -> ArtifactProfile:
    """Classify any build artifact without assuming a single language or packer."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(path)
    head = _read_head(p, 8 << 20)
    if head[:2] == b"MZ":
        return _classify_pe(head, p)
    return _classify_other(head, p)
