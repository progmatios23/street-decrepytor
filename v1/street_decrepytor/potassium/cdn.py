# language: Python 3, file: potassium/cdn.py
# Product-specific CDN client for files.potassium.pro / api.potassium.pro
# *Bypasses hosts pins (127.0.0.1) via DNS-over-HTTPS + SNI — not a generic downloader*
from __future__ import annotations

import hashlib
import json
import re
import socket
import ssl
import struct
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

# Product surface (from RE — Potassium_analysis / DOCUMENTACAO_TECNICA)
DEFAULT_FILES_HOST = "files.potassium.pro"
DEFAULT_API_HOST = "api.potassium.pro"
# Client historically hits paths with trailing slashes padding
PATH_HASHES = "/hashes"
PATH_RESOURCE = "/resource"
PATH_VERSION = "/version"
PATH_GUI_NAME = "/gui_name"
# Binary names from updater loop
PRODUCT_FILES = ("Potassium.dll", "Potassium.exe", "Decompiler.exe")
# Child lives under install bin after update — name still Potassium.exe (UI vs child distinguished by size/hash)
DOH_ENDPOINTS = (
    "https://cloudflare-dns.com/dns-query?name={host}&type=A",
    "https://dns.google/resolve?name={host}&type=A",
)


class CdnError(Exception):
    pass


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_b64(data: bytes) -> str:
    import base64
    return base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")


def resolve_host_doh(host: str, timeout: float = 15.0) -> list[str]:
    """Resolve A records via DoH — ignores Windows hosts file pins."""
    import urllib.request

    ips: list[str] = []
    ctx = ssl.create_default_context()
    for tmpl in DOH_ENDPOINTS:
        url = tmpl.format(host=host)
        req = urllib.request.Request(
            url,
            headers={
                "accept": "application/dns-json",
                "User-Agent": "Street-decrepytor/0.2 (potassium-cdn)",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                payload = json.loads(resp.read().decode("utf-8", "replace"))
            for ans in payload.get("Answer") or []:
                if ans.get("type") == 1 and ans.get("data"):
                    ip = ans["data"].strip()
                    if ip not in ips:
                        ips.append(ip)
            if ips:
                return ips
        except Exception:
            continue
    # last resort: system resolver (may hit hosts → 127.0.0.1)
    try:
        for fam, _, _, _, sockaddr in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM):
            ip = sockaddr[0]
            if ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return ips


def hosts_pin_status(host: str = DEFAULT_FILES_HOST) -> dict[str, Any]:
    hosts_path = Path(r"C:\Windows\System32\drivers\etc\hosts")
    pinned = False
    lines = []
    try:
        text = hosts_path.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            if host in line.lower() and not line.strip().startswith("#"):
                pinned = True
                lines.append(line.strip())
    except Exception as e:
        return {"checked": False, "error": str(e)}
    return {"checked": True, "pinned": pinned, "lines": lines, "hosts_path": str(hosts_path)}


def https_get(
    host: str,
    path: str,
    *,
    token: str | None = None,
    ip: str | None = None,
    timeout: float = 30.0,
    prefer_doh: bool = True,
) -> tuple[int, dict[str, str], bytes]:
    """
    HTTPS GET with product Host/SNI. When prefer_doh, dial resolved IP so hosts→127.0.0.1 cannot hijack.
    """
    ips = [ip] if ip else (resolve_host_doh(host) if prefer_doh else [])
    if not ips:
        ips = [host]  # let SSL stack resolve (may fail if hosts pinned)

    headers = {
        "Host": host,
        "User-Agent": "Potassium/Street-decrepytor",
        "Accept": "*/*",
        "Connection": "close",
    }
    if token:
        # product uses Authorization: Bearer <session>
        tok = token if not token.lower().startswith("bearer ") else token.split(" ", 1)[1]
        headers["Authorization"] = f"Bearer {tok}"

    last_err: Exception | None = None
    for dial in ips:
        try:
            return _https_get_ip(dial, host, path, headers, timeout)
        except Exception as e:
            last_err = e
            continue
    raise CdnError(f"GET https://{host}{path} failed: {last_err}")


def _https_get_ip(
    ip: str,
    server_hostname: str,
    path: str,
    headers: dict[str, str],
    timeout: float,
) -> tuple[int, dict[str, str], bytes]:
    if not path.startswith("/"):
        path = "/" + path
    ctx = ssl.create_default_context()
    # SNI must be product hostname even when dialing Cloudflare anycast IP
    sock = socket.create_connection((ip, 443), timeout=timeout)
    try:
        ssock = ctx.wrap_socket(sock, server_hostname=server_hostname)
    except Exception:
        sock.close()
        raise
    try:
        req_lines = [f"GET {path} HTTP/1.1"]
        for k, v in headers.items():
            req_lines.append(f"{k}: {v}")
        req_lines.append("")
        req_lines.append("")
        ssock.sendall("\r\n".join(req_lines).encode("ascii"))
        buf = bytearray()
        while True:
            chunk = ssock.recv(1 << 16)
            if not chunk:
                break
            buf.extend(chunk)
            if len(buf) > 80 << 20:
                break
    finally:
        try:
            ssock.close()
        except Exception:
            pass

    raw = bytes(buf)
    if b"\r\n\r\n" not in raw:
        raise CdnError("malformed HTTP response")
    head, body = raw.split(b"\r\n\r\n", 1)
    lines = head.decode("latin-1", "replace").split("\r\n")
    status_line = lines[0]
    m = re.match(r"HTTP/\d\.\d\s+(\d+)", status_line)
    code = int(m.group(1)) if m else 0
    hdrs: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()

    # chunked?
    if hdrs.get("transfer-encoding", "").lower() == "chunked":
        body = _dechunk(body)
    cl = hdrs.get("content-length")
    if cl and cl.isdigit():
        body = body[: int(cl)]
    return code, hdrs, body


def _dechunk(data: bytes) -> bytes:
    out = bytearray()
    i = 0
    while i < len(data):
        j = data.find(b"\r\n", i)
        if j < 0:
            break
        try:
            size = int(data[i:j].split(b";")[0], 16)
        except ValueError:
            break
        i = j + 2
        if size == 0:
            break
        out.extend(data[i : i + size])
        i += size + 2
    return bytes(out)


def fetch_json(host: str, path: str, **kw: Any) -> Any:
    code, _, body = https_get(host, path, **kw)
    if code != 200:
        raise CdnError(f"{path} HTTP {code}: {body[:200]!r}")
    try:
        return json.loads(body.decode("utf-8"))
    except json.JSONDecodeError as e:
        raise CdnError(f"{path} not JSON: {e}; body={body[:120]!r}") from e


def try_path_variants(host: str, base: str, **kw: Any) -> tuple[str, Any]:
    """Product client sometimes uses trailing-slash padding — try several."""
    variants = [base, base + "/", base + "////", base + "//////"]
    errs = []
    for p in variants:
        try:
            return p, fetch_json(host, p, **kw)
        except Exception as e:
            errs.append(f"{p}: {e}")
    raise CdnError("all path variants failed:\n" + "\n".join(errs))


def pull_product_stack(
    out_dir: str | Path,
    *,
    token: str | None = None,
    files_host: str = DEFAULT_FILES_HOST,
    api_host: str = DEFAULT_API_HOST,
    ip: str | None = None,
    skip_binaries: bool = False,
    auto_crack: bool = False,
) -> dict[str, Any]:
    """
    Full product CDN pull matching Potassium updater semantics:
      version → hashes → resource version → each binary by versioned name when required
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {
        "files_host": files_host,
        "api_host": api_host,
        "hosts_pin": hosts_pin_status(files_host),
        "doh_ips": resolve_host_doh(files_host),
        "token_used": bool(token),
        "steps": [],
        "files": {},
        "errors": [],
    }

    kw: dict[str, Any] = {"token": token, "ip": ip, "prefer_doh": True}

    # 1) version
    try:
        path_v, version = try_path_variants(files_host, PATH_VERSION, **kw)
        (out / "version.json").write_text(json.dumps(version, indent=2), encoding="utf-8")
        report["steps"].append({"version": version, "path": path_v})
    except Exception as e:
        report["errors"].append(f"version: {e}")
        version = {}

    # 2) hashes — map of name → sha256 hex or b64 depending on server era
    try:
        path_h, hashes = try_path_variants(files_host, PATH_HASHES, **kw)
        (out / "hashes.json").write_text(json.dumps(hashes, indent=2), encoding="utf-8")
        report["steps"].append({"hashes_keys": list(hashes.keys()) if isinstance(hashes, dict) else type(hashes).__name__, "path": path_h})
        report["hashes"] = hashes
    except Exception as e:
        report["errors"].append(f"hashes: {e}")
        hashes = {}

    # 3) resource — expects JSON with 'version' field (NOT raw binary)
    try:
        path_r, resource = try_path_variants(files_host, PATH_RESOURCE, **kw)
        (out / "resource.json").write_text(json.dumps(resource, indent=2) if not isinstance(resource, (bytes, bytearray)) else str(resource), encoding="utf-8")
        report["steps"].append({"resource": resource if isinstance(resource, dict) else "non-dict", "path": path_r})
        report["resource"] = resource if isinstance(resource, dict) else None
    except Exception as e:
        report["errors"].append(f"resource: {e}")
        resource = {}

    ver_name = None
    if isinstance(resource, dict):
        ver_name = resource.get("version") or resource.get("versionPotassium")
    if not ver_name and isinstance(version, dict):
        ver_name = version.get("versionPotassium") or version.get("version")

    report["version_name"] = ver_name

    if skip_binaries:
        (out / "cdn_report.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        return report

    # 4) download — product CDN uses opaque versioned names from resource.version
    #    hashes keys include BOTH legacy (Potassium.dll) and versioned
    #    (UJHTs….dll). Prefer exact key path /{key} then legacy layouts.
    names: list[str] = []
    if isinstance(hashes, dict):
        names = [k for k in hashes if isinstance(k, str)]
    for n in PRODUCT_FILES:
        if n not in names:
            names.append(n)
    if ver_name:
        for ext in (".dll", ".exe"):
            vn = f"{ver_name}{ext}"
            if vn not in names:
                names.append(vn)

    seen_sha: dict[str, str] = {}  # sha -> first logical name (dedupe wrong alias)

    for name in names:
        ext = Path(name).suffix.lower()
        candidates: list[str] = [f"/{name}", f"/{name.lower()}"]
        if ver_name and name in (f"{ver_name}.dll", f"{ver_name}.exe", "Potassium.dll", "Potassium.exe"):
            # versioned blob is the live build; legacy names may 404 or differ
            if name.startswith(ver_name) or name in ("Potassium.dll", "Potassium.exe"):
                candidates.insert(0, f"/{ver_name}{ext}")
        if name == "Decompiler.exe":
            # never steal versioned UI/child exe path first
            candidates = [f"/{name}", f"/bin/{name}", f"/{ver_name}/Decompiler.exe" if ver_name else "/x"]
        candidates.extend([f"/bin/{name}", f"/{ver_name}/{name}" if ver_name else "/_"])

        # unique preserve order
        uniq_c: list[str] = []
        for c in candidates:
            if c not in uniq_c and not c.endswith("/_"):
                uniq_c.append(c)

        saved = None
        last = None
        for cpath in uniq_c:
            try:
                code, hdrs, body = https_get(files_host, cpath, **kw)
                if code != 200 or len(body) < 0x200:
                    last = f"{cpath} HTTP {code} len={len(body)}"
                    continue
                if name.endswith((".exe", ".dll")) and body[:2] != b"MZ":
                    last = f"{cpath} not MZ"
                    continue
                if name.endswith(".zip") and body[:2] != b"PK":
                    last = f"{cpath} not zip"
                    continue
                sha = _sha256_hex(body)
                # reject cross-wiring: if this body already saved under another
                # hash-table key with a *different* expected hash, only keep if
                # expected matches this name
                expect = None
                if isinstance(hashes, dict) and name in hashes:
                    expect = str(hashes[name]).strip().lower()
                    if expect and expect != sha and not sha.startswith(expect[:16]):
                        # body doesn't match this key's published hash — keep looking
                        last = f"{cpath} sha mismatch for {name}"
                        continue
                dest = out / "bin" / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(body)
                meta = {
                    "path": str(dest),
                    "cdn_path": cpath,
                    "size": len(body),
                    "sha256": sha,
                    "sha16": sha[:16].upper(),
                    "sha256_b64": _sha256_b64(body),
                }
                if expect:
                    meta["hash_match"] = expect == sha or sha.startswith(expect[:16])
                    meta["expected"] = expect[:64]
                elif isinstance(hashes, dict) and name in hashes:
                    meta["expected"] = str(hashes[name])[:64]
                    meta["hash_match"] = False
                # label by hash vs known CDN table
                if sha.startswith("eb49692a") or (expect and expect.startswith("eb49692a")):
                    meta["street_label"] = "child_official_hash"
                seen_sha[sha] = name
                report["files"][name] = meta
                saved = meta
                break
            except Exception as e:
                last = f"{cpath}: {e}"
        if not saved:
            report["errors"].append(f"download {name}: {last}")

    # classify child vs UI if both present / multiple exe
    for name, meta in list(report["files"].items()):
        if name.endswith(".exe") and meta.get("size") == 138752:
            meta["street_label"] = "child_stub_size"
        elif meta.get("sha16", "").startswith("EB49692A") or (
            meta.get("expected", "").startswith("eb49692a")
        ):
            meta["street_label"] = "child_official_hash"
        elif name.endswith(".exe") and meta.get("size", 0) > 10_000_000:
            meta["street_label"] = "ui_or_full_or_versioned"
        elif name.endswith(".exe") and 100_000 < meta.get("size", 0) < 5_000_000:
            meta["street_label"] = "child_candidate"

    # Agent convenience: alias versioned blobs → Potassium.dll / .exe when legacy keys 404
    if ver_name:
        v_dll = report["files"].get(f"{ver_name}.dll")
        v_exe = report["files"].get(f"{ver_name}.exe")
        bin_dir = out / "bin"
        if v_dll and "Potassium.dll" not in report["files"]:
            alias = bin_dir / "Potassium.dll"
            alias.write_bytes(Path(v_dll["path"]).read_bytes())
            report["files"]["Potassium.dll"] = {
                **v_dll,
                "path": str(alias),
                "aliased_from": f"{ver_name}.dll",
                "note": "legacy Potassium.dll key not on CDN anonymously; versioned blob aliased",
            }
        if v_exe and "Potassium.exe" not in report["files"]:
            alias = bin_dir / "Potassium.exe"
            alias.write_bytes(Path(v_exe["path"]).read_bytes())
            report["files"]["Potassium.exe"] = {
                **v_exe,
                "path": str(alias),
                "aliased_from": f"{ver_name}.exe",
                "note": "legacy Potassium.exe (eb49692a child) may need --token; versioned blob aliased",
            }

    # rewrite soft errors for generic operators
    soft = []
    for err in report["errors"]:
        if "Potassium.dll" in err or "Potassium.exe" in err:
            soft.append(err + " · use versioned name from resource.version or pass --token")
        elif "gui.zip" in err:
            soft.append(err + " · often auth-gated; try --token")
        else:
            soft.append(err)
    report["errors"] = soft
    report["operator_notes"] = [
        "hosts pin detected → DoH+SNI used automatically",
        "Live build names = resource.version + .dll/.exe",
        "hashes.Potassium.exe=eb49692a… is the official child listed by CDN; body may require login token",
        "After pull: street-decrepytor crack output/cdn/potassium/bin/Potassium.dll",
    ]

    if auto_crack and not skip_binaries:
        from street_decrepytor.core.crack import crack_target

        crack_results = []
        bin_dir = out / "bin"
        targets = []
        for pref in ("Potassium.dll", "Potassium.exe", "Decompiler.exe"):
            p = bin_dir / pref
            if p.is_file():
                targets.append(p)
        for p in sorted(bin_dir.glob("*.dll")) + sorted(bin_dir.glob("*.exe")):
            if p not in targets and p.stat().st_size < 80 << 20:
                targets.append(p)
        for p in targets[:6]:
            try:
                cr = crack_target(
                    p,
                    out=out / "crack" / p.stem,
                    deep_simd=("dll" in p.suffix.lower()),
                    apply_gates=True,
                )
                crack_results.append({
                    "target": str(p),
                    "verdict": cr.get("verdict"),
                    "report_md": cr.get("report_md"),
                    "actions": cr.get("actions"),
                    "errors": cr.get("errors"),
                })
            except Exception as e:
                crack_results.append({"target": str(p), "error": str(e)})
        report["auto_crack"] = crack_results
        report["operator_notes"].append("auto_crack ran on downloaded bins → out/crack/")

    (out / "cdn_report.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    return report
