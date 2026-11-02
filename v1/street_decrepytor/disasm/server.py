# language: Python 3, file: disasm/server.py
# Tiny JSON HTTP API for StreetDbg UI (x64dbg-like front-end)
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from street_decrepytor.disasm.engine import disassemble_blob, disassemble_pe


class _State:
    pe_path: str | None = None
    listing: dict[str, Any] | None = None


STATE = _State()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        pass  # quiet

    def _json(self, code: int, obj: Any) -> None:
        body = json.dumps(obj, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/health":
            self._json(200, {"ok": True, "service": "street-dbg-disasm"})
            return
        if u.path == "/pe":
            self._json(200, {"path": STATE.pe_path, "loaded": STATE.listing is not None})
            return
        if u.path == "/listing":
            if not STATE.listing:
                self._json(404, {"error": "no_listing"})
                return
            start = int(q.get("start", ["0"])[0], 0)
            count = int(q.get("count", ["200"])[0])
            ins = STATE.listing.get("instructions") or []
            # find index by addr
            idx = 0
            if start:
                for i, row in enumerate(ins):
                    if int(row["addr"], 16) >= start:
                        idx = i
                        break
            chunk = ins[idx : idx + count]
            self._json(200, {
                "base": STATE.listing.get("base"),
                "total": len(ins),
                "index": idx,
                "instructions": chunk,
                "functions": STATE.listing.get("functions", [])[:200],
            })
            return
        if u.path == "/functions":
            if not STATE.listing:
                self._json(404, {"error": "no_listing"})
                return
            self._json(200, {"functions": STATE.listing.get("functions", [])})
            return
        if u.path == "/xrefs":
            if not STATE.listing:
                self._json(404, {"error": "no_listing"})
                return
            addr = q.get("addr", [None])[0]
            xrefs = STATE.listing.get("xrefs") or []
            if addr:
                xrefs = [x for x in xrefs if x.get("to") == addr or x.get("from") == addr]
            self._json(200, {"xrefs": xrefs[:200]})
            return
        self._json(404, {"error": "not_found"})

    def do_POST(self) -> None:
        u = urlparse(self.path)
        n = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(n) if n else b"{}"
        try:
            body = json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            self._json(400, {"error": "bad_json"})
            return
        if u.path == "/open":
            path = body.get("path")
            if not path or not Path(path).is_file():
                self._json(400, {"error": "bad_path"})
                return
            max_insns = int(body.get("max_insns", 80000))
            recursive = bool(body.get("recursive", True))
            rva = body.get("rva")
            if rva is not None:
                rva = int(rva, 0) if isinstance(rva, str) else int(rva)
            try:
                result = disassemble_pe(path, recursive=recursive, max_insns=max_insns, rva=rva)
                STATE.pe_path = str(Path(path).resolve())
                STATE.listing = result.to_dict()
                self._json(200, {
                    "ok": True,
                    "path": STATE.pe_path,
                    "insn_count": result.to_dict()["insn_count"],
                    "functions": len(result.functions),
                    "base": result.to_dict()["base"],
                })
            except Exception as e:
                self._json(500, {"error": str(e)})
            return
        if u.path == "/disasm_bytes":
            hx = body.get("hex", "")
            base = int(body.get("base", "0"), 0) if isinstance(body.get("base", 0), str) else int(body.get("base", 0))
            try:
                code = bytes.fromhex(hx.replace(" ", ""))
                result = disassemble_blob(code, base, recursive=False, max_insns=5000)
                self._json(200, result.to_dict())
            except Exception as e:
                self._json(500, {"error": str(e)})
            return
        self._json(404, {"error": "not_found"})


def serve(host: str = "127.0.0.1", port: int = 39847) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer((host, port), Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd


def main_blocking(host: str = "127.0.0.1", port: int = 39847) -> None:
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(json.dumps({"ok": True, "url": f"http://{host}:{port}", "endpoints": [
        "GET /health", "POST /open", "GET /listing", "GET /functions", "GET /xrefs", "POST /disasm_bytes"
    ]}))
    httpd.serve_forever()
