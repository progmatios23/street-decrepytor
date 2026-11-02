# language: Python 3.11+, file: server/api.py
# HTTP JSON API — live IDA-like endpoints + auto-refresh session
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from street_v2.live.session import LiveSession


class _Hub:
    session: LiveSession | None = None
    httpd: ThreadingHTTPServer | None = None


HUB = _Hub()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        pass

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
        s = HUB.session

        if u.path == "/health":
            self._json(200, {
                "ok": True,
                "service": "street-decrepytor-v2",
                "version": "2.0.0",
                "loaded": s is not None and s.snapshot is not None,
            })
            return

        if u.path == "/status":
            if not s:
                self._json(404, {"error": "no_session"})
                return
            self._json(200, s.status())
            return

        if u.path == "/snapshot":
            if not s or not s.snapshot:
                self._json(404, {"error": "no_snapshot"})
                return
            self._json(200, s.snapshot.to_dict())
            return

        if u.path == "/pe":
            if not s or not s.pe:
                self._json(404, {"error": "no_pe"})
                return
            self._json(200, s.pe.to_dict())
            return

        if u.path == "/entropy":
            if not s or not s.entropy:
                self._json(404, {"error": "no_entropy"})
                return
            self._json(200, s.entropy.to_dict())
            return

        if u.path == "/crypto":
            if not s or not s.crypto:
                self._json(404, {"error": "no_crypto"})
                return
            self._json(200, s.crypto.to_dict())
            return

        if u.path == "/functions":
            if not s or not s.ida:
                self._json(404, {"error": "no_ida"})
                return
            self._json(200, {"functions": s.ida.functions})
            return

        if u.path == "/xrefs":
            if not s or not s.ida:
                self._json(404, {"error": "no_ida"})
                return
            addr = q.get("addr", [None])[0]
            xt = q.get("type", [None])[0]
            rep = s.ida.xref_report
            if xt and rep:
                key = {"str": "string"}.get(xt, xt)
                items = rep.get(key) or []
                if addr:
                    items = [x for x in items if x.get("to") == addr or x.get("from") == addr]
                self._json(200, {"type": xt, "xrefs": items[:500], "counts": rep.get("counts")})
                return
            xrefs = s.ida.xrefs
            if addr:
                xrefs = [x for x in xrefs if x.get("to") == addr or x.get("from") == addr]
            self._json(200, {"xrefs": xrefs[:500], "counts": (rep or {}).get("counts")})
            return

        if u.path == "/listing":
            if not s or not s.ida:
                self._json(404, {"error": "no_ida"})
                return
            start = int(q.get("start", ["0"])[0], 0)
            count = int(q.get("count", ["200"])[0])
            self._json(200, s.ida.listing_slice(start, count))
            return

        if u.path == "/emu":
            if not s or not s.emu:
                self._json(404, {"error": "no_emu"})
                return
            self._json(200, s.emu.to_dict())
            return

        if u.path == "/report":
            if not s or not s.snapshot or not s.snapshot.report_paths:
                self._json(404, {"error": "no_report"})
                return
            self._json(200, s.snapshot.report_paths)
            return

        self._json(404, {"error": "not_found", "endpoints": [
            "GET /health /status /snapshot /pe /entropy /crypto",
            "GET /functions /xrefs /listing /emu /report",
            "POST /open /refresh /watch /stop",
        ]})

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
            interval = float(body.get("interval_sec", 2.0))
            out_dir = body.get("out_dir")
            run_emu = bool(body.get("run_emu", True))
            if HUB.session:
                HUB.session.stop_watch()
            HUB.session = LiveSession(
                path,
                out_dir=out_dir,
                interval_sec=interval,
                run_emu=run_emu,
                max_insns_disasm=int(body.get("max_insns_disasm", 60000)),
                max_insns_emu=int(body.get("max_insns_emu", 20000)),
            )
            try:
                snap = HUB.session.refresh(force=True)
                auto_watch = bool(body.get("watch", True))
                if auto_watch:
                    HUB.session.start_watch()
                self._json(200, {
                    "ok": True,
                    "status": HUB.session.status(),
                    "snapshot": snap.to_dict(),
                })
            except Exception as e:
                self._json(500, {"error": str(e)})
            return

        if u.path == "/refresh":
            if not HUB.session:
                self._json(404, {"error": "no_session"})
                return
            try:
                snap = HUB.session.refresh(force=True)
                self._json(200, {"ok": True, "snapshot": snap.to_dict()})
            except Exception as e:
                self._json(500, {"error": str(e)})
            return

        if u.path == "/watch":
            if not HUB.session:
                self._json(404, {"error": "no_session"})
                return
            if "interval_sec" in body:
                HUB.session.interval_sec = float(body["interval_sec"])
            HUB.session.start_watch()
            self._json(200, {"ok": True, "status": HUB.session.status()})
            return

        if u.path == "/stop":
            if HUB.session:
                HUB.session.stop_watch()
            self._json(200, {"ok": True, "status": HUB.session.status() if HUB.session else None})
            return

        self._json(404, {"error": "not_found"})


def serve_live(host: str = "127.0.0.1", port: int = 39848) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer((host, port), Handler)
    HUB.httpd = httpd
    t = threading.Thread(target=httpd.serve_forever, name="street-v2-http", daemon=True)
    t.start()
    return httpd


def main_blocking(host: str = "127.0.0.1", port: int = 39848) -> None:
    httpd = ThreadingHTTPServer((host, port), Handler)
    HUB.httpd = httpd
    print(json.dumps({
        "ok": True,
        "url": f"http://{host}:{port}",
        "service": "street-decrepytor-v2",
        "endpoints": [
            "GET /health /status /snapshot /pe /entropy /crypto",
            "GET /functions /xrefs?addr= /listing?start=&count=",
            "GET /emu /report",
            "POST /open {path, interval_sec, watch, run_emu, out_dir}",
            "POST /refresh /watch /stop",
        ],
    }))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        if HUB.session:
            HUB.session.stop_watch()
        httpd.shutdown()
