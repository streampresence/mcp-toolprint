#!/usr/bin/env python3
"""Standalone MCP Toolprint server (stdlib HTTP only).

Wires src/mcp_toolprint.py (the MCP protocol layer) and
src/toolprint.py (the registry logic) to HTTP:

  POST /mcp/toolprint                 MCP Streamable HTTP
  POST /api/v1/toolprints/pin         REST pin
  POST /api/v1/toolprints/check       REST check
  GET  /api/v1/toolprints/history     REST history (?server=&tool=)
  GET  /api/v1/toolprints             the entry document

State: by default the registry lives in a MemoryStore and
resets when the process restarts. For durable state, pass a
SupabaseStore (see toolprint.py) built on your own PostgREST
helper — that is what the hosted Stream Presence instance
does. This reference server carries no metering; the hosted
service's free allowances and rates are in the README.

Run: python3 src/server.py [port]        (default 8080)
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import mcp_toolprint
import toolprint

STORE = toolprint.MemoryStore()
mcp_toolprint.set_store(STORE)


def _toolprint_error(e):
    return e.status, {"error": e.message}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _send(self, status, obj):
        body = b"" if obj is None else json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        return json.loads(raw) if raw else {}

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/mcp/toolprint":
            return self._send(405, {"error": "method not allowed"})
        if path == "/api/v1/toolprints":
            return self._send(200, toolprint.entry_document())
        if path == "/api/v1/toolprints/history":
            q = parse_qs(urlparse(self.path).query)
            try:
                out = toolprint.history(
                    STORE, (q.get("server") or [None])[0],
                    (q.get("tool") or [None])[0])
            except toolprint.ToolprintError as e:
                return self._send(*_toolprint_error(e))
            return self._send(200, out)
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            body = self._body()
        except (ValueError, UnicodeDecodeError):
            return self._send(400, {"error": "invalid JSON body"})
        if path == "/mcp/toolprint":
            messages = body if isinstance(body, list) else [body]
            out = [r for r in (mcp_toolprint.handle_message(m)
                               for m in messages) if r is not None]
            if not out:
                return self._send(202, None)
            return self._send(200, out[0] if len(out) == 1 else out)
        if path == "/api/v1/toolprints/pin":
            try:
                out = toolprint.pin_print(
                    STORE, body.get("server"), body.get("tool"),
                    body.get("definition"), body.get("did"),
                    body.get("signature"),
                    body.get("provider_signature"))
            except toolprint.ToolprintError as e:
                return self._send(*_toolprint_error(e))
            return self._send(201, out)
        if path == "/api/v1/toolprints/check":
            did = None
            if body.get("did") is not None \
                    or body.get("signature") is not None:
                try:
                    toolprint.check_signature_valid(
                        body.get("server"), body.get("tool"),
                        body.get("definition"), body.get("did"),
                        body.get("signature"))
                except toolprint.ToolprintError as e:
                    return self._send(*_toolprint_error(e))
                did = body.get("did")
            try:
                out = toolprint.check_print(
                    STORE, body.get("server"), body.get("tool"),
                    body.get("definition"), did=did)
            except toolprint.ToolprintError as e:
                return self._send(*_toolprint_error(e))
            return self._send(200, out)
        return self._send(404, {"error": "not found"})


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
