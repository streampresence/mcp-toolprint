"""MCP Toolprint — standalone MCP server (Streamable HTTP).

A dedicated MCP endpoint for toolprint checks: a separate,
single-purpose server, not bundled with any other tools.
Three tools, nothing else: pin_toolprint, check_toolprint,
toolprint_history — thin protocol wrappers over
src/toolprint.py, the same code paths the REST surface
(/api/v1/toolprints) uses, so an MCP answer can never disagree
with a REST answer.

The service detects change in MCP tool definitions; it does
not judge it. Tool descriptions and instructions here follow
the same rule as the service's responses: facts only.

Transport: MCP Streamable HTTP, stateless. Each
POST /mcp/toolprint carries one JSON-RPC message (a batch
array is also accepted); requests get a JSON response,
notifications get 202, GET answers 405.

The format is specified in SPEC.md in this repository.
"""

import json

import toolprint

PROTOCOL_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"]
SERVER_INFO = {"name": "stream-presence-mcp-toolprint",
               "version": "1.0.0"}
INSTRUCTIONS = (
    "MCP Toolprint records digests (toolprints) over MCP tool "
    "definitions as presented to an agent: name, description, "
    "input schema, and stated terms where present. Pin the "
    "definition you were shown when a tool was approved "
    "(pin_toolprint); before calling a tool later, submit the "
    "definition you are being shown in the current session "
    "(check_toolprint) and the answer is match, changed (with "
    "the fields that differ), or unknown (no print on record). "
    "toolprint_history lists every print on record for a tool. "
    "The service reports what changed; it makes no assessment "
    "of any change, and it never blocks a call.")

_STORE = None


def set_store(store):
    """Wire the registry store (server_deploy passes the
    Supabase store; tests pass a MemoryStore)."""
    global _STORE
    _STORE = store


def _store():
    if _STORE is None:
        raise RuntimeError("toolprint store is not configured")
    return _STORE


TOOLS = [
    {"name": "pin_toolprint",
     "title": "Pin a toolprint",
     "description": "Pin the reference print of an MCP tool's "
                    "definition as presented to you: server "
                    "(the server's endpoint URL, or a "
                    "provider-chosen URN for a local server), "
                    "tool name, and the definition (description, "
                    "input_schema, terms where present). The "
                    "pin is signed: sign the JCS-canonical "
                    "bytes of {\"action\": \"toolprint_pin\", "
                    "\"did\": <your did>, \"print_digest\": "
                    "<digest>} with your Ed25519 key. To "
                    "record the print at the provider tier, add "
                    "provider_signature: {did, signature} — "
                    "the provider's signature over the print "
                    "core. Pinning a definition already on "
                    "record returns the existing print.",
     "inputSchema": {
         "type": "object",
         "properties": {
             "server": {"type": "string",
                        "description": "Server id: endpoint "
                                       "URL or provider URN"},
             "tool": {"type": "string",
                      "description": "The tool's name"},
             "definition": {
                 "type": "object",
                 "description": "The definition as "
                                "presented: description, "
                                "input_schema, terms (string, "
                                "object, or null)",
                 "properties": {
                     "description": {"type": "string"},
                     "input_schema": {"type": "object"},
                     "terms": {}},
                 "required": ["description", "input_schema"],
                 "additionalProperties": False},
             "did": {"type": "string",
                     "description": "Your did:key (did:key:z…)"},
             "signature": {"type": "string",
                           "description": "Base64url Ed25519 "
                                          "signature over the "
                                          "pin call object"},
             "provider_signature": {
                 "type": "object",
                 "description": "Optional {did, signature}: "
                                "the provider's signature over "
                                "the print core",
                 "properties": {
                     "did": {"type": "string"},
                     "signature": {"type": "string"}},
                 "required": ["did", "signature"],
                 "additionalProperties": False}},
         "required": ["server", "tool", "definition", "did",
                      "signature"],
         "additionalProperties": False},
     "annotations": {"readOnlyHint": False,
                     "idempotentHint": True,
                     "openWorldHint": False}},
    {"name": "check_toolprint",
     "title": "Check a toolprint",
     "description": "Check a tool's definition as presented "
                    "in your current session against the print "
                    "on record. Returns match, changed (with "
                    "the fields that differ — values for text "
                    "fields, digests for the schema), or "
                    "unknown (no print on record; the response "
                    "carries the current digest so the "
                    "definition can be pinned). Identity is "
                    "optional: pass did + signature over the "
                    "JCS-canonical {\"action\": "
                    "\"toolprint_check\", \"did\": <did>, "
                    "\"current_digest\": <digest>} to meter "
                    "under your did:key; a supplied signature "
                    "that does not verify is an error, never a "
                    "silent downgrade.",
     "inputSchema": {
         "type": "object",
         "properties": {
             "server": {"type": "string",
                        "description": "Server id: endpoint "
                                       "URL or provider URN"},
             "tool": {"type": "string",
                      "description": "The tool's name"},
             "definition": {
                 "type": "object",
                 "description": "The definition as "
                                "presented in this session",
                 "properties": {
                     "description": {"type": "string"},
                     "input_schema": {"type": "object"},
                     "terms": {}},
                 "required": ["description", "input_schema"],
                 "additionalProperties": False},
             "did": {"type": "string",
                     "description": "Optional: your did:key"},
             "signature": {"type": "string",
                           "description": "Optional: base64url "
                                          "Ed25519 signature "
                                          "over the check call "
                                          "object"}},
         "required": ["server", "tool", "definition"],
         "additionalProperties": False},
     "annotations": {"readOnlyHint": True,
                     "idempotentHint": True,
                     "openWorldHint": False}},
    {"name": "toolprint_history",
     "title": "Toolprint history",
     "description": "Every distinct print on record for a "
                    "(server, tool) pair, in first-seen order: "
                    "digest, tier, pinned by/at, first and "
                    "last seen, observation count, the field "
                    "digests, and the full pinned definition — "
                    "plus the change events: each moment a new "
                    "distinct digest was first observed for "
                    "the pair. Read-only; no signature "
                    "required.",
     "inputSchema": {
         "type": "object",
         "properties": {
             "server": {"type": "string",
                        "description": "Server id: endpoint "
                                       "URL or provider URN"},
             "tool": {"type": "string",
                      "description": "The tool's name"}},
         "required": ["server", "tool"],
         "additionalProperties": False},
     "annotations": {"readOnlyHint": True,
                     "idempotentHint": True,
                     "openWorldHint": False}},
]


# ------------------------------------------------------------- tools

def _tool_pin_toolprint(args):
    return toolprint.pin_print(
        _store(), args.get("server"), args.get("tool"),
        args.get("definition"), args.get("did"),
        args.get("signature"), args.get("provider_signature"))


def _tool_check_toolprint(args):
    did = None
    if args.get("did") is not None \
            or args.get("signature") is not None:
        # A supplied identity must verify — a hard failure,
        # never a silent downgrade to anonymous metering.
        toolprint.check_signature_valid(
            args.get("server"), args.get("tool"),
            args.get("definition"), args.get("did"),
            args.get("signature"))
        did = args.get("did")
    return toolprint.check_print(
        _store(), args.get("server"), args.get("tool"),
        args.get("definition"), did=did)


def _tool_toolprint_history(args):
    return toolprint.history(
        _store(), args.get("server"), args.get("tool"))


TOOL_FUNCS = {"pin_toolprint": _tool_pin_toolprint,
              "check_toolprint": _tool_check_toolprint,
              "toolprint_history": _tool_toolprint_history}


# ---------------------------------------------------------- protocol

def _result(rid, result):
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def _error(rid, code, message):
    return {"jsonrpc": "2.0", "id": rid,
            "error": {"code": code, "message": message}}


def handle_message(msg):
    """One JSON-RPC message → response dict, or None for
    notifications (which are answered 202 with no body)."""
    if not isinstance(msg, dict):
        return _error(None, -32600, "invalid request")
    method = msg.get("method")
    rid = msg.get("id")
    if method is None:
        return _error(rid, -32600, "invalid request: no method")
    if rid is None:  # notification — nothing to answer
        return None
    if method == "initialize":
        params = msg.get("params") or {}
        want = params.get("protocolVersion")
        version = want if want in PROTOCOL_VERSIONS \
            else PROTOCOL_VERSIONS[0]
        return _result(rid, {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": SERVER_INFO,
            "instructions": INSTRUCTIONS})
    if method == "ping":
        return _result(rid, {})
    if method == "tools/list":
        return _result(rid, {"tools": TOOLS})
    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        func = TOOL_FUNCS.get(name)
        if func is None:
            return _error(rid, -32602, f"unknown tool: {name}")
        if not isinstance(args, dict):
            return _error(rid, -32602, "arguments must be an object")
        try:
            out = func(args)
        except toolprint.ToolprintError as e:
            return _result(rid, {
                "content": [{"type": "text", "text": e.message}],
                "isError": True})
        except ValueError as e:
            return _result(rid, {
                "content": [{"type": "text", "text": str(e)}],
                "isError": True})
        except Exception as e:  # reported, not hidden
            return _result(rid, {
                "content": [{"type": "text",
                             "text": f"tool failed: {e}"}],
                "isError": True})
        return _result(rid, {
            "content": [{"type": "text",
                         "text": json.dumps(out, indent=2)}],
            "structuredContent": out,
            "isError": False})
    return _error(rid, -32601, f"method not found: {method}")
