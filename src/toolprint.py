"""MCP Toolprint — change detection for MCP tool definitions.

The format is specified in SPEC.md in this repository.

A toolprint is a digest over a tool's definition AS PRESENTED to
an agent: name, description, input schema, and the stated terms
where present. An agent pins the definition it was shown at
approval time; before a later call it submits the definition it
is being shown in the current session, and the service answers
one of three factual states — match, changed (with a field-level
diff), or unknown (no print on record).

THE CORE PRINCIPLE. The service detects change. It does not
judge it. No response field, error, or document from this module
characterizes a change or a tool; the vocabulary is limited to
the facts: what was pinned, when, by whom, and which fields
differ. BANNED_WORDS below is the mechanical form of that rule —
the test suite sweeps every emitted payload against it.

THE AGENT IS THE SENSOR. The service never connects to, fetches,
or polls the target MCP server. The baseline is pinned from the
definition as shown to the agent, and every check submits the
definition as presented in that session — so a server on a
private network this service has never seen is fully covered.

PINNING TIERS. `provider`: the provider signed the print core
with its own did:key (house object-signature pattern). `observed`:
an agent pinned the first definition it was shown, attested by
its signed pin request. Neither tier outranks the other in a
response; the response states the tier and the caller weights it.

DIGESTS are the scheme in src/jcs.py + src/signing.py: field
digests are SHA-256 over the field's exact UTF-8 bytes (strings)
or jcs.hash_obj() (objects); the print digest is jcs.hash_obj()
of the JCS-clean print core {"v": 1, "server", "tool", "fields"}.

FLOAT RULE. jcs rejects floats; wild input schemas contain them
(numeric defaults). Numbers are normalized before hashing:
integral floats become integers, non-integral floats become
their shortest round-trip decimal string. A value that cannot
be normalized (a non-finite float) is rejected with a 400
naming the path — the service never guesses. Definitions are
stored in their normalized form: the form the digest is
computed over.

STORAGE goes through a small store interface. SupabaseStore
speaks PostgREST to two tables (toolprint_prints /
toolprint_events) through a caller-supplied helper; MemoryStore
is an in-memory twin with the same interface, used by the
tests and by the standalone server in src/server.py. Events
are append-only: pin events and first-observation-of-a-new-
digest events only — raw checks are not stored.
"""

import hashlib
import math
import threading
from datetime import datetime, timezone
from urllib.parse import quote

import jcs
import signing as core

API_BASE = "https://stream-presence-pow.onrender.com"
MCP_PATH = "/mcp/toolprint"
MAX_SERVER_CHARS = 2000
MAX_TOOL_CHARS = 200
MAX_DESCRIPTION_CHARS = 20000

# The neutrality rule, mechanically: none of these words may
# appear in any field or string this service emits.
BANNED_WORDS = ("suspicious", "risky", "safe", "unsafe",
                "malicious", "tampered", "threat", "trusted",
                "untrusted")

_lock = threading.Lock()


class ToolprintError(Exception):
    """(http_status, message) rejection of a Toolprint call."""

    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


# ------------------------------------------------------------ time

def _norm_ts(ts):
    """Canonical 'YYYY-MM-DDTHH:MM:SSZ' form. PostgREST returns
    '+00:00'-style offsets; normalize before display or any
    comparison so a read-back matches the inserted form."""
    if ts is None:
        return None
    s = str(ts)
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return s
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# -------------------------------------------------- canonical form

def _normalize_numbers(obj, path, field):
    """Copy obj with every float normalized per the float rule.
    Raises ToolprintError(400) naming the path of a float that
    cannot be normalized (non-finite)."""
    if isinstance(obj, float):
        if not math.isfinite(obj):
            raise ToolprintError(
                400, f"{field} is not canonicalizable "
                     f"(unnormalized float at {path})")
        if obj == int(obj):
            return int(obj)
        return repr(obj)
    if isinstance(obj, list):
        return [_normalize_numbers(v, f"{path}[{i}]", field)
                for i, v in enumerate(obj)]
    if isinstance(obj, dict):
        return {k: _normalize_numbers(v, f"{path}.{k}", field)
                for k, v in obj.items()}
    return obj


def _field_digest(value, field):
    """The field digest: exact UTF-8 bytes for strings,
    jcs.hash_obj for objects, None stays None."""
    if value is None:
        return None
    if isinstance(value, str):
        return "sha256:" + hashlib.sha256(
            value.encode("utf-8")).hexdigest()
    return jcs.hash_obj(value)


def _check_pair(server, tool):
    if not isinstance(server, str) or not server:
        raise ToolprintError(400, "server is required")
    if len(server) > MAX_SERVER_CHARS:
        raise ToolprintError(400, "server exceeds the "
                                  f"{MAX_SERVER_CHARS}-char cap")
    if not isinstance(tool, str) or not tool:
        raise ToolprintError(400, "tool is required")
    if len(tool) > MAX_TOOL_CHARS:
        raise ToolprintError(400, "tool exceeds the "
                                  f"{MAX_TOOL_CHARS}-char cap")
    return server, tool


def compute_print(server, tool, definition):
    """(print_core, digest, print_id, normalized_definition).

    Validates the definition's shape and computes every digest
    from the normalized form. Raises ToolprintError(400) on a
    malformed definition or an uncanonicalizable number."""
    _check_pair(server, tool)
    if not isinstance(definition, dict):
        raise ToolprintError(400, "definition must be an object")
    description = definition.get("description")
    if not isinstance(description, str):
        raise ToolprintError(400, "definition.description is "
                                  "required (a string)")
    if len(description) > MAX_DESCRIPTION_CHARS:
        raise ToolprintError(
            400, "definition.description exceeds the "
                 f"{MAX_DESCRIPTION_CHARS}-char cap")
    schema = definition.get("input_schema")
    if not isinstance(schema, dict):
        raise ToolprintError(400, "definition.input_schema is "
                                  "required (an object)")
    schema = _normalize_numbers(schema, "$", "input_schema")
    terms = definition.get("terms")
    if terms is not None and not isinstance(terms, (str, dict)):
        raise ToolprintError(400, "definition.terms must be a "
                                  "string, an object, or null")
    if isinstance(terms, dict):
        terms = _normalize_numbers(terms, "$", "terms")
    normalized = {"description": description,
                  "input_schema": schema, "terms": terms}
    fields = {"name": _field_digest(tool, "name"),
              "description": _field_digest(description,
                                           "description"),
              "input_schema": _field_digest(schema,
                                            "input_schema"),
              "terms": _field_digest(terms, "terms")}
    print_core = {"v": 1, "server": server, "tool": tool,
                  "fields": fields}
    digest = jcs.hash_obj(print_core)
    print_id = "tp_" + digest[len("sha256:"):][:24]
    return print_core, digest, print_id, normalized


# ------------------------------------------------------------ store

def _shape_print(row):
    return {"print_id": row["print_id"], "seq": row.get("seq"),
            "server": row["server"],
            "tool": row["tool"], "digest": row["digest"],
            "field_digests": row["field_digests"],
            "definition": row["definition"],
            "tier": row["tier"], "pinned_by": row["pinned_by"],
            "pinned_at": _norm_ts(row["pinned_at"]),
            "first_seen": _norm_ts(row["first_seen"]),
            "last_seen": _norm_ts(row["last_seen"]),
            "observations": row["observations"],
            "source": row.get("source")}


def _shape_event(row):
    return {"ts": _norm_ts(row["ts"]), "kind": row["kind"],
            "from_digest": row.get("from_digest"),
            "to_digest": row["to_digest"],
            "actor": row.get("actor")}


class SupabaseStore:
    """Toolprint store over a PostgREST-style helper callable
    sb(path, method, body, query) -> parsed JSON, speaking to
    the toolprint_prints / toolprint_events tables."""

    def __init__(self, sb):
        self._sb = sb

    def get_print(self, print_id):
        rows = self._sb("toolprint_prints", "GET", None,
                        "print_id=eq." + quote(print_id, safe="")
                        + "&select=*")
        return _shape_print(rows[0]) if rows else None

    def add_print(self, row):
        rows = self._sb("toolprint_prints", "POST", row)
        return _shape_print(rows[0]) if rows else dict(row)

    def prints_for(self, server, tool):
        q = ("server=eq." + quote(server, safe="")
             + "&tool=eq." + quote(tool, safe="")
             + "&select=*&order=seq.asc")
        rows = self._sb("toolprint_prints", "GET", None, q)
        return [_shape_print(r) for r in (rows or [])]

    def touch_print(self, print_id, observations, last_seen):
        self._sb("toolprint_prints", "PATCH",
                 {"observations": observations,
                  "last_seen": last_seen},
                 "print_id=eq." + quote(print_id, safe=""))

    def add_event(self, row):
        self._sb("toolprint_events", "POST", row)

    def events_for(self, server, tool):
        q = ("server=eq." + quote(server, safe="")
             + "&tool=eq." + quote(tool, safe="")
             + "&select=*&order=ts.asc,id.asc")
        rows = self._sb("toolprint_events", "GET", None, q)
        return [_shape_event(r) for r in (rows or [])]


class MemoryStore:
    """In-memory store with the same interface — tests only."""

    def __init__(self):
        self._prints = {}
        self._events = []

    def get_print(self, print_id):
        row = self._prints.get(print_id)
        return _shape_print(row) if row else None

    def add_print(self, row):
        self._prints[row["print_id"]] = dict(row)
        return self.get_print(row["print_id"])

    def prints_for(self, server, tool):
        rows = [r for r in self._prints.values()
                if r["server"] == server and r["tool"] == tool]
        rows.sort(key=lambda r: (r["seq"], r["print_id"]))
        return [_shape_print(r) for r in rows]

    def touch_print(self, print_id, observations, last_seen):
        self._prints[print_id]["observations"] = observations
        self._prints[print_id]["last_seen"] = last_seen

    def add_event(self, row):
        self._events.append(dict(row))

    def events_for(self, server, tool):
        rows = [e for e in self._events
                if e["server"] == server and e["tool"] == tool]
        rows.sort(key=lambda e: e["ts"])
        return [_shape_event(e) for e in rows]


# ------------------------------------------------------- signatures

def _check_did_present(did):
    if not isinstance(did, str) \
            or not did.startswith("did:key:"):
        raise ToolprintError(400, "did (did:key) is required")
    return did


def _verify_envelope(did, obj, signature):
    try:
        ok = isinstance(signature, str) and bool(signature) \
            and core.verify_signature(did, jcs.canonical(obj),
                                      signature)
    except Exception:
        ok = False
    if not ok:
        raise ToolprintError(403, "signature does not verify "
                                  "for this did")


def check_signature_valid(server, tool, definition, did,
                          signature):
    """(current_digest) — verify a check call's optional signed
    identity: the signature over {"action": "toolprint_check",
    "did", "current_digest"}. Raises ToolprintError(403) when a
    supplied signature does not verify — a supplied signature is
    never silently downgraded to an anonymous call."""
    _check_did_present(did)
    _, digest, _, _ = compute_print(server, tool, definition)
    _verify_envelope(
        did, {"action": "toolprint_check", "did": did,
              "current_digest": digest}, signature)
    return digest


# ------------------------------------------------------------- pin

def pin_print(store, server, tool, definition, did, signature,
              provider_signature=None, source=None):
    """Pin (or re-pin) a print. Always signed. Returns the
    print record in the spec's pin output shape."""
    _check_did_present(did)
    print_core, digest, print_id, normalized = compute_print(
        server, tool, definition)
    _verify_envelope(
        did, {"action": "toolprint_pin", "did": did,
              "print_digest": digest}, signature)
    tier, pinned_by = "observed", did
    if provider_signature is not None:
        pdid = provider_signature.get("did") \
            if isinstance(provider_signature, dict) else None
        psig = provider_signature.get("signature") \
            if isinstance(provider_signature, dict) else None
        _check_did_present(pdid)
        try:
            ok = isinstance(psig, str) and bool(psig) \
                and core.verify_signature(
                    pdid, jcs.canonical(print_core), psig)
        except Exception:
            ok = False
        if not ok:
            raise ToolprintError(
                403, "provider_signature does not verify for "
                     "its did")
        tier, pinned_by = "provider", pdid
    now = core.now_iso()
    with _lock:
        existing = store.get_print(print_id)
        if existing is not None:
            # Idempotent: the print is already on record; this
            # pin is an observation of it, not a duplicate.
            store.touch_print(print_id,
                              existing["observations"] + 1, now)
            existing["observations"] += 1
            existing["last_seen"] = now
            return _pin_output(existing)
        prints = store.prints_for(server, tool)
        prev_digest = prints[-1]["digest"] if prints else None
        row = store.add_print({
            "print_id": print_id, "seq": len(prints) + 1,
            "server": server, "tool": tool,
            "digest": digest,
            "field_digests": print_core["fields"],
            "definition": normalized, "tier": tier,
            "pinned_by": pinned_by, "pinned_at": now,
            "first_seen": now, "last_seen": now,
            "observations": 1, "source": source})
        store.add_event({
            "server": server, "tool": tool, "kind": "pin",
            "ts": now, "from_digest": prev_digest,
            "to_digest": digest, "actor": pinned_by})
        return _pin_output(row)


def _pin_output(row):
    return {"print_id": row["print_id"], "server": row["server"],
            "tool": row["tool"], "digest": row["digest"],
            "tier": row["tier"], "pinned_by": row["pinned_by"],
            "pinned_at": row["pinned_at"],
            "fields": row["field_digests"]}


# ----------------------------------------------------------- check

def _changed_fields(compared, definition, current_fields):
    """The field-level diff: digests for every differing field,
    full values for string fields (digests only for the schema
    and for object terms)."""
    pinned_def = compared["definition"]
    out = []
    for field in ("name", "description", "input_schema", "terms"):
        pd = compared["field_digests"].get(field)
        cd = current_fields.get(field)
        if pd == cd:
            continue
        entry = {"field": field, "pinned_digest": pd,
                 "current_digest": cd}
        if field == "description":
            entry["pinned_value"] = pinned_def.get("description")
            entry["current_value"] = definition.get("description")
        elif field == "terms":
            pv, cv = pinned_def.get("terms"), \
                definition.get("terms")
            if isinstance(pv, str) and isinstance(cv, str):
                entry["pinned_value"] = pv
                entry["current_value"] = cv
        out.append(entry)
    return out


def _latest_observed(prints, events, exclude_digest,
                     compared_digest):
    """(digest, ts) of the most recent observation of a digest
    other than the current submission's and the compared
    print's — or (None, None). A statement of record only."""
    best = (None, None)
    for p in prints:
        if p["digest"] in (exclude_digest, compared_digest):
            continue
        if best[1] is None or p["last_seen"] > best[1]:
            best = (p["digest"], p["last_seen"])
    for e in events:
        if e["to_digest"] in (exclude_digest, compared_digest):
            continue
        if best[1] is None or e["ts"] > best[1]:
            best = (e["to_digest"], e["ts"])
    return best


def check_print(store, server, tool, definition, did=None):
    """The call-time check. `did` is the caller's verified
    signed identity when one was supplied (used only as the
    observation actor); any metering is the caller's layer."""
    print_core, digest, _, normalized = compute_print(
        server, tool, definition)
    current_fields = print_core["fields"]
    now = core.now_iso()
    with _lock:
        prints = store.prints_for(server, tool)
        events = store.events_for(server, tool)
        known = {p["digest"] for p in prints}
        known.update(e["to_digest"] for e in events)
        matched = next((p for p in prints
                        if p["digest"] == digest), None)
        if matched is not None:
            store.touch_print(matched["print_id"],
                              matched["observations"] + 1, now)
            matched["observations"] += 1
            matched["last_seen"] = now
        elif digest not in known:
            store.add_event({
                "server": server, "tool": tool,
                "kind": "first_observation", "ts": now,
                "from_digest": (prints[-1]["digest"]
                                if prints else None),
                "to_digest": digest, "actor": did})
            events.append({"ts": now, "kind": "first_observation",
                           "from_digest": (prints[-1]["digest"]
                                           if prints else None),
                           "to_digest": digest, "actor": did})
        if not prints:
            return {"status": "unknown", "server": server,
                    "tool": tool, "current_digest": digest,
                    "checked_at": now, "prints_on_record": 0,
                    "note": "No print is on record for this tool. "
                            "The definition presented in this "
                            "session can be pinned as the "
                            "reference print with pin_toolprint."}
        compared = prints[-1]
        out = {"server": server, "tool": tool,
               "print_id": compared["print_id"],
               "tier": compared["tier"],
               "pinned_by": compared["pinned_by"],
               "pinned_at": compared["pinned_at"],
               "checked_at": now,
               "prints_on_record": len(prints)}
        latest_digest, latest_at = _latest_observed(
            prints, events, digest, compared["digest"])
        if digest == compared["digest"]:
            out.update({"status": "match",
                        "digest": compared["digest"]})
        else:
            out.update({
                "status": "changed",
                "pinned_digest": compared["digest"],
                "current_digest": digest,
                "changed_fields": _changed_fields(
                    compared, normalized, current_fields),
                "note": "The definition presented in this "
                        "session differs from the print pinned "
                        f"{compared['pinned_at']} in the fields "
                        "listed. No assessment of the change "
                        "is made."})
        if latest_digest is not None:
            out["latest_observed_digest"] = latest_digest
            out["latest_observed_at"] = latest_at
        return out


# --------------------------------------------------------- history

def history(store, server, tool):
    _check_pair(server, tool)
    prints = store.prints_for(server, tool)
    events = store.events_for(server, tool)
    out_prints = []
    for p in prints:
        entry = {"print_id": p["print_id"],
                 "digest": p["digest"], "tier": p["tier"],
                 "pinned_by": p["pinned_by"],
                 "pinned_at": p["pinned_at"],
                 "first_seen": p["first_seen"],
                 "last_seen": p["last_seen"],
                 "observations": p["observations"],
                 "fields": p["field_digests"],
                 "definition": p["definition"]}
        if p.get("source"):
            entry["source"] = p["source"]
        out_prints.append(entry)
    return {"server": server, "tool": tool,
            "prints": out_prints,
            "change_events": [
                {"ts": e["ts"],
                 "from_digest": e["from_digest"],
                 "to_digest": e["to_digest"],
                 "observed_by": e["actor"]} for e in events]}


# ----------------------------------------------------- entry point

def entry_document():
    return {
        "name": "MCP Toolprint",
        "what": "A registry of toolprints: digests over MCP "
                "tool definitions as presented to an agent "
                "(name, description, input schema, and the "
                "stated terms where present). Pin the "
                "definition shown at approval time; before a "
                "later call, check the definition being shown "
                "in the current session. The answer is one of "
                "three factual states — match, changed (with "
                "a field-level diff), or unknown (no print on "
                "record). The service reports which fields "
                "differ; it makes no assessment of any change, "
                "and it never blocks a call — the calling agent "
                "decides what to do with the fact.",
        "no_endorsement": "A provider-signed print means the "
                          "provider signed this definition on "
                          "this date — nothing more. A print "
                          "on record is a record of what was "
                          "presented, not an endorsement of the "
                          "tool.",
        "mcp": f"POST {MCP_PATH} (Streamable HTTP) — tools: "
               "pin_toolprint, check_toolprint, "
               "toolprint_history",
        "rest": {
            "pin": "POST /api/v1/toolprints/pin — signed "
                   "{server, tool, definition, did, signature"
                   "} (signature over the JCS-canonical "
                   "{\"action\": \"toolprint_pin\", \"did\": "
                   "did, \"print_digest\": digest}); add "
                   "provider_signature {did, signature} over "
                   "the print core to record the print at the "
                   "provider tier",
            "check": "POST /api/v1/toolprints/check — "
                     "{server, tool, definition}; identity "
                     "optional: add {did, signature} over "
                     "{\"action\": \"toolprint_check\", "
                     "\"did\": did, \"current_digest\": "
                     "digest} to meter under your did:key — a "
                     "supplied signature that does not verify "
                     "is a 403, never a silent downgrade",
            "history": "GET /api/v1/toolprints/history?"
                       "server=<urlencoded>&tool=<name>"},
        "tiers": {
            "provider": "the provider signed the print core "
                        "with its own did:key",
            "observed": "an agent pinned the first definition "
                        "it was shown, attested by its signed "
                        "pin request (trust on first use)"},
        "private_servers": "The service never connects to the "
                           "target server. The agent is the "
                           "sensor: the baseline is pinned "
                           "from the definition as shown to "
                           "the agent, and each check submits "
                           "the definition as presented in "
                           "that session, so servers on private "
                           "networks are covered by the same "
                           "calls.",
        "billing": "Checks: 1,000 free per customer per day, "
                   "then $0.001 per check. Pins: 100 free per "
                   "day, then $0.01. History reads: 1,000 free "
                   "per day, then $0.001. One meter, one "
                   "spending cap — see "
                   "https://streampresence.dev/docs/billing",
        "docs": "https://streampresence.dev/docs/toolprints"}
