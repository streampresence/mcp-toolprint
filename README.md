# MCP Toolprint

**Pin an MCP tool's definition at approval time. Check it at call time.**

You wouldn't drive a car whose brakes were taken out overnight and call it the same car. A tool that changes after you approved it isn't the same tool.

An MCP tool's definition — its description, its input schema, the terms it was offered under — is presented to an agent when the agent (or its operator) approves the tool. After that, the definition can change: a sentence added to the description, a new parameter in the schema, different terms. Nothing in the protocol announces the change, and the agent goes on calling what it believes is the approved tool.

MCP Toolprint records a **toolprint**: a digest over a tool's definition exactly as presented. Pin the definition shown at approval time; before a later call, check the definition being shown in the current session. The answer is one of three factual states:

- **match** — the definition presented now is the definition on record.
- **changed** — it differs, and the response lists the fields that differ (values for text fields, digests for the schema).
- **unknown** — no print is on record for this tool; the response carries the current digest so the definition can be pinned.

The service detects change. It does not judge it. A changed print is a fact to put in front of the calling agent, whose own policy decides what to do with it — the service never blocks a call, and no response it emits characterizes a change or a tool. Registration confers no endorsement: **a provider-signed print means the provider signed this definition on this date — nothing more.**

## Use the hosted service

- **MCP endpoint:** `POST https://stream-presence-pow.onrender.com/mcp/toolprint` (Streamable HTTP)
- **MCP Registry:** `dev.streampresence/mcp-toolprint`
- **REST:** `POST /api/v1/toolprints/pin` · `POST /api/v1/toolprints/check` · `GET /api/v1/toolprints/history?server=…&tool=…`
- **Docs:** https://streampresence.dev/docs/toolprints
- **Quickstart prompt:** https://streampresence.dev/toolprint-prompt.txt — hand it to an agent and it wires itself up end to end.

### The three tools

| Tool | What it does |
|---|---|
| `pin_toolprint` | Pin the reference print of a tool's definition as presented to you. Always signed with your did:key. Add the provider's signature over the print core to record the print at the provider tier. |
| `check_toolprint` | Check the definition presented in your current session against the print on record: match, changed (with the field-level diff), or unknown. |
| `toolprint_history` | Every distinct print on record for a (server, tool) pair, in first-seen order, plus the change events — each moment a new distinct digest was first observed. |

### Two tiers of print

- **Provider** — the provider signed the print core with its own did:key.
- **Observed** — an agent pinned the first definition it was shown, attested by its signed pin request (trust on first use).

Neither tier outranks the other in a response; the response states which tier the compared print is, and the caller weights it. If different agents have pinned divergent definitions for the same tool, the registry holds each distinct print and history shows all of them — a statement of record, with no conclusion drawn.

### Private servers are covered

The agent is the sensor. The service never connects to, fetches, or polls the target MCP server: the baseline is pinned from the definition as shown to the agent, and every check submits the definition as presented in that session. A server on a private network this service has never seen is fully covered, because it cannot present a changed definition to the agent without the agent's next check seeing the changed bytes.

### Pricing on the hosted service

Checks: **1,000 free per customer per day**, then $0.001 per check. Pins: 100 free per day, then $0.01. History reads: 1,000 free per day, then $0.001. Overage accrues pay-as-you-go against the customer's spending cap on the Stream Presence platform — see [billing](https://streampresence.dev/docs/billing).

## Run it yourself

The code in this repository is the code behind the hosted service's Toolprint surface (the hosted instance stores prints in Supabase via `SupabaseStore`; the standalone server below uses an in-memory store).

```bash
pip install -r requirements.txt
python3 src/server.py 8080
python3 tests/test_toolprint.py   # 50 checks
```

- `src/toolprint.py` — the registry: digest scheme, pin / check / history, both stores.
- `src/mcp_toolprint.py` — the standalone MCP protocol layer (three tools, nothing else).
- `src/server.py` — a stdlib HTTP reference server wiring both to the routes above.
- `src/jcs.py` — JCS (RFC 8785 subset) canonical JSON; `src/signing.py` — did:key / Ed25519 helpers.

## The format

[SPEC.md](SPEC.md) specifies the toolprint format: the digest scheme, the print record, the two tiers, and the three check responses — precisely enough to implement a compatible client or registry. The format is protocol-neutral: a toolprint is a digest over a presented definition, keyed by a string id.

## What a print does not cover

A print covers the definition *as shown*. It says nothing about a tool's runtime behavior — a tool can match its print and still do something unexpected in its handler. Prints record what was presented; delivery receipts record what was done. The two are complements, not substitutes.

## About

MCP Toolprint is a Stream Presence service. Stream Presence builds infrastructure for the agent economy — receipts, registries, and the records agents and their operators settle by. https://streampresence.dev

## License

MIT — see [LICENSE](LICENSE).
