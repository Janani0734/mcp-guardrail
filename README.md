# 🛡 MCP-Guardrail

![e2e](https://github.com/Janani0734/mcp-guardrail/actions/workflows/e2e-dashboard.yml/badge.svg)

**Approve AI agent actions before they execute.**

MCP-Guardrail is a human-in-the-loop safety and governance layer for AI agents
using the Model Context Protocol (MCP). It can run as a gateway in front of an
upstream MCP server: risky tool calls are inspected, policy rules are applied,
and high-risk actions are held as expiring approval requests until a human
approves or rejects them.

## Live demo

- Product landing page:  
  [https://janani0734.github.io/mcp-guardrail/](https://janani0734.github.io/mcp-guardrail/)

- Admin sandbox console:  
  Open the console from the landing page and sign in with `ADMIN_API_KEY`.

- Backend health check:  
  [https://mcp-guardrail-backend.onrender.com/healthz](https://mcp-guardrail-backend.onrender.com/healthz)

The backend runs on a free hosting tier and sleeps when idle. The first request
after a pause can take 20 to 60 seconds.

## How it works

```text
Claude / MCP client
        |
        | tool call
        v
MCP-Guardrail gateway or built-in MCP server
        |
        | Policy engine: DENY, REQUIRE_APPROVAL, or forward
        v
Supabase PostgreSQL
        |
        | Admin dashboard displays pending request
        v
Human approves or rejects
        |
        | Atomic database RPC
        v
Action forwarded / blocked / preserved
```

## Two modes

### Built-in sandbox tools

The built-in MCP server exposes `list_tasks`, `request_delete_task`, and
`get_request_status`. Deletion requests are policy-checked and held for human
approval before execution.

### Gateway proxy mode

MCP-Guardrail can also run as a gateway in front of a third-party MCP server.
Clients connect to the Guardrail gateway endpoint instead of the upstream
server. The gateway inspects `tools/call` requests, applies policy rules, and
either forwards, denies, or holds the call for human approval.

```text
Claude → MCP-Guardrail Gateway → Upstream MCP server
```

Gateway requests are stored with their original payload and upstream server
reference. When an administrator approves the request, the gateway forwards the
original tool call to the upstream server and records the forwarding outcome in
the audit chain.

## Manually verified MVP results

The complete approval loop has been manually tested end-to-end with Claude,
Supabase, Render, and the MCP-Guardrail dashboard. The dashboard itself is
covered by automated Playwright end-to-end tests in GitHub Actions.

| Test | Result |
|---|---|
| AI requests deletion | Approval request created as `PENDING` |
| Human approves deletion | Target task deleted; request became `COMMITTED` |
| Human rejects deletion (admin `ABORT`) | Target task preserved; request became `REJECTED`; decision recorded in the audit chain |
| Approval expires | No deletion executed; request became `EXPIRED` |
| Audit chain verification | `verified: true`; 15-event chain verified with no broken links |
| External R2 anchoring | `anchored: true` |
| AI requests deletion of a protected task | Server refused it; no approval request was created |
| Policy rule with custom expiry | Approval window was exactly 10 minutes instead of the 5-minute default |

## Features

- MCP tool integration over Streamable HTTP
- Gateway proxy mode for upstream MCP servers
- Expiring approval requests
- Human approval dashboard
- Approve and reject controls
- Persistent PostgreSQL state
- Atomic finalization through Supabase RPC
- Policy engine with database-stored rules (`DENY` / `REQUIRE_APPROVAL`)
- Per-rule approval windows (custom expiry)
- Protected tasks enforced by the server, not left to the AI client
- SHA-256 hash-chained audit trail
- External audit anchoring to Cloudflare R2
- Administrator API authentication
- CORS-restricted frontend access
- Automated GitHub Actions anchoring
- Playwright end-to-end tests for the dashboard, with a GitHub Actions workflow

## Connect Claude

Claude Desktop connects to the backend as a custom connector:

1. Open **Settings → Customize → Connectors**.
2. Choose **Add custom connector**.
3. Use the URL `https://mcp-guardrail-backend.onrender.com/mcp`.

Available built-in MCP tools: `list_tasks`, `request_delete_task`,
`get_request_status`.

## Gateway mode

To route Claude through the gateway, register an upstream MCP server and use
the gateway endpoint:

```text
[https://mcp-guardrail-backend.onrender.com/gateway/](https://mcp-guardrail-backend.onrender.com/gateway/)<upstream-server-id>/mcp
```

The gateway evaluates each `tools/call` request against the policy rules:

| Policy outcome | Behaviour |
|---|---|
| `DENY` | Request is blocked before reaching the upstream server |
| `REQUIRE_APPROVAL` | Request is held as a `PENDING` approval request |
| No matching rule | Request is held for approval with the default window |

Non-tool-call MCP traffic, such as `initialize` and `tools/list`, is forwarded
to the upstream server.

## Policy engine

Rules decide what happens when an AI agent calls a high-risk tool. They are
stored in the `policies` table (see `db/policies.sql`) and managed through
the admin API.

- **Matching:** a rule matches on tool name and a target pattern. Patterns use
  glob-style wildcards, so `temp-*` matches `temp-1`. Regular expressions are
  not accepted, avoiding ReDoS risk and ambiguous matching.
- **Priority:** rules are checked in ascending `priority` order, and the first
  match wins. Equal priorities are broken by creation time.
- **Actions:** `DENY` blocks the request before any approval request is
  created. `REQUIRE_APPROVAL` stages the request for a human.
- **Default:** with no matching rule, a human must approve, with a
  5-minute window.
- **Custom expiry:** a rule can set its own approval window with
  `expiry_seconds` (30 to 86400).
- **Fail closed:** if the policy table cannot be read, no request is staged.

Example rule:

```json
{
  "tool_name": "request_delete_task",
  "target_pattern": "demo-task-3",
  "action": "REQUIRE_APPROVAL",
  "priority": 20,
  "expiry_seconds": 600,
  "reason": "10-minute review window"
}
```

Policy API (all require `Authorization: Bearer <ADMIN_API_KEY>`):

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/policies` | List rules |
| POST | `/api/policies` | Create a rule |
| DELETE | `/api/policies/:id` | Delete a rule |

## Cryptographic audit chain

MCP-Guardrail records approval activity in a SHA-256 hash-chained,
append-only audit trail.

Each approval request creates a `REQUEST_CREATED` audit event. Each
dashboard decision creates an `ADMIN_DECISION` audit event.

Every audit event stores:

- Event ID
- Timestamp
- Approval request ID
- Event type
- Actor
- Outcome
- JSON event payload
- Previous event hash
- SHA-256 hash of the current event

If an existing audit event is edited, deleted, reordered, or its payload
is changed, the stored hash no longer matches the recomputed hash. The
verification function detects the broken chain.

Audit appends are serialized through the database so concurrent events cannot
fork the chain.

## External anchoring

The backend exports the latest audit-chain hash to Cloudflare R2 as an
external checkpoint.

Example checkpoint:

```json
{
  "schema": "mcp-guardrail-audit-anchor-v1",
  "anchoredAt": "2026-11-03T09:45:00.000Z",
  "lastEventId": 2,
  "chainHeadHash": "64-character-sha256-hash",
  "eventCount": 2,
  "provider": "cloudflare-r2"
}
```

The R2 bucket uses a retention lock on the `anchors/` prefix. This helps
prevent checkpoint deletion or overwrite for the configured retention
period.

### Anchor verification

`GET /api/audit` verifies both the internal hash chain and the external
anchor:

- `verified` — the internal hash chain is intact.
- `anchored` — at least one external checkpoint exists.
- `anchorsMatchChain` — the latest anchor matches the chain at its recorded
  event count.
- `unanchoredEvents` — events created after the latest anchor.

Events created after the latest anchor are still protected by the internal
hash chain, but they are not yet externally anchored.

### Security model

This system is **tamper-evident**, not absolutely immutable.

A database superuser could theoretically rewrite the entire Supabase chain
and recompute hashes. External R2 checkpoints make that much harder to do
silently because the externally stored chain-head hash would no longer
match the rewritten database chain.

For stronger independent time-existence proof, checkpoint files can also be
timestamped with OpenTimestamps.

## Tech stack

- Node.js
- Express
- Model Context Protocol SDK
- Supabase PostgreSQL
- Cloudflare R2
- Render
- GitHub Pages
- GitHub Actions
- Playwright
- Postman

## Project structure

```text
.
├── index.html
├── package.json
├── src/
│   └── server.js
├── db/
│   └── policies.sql
├── tests/
│   └── e2e/
│       └── dashboard.spec.js
├── docs/
│   ├── architecture.png
│   └── dashboard.png
└── .github/
    └── workflows/
        ├── anchor-audit-chain.yml
        ├── backend-health.yml
        └── e2e-dashboard.yml
```

## Environment variables

The following values are stored only in Render environment variables and
GitHub Actions secrets. They are never committed to this repository.

```text
ADMIN_API_KEY
SUPABASE_URL
SUPABASE_SERVICE_ROLE_KEY
FRONTEND_ORIGIN
R2_ACCOUNT_ID
R2_ACCESS_KEY_ID
R2_SECRET_ACCESS_KEY
R2_BUCKET_NAME
```

Optional:

```text
PROTECTED_TASK_IDS   Comma-separated task IDs that can never be deleted
                     (defaults to demo-task-2)
```

For the end-to-end tests, store the admin key as a GitHub Actions secret
named `RENDER_ADMIN_API_KEY`.

## Local setup

```bash
npm install
cp .env.example .env
```

Fill `.env` with your own local development values, then run:

```bash
npm start
```

Create the policy table once by running `db/policies.sql` in the Supabase
SQL Editor.

Run the end-to-end tests:

```bash
npx playwright test tests/e2e/dashboard.spec.js
```

The second test needs `RENDER_ADMIN_API_KEY` set in your terminal and is
skipped without it.

## API endpoints

### Health check

```http
GET /healthz
```

### Built-in MCP endpoint

```http
POST /mcp
```

### Gateway endpoint

```http
POST /gateway/:upstreamServerId/mcp
```

### Admin approval ledger

```http
GET /api/ledger
Authorization: Bearer <ADMIN_API_KEY>
```

### Approve or reject request

```http
POST /api/override
Authorization: Bearer <ADMIN_API_KEY>
Content-Type: application/json

{
  "txId": "request-uuid",
  "action": "APPROVE"
}
```

`action` is `APPROVE` or `ABORT`. An `ABORT` leaves the task in place and
the request becomes `REJECTED`. Requests that are already finalized or
expired return a clear 404, 409 or 410 response.

### Create a sandbox task

```http
POST /api/tasks
Authorization: Bearer <ADMIN_API_KEY>
Content-Type: application/json

{
  "id": "demo-task-3",
  "title": "Temporary test task"
}
```

### Manage policies

```http
GET    /api/policies
POST   /api/policies
DELETE /api/policies/:id
Authorization: Bearer <ADMIN_API_KEY>
```

### Verify audit chain

```http
GET /api/audit
Authorization: Bearer <ADMIN_API_KEY>
```

### Create external audit anchor

```http
POST /api/audit/anchor
Authorization: Bearer <ADMIN_API_KEY>
```

### Read latest external anchor

```http
GET /api/audit/anchor/latest
Authorization: Bearer <ADMIN_API_KEY>
```

## Limitations

- MCP-Guardrail is a reference implementation of the human-in-the-loop
  approval pattern. The gateway mode forwards requests to registered upstream
  servers, but it does not yet provide a full multi-tenant proxy platform.
- The `/mcp` and gateway endpoints currently have no end-user authentication.
  Rate limiting and pending-request limits reduce abuse, but per-workspace
  API keys are planned before real production use.
- A single shared administrator key means audit events identify the
  administrator role, not an individual human. Multi-user identity is planned
  for the Team tier.
- The dashboard stores the administrator key in browser storage. This is
  acceptable for the developer preview, but a session-based authentication flow
  is planned.
- Audit anchoring provides point-in-time external checkpoints. Events created
  after the latest anchor are protected by the internal hash chain but are not
  yet externally anchored.
- This is an early developer preview, not a certified enterprise security
  product.

## Security notes

- Do not commit `.env`, API keys, database keys, or administrator secrets.
- Use disposable sandbox data for public demos.
- Do not connect production databases, payment systems, cloud credentials,
  or customer data without an additional security review.
- This is an early developer preview, not a certified enterprise security
  product.

## Roadmap

- [ ] Multi-user authentication and per-workspace API keys
- [ ] Team roles and delegated approvals
- [ ] Slack and email approval notifications
- [ ] Mobile push approvals
- [ ] OpenTimestamps blockchain anchoring
- [ ] Exportable compliance reports
- [ ] SDK for custom MCP servers
- [ ] LLM evaluation suite for prompt-injection and unsafe-action scenarios

## License

MIT
