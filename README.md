# 🛡 MCP-Guardrail

![e2e](https://github.com/Janani0734/mcp-guardrail/actions/workflows/e2e-dashboard.yml/badge.svg)

**Approve AI agent actions before they execute.**

MCP-Guardrail is a human-in-the-loop safety layer for AI agents using the
Model Context Protocol (MCP). Instead of allowing an AI agent to perform a
risky action immediately, MCP-Guardrail converts the request into an
expiring approval request. A human reviews it in a dashboard and approves
or rejects it.

## Live demo

- Frontend dashboard:  
  https://janani0734.github.io/mcp-guardrail/

- Backend health check:  
  https://mcp-guardrail-backend.onrender.com/healthz

The backend runs on a free hosting tier and sleeps when idle. The first
request after a pause can take 20 to 60 seconds.

## What it does

```text
Claude / MCP client
        |
        | request_delete_task
        v
MCP-Guardrail backend
        |
        | Policy engine: DENY, or create PENDING approval request
        v
Supabase PostgreSQL
        |
        | Admin dashboard displays request
        v
Human approves or rejects
        |
        | Atomic database RPC
        v
Task deleted OR preserved
```

## Verified MVP results

The complete approval loop has been tested end-to-end with Claude,
Supabase, Render, and the MCP-Guardrail dashboard.

| Test | Result |
|---|---|
| AI requests deletion | Approval request created as `PENDING` |
| Human approves deletion | Target task deleted; request became `COMMITTED` |
| Human rejects deletion (admin `ABORT`) | Target task preserved; request became `REJECTED` |
| Approval expires | No deletion executed; request became `EXPIRED` |
| Audit chain verification | `verified: true` |
| External R2 anchoring | `anchored: true` |
| AI requests deletion of a protected task | Server refused it; no approval request was created |
| Policy rule with custom expiry | Approval window was exactly 10 minutes instead of the 5-minute default |

## Features

- MCP tool integration over Streamable HTTP
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

Available MCP tools: `list_tasks`, `request_delete_task`,
`get_request_status`.

## Policy engine

Rules decide what happens when an AI agent calls a high-risk tool. They are
stored in the `policies` table (see `db/policies.sql`) and managed through
the admin API.

- **Matching:** a rule matches on tool name and a target pattern. Wildcards
  work, so `temp-*` matches `temp-1`. Rules are checked by priority (lowest
  number first), and the first match wins.
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

### MCP endpoint

```http
POST /mcp
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

## Security notes

- Do not commit `.env`, API keys, database keys, or administrator secrets.
- Use disposable sandbox data for public demos.
- Do not connect production databases, payment systems, cloud credentials,
  or customer data without an additional security review.
- The `/mcp` endpoint has no login yet. It can only stage requests, and
  nothing executes without human approval, but per-workspace keys are
  planned before any real use.
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

## License

MIT
