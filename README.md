# 🛡 MCP-Guardrail

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

## What it does

```text
Claude / MCP client
        |
        | request_delete_task
        v
MCP-Guardrail backend
        |
        | Creates PENDING approval request
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
| Human rejects deletion | Target task preserved; request became `REJECTED` |
| Approval expires | No deletion executed; request became `EXPIRED` |
| Audit chain verification | `verified: true` |
| External R2 anchoring | `anchored: true` |

## Features

- MCP tool integration
- Expiring approval requests
- Human approval dashboard
- Approve and reject controls
- Persistent PostgreSQL state
- Atomic finalization through Supabase RPC
- SHA-256 hash-chained audit trail
- External audit anchoring to Cloudflare R2
- Administrator API authentication
- CORS-restricted frontend access
- Automated GitHub Actions anchoring

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

## Project structure

```text
.
├── index.html
├── package.json
├── src/
│   └── server.js
├── docs/
│   ├── architecture.png
│   └── dashboard.png
└── .github/
    └── workflows/
        ├── anchor-audit-chain.yml
        └── backend-health.yml
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

## Local setup

```bash
npm install
cp .env.example .env
```

Fill `.env` with your own local development values, then run:

```bash
npm start
```

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
- This is an early developer preview, not a certified enterprise security
  product.

## Roadmap

- [ ] Multi-user authentication
- [ ] Team roles and delegated approvals
- [ ] Slack and email approval notifications
- [ ] Mobile push approvals
- [ ] Approval policies by operation type
- [ ] OpenTimestamps blockchain anchoring
- [ ] Exportable compliance reports
- [ ] SDK for custom MCP servers

## License

MIT
