# 🛡 MCP-Guardrail

**Approve AI agent actions before they execute.**

MCP-Guardrail is a human-in-the-loop safety layer for AI agents using the
Model Context Protocol (MCP). Instead of letting an AI agent immediately
perform a risky action, it converts the request into an expiring approval
request. A human reviews it in a dashboard and approves or rejects it.

## Dashboard preview

![MCP-Guardrail approval dashboard](docs/dashboard.png)

## Architecture

![MCP-Guardrail architecture](docs/architecture.png)


## Verified MVP result

This project has been tested end-to-end with Claude and Supabase:

- An AI agent requested deletion of a sandbox task.
- The request appeared as `PENDING` in the admin dashboard.
- An approved deletion request removed only the approved target task.
- A rejected deletion request preserved the target task.
- An expired request did not execute any deletion.

## How it works

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
        | Admin dashboard reads request
        v
Human approves or rejects
        |
        | Atomic database RPC
        v
Task deleted OR preserved
```

## Features

- MCP tool integration
- Expiring approval requests
- Human approval dashboard
- Approve and reject actions
- Persistent PostgreSQL state
- Atomic finalization through a Supabase RPC function
- Admin API authentication
- CORS-restricted frontend access

## Tech stack

- Node.js
- Express
- Model Context Protocol SDK
- Supabase PostgreSQL
- Render
- GitHub Pages

## Live demo

- Frontend dashboard: https://janani0734.github.io/mcp-guardrail/
- Backend health check: https://mcp-guardrail-backend.onrender.com/healthz

## Security model

Secrets are never committed to this repository.

The following values are stored only in Render environment variables:

```text
ADMIN_API_KEY
SUPABASE_URL
SUPABASE_SERVICE_ROLE_KEY
FRONTEND_ORIGIN
```

The repository includes an `.env.example` file showing the required variable
names, but it does not contain real credentials.

## Important note

This is an early developer preview, not a certified enterprise security
product. Do not connect production databases, payment systems, cloud
credentials, or customer data without additional security review.
