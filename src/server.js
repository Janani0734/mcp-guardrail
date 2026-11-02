import express from "express";
import { randomUUID, timingSafeEqual } from "node:crypto";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  StreamableHTTPServerTransport
} from "@modelcontextprotocol/sdk/server/streamableHttp.js";

const app = express();

const PORT = Number(process.env.PORT || 10000);
const FRONTEND_ORIGIN =
  process.env.FRONTEND_ORIGIN ||
  "https://janani0734.github.io";

const ADMIN_API_KEY = process.env.ADMIN_API_KEY;

if (!ADMIN_API_KEY || ADMIN_API_KEY.length < 32) {
  throw new Error(
    "Set ADMIN_API_KEY to a random secret of at least 32 characters."
  );
}

app.disable("x-powered-by");

// Browser origin restriction. This is not authentication.
// Claude's server-to-server requests may have no Origin header.
app.use((req, res, next) => {
  const origin = req.get("Origin");

  if (origin && origin !== FRONTEND_ORIGIN) {
    return res.status(403).json({ error: "Origin not allowed" });
  }

  if (origin) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.vary("Origin");
  }

  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, DELETE, OPTIONS"
  );
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, MCP-Protocol-Version, MCP-Session-Id"
  );

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

app.use(express.json({ limit: "50kb" }));

// Disposable shared sandbox only. No production database.
const tasks = new Map([
  ["demo-task-1", {
    id: "demo-task-1",
    title: "Disposable MCP approval test",
    completed: true
  }],
  ["demo-task-2", {
    id: "demo-task-2",
    title: "Keep this record unchanged",
    completed: false
  }]
]);

const requests = new Map();
const auditEvents = [];

const MAX_REQUESTS = 500;
const APPROVAL_WINDOW_MS = 5 * 60 * 1000;

function audit(action, details) {
  auditEvents.push({
    id: randomUUID(),
    timestamp: new Date().toISOString(),
    action,
    ...details
  });

  // Bounded diagnostic history, not a compliance ledger.
  if (auditEvents.length > 1000) auditEvents.shift();
}

function expireIfNeeded(request) {
  if (
    request.status === "PENDING" &&
    Date.now() >= Date.parse(request.expiresAt)
  ) {
    request.status = "EXPIRED";
    audit("REQUEST_EXPIRED", { requestId: request.id });
  }

  return request;
}

function textResult(value, isError = false) {
  return {
    content: [{
      type: "text",
      text: JSON.stringify(value, null, 2)
    }],
    ...(isError ? { isError: true } : {})
  };
}

function createMcpServer() {
  const server = new McpServer({
    name: "mcp-guardrail-sandbox",
    version: "0.1.0"
  });

  server.registerTool(
    "list_tasks",
    {
      description:
        "Read disposable sandbox tasks. No production data is accessible.",
      inputSchema: {}
    },
    async () => textResult({
      sandbox: true,
      tasks: Array.from(tasks.values())
    })
  );

  server.registerTool(
    "request_delete_task",
    {
      description:
        "Stage deletion of one sandbox task. Does not delete it. " +
        "A separate administrator must approve in the control API.",
      inputSchema: {
        task_id: z.string().min(1).max(100)
      }
    },
    async ({ task_id }) => {
      const task = tasks.get(task_id);

      if (!task) {
        return textResult({ error: "Task not found" }, true);
      }

      for (const request of requests.values()) {
        expireIfNeeded(request);

        if (
          request.target === task_id &&
          request.status === "PENDING"
        ) {
          return textResult({
            requestId: request.id,
            status: request.status,
            expiresAt: request.expiresAt,
            message: "An approval request already exists."
          });
        }
      }

      if (requests.size >= MAX_REQUESTS) {
        return textResult({
          error: "Sandbox request capacity reached."
        }, true);
      }

      const request = {
        id: randomUUID(),
        operation: "DELETE_TASK",
        target: task_id,
        targetTitle: task.title,
        requester: "unauthenticated-demo-mcp-client",
        status: "PENDING",
        createdAt: new Date().toISOString(),
        expiresAt:
          new Date(Date.now() + APPROVAL_WINDOW_MS).toISOString()
      };

      requests.set(request.id, request);
      audit("REQUEST_STAGED", { requestId: request.id, taskId: task_id });

      return textResult({
        requestId: request.id,
        status: request.status,
        expiresAt: request.expiresAt,
        message:
          "Pending separate administrator approval. " +
          "No data has been deleted. No automatic execution."
      });
    }
  );

  server.registerTool(
    "get_request_status",
    {
      description: "Read the outcome of a sandbox approval request.",
      inputSchema: {
        request_id: z.string().uuid()
      }
    },
    async ({ request_id }) => {
      const request = requests.get(request_id);

      if (!request) {
        return textResult({ error: "Request not found" }, true);
      }

      return textResult(expireIfNeeded(request));
    }
  );

  return server;
}

// Each POST gets an isolated MCP server and transport.
// Tools share only the explicit disposable sandbox state above.
app.post("/mcp", async (req, res) => {
  const server = createMcpServer();
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true
  });

  res.on("close", () => {
    void transport.close().catch(console.error);
    void server.close().catch(console.error);
  });

  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (error) {
    console.error("MCP request failed:", error.message);

    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: "2.0",
        id: null,
        error: { code: -32603, message: "Internal MCP error" }
      });
    }
  }
});

// No standalone event stream or resumable sessions in this demo.
app.get("/mcp", (_req, res) => res.sendStatus(405));
app.delete("/mcp", (_req, res) => res.sendStatus(405));

function requireAdmin(req, res, next) {
  const header = req.get("Authorization") || "";
  const supplied = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  const expectedBuffer = Buffer.from(ADMIN_API_KEY);
  const suppliedBuffer = Buffer.from(supplied);

  if (
    suppliedBuffer.length !== expectedBuffer.length ||
    !timingSafeEqual(suppliedBuffer, expectedBuffer)
  ) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  next();
}

app.get("/", (_req, res) => {
  res.json({
    name: "MCP-Guardrail Sandbox",
    mcpEndpoint: "/mcp",
    transport: "Streamable HTTP",
    sandbox: true,
    persistence: "In-memory; resets on restart"
  });
});

app.get("/healthz", (_req, res) => {
  res.json({ status: "ok" });
});

app.get("/api/ledger", requireAdmin, (_req, res) => {
  res.setHeader("Cache-Control", "no-store");

  res.json({
    serverTime: new Date().toISOString(),
    transactions:
      Array.from(requests.values()).map(expireIfNeeded)
  });
});

const overrideSchema = z.object({
  txId: z.string().uuid(),
  action: z.enum(["APPROVE", "ABORT"])
}).strict();

app.post("/api/override", requireAdmin, (req, res) => {
  const parsed = overrideSchema.safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({ error: "Invalid command" });
  }

  const { txId, action } = parsed.data;
  const request = requests.get(txId);

  if (!request) {
    return res.status(404).json({ error: "Request not found" });
  }

  expireIfNeeded(request);

  if (request.status === "EXPIRED") {
    return res.status(410).json({ error: "Request expired" });
  }

  if (request.status !== "PENDING") {
    return res.status(409).json({
      error: "Request already finalized",
      status: request.status
    });
  }

  // Synchronous single-process demo transition.
  // Replace with a database transaction for durable/multi-instance use.
  if (action === "ABORT") {
    request.status = "REJECTED";
  } else {
    const deleted = tasks.delete(request.target);
    request.status = deleted ? "COMMITTED" : "FAILED";
  }

  request.completedAt = new Date().toISOString();

  audit("REQUEST_FINALIZED", {
    requestId: request.id,
    decision: action,
    outcome: request.status,
    actor: "demo-admin-api-key"
  });

  res.json({
    success:
      request.status === "COMMITTED" ||
      request.status === "REJECTED",
    transaction: request
  });
});

app.get("/api/audit", requireAdmin, (_req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.json(auditEvents);
});

app.use((error, _req, res, _next) => {
  if (error.type === "entity.too.large") {
    return res.status(413).json({ error: "Body exceeds 50 KB" });
  }

  if (error.type === "entity.parse.failed") {
    return res.status(400).json({ error: "Invalid JSON" });
  }

  console.error(error.message);
  res.status(500).json({ error: "Internal server error" });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`MCP sandbox listening on port ${PORT}`);
});
