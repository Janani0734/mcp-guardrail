import express from "express";
import https from "node:https";
import { randomUUID, timingSafeEqual } from "node:crypto";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

const app = express();
const PORT = Number(process.env.PORT || 10000);
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "https://github.io";
const ADMIN_API_KEY = process.env.ADMIN_API_KEY;

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!ADMIN_API_KEY || ADMIN_API_KEY.length < 32) {
  throw new Error("Set ADMIN_API_KEY to a random secret of at least 32 characters.");
}

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  throw new Error("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required.");
}

const databaseBase = new URL(SUPABASE_URL);
if (databaseBase.protocol !== "https:") {
  throw new Error("SUPABASE_URL must use HTTPS.");
}

app.disable("x-powered-by");

app.use((req, res, next) => {
  const origin = req.get("Origin");
  if (origin && origin !== FRONTEND_ORIGIN) {
    return res.status(403).json({ error: "Origin not allowed" });
  }
  if (origin) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.vary("Origin");
  }
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, MCP-Protocol-Version, MCP-Session-Id");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

app.use(express.json({ limit: "50kb" }));

const asyncRoute = (handler) => (req, res, next) => {
  Promise.resolve(handler(req, res, next)).catch(next);
};

function queryDatabase(endpointPath, httpMethod, dataBody = null) {
  return new Promise((resolve, reject) => {
    try {
      const urlTarget = new URL(`${SUPABASE_URL}/rest/v1${endpointPath}`);
      const payloadText = dataBody ? JSON.stringify(dataBody) : "";
      
      const requestOptions = {
        hostname: urlTarget.hostname,
        port: 443,
        path: urlTarget.pathname + urlTarget.search,
        method: httpMethod,
        headers: {
          "apikey": SUPABASE_SERVICE_ROLE_KEY,
          "Authorization": `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
          "Content-Type": "application/json",
          "Prefer": "return=representation"
        }
      };

      if (dataBody && httpMethod !== "GET") {
        requestOptions.headers["Content-Length"] = Buffer.byteLength(payloadText);
      }

      const databaseRequest = https.request(requestOptions, (databaseResponse) => {
        let cumulativeChunks = "";
        databaseResponse.on("data", (chunk) => { cumulativeChunks += chunk; });
        databaseResponse.on("end", () => {
          if (databaseResponse.statusCode >= 400) {
            return reject(new Error(`DB Error: ${databaseResponse.statusCode} - ${cumulativeChunks}`));
          }
          try { resolve(JSON.parse(cumulativeChunks)); } catch { resolve(cumulativeChunks); }
        });
      });

      databaseRequest.setTimeout(15000, () => {
        databaseRequest.destroy(new Error("Database request timed out."));
      });

      databaseRequest.on("error", (error) => reject(error));
      if (dataBody && httpMethod !== "GET") databaseRequest.write(payloadText);
      databaseRequest.end();
    } catch (exception) {
      reject(exception);
    }
  });
}

async function expireRequestIfNeeded(request) {
  const deadline = Date.parse(request.expires_at);
  if (!Number.isFinite(deadline)) {
    throw new Error("Approval request has an invalid expires_at.");
  }
  if (request.status === "PENDING" && Date.now() >= deadline) {
    const updated = await queryDatabase(
      `/approval_requests?id=eq.${request.id}&status=eq.PENDING`,
      "PATCH",
      { status: "EXPIRED" }
    );
    if (Array.isArray(updated) && updated.length === 1) {
      return updated[0];
    }
    const latest = await queryDatabase(`/approval_requests?id=eq.${encodeURIComponent(request.id)}&select=*`, "GET");
    if (!Array.isArray(latest) || latest.length !== 1) {
      throw new Error("Unable to retrieve current approval status.");
    }
    return latest[0];
  }
  return request;
}

function textResult(value, isError = false) {
  return {
    content: [{ type: "text", text: JSON.stringify(value, null, 2) }],
    ...(isError ? { isError: true } : {})
  };
}

function createMcpServer() {
  const server = new McpServer({ name: "mcp-guardrail-sandbox", version: "0.1.0" });

  server.registerTool("list_tasks", { description: "List all tasks inside the database sandbox." }, async () => {
    const databaseTasks = await queryDatabase("/sandbox_tasks?select=id,title,completed", "GET");
    return textResult({ sandbox: true, tasks: databaseTasks });
  });

  server.registerTool("request_delete_task", {
    description: "Stage deletion of one sandbox task.",
    inputSchema: {
      task_id: z.string().min(1).max(100)
    }
  }, async ({ task_id }) => {
    const taskRecord = await queryDatabase(`/sandbox_tasks?id=eq.${task_id}&select=*`, "GET");
    if (!Array.isArray(taskRecord) || taskRecord.length === 0) return textResult({ error: "Task not found" }, true);

    const actualTask = taskRecord[0];
    const activeRequests = await queryDatabase(`/approval_requests?target=eq.${task_id}&status=eq.PENDING&select=*`, "GET");
    
    if (activeRequests && activeRequests.length > 0) {
      const existingRequest = await expireRequestIfNeeded(activeRequests[0]);
      if (existingRequest.status === "PENDING") {
        return textResult({ requestId: existingRequest.id, status: existingRequest.status, message: "Approval request already exists." });
      }
    }

    const newRequest = {
      id: randomUUID(), operation: "DELETE_TASK", target: task_id, target_title: actualTask.title,
      requester: "demo-mcp-client", status: "PENDING",
      created_at: new Date().toISOString(), expires_at: new Date(Date.now() + 300000).toISOString()
    };

    await queryDatabase("/approval_requests", "POST", newRequest);
    return textResult({ requestId: newRequest.id, status: newRequest.status, expiresAt: newRequest.expires_at, message: "Pending admin approval." });
  });

  server.registerTool("get_request_status", {
    description: "Fetch the current processing outcome of a tracking token transaction.",
    inputSchema: {
      request_id: z.string().uuid()
    }
  }, async ({ request_id }) => {
    const matchedRequests = await queryDatabase(`/approval_requests?id=eq.${request_id}&select=*`, "GET");
    if (!Array.isArray(matchedRequests) || matchedRequests.length === 0) return textResult({ error: "Request not found" }, true);
    
    const validatedRequest = await expireRequestIfNeeded(matchedRequests[0]);
    return textResult({
      id: validatedRequest.id, operation: validatedRequest.operation, target: validatedRequest.target,
      targetTitle: validatedRequest.target_title, requester: validatedRequest.requester,
      status: validatedRequest.status, createdAt: validatedRequest.created_at, expiresAt: validatedRequest.expires_at
    });
  });

  return server;
}

app.post("/mcp", async (req, res) => {
  const server = createMcpServer();
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
  res.on("close", () => {
    void transport.close().catch(console.error);
    void server.close().catch(console.error);
  });
  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (error) {
    if (!res.headersSent) res.status(500).json({ jsonrpc: "2.0", id: null, error: { code: -32603, message: "Internal error" } });
  }
});

function requireAdmin(req, res, next) {
  const header = req.get("Authorization") || "";
  const supplied = header.startsWith("Bearer ") ? header.slice(7) : "";
  const suppliedBuffer = Buffer.from(supplied, "utf8");
  const expectedBuffer = Buffer.from(ADMIN_API_KEY, "utf8");
  if (suppliedBuffer.length !== expectedBuffer.length || !timingSafeEqual(suppliedBuffer, expectedBuffer)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

app.get("/api/ledger", requireAdmin, asyncRoute(async (_req, res) => {
  const openRequests = await queryDatabase("/approval_requests?select=*&order=created_at.desc", "GET");
  if (!Array.isArray(openRequests)) {
    throw new Error("Unexpected database response.");
  }
  const processedList = await Promise.all(openRequests.map(expireRequestIfNeeded));
  res.setHeader("Cache-Control", "no-store");
  res.json({
    serverTime: new Date().toISOString(),
    transactions: processedList.map(tx => ({
      id: tx.id, operation: tx.operation, target: tx.target, targetTitle: tx.target_title,
      requester: tx.requester, status: tx.status, createdAt: tx.created_at, expiresAt: tx.expires_at
    }))
  });
}));

// Fixed & Hardened: Hooks natively into your high-performance PostgreSQL RPC function for true atomic transaction execution
app.post("/api/override", requireAdmin, asyncRoute(async (req, res) => {
  const parsed = z.object({
    txId: z.string().uuid(),
    action: z.enum(["APPROVE", "ABORT"])
  }).strict().safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({ error: "Invalid transaction ID or action." });
  }

  const { txId, action } = parsed.data;

  // Calls your newly deployed public database stored procedure
  const resultRPC = await queryDatabase("/rpc/guardrail_finalize_request", "POST", {
    p_request_id: txId,
    p_action: action
  });

  if (!resultRPC) {
    throw new Error("Unable to confirm finalized request via Database RPC transaction.");
  }

  const tx = Array.isArray(resultRPC) ? resultRPC[0] : resultRPC;

  res.json({
    success: true,
    transaction: {
      id: tx.id,
      operation: tx.operation,
Use code with caution.
target: tx.target,
targetTitle: tx.target_title,
requester: tx.requester,
status: tx.status,
createdAt: tx.created_at,
expiresAt: tx.expires_at
}
});
}));
app.get("/healthz", (_req, res) => res.json({ status: "ok" }));
app.get("/", (_req, res) => res.json({ persistent: true }));
app.use((error, req, res, next) => {
if (res.headersSent) return next(error);
if (error.type === "entity.too.large") {
return res.status(413).json({ error: "Request exceeds 50 KB." });
}
if (error.type === "entity.parse.failed") {
return res.status(400).json({ error: "Invalid JSON." });
}
console.error("Request failed:", error.message);
res.status(500).json({ error: "Request failed. Check server logs." });
});
app.listen(PORT, "0.0.0.0", () => {
console.log(MCP persistent server active on port ${PORT});
});
