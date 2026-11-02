import express from "express";
import { randomUUID, timingSafeEqual } from "node:crypto";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

const app = express();
const PORT = Number(process.env.PORT || 10000);
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "https://janani0734.github.io";
const ADMIN_API_KEY = process.env.ADMIN_API_KEY;
const SUPABASE_URL = process.env.SUPABASE_URL;
const DB_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
if (!ADMIN_API_KEY || ADMIN_API_KEY.length < 32) throw new Error("ADMIN_API_KEY must contain at least 32 characters.");
if (!SUPABASE_URL || !DB_KEY) throw new Error("Supabase environment variables are required.");
const dbBase = new URL(SUPABASE_URL);
if (dbBase.protocol !== "https:") throw new Error("SUPABASE_URL must use HTTPS.");

app.disable("x-powered-by");
app.use((req, res, next) => {
  const origin = req.get("Origin");
  if (origin && origin !== FRONTEND_ORIGIN) return res.status(403).json({ error: "Origin not allowed" });
  if (origin) { res.setHeader("Access-Control-Allow-Origin", origin); res.vary("Origin"); }
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, MCP-Protocol-Version, MCP-Session-Id");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});
app.use(express.json({ limit: "50kb" }));
const asyncRoute = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

async function queryDatabase(path, method = "GET", body) {
  const response = await fetch(new URL("/rest/v1" + path, dbBase), {
    method,
    headers: { apikey: DB_KEY, Authorization: `Bearer ${DB_KEY}`, "Content-Type": "application/json", Prefer: "return=representation" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    signal: AbortSignal.timeout(15000)
  });
  const raw = await response.text();
  if (!response.ok) throw new Error(`Database HTTP ${response.status}`);
  if (!raw) return [];
  return JSON.parse(raw);
}
function pathFor(table, filters = {}) {
  return `/${table}?${new URLSearchParams(filters).toString()}`;
}
function publicRequest(tx) {
  return { id: tx.id, operation: tx.operation, target: tx.target, targetTitle: tx.target_title,
    requester: tx.requester, status: tx.status, createdAt: tx.created_at, expiresAt: tx.expires_at };
}
async function expireRequestIfNeeded(request) {
  const deadline = Date.parse(request.expires_at);
  if (!Number.isFinite(deadline)) throw new Error("Invalid approval expiry.");
  if (request.status === "PENDING" && Date.now() >= deadline) {
    const updated = await queryDatabase(pathFor("approval_requests", { id: `eq.${request.id}`, status: "eq.PENDING" }), "PATCH", { status: "EXPIRED" });
    if (updated.length === 1) return updated[0];
    const latest = await queryDatabase(pathFor("approval_requests", { id: `eq.${request.id}`, select: "*" }));
    if (latest.length !== 1) throw new Error("Request disappeared.");
    return latest[0];
  }
  return request;
}
function textResult(value, isError = false) {
  return { content: [{ type: "text", text: JSON.stringify(value, null, 2) }], ...(isError ? { isError: true } : {}) };
}
function toolHandler(fn) {
  return async args => {
    try { return await fn(args); }
    catch (error) { console.error("Tool failure:", error.message); return textResult({ error: "Database/tool operation failed. Check server logs." }, true); }
  };
}
function createMcpServer() {
  const server = new McpServer({ name: "mcp-guardrail-sandbox", version: "0.2.0" });
  server.registerTool("list_tasks", {
    description: "Read shared disposable sandbox tasks only.", inputSchema: {}
  }, toolHandler(async () => textResult({ sandbox: true, tasks: await queryDatabase("/sandbox_tasks?select=id,title,completed") })));
  server.registerTool("request_delete_task", {
    description: "Stage deletion of one sandbox task; requires separate admin approval.",
    inputSchema: { task_id: z.string().min(1).max(100) }
  }, toolHandler(async ({ task_id }) => {
    const found = await queryDatabase(pathFor("sandbox_tasks", { id: `eq.${task_id}`, select: "id,title,completed" }));
    if (found.length !== 1) return textResult({ error: "Task not found" }, true);
    const existing = await queryDatabase(pathFor("approval_requests", { target: `eq.${task_id}`, status: "eq.PENDING", select: "*" }));
    for (const old of existing) {
      const current = await expireRequestIfNeeded(old);
      if (current.status === "PENDING") return textResult({ requestId: current.id, status: current.status, expiresAt: current.expires_at, message: "Existing pending request." });
    }
    const request = { id: randomUUID(), operation: "DELETE_TASK", target: task_id, target_title: found[0].title,
      requester: "unauthenticated-demo-mcp-client", status: "PENDING", created_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 300000).toISOString() };
    const inserted = await queryDatabase("/approval_requests", "POST", request);
    if (inserted.length !== 1) throw new Error("Insert not confirmed.");
    return textResult({ requestId: request.id, status: "PENDING", expiresAt: request.expires_at, message: "No deletion executed. Await separate administrator approval." });
  }));
  server.registerTool("get_request_status", {
    description: "Read a sandbox approval request outcome.",
    inputSchema: { request_id: z.string().uuid() }
  }, toolHandler(async ({ request_id }) => {
    const rows = await queryDatabase(pathFor("approval_requests", { id: `eq.${request_id}`, select: "*" }));
    if (rows.length !== 1) return textResult({ error: "Request not found" }, true);
    return textResult(publicRequest(await expireRequestIfNeeded(rows[0])));
  }));
  return server;
}
app.post("/mcp", async (req, res) => {
  const server = createMcpServer();
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
  res.on("close", () => { void transport.close().catch(console.error); void server.close().catch(console.error); });
  try { await server.connect(transport); await transport.handleRequest(req, res, req.body); }
  catch (error) {
    console.error("MCP failure:", error.message);
    if (!res.headersSent) res.status(500).json({ jsonrpc: "2.0", id: null, error: { code: -32603, message: "Internal MCP error" } });
  }
});
app.get("/mcp", (_req, res) => res.sendStatus(405));
app.delete("/mcp", (_req, res) => res.sendStatus(405));
function requireAdmin(req, res, next) {
  const header = req.get("Authorization") || "";
  const supplied = Buffer.from(header.startsWith("Bearer ") ? header.slice(7) : "", "utf8");
  const expected = Buffer.from(ADMIN_API_KEY, "utf8");
  if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) return res.status(401).json({ error: "Unauthorized" });
  res.setHeader("Cache-Control", "no-store"); next();
}
app.get("/api/ledger", requireAdmin, asyncRoute(async (_req, res) => {
  const rows = await queryDatabase("/approval_requests?select=*&order=created_at.desc&limit=200");
  const processed = await Promise.all(rows.map(expireRequestIfNeeded));
  res.json({ serverTime: new Date().toISOString(), transactions: processed.map(publicRequest) });
}));
const commandSchema = z.object({ txId: z.string().uuid(), action: z.enum(["APPROVE", "ABORT"]) }).strict();
app.post("/api/override", requireAdmin, asyncRoute(async (req, res) => {
  const parsed = commandSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Invalid transaction ID or action." });
  const { txId, action } = parsed.data;
  // The RPC migration is deliberately required for mutations.
  // It must validate, lock, execute and finalize inside ONE database transaction.
  const result = await queryDatabase("/rpc/guardrail_finalize_request", "POST", {
    p_request_id: txId, p_action: action
  });
  const tx = Array.isArray(result) ? result[0] : result;
  if (!tx || tx.id !== txId) throw new Error("RPC returned an unexpected result.");
  if (tx.status === "EXPIRED") return res.status(410).json({ error: "Request expired", transaction: publicRequest(tx) });
  res.json({ success: ["COMMITTED", "REJECTED"].includes(tx.status), transaction: publicRequest(tx) });
}));
app.get("/healthz", (_req, res) => res.json({ status: "ok", databaseChecked: false }));
app.get("/", (_req, res) => res.json({ name: "MCP-Guardrail database sandbox", mcpEndpoint: "/mcp", publicSharedSandbox: true }));
app.use((error, _req, res, next) => {
  if (res.headersSent) return next(error);
  if (error.type === "entity.too.large") return res.status(413).json({ error: "Body exceeds 50 KB." });
  if (error.type === "entity.parse.failed") return res.status(400).json({ error: "Invalid JSON." });
  console.error("Request failed:", error.message);
  res.status(500).json({ error: "Operation failed. Check server logs; do not blindly retry mutations." });
});
app.listen(PORT, "0.0.0.0", () => console.log(`Sandbox listening on ${PORT}`));
