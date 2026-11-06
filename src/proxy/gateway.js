import { randomUUID, timingSafeEqual } from "node:crypto";
import { z } from "zod";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema
} from "@modelcontextprotocol/sdk/types.js";

// MCP-Guardrail gateway: sits in front of ANOTHER MCP server.
//   agent -> /proxy/mcp -> policy (ALLOW / DENY / REQUIRE_APPROVAL) -> upstream
// Only tools/call is gated. A gated call is stored, a person decides, and the
// call is sent upstream only after approval (at most once).

const DEMO = process.env.ENABLE_DEMO_UPSTREAM === "true";
const PORT = Number(process.env.PORT || 10000);

const UPSTREAM_URL =
  process.env.PROXY_UPSTREAM_URL ||
  (DEMO ? `http://127.0.0.1:${PORT}/demo-upstream/mcp` : "");

const UPSTREAM_NAME =
  (process.env.PROXY_UPSTREAM_NAME || (DEMO ? "demo" : "upstream"))
    .replace(/[^A-Za-z0-9_-]/g, "") || "upstream";

const UPSTREAM_BEARER = process.env.PROXY_UPSTREAM_BEARER || "";
const ACCESS_TOKEN = process.env.PROXY_ACCESS_TOKEN || "";

const MAX_PENDING = 20;
const MAX_ARGUMENT_CHARS = 10000;
const MAX_RESULT_CHARS = 20000;
const CALL_TIMEOUT_MS = 30000;
const DEFAULT_EXPIRY_SECONDS = 300;

const STATUS_TOOL = {
  name: "guardrail_get_call_status",
  description:
    "Check a call that is waiting for human approval. Returns its status " +
    "and, once approved and executed, the upstream result.",
  inputSchema: {
    type: "object",
    properties: { call_id: { type: "string", description: "UUID of the call" } },
    required: ["call_id"]
  }
};

function upstreamUrlAllowed(value) {
  try {
    const url = new URL(value);

    if (url.protocol === "https:") {
      return true;
    }

    return (
      url.protocol === "http:" &&
      ["127.0.0.1", "localhost"].includes(url.hostname)
    );
  } catch {
    return false;
  }
}

function textResult(value, isError = false) {
  return {
    content: [{ type: "text", text: JSON.stringify(value, null, 2) }],
    ...(isError ? { isError: true } : {})
  };
}

function policyTarget(args) {
  for (const value of Object.values(args || {})) {
    if (typeof value === "string" && value) {
      return value.slice(0, 200);
    }
  }

  return "*";
}

function packResult(output) {
  const text = JSON.stringify(output);

  if (text.length <= MAX_RESULT_CHARS) {
    return output;
  }

  return { truncated: true, text: text.slice(0, MAX_RESULT_CHARS) };
}

export function mountProxy(app, deps) {
  const {
    queryDatabase,
    requireAdmin,
    asyncRoute,
    appendAuditEvent,
    evaluatePolicy
  } = deps;

  if (!UPSTREAM_URL || !upstreamUrlAllowed(UPSTREAM_URL)) {
    console.warn(
      "Proxy disabled: set PROXY_UPSTREAM_URL to an https URL " +
      "(or ENABLE_DEMO_UPSTREAM=true)."
    );
    return;
  }

  if (ACCESS_TOKEN.length < 24) {
    console.warn(
      "Proxy disabled: set PROXY_ACCESS_TOKEN (24+ characters)."
    );
    return;
  }

  // ---------- helpers ----------

  function accessAllowed(req) {
    const header = req.get("Authorization") || "";
    const supplied = header.startsWith("Bearer ")
      ? header.slice(7)
      : String(req.query.key || "");

    const a = Buffer.from(supplied, "utf8");
    const b = Buffer.from(ACCESS_TOKEN, "utf8");

    return a.length === b.length && timingSafeEqual(a, b);
  }

  const hits = new Map();

  function rateLimited(ip) {
    const now = Date.now();

    if (hits.size > 1000) {
      for (const [key, entry] of hits) {
        if (entry.resetAt <= now) {
          hits.delete(key);
        }
      }
    }

    const entry = hits.get(ip);

    if (!entry || entry.resetAt <= now) {
      hits.set(ip, { count: 1, resetAt: now + 60000 });
      return false;
    }

    entry.count += 1;
    return entry.count > 120;
  }

  async function withUpstream(task) {
    const transport = new StreamableHTTPClientTransport(
      new URL(UPSTREAM_URL),
      UPSTREAM_BEARER
        ? {
            requestInit: {
              headers: { Authorization: `Bearer ${UPSTREAM_BEARER}` }
            }
          }
        : undefined
    );

    const client = new Client({
      name: "mcp-guardrail-proxy",
      version: "0.1.0"
    });

    await client.connect(transport);

    try {
      return await task(client);
    } finally {
      await client.close().catch(() => {});
    }
  }

  let toolCache = { tools: [], until: 0 };

  async function upstreamTools() {
    if (toolCache.until > Date.now()) {
      return toolCache.tools;
    }

    const listed = await withUpstream((client) => client.listTools());
    toolCache = { tools: listed.tools || [], until: Date.now() + 60000 };

    return toolCache.tools;
  }

  async function patchCalls(filter, body) {
    const rows = await queryDatabase(`/proxy_calls?${filter}`, "PATCH", body);
    return Array.isArray(rows) ? rows : [];
  }

  async function expireStale() {
    const now = encodeURIComponent(new Date().toISOString());

    await patchCalls(
      `status=eq.PENDING&expires_at=lt.${now}`,
      { status: "EXPIRED" }
    );
  }

  async function insertCall(fields) {
    const row = {
      id: randomUUID(),
      upstream: UPSTREAM_NAME,
      created_at: new Date().toISOString(),
      ...fields
    };

    await queryDatabase("/proxy_calls", "POST", row);

    return row;
  }

  // Sends the call upstream and records the outcome. The caller must have
  // already moved the row to EXECUTING, so this runs at most once per call.
  async function executeAndStore(call) {
    let status = "EXECUTED";
    let output;
    let stored;

    try {
      output = await withUpstream((client) =>
        client.callTool(
          { name: call.tool_name, arguments: call.arguments },
          undefined,
          { timeout: CALL_TIMEOUT_MS }
        )
      );

      stored = packResult(output);

      if (output.isError) {
        status = "FAILED";
      }
    } catch (error) {
      status = "FAILED";
      stored = { error: String(error.message).slice(0, 500) };
    }

    const rows = await patchCalls(
      `id=eq.${encodeURIComponent(call.id)}`,
      {
        status,
        result: stored,
        executed_at: new Date().toISOString()
      }
    );

    return { row: rows[0] || { ...call, status, result: stored }, output };
  }

  async function callStatus(rawId) {
    const parsed = z.string().uuid().safeParse(rawId);

    if (!parsed.success) {
      return textResult({ error: "call_id must be a UUID." }, true);
    }

    await expireStale();

    const rows = await queryDatabase(
      `/proxy_calls?id=eq.${encodeURIComponent(parsed.data)}&select=*`,
      "GET"
    );

    if (!Array.isArray(rows) || rows.length === 0) {
      return textResult({ error: "Call not found." }, true);
    }

    const call = rows[0];

    const body = {
      callId: call.id,
      tool: call.tool_name,
      status: call.status,
      createdAt: call.created_at,
      expiresAt: call.expires_at
    };

    if (call.status === "EXECUTED" || call.status === "FAILED") {
      body.result = call.result;
    }

    return textResult(body);
  }

  // ---------- the gated MCP server ----------

  async function handleToolCall(request) {
    const name = request.params.name;
    const args = request.params.arguments || {};

    if (name === STATUS_TOOL.name) {
      return callStatus(args.call_id);
    }

    if (JSON.stringify(args).length > MAX_ARGUMENT_CHARS) {
      return textResult({ error: "Arguments are too large." }, true);
    }

    const tools = await upstreamTools();

    if (!tools.some((tool) => tool.name === name)) {
      return textResult({ error: "Unknown tool." }, true);
    }

    // Fail closed: if the rules cannot be read, nothing is forwarded.
    let decision;

    try {
      decision = await evaluatePolicy(
        `${UPSTREAM_NAME}.${name}`,
        policyTarget(args)
      );
    } catch (error) {
      console.error("Proxy policy check failed:", error.message);

      return textResult(
        { error: "Policy check unavailable. The call was not forwarded." },
        true
      );
    }

    const nowIso = new Date().toISOString();

    if (decision.action === "DENY") {
      await insertCall({
        tool_name: name,
        arguments: args,
        status: "DENIED",
        decision_reason: decision.reason,
        expires_at: nowIso
      });

      return textResult(
        { error: "Blocked by policy.", reason: decision.reason },
        true
      );
    }

    if (decision.action === "ALLOW") {
      const call = await insertCall({
        tool_name: name,
        arguments: args,
        status: "EXECUTING",
        decision_reason: decision.reason,
        expires_at: nowIso
      });

      const { output } = await executeAndStore(call);

      return output || textResult({ error: "Upstream call failed." }, true);
    }

    // REQUIRE_APPROVAL: store the call, do not forward it.
    const pending = await queryDatabase(
      `/proxy_calls?select=id&status=eq.PENDING&limit=${MAX_PENDING + 1}`,
      "GET"
    );

    if (Array.isArray(pending) && pending.length >= MAX_PENDING) {
      return textResult(
        { error: "Too many calls are waiting for approval. Try again later." },
        true
      );
    }

    const expiresAt = new Date(
      Date.now() + (decision.expirySeconds || DEFAULT_EXPIRY_SECONDS) * 1000
    ).toISOString();

    const call = await insertCall({
      tool_name: name,
      arguments: args,
      status: "PENDING",
      decision_reason: decision.reason,
      expires_at: expiresAt
    });

    try {
      await appendAuditEvent(
        call.id,
        "PROXY_CALL_REQUESTED",
        "mcp-client",
        "PENDING",
        {
          upstream: UPSTREAM_NAME,
          tool: name,
          argumentKeys: Object.keys(args),
          expiresAt
        }
      );
    } catch (error) {
      await patchCalls(
        `id=eq.${call.id}&status=eq.PENDING`,
        { status: "ABORTED", decision_reason: "Audit log unavailable" }
      );

      throw error;
    }

    return textResult({
      status: "PENDING_APPROVAL",
      callId: call.id,
      expiresAt,
      note:
        "A person must approve this call before it runs. Do not retry it. " +
        `Use ${STATUS_TOOL.name} with this callId to check the outcome.`
    });
  }

  function buildServer() {
    const server = new Server(
      { name: "mcp-guardrail-proxy", version: "0.1.0" },
      { capabilities: { tools: {} } }
    );

    server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [...(await upstreamTools()), STATUS_TOOL]
    }));

    server.setRequestHandler(CallToolRequestSchema, handleToolCall);

    return server;
  }

  app.post("/proxy/mcp", async (req, res) => {
    if (rateLimited(req.ip)) {
      return res.status(429).json({ error: "Too many requests." });
    }

    if (!accessAllowed(req)) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const server = buildServer();

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
      console.error("Proxy request failed:", error.message);

      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: "2.0",
          id: null,
          error: { code: -32603, message: "Internal error" }
        });
      }
    }
  });

  // ---------- administrator routes ----------

  app.get(
    "/api/proxy/calls",
    requireAdmin,
    asyncRoute(async (_req, res) => {
      await expireStale();

      const rows = await queryDatabase(
        "/proxy_calls?select=*&order=created_at.desc&limit=50",
        "GET"
      );

      res.setHeader("Cache-Control", "no-store");
      res.json({ calls: Array.isArray(rows) ? rows : [] });
    })
  );

  app.post(
    "/api/proxy/calls/:id/decision",
    requireAdmin,
    asyncRoute(async (req, res) => {
      const id = z.string().uuid().safeParse(req.params.id);

      const body = z
        .object({ action: z.enum(["APPROVE", "REJECT"]) })
        .strict()
        .safeParse(req.body);

      if (!id.success || !body.success) {
        return res.status(400).json({ error: "Invalid call id or action." });
      }

      const actor = req.admin?.actor || "admin-api-key";
      const nowIso = new Date().toISOString();
      const newStatus = body.data.action === "APPROVE" ? "APPROVED" : "REJECTED";

      // One conditional update decides it: only a still-pending, unexpired
      // call can be decided, and only once.
      const decided = await patchCalls(
        `id=eq.${encodeURIComponent(id.data)}&status=eq.PENDING` +
        `&expires_at=gt.${encodeURIComponent(nowIso)}`,
        { status: newStatus, decided_by: actor, decided_at: nowIso }
      );

      if (decided.length === 0) {
        await expireStale();

        const existing = await queryDatabase(
          `/proxy_calls?id=eq.${encodeURIComponent(id.data)}&select=id,status`,
          "GET"
        );

        if (!Array.isArray(existing) || existing.length === 0) {
          return res.status(404).json({ error: "Call not found." });
        }

        return res.status(
          existing[0].status === "EXPIRED" ? 410 : 409
        ).json({
          error: "Call can no longer be decided.",
          status: existing[0].status
        });
      }

      const call = decided[0];

      try {
        await appendAuditEvent(
          call.id,
          "ADMIN_DECISION",
          actor,
          newStatus,
          {
            upstream: call.upstream,
            tool: call.tool_name,
            requestedAction: body.data.action
          }
        );
      } catch (error) {
        await patchCalls(
          `id=eq.${call.id}`,
          { status: "ABORTED", decision_reason: "Audit log unavailable" }
        );

        throw error;
      }

      if (newStatus === "REJECTED") {
        return res.json({ call });
      }

      // Move APPROVED to EXECUTING once; only the request that wins runs it.
      const claimed = await patchCalls(
        `id=eq.${call.id}&status=eq.APPROVED`,
        { status: "EXECUTING" }
      );

      if (claimed.length === 0) {
        return res.json({ call });
      }

      const { row } = await executeAndStore(claimed[0]);

      res.json({ call: row });
    })
  );

  console.log(`Proxy active: ${UPSTREAM_NAME} -> upstream, endpoint /proxy/mcp`);
}
