import express from "express";
import https from "node:https";
import { randomUUID, timingSafeEqual } from "node:crypto";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  S3Client,
  PutObjectCommand
} from "@aws-sdk/client-s3";

const app = express();
const PORT = Number(process.env.PORT || 10000);

const FRONTEND_ORIGIN =
  process.env.FRONTEND_ORIGIN || "https://janani0734.github.io";

const ADMIN_API_KEY = process.env.ADMIN_API_KEY;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

const R2_ACCOUNT_ID = process.env.R2_ACCOUNT_ID;
const R2_ACCESS_KEY_ID = process.env.R2_ACCESS_KEY_ID;
const R2_SECRET_ACCESS_KEY = process.env.R2_SECRET_ACCESS_KEY;
const R2_BUCKET_NAME = process.env.R2_BUCKET_NAME;

if (!ADMIN_API_KEY || ADMIN_API_KEY.length < 32) {
  throw new Error(
    "Set ADMIN_API_KEY to a random secret of at least 32 characters."
  );
}

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  throw new Error(
    "SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required."
  );
}

const databaseBase = new URL(SUPABASE_URL);

if (databaseBase.protocol !== "https:") {
  throw new Error("SUPABASE_URL must use HTTPS.");
}

const externalAnchoringEnabled = Boolean(
  R2_ACCOUNT_ID &&
  R2_ACCESS_KEY_ID &&
  R2_SECRET_ACCESS_KEY &&
  R2_BUCKET_NAME
);

const r2Client = externalAnchoringEnabled
  ? new S3Client({
      region: "auto",
      endpoint: `https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
      credentials: {
        accessKeyId: R2_ACCESS_KEY_ID,
        secretAccessKey: R2_SECRET_ACCESS_KEY
      }
    })
  : null;

app.disable("x-powered-by");

app.use((req, res, next) => {
  const origin = req.get("Origin");

  if (origin && origin !== FRONTEND_ORIGIN) {
    return res.status(403).json({
      error: "Origin not allowed"
    });
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

const asyncRoute = (handler) => (req, res, next) => {
  Promise.resolve(handler(req, res, next)).catch(next);
};

function queryDatabase(endpointPath, httpMethod, dataBody = null) {
  return new Promise((resolve, reject) => {
    try {
      const urlTarget = new URL(
        `${SUPABASE_URL}/rest/v1${endpointPath}`
      );

      const payloadText = dataBody
        ? JSON.stringify(dataBody)
        : "";

      const requestOptions = {
        hostname: urlTarget.hostname,
        port: 443,
        path: urlTarget.pathname + urlTarget.search,
        method: httpMethod,
        headers: {
          apikey: SUPABASE_SERVICE_ROLE_KEY,
          Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
          "Content-Type": "application/json",
          Prefer: "return=representation"
        }
      };

      if (dataBody && httpMethod !== "GET") {
        requestOptions.headers["Content-Length"] =
          Buffer.byteLength(payloadText);
      }

      const databaseRequest = https.request(
        requestOptions,
        (databaseResponse) => {
          let responseText = "";

          databaseResponse.on("data", (chunk) => {
            responseText += chunk;
          });

          databaseResponse.on("end", () => {
            if (databaseResponse.statusCode >= 400) {
              reject(
                new Error(
                  `Database request failed: ` +
                  `${databaseResponse.statusCode} - ${responseText}`
                )
              );
              return;
            }

            try {
              resolve(JSON.parse(responseText));
            } catch {
              resolve(responseText);
            }
          });
        }
      );

      databaseRequest.setTimeout(15000, () => {
        databaseRequest.destroy(
          new Error("Database request timed out.")
        );
      });

      databaseRequest.on("error", reject);

      if (dataBody && httpMethod !== "GET") {
        databaseRequest.write(payloadText);
      }

      databaseRequest.end();
    } catch (error) {
      reject(error);
    }
  });
}

async function expireRequestIfNeeded(request) {
  const deadline = Date.parse(request.expires_at);

  if (!Number.isFinite(deadline)) {
    throw new Error(
      "Approval request has an invalid expires_at."
    );
  }

  if (request.status !== "PENDING" || Date.now() < deadline) {
    return request;
  }

  const updated = await queryDatabase(
    `/approval_requests?id=eq.${request.id}&status=eq.PENDING`,
    "PATCH",
    { status: "EXPIRED" }
  );

  if (Array.isArray(updated) && updated.length === 1) {
    return updated[0];
  }

  const latest = await queryDatabase(
    `/approval_requests?id=eq.${encodeURIComponent(request.id)}&select=*`,
    "GET"
  );

  if (!Array.isArray(latest) || latest.length !== 1) {
    throw new Error(
      "Unable to retrieve current approval status."
    );
  }

  return latest[0];
}

async function appendAuditEvent(
  requestId,
  eventType,
  actor,
  outcome,
  eventPayload = {}
) {
  return queryDatabase(
    "/rpc/audit_append_event",
    "POST",
    {
      p_request_id: requestId,
      p_event_type: eventType,
      p_actor: actor,
      p_outcome: outcome,
      p_event_payload: eventPayload
    }
  );
}

async function anchorAuditChain() {
  if (!externalAnchoringEnabled) {
    return {
      anchored: false,
      reason:
        "External anchoring is not configured. " +
        "Set R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, " +
        "R2_SECRET_ACCESS_KEY, and R2_BUCKET_NAME."
    };
  }

  const headResult = await queryDatabase(
    "/rpc/audit_get_chain_head",
    "POST",
    {}
  );

  const head = Array.isArray(headResult)
    ? headResult[0]
    : headResult;

  if (!head?.chain_head_hash || !head?.last_event_id) {
    throw new Error(
      "Audit chain is empty or returned an invalid head."
    );
  }

  const anchoredAt = new Date().toISOString();
  const objectKey =
    `anchors/${head.last_event_id}-${Date.now()}.json`;

  const checkpoint = {
    schema: "mcp-guardrail-audit-anchor-v1",
    anchoredAt,
    lastEventId: head.last_event_id,
    chainHeadHash: head.chain_head_hash,
    eventCount: head.event_count,
    provider: "cloudflare-r2"
  };

  await r2Client.send(
    new PutObjectCommand({
      Bucket: R2_BUCKET_NAME,
      Key: objectKey,
      Body: JSON.stringify(checkpoint, null, 2),
      ContentType: "application/json",
      Metadata: {
        "chain-head-hash": head.chain_head_hash,
        "last-event-id": String(head.last_event_id)
      }
    })
  );

  await queryDatabase(
    "/audit_chain_anchors",
    "POST",
    {
      anchored_at: anchoredAt,
      last_event_id: head.last_event_id,
      chain_head_hash: head.chain_head_hash,
      anchor_provider: "cloudflare-r2",
      external_reference: objectKey,
      anchor_status: "ANCHORED"
    }
  );

  return {
    anchored: true,
    objectKey,
    lastEventId: head.last_event_id,
    chainHeadHash: head.chain_head_hash,
    eventCount: head.event_count,
    anchoredAt
  };
}

function textResult(value, isError = false) {
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(value, null, 2)
      }
    ],
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
      description: "List all tasks inside the database sandbox."
    },
    async () => {
      const tasks = await queryDatabase(
        "/sandbox_tasks?select=id,title,completed",
        "GET"
      );

      return textResult({
        sandbox: true,
        tasks
      });
    }
  );

  server.registerTool(
    "request_delete_task",
    {
      description: "Stage deletion of one sandbox task.",
      inputSchema: {
        task_id: z.string().min(1).max(100)
      }
    },
    async ({ task_id }) => {
      const taskRecords = await queryDatabase(
        `/sandbox_tasks?id=eq.${task_id}&select=*`,
        "GET"
      );

      if (!Array.isArray(taskRecords) || taskRecords.length === 0) {
        return textResult(
          { error: "Task not found" },
          true
        );
      }

      const task = taskRecords[0];

      const activeRequests = await queryDatabase(
        `/approval_requests?target=eq.${task_id}&status=eq.PENDING&select=*`,
        "GET"
      );

      if (
        Array.isArray(activeRequests) &&
        activeRequests.length > 0
      ) {
        const existingRequest =
          await expireRequestIfNeeded(activeRequests[0]);

        if (existingRequest.status === "PENDING") {
          return textResult({
            requestId: existingRequest.id,
            status: existingRequest.status,
            message: "Approval request already exists."
          });
        }
      }

      const newRequest = {
        id: randomUUID(),
        operation: "DELETE_TASK",
        target: task_id,
        target_title: task.title,
        requester: "demo-mcp-client",
        status: "PENDING",
        created_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 300000).toISOString()
      };

      await queryDatabase(
        "/approval_requests",
        "POST",
        newRequest
      );

      await appendAuditEvent(
        newRequest.id,
        "REQUEST_CREATED",
        "mcp-client",
        "PENDING",
        {
          operation: newRequest.operation,
          target: newRequest.target,
          targetTitle: newRequest.target_title,
          expiresAt: newRequest.expires_at
        }
      );

      return textResult({
        requestId: newRequest.id,
        status: newRequest.status,
        expiresAt: newRequest.expires_at,
        message: "Pending admin approval."
      });
    }
  );

  server.registerTool(
    "get_request_status",
    {
      description:
        "Fetch the current processing outcome of a tracking token transaction.",
      inputSchema: {
        request_id: z.string().uuid()
      }
    },
    async ({ request_id }) => {
      const matchedRequests = await queryDatabase(
        `/approval_requests?id=eq.${request_id}&select=*`,
        "GET"
      );

      if (
        !Array.isArray(matchedRequests) ||
        matchedRequests.length === 0
      ) {
        return textResult(
          { error: "Request not found" },
          true
        );
      }

      const request =
        await expireRequestIfNeeded(matchedRequests[0]);

      return textResult({
        id: request.id,
        operation: request.operation,
        target: request.target,
        targetTitle: request.target_title,
        requester: request.requester,
        status: request.status,
        createdAt: request.created_at,
        expiresAt: request.expires_at
      });
    }
  );

  return server;
}

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
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: "2.0",
        id: null,
        error: {
          code: -32603,
          message: "Internal error"
        }
      });
    }
  }
});

function requireAdmin(req, res, next) {
  const header = req.get("Authorization") || "";
  const supplied = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  const suppliedBuffer = Buffer.from(supplied, "utf8");
  const expectedBuffer = Buffer.from(ADMIN_API_KEY, "utf8");

  const isSameLength =
    suppliedBuffer.length === expectedBuffer.length;

  const isSameValue =
    isSameLength &&
    timingSafeEqual(suppliedBuffer, expectedBuffer);

  if (!isSameValue) {
    return res.status(401).json({
      error: "Unauthorized"
    });
  }

  next();
}

app.get(
  "/api/ledger",
  requireAdmin,
  asyncRoute(async (_req, res) => {
    const records = await queryDatabase(
      "/approval_requests?select=*&order=created_at.desc",
      "GET"
    );

    if (!Array.isArray(records)) {
      throw new Error("Unexpected database response.");
    }

    const transactions = await Promise.all(
      records.map(expireRequestIfNeeded)
    );

    res.setHeader("Cache-Control", "no-store");

    res.json({
      serverTime: new Date().toISOString(),
      transactions: transactions.map((request) => ({
        id: request.id,
        operation: request.operation,
        target: request.target,
        targetTitle: request.target_title,
        requester: request.requester,
        status: request.status,
        createdAt: request.created_at,
        expiresAt: request.expires_at
      }))
    });
  })
);

app.post(
  "/api/override",
  requireAdmin,
  asyncRoute(async (req, res) => {
    const parsed = z
      .object({
        txId: z.string().uuid(),
        action: z.enum(["APPROVE", "ABORT"])
      })
      .strict()
      .safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        error: "Invalid transaction ID or action."
      });
    }

    const { txId, action } = parsed.data;

    const rpcResult = await queryDatabase(
      "/rpc/guardrail_finalize_request",
      "POST",
      {
        p_request_id: txId,
        p_action: action
      }
    );

    const transaction = Array.isArray(rpcResult)
      ? rpcResult[0]
      : rpcResult;

    if (
      !transaction ||
      transaction.id !== txId ||
      typeof transaction.status !== "string"
    ) {
      throw new Error(
        "Database RPC returned an unexpected transaction."
      );
    }

    const responseTransaction = {
      id: transaction.id,
      operation: transaction.operation,
      target: transaction.target,
      targetTitle: transaction.target_title,
      requester: transaction.requester,
      status: transaction.status,
      createdAt: transaction.created_at,
      expiresAt: transaction.expires_at
    };

    await appendAuditEvent(
      transaction.id,
      "ADMIN_DECISION",
      "dashboard-admin",
      transaction.status,
      {
        requestedAction: action,
        operation: transaction.operation,
        target: transaction.target,
        targetTitle: transaction.target_title
      }
    );

    if (transaction.status === "EXPIRED") {
      return res.status(410).json({
        success: false,
        error: "Request expired.",
        transaction: responseTransaction
      });
    }

    res.json({
      success:
        transaction.status === "COMMITTED" ||
        transaction.status === "REJECTED",
      transaction: responseTransaction
    });
  })
);

app.get(
  "/api/audit",
  requireAdmin,
  asyncRoute(async (_req, res) => {
    const events = await queryDatabase(
      "/audit_events?select=*&order=id.asc",
      "GET"
    );

    const verification = await queryDatabase(
      "/rpc/audit_verify_chain",
      "POST",
      {}
    );

    const result = Array.isArray(verification)
      ? verification[0]
      : verification;

    res.setHeader("Cache-Control", "no-store");

    res.json({
      verified: result?.verified === true,
      checkedEvents: result?.checked_events ?? 0,
      firstBrokenEvent: result?.first_broken_event ?? null,
      message:
        result?.message ?? "Verification result unavailable.",
      events
    });
  })
);

app.post(
  "/api/audit/anchor",
  requireAdmin,
  asyncRoute(async (_req, res) => {
    const result = await anchorAuditChain();

    res.setHeader("Cache-Control", "no-store");

    res.json({
      success: result.anchored,
      ...result
    });
  })
);

app.get(
  "/api/audit/anchor/latest",
  requireAdmin,
  asyncRoute(async (_req, res) => {
    const anchors = await queryDatabase(
      "/audit_chain_anchors?select=*&order=id.desc&limit=1",
      "GET"
    );

    const latest = Array.isArray(anchors) ? anchors[0] : null;

    res.setHeader("Cache-Control", "no-store");

    res.json({
      anchored: Boolean(latest),
      anchor: latest
    });
  })
);

app.get("/healthz", (_req, res) => {
  res.json({ status: "ok" });
});

app.get("/", (_req, res) => {
  res.json({ persistent: true });
});

app.use((error, req, res, next) => {
  if (res.headersSent) {
    return next(error);
  }

  if (error.type === "entity.too.large") {
    return res.status(413).json({
      error: "Request exceeds 50 KB."
    });
  }

  if (error.type === "entity.parse.failed") {
    return res.status(400).json({
      error: "Invalid JSON."
    });
  }

  console.error("Request failed:", error.message);

  res.status(500).json({
    error: "Request failed. Check server logs."
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(
    "MCP persistent server active on port " + PORT
  );
});
