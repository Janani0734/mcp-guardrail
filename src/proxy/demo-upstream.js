import { timingSafeEqual } from "node:crypto";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

// A stand-in for "someone else's MCP server", used to test the gateway.
// It only trusts calls that carry PROXY_UPSTREAM_BEARER, so the gateway is
// the only way in. Everything here is simulated: no email is ever sent.

export function mountDemoUpstream(app) {
  if (process.env.ENABLE_DEMO_UPSTREAM !== "true") {
    return;
  }

  const bearer = process.env.PROXY_UPSTREAM_BEARER || "";

  if (bearer.length < 24) {
    console.warn(
      "Demo upstream disabled: set PROXY_UPSTREAM_BEARER (24+ characters)."
    );
    return;
  }

  const notes = new Map([
    ["n1", { title: "Shopping list", body: "Milk, rice, lentils" }],
    ["n2", { title: "Meeting notes", body: "Review the approval policy rules" }],
    ["n3", { title: "Old draft", body: "Safe to delete" }]
  ]);

  const outbox = [];

  const text = (value, isError = false) => ({
    content: [{ type: "text", text: JSON.stringify(value, null, 2) }],
    ...(isError ? { isError: true } : {})
  });

  function build() {
    const server = new McpServer({
      name: "demo-notes-upstream",
      version: "0.1.0"
    });

    server.registerTool(
      "list_notes",
      { description: "List all notes (read-only)." },
      async () =>
        text({
          notes: [...notes].map(([id, note]) => ({ id, title: note.title }))
        })
    );

    server.registerTool(
      "read_note",
      {
        description: "Read one note (read-only).",
        inputSchema: { id: z.string().min(1).max(50) }
      },
      async ({ id }) =>
        notes.has(id)
          ? text({ id, ...notes.get(id) })
          : text({ error: "Note not found" }, true)
    );

    server.registerTool(
      "send_email",
      {
        description: "Send an email (simulated; nothing is really sent).",
        inputSchema: {
          to: z.string().min(1).max(200),
          subject: z.string().max(200),
          body: z.string().max(2000)
        }
      },
      async ({ to, subject, body }) => {
        outbox.push({ to, subject, body, at: new Date().toISOString() });

        return text({
          status: "queued (simulated)",
          to,
          outboxSize: outbox.length
        });
      }
    );

    server.registerTool(
      "delete_note",
      {
        description: "Permanently delete a note.",
        inputSchema: { id: z.string().min(1).max(50) }
      },
      async ({ id }) =>
        notes.delete(id)
          ? text({ deleted: id })
          : text({ error: "Note not found" }, true)
    );

    return server;
  }

  app.post("/demo-upstream/mcp", async (req, res) => {
    const header = req.get("Authorization") || "";
    const supplied = header.startsWith("Bearer ") ? header.slice(7) : "";

    const a = Buffer.from(supplied, "utf8");
    const b = Buffer.from(bearer, "utf8");

    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const server = build();

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
      console.error("Demo upstream failed:", error.message);

      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: "2.0",
          id: null,
          error: { code: -32603, message: "Internal error" }
        });
      }
    }
  });

  console.log("Demo upstream active at /demo-upstream/mcp");
}
