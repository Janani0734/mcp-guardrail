import { createHash, randomBytes } from "node:crypto";
import { z } from "zod";

// Workspace and API key management (slice 1c-i).
//
// Platform routes are for YOU, the owner of the service, and are protected
// by the existing ADMIN_API_KEY. Customers never see them.
// A customer API key looks like  mgk_live_<43 random characters>.
// Only its SHA-256 hash is stored; the key itself is returned once.

const KEY_PATTERN = /^mgk_live_[A-Za-z0-9_-]{43}$/;

export function generateApiKey() {
  const key = `mgk_live_${randomBytes(32).toString("base64url")}`;

  return {
    key,
    prefix: key.slice(0, 13),
    hash: hashApiKey(key)
  };
}

export function hashApiKey(key) {
  return createHash("sha256").update(key).digest("hex");
}

export function mountWorkspaceAdmin(app, deps) {
  const { queryDatabase, requirePlatformAdmin, asyncRoute } = deps;

  const lastTouched = new Map();

  // Used by the next slice: turns a customer key into a workspace.
  // Returns null for unknown, revoked or suspended keys.
  async function resolveWorkspaceKey(token) {
    if (typeof token !== "string" || !KEY_PATTERN.test(token)) {
      return null;
    }

    const rows = await queryDatabase(
      `/api_keys?key_hash=eq.${hashApiKey(token)}&revoked_at=is.null` +
      "&select=id,workspace_id,role,workspaces(slug,status)",
      "GET"
    );

    if (!Array.isArray(rows) || rows.length !== 1) {
      return null;
    }

    const row = rows[0];

    if (row.workspaces?.status !== "active") {
      return null;
    }

    // Record last use at most once a minute per key.
    const now = Date.now();

    if ((lastTouched.get(row.id) || 0) < now - 60000) {
      lastTouched.set(row.id, now);

      void queryDatabase(
        `/api_keys?id=eq.${encodeURIComponent(row.id)}`,
        "PATCH",
        { last_used_at: new Date(now).toISOString() }
      ).catch(() => {});
    }

    return {
      keyId: row.id,
      workspaceId: row.workspace_id,
      slug: row.workspaces.slug,
      role: row.role
    };
  }

  app.get(
    "/api/platform/workspaces",
    requirePlatformAdmin,
    asyncRoute(async (_req, res) => {
      const rows = await queryDatabase(
        "/workspaces?select=id,name,slug,plan,status,created_at&order=created_at.asc",
        "GET"
      );

      res.setHeader("Cache-Control", "no-store");
      res.json({ workspaces: Array.isArray(rows) ? rows : [] });
    })
  );

  app.post(
    "/api/platform/workspaces",
    requirePlatformAdmin,
    asyncRoute(async (req, res) => {
      const parsed = z
        .object({
          name: z.string().min(1).max(80),
          slug: z.string().regex(/^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$/)
        })
        .strict()
        .safeParse(req.body);

      if (!parsed.success) {
        return res.status(400).json({ error: "Invalid workspace." });
      }

      let created;

      try {
        created = await queryDatabase("/workspaces", "POST", parsed.data);
      } catch (error) {
        if (error.db?.code === "23505") {
          return res.status(409).json({ error: "Workspace slug is taken." });
        }

        throw error;
      }

      res.status(201).json({
        workspace: Array.isArray(created) ? created[0] : created
      });
    })
  );

  app.get(
    "/api/platform/workspaces/:id/keys",
    requirePlatformAdmin,
    asyncRoute(async (req, res) => {
      const id = z.string().uuid().safeParse(req.params.id);

      if (!id.success) {
        return res.status(400).json({ error: "Invalid workspace id." });
      }

      // The hash is never selected, so it can never be returned.
      const rows = await queryDatabase(
        `/api_keys?workspace_id=eq.${encodeURIComponent(id.data)}` +
        "&select=id,name,key_prefix,role,created_at,last_used_at,revoked_at" +
        "&order=created_at.asc",
        "GET"
      );

      res.setHeader("Cache-Control", "no-store");
      res.json({ keys: Array.isArray(rows) ? rows : [] });
    })
  );

  app.post(
    "/api/platform/workspaces/:id/keys",
    requirePlatformAdmin,
    asyncRoute(async (req, res) => {
      const id = z.string().uuid().safeParse(req.params.id);

      const body = z
        .object({
          name: z.string().min(1).max(80),
          role: z.enum(["admin", "approver", "viewer"]).default("admin")
        })
        .strict()
        .safeParse(req.body);

      if (!id.success || !body.success) {
        return res.status(400).json({ error: "Invalid key request." });
      }

      const workspace = await queryDatabase(
        `/workspaces?id=eq.${encodeURIComponent(id.data)}&select=id,status`,
        "GET"
      );

      if (!Array.isArray(workspace) || workspace.length === 0) {
        return res.status(404).json({ error: "Workspace not found." });
      }

      const { key, prefix, hash } = generateApiKey();

      const created = await queryDatabase("/api_keys", "POST", {
        workspace_id: id.data,
        name: body.data.name,
        key_prefix: prefix,
        key_hash: hash,
        role: body.data.role
      });

      const row = Array.isArray(created) ? created[0] : created;

      res.setHeader("Cache-Control", "no-store");

      res.status(201).json({
        id: row.id,
        name: row.name,
        role: row.role,
        prefix,
        key,
        warning:
          "This is the only time the key is shown. Store it now; " +
          "it cannot be retrieved later."
      });
    })
  );

  app.delete(
    "/api/platform/keys/:id",
    requirePlatformAdmin,
    asyncRoute(async (req, res) => {
      const id = z.string().uuid().safeParse(req.params.id);

      if (!id.success) {
        return res.status(400).json({ error: "Invalid key id." });
      }

      const revoked = await queryDatabase(
        `/api_keys?id=eq.${encodeURIComponent(id.data)}&revoked_at=is.null`,
        "PATCH",
        { revoked_at: new Date().toISOString() }
      );

      if (!Array.isArray(revoked) || revoked.length === 0) {
        return res.status(404).json({
          error: "Key not found or already revoked."
        });
      }

      res.json({ revoked: revoked[0].id });
    })
  );

  console.log("Workspace admin routes active at /api/platform/*");

  return { resolveWorkspaceKey };
}
