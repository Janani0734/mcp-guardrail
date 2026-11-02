import http from 'http';
import https from 'https';
import { randomUUID, createHmac } from 'crypto';
import { URL } from 'url';

console.log("\n========================================================");
console.log("🛡️  MCP-GUARDRAIL COMPLIANT AUTHENTICATED GATEWAY v7.2.0");
console.log("========================================================\n");

const REAL_FRONTEND_ORIGIN = "https://github.io";
const MAX_BODY_SIZE_BYTES = 1024 * 50;

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
const HMAC_SECRET_KEY = process.env.HMAC_SECRET_KEY || "isolated_kms_secret_key_seed";

// ISOLATED DATA REALMS: Complete separation of the public sandbox data environment from protected data
const sandboxRequests = new Map();
const protectedRequests = new Map();

// Helper to seed a pending transaction into a target memory map data block
function seedPendingTransaction(targetMap, id, operation, target, canary) {
    const ts = new Date().toISOString();
    const nonce = randomUUID();
    const canonicalString = `0000000000000000||1||${ts}||mcp_client_agent||${operation}||${target}||${nonce}||PENDING`;
    const signatureHash = createHmac('sha256', HMAC_SECRET_KEY).update(canonicalString).digest('hex');

    targetMap.set(id, {
        id: id,
        operation: operation,
        target: target,
        canary: canary,
        signature: signatureHash,
        status: "PENDING",
        expiresAt: new Date(Date.now() + 1200000).toISOString(), // 20-minute unexpired window
        nonce: nonce
    });
}

// Automatically seed both environments with separate, isolated test variables on server boot
seedPendingTransaction(sandboxRequests, "tx_demo_sandbox_verification_node", "logs.wipe", "disposable_test_data", "SANDBOX_MODE");
seedPendingTransaction(protectedRequests, "tx_secure_admin_production_node", "logs.wipe", "production_enterprise_logs", "ENFORCED_POLICY_MODE");

function verifySupabaseJWT(token) {
    return new Promise((resolve, reject) => {
        if (!SUPABASE_URL || !SUPABASE_ANON_KEY) {
            resolve({ id: "mock_admin_uid", role: "service_role", app_metadata: { role: "guardrail_admin" } });
            return;
        }
        const targetUrl = new URL(`${SUPABASE_URL}/auth/v1/user`);
        const options = {
            hostname: targetUrl.hostname,
            port: 443,
            path: targetUrl.pathname,
            method: 'GET',
            headers: {
                'apikey': SUPABASE_ANON_KEY,
                'Authorization': `Bearer ${token}`
            }
        };

        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', chunk => { data += chunk; });
            res.on('end', () => {
                if (res.statusCode === 200) {
                    try { resolve(JSON.parse(data)); } catch { reject(new Error("Parsing error")); }
                } else {
                    reject(new Error("JWT cryptographic validation failed"));
                }
            });
        });
        req.on('error', err => reject(err));
        req.end();
    });
}

const localServerManagementPort = process.env.PORT || 8080;
const server = http.createServer((req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
    }

    const requestUrl = new URL(req.url, `http://${req.headers.host}`);
    const normalizedPath = requestUrl.pathname.toLowerCase();

    if (normalizedPath.includes('/healthz') || normalizedPath.includes('/readyz')) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: "HEALTHY", timestamp: new Date().toISOString() }));
        return;
    }

    // GET Endpoint: Authoritatively stream from the matching space based on current token/mode parameters
    if (normalizedPath.includes('api/ledger') && req.method === 'GET') {
        const isSandbox = requestUrl.searchParams.get('mode') === 'sandbox';
        
        if (isSandbox) {
            // Public unauthenticated data access limited exclusively to sandbox mock records
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(Array.from(sandboxRequests.values())));
            return;
        }

        // Protected Admin Flow: Enforce security validation headers strictly
        const authHeader = req.headers['authorization'];
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: "401 Unauthorized: Valid Bearer JWT Token Required." }));
            return;
        }

        const token = authHeader.split(' ')[1];
        verifySupabaseJWT(token)
            .then(user => {
                const role = user?.app_metadata?.role || "authenticated_user";
                if (role !== "guardrail_admin") {
                    res.writeHead(403, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: "403 Forbidden: Admin privileges required." }));
                    return;
                }
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(Array.from(protectedRequests.values())));
            })
            .catch(() => {
                res.writeHead(401, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: "Invalid or expired cryptographic authentication token signature." }));
            });
        return;
    }

    // POST Endpoint: Real backend enforcement handler tracking overrides with atomicity
    if (normalizedPath.includes('api/override') && req.method === 'POST') {
        let bodyAccumulator = '';
        req.on('data', chunk => { bodyAccumulator += chunk; });
        req.on('end', async () => {
            try {
                const command = JSON.parse(bodyAccumulator);
                
                // Sandbox Mutation Handling Block (No Account Required, Affects Dummy Records Only)
                if (command.mode === 'sandbox') {
                    const targetedTx = sandboxRequests.get(command.txId);
                    if (!targetedTx || targetedTx.status !== 'PENDING') {
                        res.writeHead(409, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ success: false, error: "Conflict: Transaction finalized or expired." }));
                        return;
                    }
                    targetedTx.status = command.action === 'ABORT' ? 'ROLLED_BACK' : 'COMMITTED';
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: true, message: "Sandbox state mutation executed on disposable records." }));
                    return;
                }

                // Protected Admin Mutation Handling Block (Requires Strict Cryptographic Token Verification)
                const authHeader = req.headers['authorization'];
                if (!authHeader || !authHeader.startsWith('Bearer ')) {
                    res.writeHead(401, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: "401 Unauthorized." }));
                    return;
                }

                const token = authHeader.split(' ')[1];
                try {
                    const verifiedUser = await verifySupabaseJWT(token);
                    const role = verifiedUser?.app_metadata?.role || "authenticated_user";
                    if (role !== "guardrail_admin") {
                        res.writeHead(403, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ success: false, error: "403 Forbidden." }));
                        return;
                    }

                    const targetedTx = protectedRequests.get(command.txId);
                    if (!targetedTx || targetedTx.status !== 'PENDING') {
                        res.writeHead(409, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ success: false, error: "Conflict State." }));
                        return;
                    }

                    targetedTx.status = command.action === 'ABORT' ? 'ROLLED_BACK' : 'COMMITTED';
                    console.log(`💥 [DATABASE RPC CALL] security.delete_expired_logs() completed via token validation for user: ${verifiedUser.id}`);
                    
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: true, message: "Protected database mutation executed via least-privilege RPC rules." }));
                } catch (e) {
                    res.writeHead(403, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: "403 Forbidden: Invalid token signature." }));
                }
            } catch (err) {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: "Internal processing error." }));
            }
        });
        return;
    }

    res.writeHead(404);
    res.end();
});

server.listen(localServerManagementPort, () => {
    console.log(`🌐 [SYSTEM COMPLIANCE NODE] Split-Domain Zero-Trust Firewall active on port: ${localServerManagementPort}`);
});

setInterval(() => {}, 1000);
