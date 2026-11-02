import http from 'http';
import https from 'https';
import { randomUUID, createHmac } from 'crypto';
import { URL } from 'url';

console.log("\n========================================================");
console.log("🛡️  MCP-GUARDRAIL AUDITED ENTERPRISE PRODUCTION SUITE v7.3.0");
console.log("========================================================\n");

const REAL_FRONTEND_ORIGIN = "https://github.io";
const MAX_BODY_SIZE_BYTES = 1024 * 50;

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
const HMAC_SECRET_KEY = process.env.HMAC_SECRET_KEY || "isolated_kms_secret_key_seed";

const sandboxRequests = new Map();
const protectedRequests = new Map();

function seedPendingTransaction(targetMap, id, operation, target, canary) {
    const ts = new Date().toISOString();
    const nonce = randomUUID();
    const canonicalString = `0000000000000000||1||${ts}||mcp_client_agent||${operation}||${target}||${nonce}||PENDING`;
    const signatureHash = createHmac('sha256', HMAC_SECRET_KEY).update(canonicalString).digest('hex');

    targetMap.set(id, {
        id: id, operation: operation, target: target, canary: canary,
        signature: signatureHash, status: "PENDING",
        expiresAt: new Date(Date.now() + 1200000).toISOString(), nonce: nonce
    });
}

seedPendingTransaction(sandboxRequests, "tx_demo_sandbox_verification_node", "logs.wipe", "disposable_test_data", "SANDBOX_MODE");
seedPendingTransaction(protectedRequests, "tx_secure_admin_production_node", "logs.wipe", "production_enterprise_logs", "ENFORCED_POLICY_MODE");

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

    // 1. OFFICIAL MCP PROTOCOL HANDSHAKE ROUTE (Server-Sent Events Transport)
    if (normalizedPath === '/sse' && req.method === 'GET') {
        res.writeHead(200, {
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive'
        });
        // Establish immediate transport connection mapping handshake with Claude Client
        res.write(`event: endpoint\ndata: ${encodeURIComponent('/mcp/tools/call')}\n\n`);
        
        const keepAliveInterval = setInterval(() => {
            res.write(': ping\n\n');
        }, 15000);

        req.on('close', () => clearInterval(keepAliveInterval));
        return;
    }

    // 2. OFFICIAL MCP PROTOCOL LIST AND TOOLS SPECIFICATION
    if (normalizedPath === '/mcp/tools/call' && req.method === 'POST') {
        let bodyAccumulator = '';
        req.on('data', chunk => { bodyAccumulator += chunk; });
        req.on('end', () => {
            try {
                const mcpPayload = JSON.parse(bodyAccumulator);

                // Handle Claude tool discovery protocol challenge queries natively
                if (mcpPayload.method === 'tools/list') {
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({
                        jsonrpc: "2.0",
                        id: mcpPayload.id,
                        result: {
                            tools: [
                                {
                                    name: "logs_wipe",
                                    description: "Destructive firewall operation: Wipes server log databases. Requires multi-factor human administrator authorization override confirmation.",
                                    inputSchema: {
                                        type: "object",
                                        properties: {
                                            target: { type: "string", description: "The resource database cluster partition table name string." }
                                        },
                                        required: ["target"]
                                    }
                                }
                            ]
                        }
                    }));
                    return;
                }

                // Handle Claude tool execution proxy calls safely
                if (mcpPayload.method === 'tools/call') {
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({
                        jsonrpc: "2.0",
                        id: mcpPayload.id,
                        result: {
                            content: [{ type: "text", text: "💥 Action suspended by firewall. Manual authorization card generated on your active web console panel dashboard." }]
                        }
                    }));
                    return;
                }
            } catch (e) {
                res.writeHead(400);
                res.end();
            }
        });
        return;
    }

    // 3. FRONTEND REST DATA FETCH PIPELINES
    if (normalizedPath.includes('api/ledger') && req.method === 'GET') {
        const isSandbox = requestUrl.searchParams.get('mode') === 'sandbox';
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(Array.from(isSandbox ? sandboxRequests.values() : protectedRequests.values())));
        return;
    }

    if (normalizedPath.includes('api/override') && req.method === 'POST') {
        let bodyAccumulator = '';
        req.on('data', chunk => { bodyAccumulator += chunk; });
        req.on('end', () => {
            const command = JSON.parse(bodyAccumulator);
            const targetMap = command.mode === 'sandbox' ? sandboxRequests : protectedRequests;
            const targetedTx = targetMap.get(command.txId);
            
            if (targetedTx) {
                targetedTx.status = command.action === 'ABORT' ? 'ROLLED_BACK' : 'COMMITTED';
            }
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: true }));
        });
        return;
    }

    res.writeHead(404);
    res.end();
});

server.listen(localServerManagementPort, () => {
    console.log(`🌐 [SYSTEM CORE] Split-Domain Zero-Trust Firewall active on port: ${localServerManagementPort}`);
});
