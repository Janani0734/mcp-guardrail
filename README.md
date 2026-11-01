# MCP-Guardrail Enterprise Suite 🛡️

A production-grade, zero-trust security proxy firewall middleware layer designed for the Model Context Protocol (MCP).

## 🌐 Live Systems Framework
* **Live Operations Control Panel UI:** https://janani0734.github.io/mcp-guardrail/
* **24/7 Cloud Telemetry Backend Engine:** Deployed on Render Node Container Environment

## 📈 Market Context & core Problem Space
With the massive 970x explosion in Model Context Protocol adoption—scaling rapidly from 1 lakh downloads/month in late 2024 to 9.6 crores/month by early 2026, enterprises are swiftly wiring autonomous AI clients (Cursor, Claude Code, custom agents) directly to core corporate database clusters. However, granting models raw, unfettered permission layers creates catastrophic vectors for indirect prompt injections or accidental recursive batch mutations. 

`mcp-guardrail` blocks this security loophole by introducing a high-performance proxy gateway that intercepts data mutation attempts out-of-band and enforces an absolute Human-in-the-Loop gateway before queries can resolve.

## 🛠️ Key Architectural Protective Layers

### 1. Time-Collateralized Staging Queue Manager ⏱️
* **Implementation Path:** `src/security/staging.js`
* **Mechanism:** Intercepts high-risk destructive structural intents (`WIPE_LOGS`, `DELETE`, `DROP`). It shifts the context payload execution into an isolated internal memory array queue and activates a 30-second rollback clock window, exposing unique transaction signature tokens (`tx_xxxxxx`) to allow manual administrative override cancellations.

### 2. Cryptographic Compliance Audit Trail Ledger 🔐
* **Implementation Path:** `src/security/ledger.js`
* **Mechanism:** Guarantees absolute, non-falsifiable historical auditing trail tracking by generating a mathematical SHA-256 signature string pairing the model's query plan directly to the specific timestamped human approval event metadata.

### 3. Semantic Canary Honeypot Boundary Verification 🪤
* **Implementation Path:** `src/security/canary.js`
* **Mechanism:** Injects hidden, deterministic parameter verification elements inside query schemas to instantly flag structural alterations caused by indirect adversarial context injections before data blocks execute against production nodes.

## ⚙️ Local Development Quickstart Guide

1. Clone the project folder directly to your workstation layout.
2. Inject your production database tracking keys cleanly into your current terminal memory space session:
   ```cmd
   set SUPABASE_URL=https://supabase.co
   set SUPABASE_ANON_KEY=your-anon-public-key-string
   ```
3. Boot up the high-performance local security proxy layer loop:
   ```cmd
   node src/server.js
   ```
