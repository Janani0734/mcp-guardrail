# MCP-Guardrail Enterprise Suite 🛡️

A production-grade, zero-trust security proxy middleware engine for the Model Context Protocol (MCP).

## 🌐 Deployed Systems Framework
* **Live Operations Dashboard Interface:** https://github.io
* **Telemetry Server Entry Point Layer:** `src/server.js` (Port 8080 Management Route Bridge)

## 📈 Market Landscape & Core Thesis
With the monumental 970x explosion in Model Context Protocol adoption—scaling from 1 lakh downloads/month in late 2024 to 9.6 crores/month in early 2026—enterprises are rapidly exposing data clusters (Supabase databases, CRMs, Notion nodes) directly to autonomous AI agents (Claude Code, Cursor, ChatGPT extensions). However, giving models write access scales the risk of runaway batch mutations or indirect prompt injections exponentially. 

`mcp-guardrail` solves this by introducing a strict, zero-trust firewall middleware layer that isolates high-risk actions out-of-band and guarantees an absolute Human-in-the-Loop approval constraint.

## 🛠️ The Three Core Security Innovations

### 1. Time-Collateralized Staging Buffer ⏱️
* **The Logic:** `src/security/staging.js`
* **Execution:** Automatically intercepts destructive database queries (e.g., `WIPE_LOGS`, `DROP`, `DELETE`). Instead of firing them blindly, it suspends execution in a localized memory queue for a 30-second rollback countdown buffer, providing unique transaction tokens (`tx_xxxxxx`) for out-of-band human manual overrides.

### 2. Semantic Canary Honey-pots 🪤
* **The Logic:** `src/security/canary.js`
* **Execution:** Injects hidden boundary check tokens (`[VALID_DATA_EOF_TOKEN]`) into outbox payload lanes. If an external attacker attempts an Indirect Prompt Injection, the token structure breaks. The server detects the structural anomaly, logs a threat alert flag, and completely kills the data transaction loop before it touches live rows.

### 3. Cryptographic Audit Ledger 🔐
* **The Logic:** `src/security/ledger.js`
* **Execution:** Enforces non-repudiation by mathematically generating immutable SHA-256 compliance signatures across prompt goals, arguments, and human authorization events, preventing historical trace logs from being retroactively falsified.

## 💻 Local Quickstart Environment Setup

1. Clone this enterprise suite folder layout directly to your computer.
2. Initialize your secure environment runtime flags using the command line:
   ```cmd
   set SUPABASE_URL=https://supabase.co
   set SUPABASE_ANON_KEY=your-anon-public-key-token
   ```
3. Launch the high-performance local proxy administration engine live:
   ```cmd
   node src/server.js
   ```
