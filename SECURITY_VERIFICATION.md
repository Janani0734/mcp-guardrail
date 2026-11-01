```markdown
# SECURITY_VERIFICATION.md (OWASP ASVS ALIGNED METRICS)

This manifest logs the pass/fail results for the security controls of the `mcp-guardrail` proxy firewall suite.

## 🧪 Automated Testing Response Matrix

| ASVS ID | Test Scenario | Threat Vector / Attack Vector | Expected Result | Live Status |
| :--- | :--- | :--- | :--- | :--- |
| **V1.1** | No Authorization Header passed | Broken Object Authentication | `401 / 403 Access Terminated` | **PASS** ✅ |
| **V1.2** | Expired Session JWT submission | Token Expiration Decay Failure | `401 / 403 Token Invalid` | **PASS** ✅ |
| **V1.3** | Valid Non-Admin User JWT payload | Insufficient Authorization Scope | `403 Forbidden` Status | **PASS** ✅ |
| **V1.4** | Override targeted to different tenant | Broken Object Level Authorization (BOLA) | `403 Access Blocked` | **PASS** ✅ |
| **V2.1** | Post request to unknown transaction token | Parameter ID Guessing | `404 Record Missing` | **PASS** ✅ |
| **V2.2** | Admin authorization after 30s limit | Processing Stale Operations | `409 Conflict / 410 Gone` | **PASS** ✅ |
| **V2.3** | Repeated duplicate override calls | Execution Replay Attacks | `409 Conflict: Finalized` | **PASS** ✅ |
| **V3.1** | Unregistered tool request parameter | Schema Bypassing Synonyms | `400 Input Validation Fail` | **PASS** ✅ |
| **V4.1** | CORS query origin from `github.io` | Cross-Origin Header Spoofing | `Access Blocked (No header)` | **PASS** ✅ |
| **V4.2** | CORS query origin from `janani0734.github.io` | Verified Dashboard Access | `200 Allowed Handshake` | **PASS** ✅ |
| **V5.1** | Manual log deletion manipulation | Audit Ledger Deletion Attempts | `Hash-Chain Verification Failure`| **PASS** ✅ |
