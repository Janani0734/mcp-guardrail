$ npm run test --project=mcp-guardrail

🧪 RUNNING DETERMINISTIC REPEATABLE ADVERSARIAL TEST LAYER...
✅ TEST PASS: [V1.1_No_Auth_Header_Aborts]
✅ TEST PASS: [V1.2_Expired_JWT_Throws_401]
✅ TEST PASS: [V1.3_Non_Admin_Role_Throws_403]
✅ TEST PASS: [V2.3_Idempotency_Double_Approve_Rejected]
✅ TEST PASS: [V2.2_Post_Expiry_Action_Fails]
✅ TEST PASS: [V3.1_Unregistered_Tool_Arguments_Blocked]
✅ TEST PASS: [V4.1_Rogue_CORS_Origin_Denied]

📋 EXECUTION SUMMARY: Passed 7 out of 7 automated assertions against target commit hash: ca00991
