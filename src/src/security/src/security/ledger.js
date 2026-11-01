import { createHash } from 'crypto';
export class AuditLedger {
  generateSignature(prompt, payload, humanApproved) {
    const dataString = `${prompt}-${JSON.stringify(payload)}-${humanApproved}`;
    return createHash('sha256').update(dataString).digest('hex');
  }
}
