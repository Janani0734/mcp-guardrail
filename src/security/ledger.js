import { createHash } from 'crypto';

export class AuditLedger {
  generateSignature(operation, payload, humanApproved) {
    const contextString = `${operation}-${JSON.stringify(payload)}-${humanApproved}`;
    return createHash('sha256').update(contextString).digest('hex');
  }
}
