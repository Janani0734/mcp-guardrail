export class StagingManager {
  constructor(delaySeconds = 30) {
    this.delaySeconds = delaySeconds;
    this.registry = new Map();
  }
  async stage(toolName, args, executeCallback) {
    const txId = "tx_" + Math.random().toString(36).substring(2, 9);
    console.log(`\n🚨 STAGED ACTION: ${toolName} queued. ${this.delaySeconds}s to UNDO. ID: ${txId}`);
    console.log(`Payload: ${JSON.stringify(args)}`);
    
    const timer = setTimeout(async () => {
      const tx = this.registry.get(txId);
      if (tx && tx.status === 'PENDING') {
        tx.status = 'COMMITTED';
        console.log(`\n✅ TIMER FINISHED: Executing transaction ${txId}...`);
        await executeCallback();
      }
    }, this.delaySeconds * 1000);

    this.registry.set(txId, { toolName, args, status: 'PENDING', timer });
    return { message: `Action staged securely. Undo ID: ${txId}`, txId };
  }
  rollback(txId) {
    const tx = this.registry.get(txId);
    if (!tx || tx.status !== 'PENDING') return { success: false, message: 'Invalid or expired transaction.' };
    clearTimeout(tx.timer);
    tx.status = 'ROLLED_BACK';
    console.log(`\n🛡️ GUARDRAIL RECOVERY: Transaction ${txId} has been rolled back safely.`);
    return { success: true, message: `Rollback complete. Transaction ${txId} killed.` };
  }
}
