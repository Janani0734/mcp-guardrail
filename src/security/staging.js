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
    return { txId, message: `Action staged securely. Undo ID: ${txId}` };
  }

  rollback(txId) {
    const tx = this.registry.get(txId);
    if (tx && tx.status === 'PENDING') {
      clearTimeout(tx.timer);
      tx.status = 'ROLLED_BACK';
      console.log(`\n🛡️ ACTION ROLLED BACK: Transaction ${txId} cancelled by proxy override.`);
      return { success: true };
    }
    return { success: false };
  }
}
