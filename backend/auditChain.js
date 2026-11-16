const crypto = require('crypto');
const db = require('./database');

const GENESIS_PREV_HASH = '0'.repeat(64);

function calculateBlockHash(prevHash, timestamp, actorId, action, targetDocId, outcome) {
  const payload = `${prevHash}|${timestamp}|${actorId}|${action}|${targetDocId || 'NONE'}|${outcome}`;
  return crypto.createHash('sha256').update(payload, 'utf8').digest('hex');
}

async function initGenesisIfNeeded() {
  const logs = await db.getAuditLogs();
  if (logs.length === 0) {
    const timestamp = new Date().toISOString();
    const actorId = 'SYSTEM_GENESIS';
    const action = 'SYSTEM_INITIALIZATION';
    const targetDocId = 'NONE';
    const outcome = 'SUCCESS';
    const currHash = calculateBlockHash(GENESIS_PREV_HASH, timestamp, actorId, action, targetDocId, outcome);

    const genesisBlock = {
      index: 0,
      timestamp: new Date(timestamp),
      actorId,
      actorName: 'Security Subsystem',
      actorRole: 'system',
      action,
      targetDocId: null,
      targetDocName: 'Root Security Anchor',
      outcome,
      details: {
        event: 'Cryptographic Hash-Chain Ledger initialized in MongoDB',
        algorithm: 'SHA-256 Chained Block Integrity',
        standard: 'CS3002 Zero-Trust Spec'
      },
      prevHash: GENESIS_PREV_HASH,
      currHash
    };
    await db.appendAuditLog(genesisBlock);
  }
}

const auditChain = {
  async recordEvent({ actorId, actorName, actorRole, action, targetDocId = null, targetDocName = null, outcome = 'SUCCESS', details = {} }) {
    await initGenesisIfNeeded();
    const logs = await db.getAuditLogs();
    const lastBlock = logs[logs.length - 1];
    const prevHash = lastBlock.currHash;
    const timestamp = new Date().toISOString();
    const index = logs.length;

    const currHash = calculateBlockHash(prevHash, timestamp, actorId, action, targetDocId, outcome);

    const logEntry = {
      index,
      timestamp: new Date(timestamp),
      actorId: actorId || 'ANONYMOUS',
      actorName: actorName || 'Unknown User',
      actorRole: actorRole || 'guest',
      action,
      targetDocId,
      targetDocName,
      outcome,
      details,
      prevHash,
      currHash
    };

    await db.appendAuditLog(logEntry);
    return logEntry;
  },

  async verifyChainIntegrity() {
    await initGenesisIfNeeded();
    const logs = await db.getAuditLogs();

    if (logs.length === 0) {
      return { valid: true, totalBlocks: 0, message: 'Audit log is empty' };
    }

    for (let i = 0; i < logs.length; i++) {
      const block = logs[i];

      // 1. Verify index sequence
      if (block.index !== i) {
        return {
          valid: false,
          brokenIndex: i,
          reason: `Block index sequence broken. Expected ${i}, got ${block.index}`,
          block
        };
      }

      // 2. Verify prevHash linking
      const expectedPrevHash = (i === 0) ? GENESIS_PREV_HASH : logs[i - 1].currHash;
      if (block.prevHash !== expectedPrevHash) {
        return {
          valid: false,
          brokenIndex: i,
          reason: `Cryptographic link severed at block #${i}. Stored prevHash does not match previous block's currHash.`,
          storedPrevHash: block.prevHash,
          expectedPrevHash,
          block
        };
      }

      // 3. Recalculate currHash
      const isoTimestamp = new Date(block.timestamp).toISOString();
      const recalculatedHash = calculateBlockHash(
        block.prevHash,
        isoTimestamp,
        block.actorId,
        block.action,
        block.targetDocId,
        block.outcome
      );

      if (block.currHash !== recalculatedHash) {
        return {
          valid: false,
          brokenIndex: i,
          reason: `Content tampering detected at block #${i}. Block data has been modified, invalidating the SHA-256 digest.`,
          storedHash: block.currHash,
          recalculatedHash,
          block
        };
      }
    }

    return {
      valid: true,
      totalBlocks: logs.length,
      lastBlockHash: logs[logs.length - 1].currHash,
      message: `Audit chain integrity verified across all ${logs.length} MongoDB blocks without tampering.`
    };
  },

  // Part 3 Adversarial Simulation: Tamper with a historical log entry
  async tamperLog(index, fakeAction = 'UNAUTHORIZED_ALTERATION') {
    const logs = await db.getAuditLogs();
    if (index < 0 || index >= logs.length) {
      throw new Error(`Invalid log index: ${index}`);
    }
    const original = { ...logs[index] };
    logs[index].action = fakeAction;
    logs[index].details = {
      ...logs[index].details,
      tampered: true,
      tamperedAt: new Date().toISOString()
    };
    await db.overwriteAuditLogs(logs);
    return {
      message: `Log #${index} intentionally modified in MongoDB. Chain integrity should now fail on verification.`,
      original,
      tampered: logs[index]
    };
  }
};

module.exports = auditChain;
