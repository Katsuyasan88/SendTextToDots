import { randomUUID, timingSafeEqual } from 'node:crypto';
import type { Firestore, Transaction } from '@google-cloud/firestore';

import { grantReceiverGenerationOf } from '../access/policy.js';
import { createCommandDeliveryAttempt, type CommandDeliveryEgress } from '../commands/delivery-attempt.js';
import type { ConnectStorage } from '../connect/firestore.js';
import type { SubscriptionAuth } from '../events/subscriptions.js';
import type { McpRequestOperation, RequestScopedSendTextPort, SendTextResult } from '../mcp/request-operation.js';
import type { Clock } from '../policy.js';
import type { SecretHasher } from '../secrets.js';
import { isAccountGrant } from '../source/connected-apps.js';
import { parseSourceRecord } from '../source/contract.js';
import { ownerReceiverGeneration } from '../storage/firestore/receiver-reset.js';
import { createKmsRequestDeliveryRuntime, type KmsRequestDeliveryRuntime, type KmsRequestDeliveryRuntimeOptions } from './kms-runtime.js';

export interface McpSendTextOptions {
  readonly namespace: string;
  readonly egress: CommandDeliveryEgress;
  loadDigestKey(operation: McpRequestOperation): Promise<Buffer>;
}

interface RuntimeOptions extends McpSendTextOptions {
  readonly db: Firestore;
  readonly storage: ConnectStorage;
  readonly hasher: SecretHasher;
  readonly identifierKey: Buffer;
  readonly clock: Clock;
  readonly kms: KmsRequestDeliveryRuntimeOptions['kms'];
}

export async function createMcpSendText(options: RuntimeOptions, startup: McpRequestOperation): Promise<RequestScopedSendTextPort & { dispose(): void }> {
  const { db, storage, namespace, clock, egress, hasher, identifierKey, kms } = options;
  const digestKey = await options.loadDigestKey(startup);
  let runtime: KmsRequestDeliveryRuntime;
  try {
    if (!Buffer.isBuffer(digestKey) || digestKey.length !== 32 || timingSafeEqual(digestKey, identifierKey) || startup.signal.aborted || clock.now() >= startup.deadlineAt) {
      throw new Error('mcp_send_config_invalid');
    }
    const attempt = createCommandDeliveryAttempt({ egress, clock });
    try {
      runtime = createKmsRequestDeliveryRuntime({ db, connect: storage, namespace, clock, hasher, digestKey, attempt, newAttemptId: randomUUID, kms });
    } catch (error) {
      attempt.dispose();
      throw error;
    }
  } finally {
    if (Buffer.isBuffer(digestKey)) digestKey.fill(0);
  }

  async function canSend(tx: Transaction, auth: SubscriptionAuth, operation: McpRequestOperation): Promise<boolean> {
    const { ownerId, grantId } = auth;
    const bindingRef = storage.grantSourceDocRef(grantId);
    if (bindingRef === null) return false;
    const owner = await tx.get(storage.ownerDocRef(ownerId));
    const ownerData = owner.data();
    const accessRef = storage.accessDocRefForOwner(ownerData);
    if (accessRef === null) return false;
    const access = await tx.get(accessRef);
    const grant = await tx.get(storage.grantDocRef(grantId));
    const meta = await tx.get(storage.grantMetaDocRef(grantId));
    const binding = await tx.get(bindingRef);
    const sourceRef = storage.grantSourceRecordRef({ exists: binding.exists, data: binding.data() });
    const source = sourceRef === null ? null : await tx.get(sourceRef);
    const at = clock.now();
    if (operation.signal.aborted || at >= operation.deadlineAt || !storage.ownerDocActive(ownerData, at) || !storage.grantDocLive(grant.data(), ownerId, grantId, at)) return false;
    if (storage.grantUseDecision({ exists: access.exists, data: access.data() }, { exists: meta.exists, data: meta.data() }, ownerId) !== 'allowed') return false;
    if (grantReceiverGenerationOf(meta.data()) !== ownerReceiverGeneration(ownerData)) return false;
    if (storage.grantSourceDecision({ exists: binding.exists, data: binding.data() }, source === null ? null : { exists: source.exists, id: source.id, data: source.data() }, at) !== 'allowed') return false;
    return isAccountGrant(binding.data()) || (source !== null && parseSourceRecord(source.data(), source.id).operations.includes('send'));
  }

  return Object.freeze({
    async send(auth: SubscriptionAuth, text: string, operation: McpRequestOperation): Promise<SendTextResult> {
      const receivedAt = clock.now();
      if (operation.signal.aborted || receivedAt >= operation.deadlineAt) return 'not_delivered';
      if (!(await db.runTransaction((tx) => canSend(tx, auth, operation)))) return 'not_delivered';
      const commandId = randomUUID();
      const iso = (at: number) => new Date(Math.floor(at / 1000) * 1000).toISOString().replace('.000Z', 'Z');
      const body = Buffer.from(JSON.stringify({ schemaVersion: 2, commandId, text, createdAt: iso(receivedAt), expiresAt: iso(receivedAt + 60_000) }));
      try {
        const result = await runtime.service.post(auth.ownerId, commandId, body, receivedAt, operation, (tx) => canSend(tx, auth, operation));
        const status = typeof result.body === 'object' && result.body !== null && 'state' in result.body ? result.body.state : undefined;
        if (status === 'delivered') return 'delivered';
        if (result.status >= 500 || status === 'delivery_unknown' || status === 'in_flight') return 'delivery_unknown';
        return 'not_delivered';
      } finally {
        body.fill(0);
      }
    },
    dispose: () => runtime.dispose(),
  });
}
