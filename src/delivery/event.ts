// 送信APIの応答形と、送出するevent（docs/API.md §4）のID・bytesの組立て。

import { EVENT_NAME } from '../events/contract.js';
import type { CommandInputFields } from '../commands/input.js';
import type { SecretHasher } from '../secrets.js';

const EVENT_ID_PURPOSE = 't257:event-id';

export interface DeliveryResponse {
  readonly status: number;
  readonly body: unknown;
  readonly headers?: Readonly<Record<string, string>>;
}

const iso = (ms: number) => new Date(ms).toISOString();

export function errorResponse(status: number, code: string, retryable = false, headers?: Record<string, string>): DeliveryResponse {
  return { status, body: { error: { code, retryable } }, ...(headers ? { headers } : {}) };
}

/** owner＋commandIdから安定したUUIDv8（eventId）。別ownerの同じcommandIdでも重ならない。 */
export function eventIdFor(hasher: SecretHasher, ownerId: string, commandId: string): string {
  const hex = hasher.hash(EVENT_ID_PURPOSE, `${ownerId}\0${commandId}`).slice(0, 32).split('');
  hex[12] = '8';
  hex[16] = ((Number.parseInt(hex[16]!, 16) & 0x3) | 0x8).toString(16);
  const h = hex.join('');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}

/** eventのUTF-8（docs/API.md §4の順）。dataは4項目で、fieldsの文字列は送られた表記のまま。createdAtは入れない。 */
export function buildEventBytes(fields: CommandInputFields, eventId: string, receivedAt: number, expiresAt: number): Buffer {
  const json = JSON.stringify({
    eventId,
    name: EVENT_NAME,
    timestamp: iso(receivedAt),
    data: {
      schemaVersion: fields.schemaVersion,
      commandId: fields.commandId,
      text: fields.text,
      expiresAt: iso(expiresAt),
    },
    cursor: null,
  });
  const bytes = Buffer.allocUnsafeSlow(Buffer.byteLength(json, 'utf8'));
  bytes.write(json, 'utf8');
  return bytes;
}
