import { FORMAT } from './config/format.js';
import { open, seal } from './crypto.js';
import { SyncError } from './errors.js';
import { fromBase64Url, fromUtf8, toBase64Url, utf8 } from './lib/bytes.js';
import { isRecord } from './lib/json.js';
import type { HistoryKeys } from './keys.js';

/**
 * One chat as the device stores it: only its ID is in the clear. The ID is bound into the seal, so
 * a stored chat cannot pass for another one.
 */
export interface SealedRecord {
  v: typeof FORMAT.version;
  id: string;
  nonce: string;
  ciphertext: string;
}

/** Seals a value, such as a chat, as JSON under the record key of the history. */
export async function sealRecord(
  keys: HistoryKeys,
  id: string,
  value: unknown,
): Promise<SealedRecord> {
  if (id === '') {
    throw new SyncError('INVALID_DATA', 'A record needs an ID.');
  }
  const sealed = await seal(
    keys.recordKey,
    utf8(JSON.stringify(value)),
    FORMAT.labels.recordData,
    id,
  );
  return {
    v: FORMAT.version,
    id,
    nonce: toBase64Url(sealed.nonce),
    ciphertext: toBase64Url(sealed.ciphertext),
  };
}

/**
 * Opens a stored record and returns its value, parsed from JSON. The caller checks the value
 * against its own schema. Throws INVALID_DATA when the record was changed or belongs to another key.
 */
export async function openRecord(keys: HistoryKeys, record: unknown): Promise<unknown> {
  const sealed = parseSealedRecord(record);
  const plaintext = await open(
    keys.recordKey,
    { nonce: fromBase64Url(sealed.nonce), ciphertext: fromBase64Url(sealed.ciphertext) },
    FORMAT.labels.recordData,
    sealed.id,
  );
  if (plaintext === undefined) {
    throw new SyncError('INVALID_DATA', `The record ${sealed.id} does not open with this history.`);
  }
  return JSON.parse(fromUtf8(plaintext));
}

function parseSealedRecord(value: unknown): SealedRecord {
  if (
    !isRecord(value) ||
    value.v !== FORMAT.version ||
    typeof value.id !== 'string' ||
    typeof value.nonce !== 'string' ||
    typeof value.ciphertext !== 'string'
  ) {
    throw new SyncError('INVALID_DATA', 'A stored record does not match the format.');
  }
  return value as unknown as SealedRecord;
}
