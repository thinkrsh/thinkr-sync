import { FORMAT } from './config/format.js';
import { open, seal } from './crypto.js';
import { SyncError } from './errors.js';
import { fromBase64Url, fromUtf8, toBase64Url, transform, utf8 } from './lib/bytes.js';
import { isRecord } from './lib/json.js';
import type { HistoryKeys } from './keys.js';
import { parseWrappedKey, type WrappedKey } from './wrap.js';

/** One record inside a backup, such as a chat. The app gives each record an ID of its own. */
export interface BackupRecord {
  id: string;
  value: unknown;
}

/** What a backup holds once it is open. */
export interface BackupContent {
  /** Rises by one with each backup; a lower one than the device has seen is a rollback. */
  revision: number;
  createdAt: string;
  records: BackupRecord[];
}

/**
 * The backup of a history, as the server keeps it. The wrapped keys stay readable, so a new device
 * can open the history with a passkey; the recovery code gives the secret without them. The records
 * are one sealed blob.
 */
export interface Backup {
  v: typeof FORMAT.version;
  format: typeof FORMAT.backupFormat;
  keys: WrappedKey[];
  nonce: string;
  ciphertext: string;
}

/** Seals the records of a history into a backup: JSON, gzip, then AES-256-GCM. */
export async function sealBackup(
  keys: HistoryKeys,
  wrappedKeys: readonly WrappedKey[],
  content: BackupContent,
): Promise<Backup> {
  const packed = await transform(utf8(JSON.stringify(content)), new CompressionStream('gzip'));
  const sealed = await seal(keys.backupKey, packed, FORMAT.labels.backupData, keys.storeId);
  return {
    v: FORMAT.version,
    format: FORMAT.backupFormat,
    keys: [...wrappedKeys],
    nonce: toBase64Url(sealed.nonce),
    ciphertext: toBase64Url(sealed.ciphertext),
  };
}

/**
 * Opens a backup. With `lastRevision`, the revision the device saw last, it throws ROLLBACK when
 * the server serves an older backup.
 */
export async function openBackup(
  keys: HistoryKeys,
  value: unknown,
  lastRevision?: number,
): Promise<BackupContent> {
  const backup = parseBackup(value);
  const packed = await open(
    keys.backupKey,
    { nonce: fromBase64Url(backup.nonce), ciphertext: fromBase64Url(backup.ciphertext) },
    FORMAT.labels.backupData,
    keys.storeId,
  );
  if (packed === undefined) {
    throw new SyncError('INVALID_DATA', 'The backup does not open with this history.');
  }
  const content = parseContent(
    JSON.parse(fromUtf8(await transform(packed, new DecompressionStream('gzip')))),
  );
  if (lastRevision !== undefined && content.revision < lastRevision) {
    throw new SyncError(
      'ROLLBACK',
      `The server sent revision ${String(content.revision)}, older than ${String(lastRevision)}.`,
    );
  }
  return content;
}

/** Reads the envelope of a backup, such as its wrapped keys before the history is unlocked. */
export function parseBackup(value: unknown): Backup {
  if (
    !isRecord(value) ||
    value.v !== FORMAT.version ||
    value.format !== FORMAT.backupFormat ||
    !Array.isArray(value.keys) ||
    typeof value.nonce !== 'string' ||
    typeof value.ciphertext !== 'string'
  ) {
    throw new SyncError('INVALID_DATA', 'The backup does not match the format.');
  }
  return {
    v: FORMAT.version,
    format: FORMAT.backupFormat,
    keys: value.keys.map(parseWrappedKey),
    nonce: value.nonce,
    ciphertext: value.ciphertext,
  };
}

function parseContent(value: unknown): BackupContent {
  const records = isRecord(value) ? value.records : undefined;
  if (
    !isRecord(value) ||
    !Number.isSafeInteger(value.revision) ||
    typeof value.createdAt !== 'string' ||
    !Array.isArray(records) ||
    !records.every((record) => isRecord(record) && typeof record.id === 'string')
  ) {
    throw new SyncError('INVALID_DATA', 'The content of the backup does not match the format.');
  }
  return value as unknown as BackupContent;
}
