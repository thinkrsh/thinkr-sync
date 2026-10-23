import { FORMAT } from './config/format.js';
import { deriveAesKey, deriveBytes } from './crypto.js';
import { SyncError } from './errors.js';
import { randomBytes, toHex } from './lib/bytes.js';

/**
 * The keys of one history, derived from its secret. Only the device holds them; the server sees the
 * store ID and the write token, which reveal nothing about the content.
 */
export interface HistoryKeys {
  /** Encrypts each chat stored on the device. */
  recordKey: CryptoKey;
  /** Encrypts the backup that the server keeps. */
  backupKey: CryptoKey;
  /** The opaque name of the backup on the server, as hex. */
  storeId: string;
  /** The token that lets this history change or delete its backup, as hex. */
  writeToken: string;
}

/** A new random secret for a history. Wrap it with a passkey or a recovery code before storing it. */
export function newHistorySecret(): Uint8Array {
  return randomBytes(FORMAT.historyKeyBytes);
}

/** Derives every key of a history from its secret. */
export async function deriveHistoryKeys(secret: Uint8Array): Promise<HistoryKeys> {
  if (secret.length !== FORMAT.historyKeyBytes) {
    throw new SyncError(
      'INVALID_DATA',
      `A history secret has ${String(FORMAT.historyKeyBytes)} bytes.`,
    );
  }
  const { labels } = FORMAT;
  return {
    recordKey: await deriveAesKey(secret, labels.recordKey),
    backupKey: await deriveAesKey(secret, labels.backupKey),
    storeId: toHex(await deriveBytes(secret, labels.storeId, FORMAT.storeIdBytes)),
    writeToken: toHex(await deriveBytes(secret, labels.writeToken, FORMAT.writeTokenBytes)),
  };
}
