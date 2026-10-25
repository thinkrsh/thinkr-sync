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

/**
 * A new random secret for a history that has no recovery code. A history with a recovery code takes
 * its secret from `historySecretFromRecoveryCode` instead.
 */
export function newHistorySecret(): Uint8Array {
  return randomBytes(FORMAT.historyKeyBytes);
}

/** Derives every key of a history from its secret. */
export async function deriveHistoryKeys(secret: Uint8Array): Promise<HistoryKeys> {
  assertSecret(secret);
  const { labels } = FORMAT;
  return {
    recordKey: await deriveAesKey(secret, labels.recordKey),
    backupKey: await deriveAesKey(secret, labels.backupKey),
    storeId: toHex(await storeIdBytes(secret)),
    writeToken: toHex(await deriveBytes(secret, labels.writeToken, FORMAT.writeTokenBytes)),
  };
}

/** The store ID of a history as bytes: the user handle of each of its passkeys. */
export async function storeIdBytes(secret: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  assertSecret(secret);
  return deriveBytes(secret, FORMAT.labels.storeId, FORMAT.storeIdBytes);
}

function assertSecret(secret: Uint8Array): void {
  if (secret.length !== FORMAT.historyKeyBytes) {
    throw new SyncError(
      'INVALID_DATA',
      `A history secret has ${String(FORMAT.historyKeyBytes)} bytes.`,
    );
  }
}
