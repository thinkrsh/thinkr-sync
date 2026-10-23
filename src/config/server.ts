/** The limits of the reference sync server. */
export const SYNC_SERVER = {
  /** The largest backup the server keeps, in bytes. */
  maxBackupBytes: 32 * 1024 * 1024,
  /** A store ID is the hex of 32 bytes. */
  storeIdPattern: /^[0-9a-f]{64}$/,
  /** A write token is the hex of 32 bytes, sent as a bearer token. */
  writeTokenPattern: /^[0-9a-f]{64}$/,
  backupMediaType: 'application/json',
} as const;
