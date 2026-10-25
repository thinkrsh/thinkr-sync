/** Why an operation of Thinkr sync failed. */
export const SYNC_ERROR_CODES = [
  /** The key, the recovery code, or the passkey does not open the data. */
  'WRONG_KEY',
  /** Stored data does not match the format, or someone changed it. */
  'INVALID_DATA',
  /** The passkey or its authenticator does not support the PRF extension of WebAuthn. */
  'PRF_UNSUPPORTED',
  /** The user closed the passkey prompt, or no passkey of the history was chosen. */
  'PASSKEY_CANCELLED',
  /** The server holds an older revision than this device has seen: a rollback. */
  'ROLLBACK',
  /** The backup on the server changed since the last pull. */
  'CONFLICT',
  /** The server refused or failed the request. */
  'SERVER',
] as const;

export type SyncErrorCode = (typeof SYNC_ERROR_CODES)[number];

/**
 * An error of Thinkr sync, with a code for the caller and a message for people. A SERVER error
 * carries the HTTP status of the answer, such as 413 for a backup over the limit of the server.
 */
export class SyncError extends Error {
  override readonly name = 'SyncError';
  readonly status: number | undefined;

  constructor(
    readonly code: SyncErrorCode,
    message: string,
    options?: { cause?: unknown; status?: number },
  ) {
    super(message, options);
    this.status = options?.status;
  }
}
