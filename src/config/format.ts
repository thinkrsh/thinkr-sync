/**
 * The formats of Thinkr sync, version 1. Each label separates one use of the history key, so no
 * key serves two purposes. Changing a label or a size breaks every stored record: raise the version.
 */
export const FORMAT = {
  version: 1,
  /** The secret that encrypts the history, 256 bits. */
  historyKeyBytes: 32,
  /** The nonce of AES-256-GCM. */
  aesNonceBytes: 12,
  /** The input of the PRF of a passkey, new for each wrapped key. */
  prfSaltBytes: 32,
  /** The output of the PRF that WebAuthn returns (HMAC-SHA-256). */
  prfOutputBytes: 32,
  /** The opaque name of a backup on the sync server, and the token that may change it. */
  storeIdBytes: 32,
  writeTokenBytes: 32,
  backupFormat: 'thinkr-sync-backup',
  labels: {
    recordKey: 'thinkr-sync record key v1',
    backupKey: 'thinkr-sync backup key v1',
    storeId: 'thinkr-sync store id v1',
    writeToken: 'thinkr-sync write token v1',
    passkeyWrap: 'thinkr-sync passkey wrap v1',
    recoveryWrap: 'thinkr-sync recovery wrap v1',
    recordData: 'thinkr-sync record v1',
    backupData: 'thinkr-sync backup v1',
    wrappedKeyData: 'thinkr-sync wrapped key v1',
  },
} as const;

/**
 * The recovery code: 160 random bits in Crockford base32, 32 characters in groups of 4. Crockford
 * leaves out I, L, O, and U, so a code copied by hand reads back the same.
 */
export const RECOVERY_CODE = {
  bytes: 20,
  alphabet: '0123456789ABCDEFGHJKMNPQRSTVWXYZ',
  groupLength: 4,
  separator: '-',
} as const;

/** The options of a passkey for the PRF extension of WebAuthn. */
export const PASSKEY = {
  /** ES256 first, then RS256, as most authenticators support one of them. */
  algorithms: [-7, -257],
  challengeBytes: 32,
  userIdBytes: 32,
  timeoutMs: 120_000,
} as const;
