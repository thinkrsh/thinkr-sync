import { FORMAT } from './config/format.js';
import { deriveAesKey, open, seal } from './crypto.js';
import { SyncError } from './errors.js';
import { fromBase64Url, toBase64Url } from './lib/bytes.js';
import { isRecord } from './lib/json.js';

/** How a wrapped key opens: with a passkey, through its PRF. */
export type WrapKind = 'passkey';

/**
 * The secret of a history, sealed under a key derived from the PRF of a passkey. It is safe to
 * store anywhere: without the passkey it opens nothing.
 */
export interface WrappedKey {
  v: typeof FORMAT.version;
  kind: WrapKind;
  /** The WebAuthn credential ID of the passkey, base64url. */
  credentialId: string;
  /** The input of the PRF of the passkey, base64url. */
  prfSalt: string;
  nonce: string;
  ciphertext: string;
}

/** The context that binds a wrapped key to its passkey. */
function wrapContext(credentialId: string): string {
  return `passkey:${credentialId}`;
}

/** Seals the secret of a history under a key derived from the PRF output of a passkey. */
export async function wrapSecret(
  secret: Uint8Array,
  prfOutput: Uint8Array,
  details: { credentialId: string; prfSalt: string },
): Promise<WrappedKey> {
  const key = await deriveAesKey(prfOutput, FORMAT.labels.passkeyWrap);
  const sealed = await seal(
    key,
    secret,
    FORMAT.labels.wrappedKeyData,
    wrapContext(details.credentialId),
  );
  return {
    v: FORMAT.version,
    kind: 'passkey',
    credentialId: details.credentialId,
    prfSalt: details.prfSalt,
    nonce: toBase64Url(sealed.nonce),
    ciphertext: toBase64Url(sealed.ciphertext),
  };
}

/** Opens a wrapped key with a PRF output; throws WRONG_KEY when the output does not fit. */
export async function unwrapSecret(
  wrapped: WrappedKey,
  prfOutput: Uint8Array,
): Promise<Uint8Array> {
  const key = await deriveAesKey(prfOutput, FORMAT.labels.passkeyWrap);
  const secret = await open(
    key,
    { nonce: fromBase64Url(wrapped.nonce), ciphertext: fromBase64Url(wrapped.ciphertext) },
    FORMAT.labels.wrappedKeyData,
    wrapContext(wrapped.credentialId),
  );
  if (secret?.length !== FORMAT.historyKeyBytes) {
    throw new SyncError('WRONG_KEY', 'This key does not open the history.');
  }
  return secret;
}

/** Reads a wrapped key from stored JSON; throws INVALID_DATA on any other shape. */
export function parseWrappedKey(value: unknown): WrappedKey {
  const fields = ['credentialId', 'prfSalt', 'nonce', 'ciphertext'] as const;
  if (
    !isRecord(value) ||
    value.v !== FORMAT.version ||
    value.kind !== 'passkey' ||
    fields.some((field) => typeof value[field] !== 'string' || value[field] === '')
  ) {
    throw new SyncError('INVALID_DATA', 'A wrapped key does not match the format.');
  }
  return value as unknown as WrappedKey;
}
