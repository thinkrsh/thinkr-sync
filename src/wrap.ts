import { FORMAT } from './config/format.js';
import { deriveAesKey, open, seal } from './crypto.js';
import { SyncError } from './errors.js';
import { fromBase64Url, toBase64Url } from './lib/bytes.js';
import { isRecord } from './lib/json.js';

/** How a wrapped key opens: with a passkey through its PRF, or with a recovery code. */
export type WrapKind = 'passkey' | 'recovery';

/**
 * The secret of a history, sealed under a key derived from a passkey or a recovery code. It is
 * safe to store anywhere: without the passkey or the code it opens nothing.
 */
export interface WrappedKey {
  v: typeof FORMAT.version;
  kind: WrapKind;
  /** The WebAuthn credential ID, base64url, for a passkey; empty for a recovery code. */
  credentialId: string;
  /** The input of the PRF of the passkey, base64url; empty for a recovery code. */
  prfSalt: string;
  nonce: string;
  ciphertext: string;
}

const WRAP_LABELS: Readonly<Record<WrapKind, string>> = {
  passkey: FORMAT.labels.passkeyWrap,
  recovery: FORMAT.labels.recoveryWrap,
};

/** The context that binds a wrapped key to its kind and its passkey. */
function wrapContext(kind: WrapKind, credentialId: string): string {
  return `${kind}:${credentialId}`;
}

/** Seals the secret of a history under a key derived from `material` (a PRF output or a code). */
export async function wrapSecret(
  secret: Uint8Array,
  material: Uint8Array,
  kind: WrapKind,
  details: { credentialId: string; prfSalt: string },
): Promise<WrappedKey> {
  const key = await deriveAesKey(material, WRAP_LABELS[kind]);
  const sealed = await seal(
    key,
    secret,
    FORMAT.labels.wrappedKeyData,
    wrapContext(kind, details.credentialId),
  );
  return {
    v: FORMAT.version,
    kind,
    credentialId: details.credentialId,
    prfSalt: details.prfSalt,
    nonce: toBase64Url(sealed.nonce),
    ciphertext: toBase64Url(sealed.ciphertext),
  };
}

/** Opens a wrapped key with `material`; throws WRONG_KEY when the material does not fit. */
export async function unwrapSecret(wrapped: WrappedKey, material: Uint8Array): Promise<Uint8Array> {
  const key = await deriveAesKey(material, WRAP_LABELS[wrapped.kind]);
  const secret = await open(
    key,
    { nonce: fromBase64Url(wrapped.nonce), ciphertext: fromBase64Url(wrapped.ciphertext) },
    FORMAT.labels.wrappedKeyData,
    wrapContext(wrapped.kind, wrapped.credentialId),
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
    (value.kind !== 'passkey' && value.kind !== 'recovery') ||
    fields.some((field) => typeof value[field] !== 'string')
  ) {
    throw new SyncError('INVALID_DATA', 'A wrapped key does not match the format.');
  }
  const wrapped = value as unknown as WrappedKey;
  const passkeyFields = wrapped.credentialId !== '' && wrapped.prfSalt !== '';
  const noPasskeyFields = wrapped.credentialId === '' && wrapped.prfSalt === '';
  if (wrapped.kind === 'passkey' ? !passkeyFields : !noPasskeyFields) {
    throw new SyncError('INVALID_DATA', `A ${wrapped.kind} key has the wrong passkey fields.`);
  }
  return wrapped;
}
