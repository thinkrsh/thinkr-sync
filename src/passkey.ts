import { FORMAT, PASSKEY } from './config/format.js';
import { SyncError } from './errors.js';
import { storeIdBytes } from './keys.js';
import { fromBase64Url, randomBytes, sha256, toBase64Url, toHex, utf8 } from './lib/bytes.js';
import { unwrapSecret, wrapSecret, type WrappedKey } from './wrap.js';

/** What one WebAuthn ceremony gives back: the credential, and the PRF output when there is one. */
export interface PasskeyResult {
  /** The raw ID of the credential, base64url. */
  credentialId: string;
  prfOutput: Uint8Array | undefined;
  /** From registration only: whether the authenticator supports the PRF at all. */
  prfEnabled: boolean | undefined;
  /** From sign-in only: the user handle of the passkey, which names the store of its history. */
  userHandle: Uint8Array | undefined;
}

/**
 * The two ceremonies of WebAuthn, so a test or another platform can stand in for the browser. A
 * prompt that the user closes, or that offers no passkey, rejects with a SyncError PASSKEY_CANCELLED.
 */
export interface PasskeyAuthenticator {
  create(options: PublicKeyCredentialCreationOptions): Promise<PasskeyResult>;
  get(options: PublicKeyCredentialRequestOptions): Promise<PasskeyResult>;
}

/** The account that a new passkey names, as the passkey manager of the user shows it. */
export interface PasskeyAccount {
  /** The domain of the app, such as `chat.thinkr.sh`. */
  rpId: string;
  rpName: string;
  userName: string;
}

/** A passkey that the user picked on a device that knows no history yet, with what it unlocks. */
export interface FoundPasskey {
  /** The store ID of its history, from its user handle, as hex. */
  storeId: string;
  credentialId: string;
  prfOutput: Uint8Array;
}

/** The ceremonies of the browser, through `navigator.credentials`. */
export function browserAuthenticator(): PasskeyAuthenticator {
  return {
    create: async (publicKey) =>
      toResult(await ceremony(() => navigator.credentials.create({ publicKey }))),
    get: async (publicKey) =>
      toResult(await ceremony(() => navigator.credentials.get({ publicKey }))),
  };
}

/**
 * Registers a passkey and wraps the secret of a history with its PRF. The user handle of the passkey
 * is the store ID of the history, so a new device finds the backup from the passkey alone. Some
 * authenticators return the PRF output at registration; for the others, one more prompt reads it.
 * Throws PRF_UNSUPPORTED when the passkey cannot give one: the user then needs the recovery code.
 */
export async function addPasskey(
  secret: Uint8Array,
  authenticator: PasskeyAuthenticator,
  account: PasskeyAccount,
): Promise<WrappedKey> {
  const prfSalt = await passkeyPrfSalt();
  const created = await authenticator.create(
    creationOptions(account, await storeIdBytes(secret), prfSalt),
  );
  if (created.prfEnabled === false) {
    throw new SyncError('PRF_UNSUPPORTED', 'This passkey cannot derive keys (no PRF support).');
  }
  const prfOutput =
    created.prfOutput ??
    (await readPrf(authenticator, account.rpId, [{ credentialId: created.credentialId, prfSalt }]))
      .prfOutput;
  return wrapSecret(secret, requirePrf(prfOutput), {
    credentialId: created.credentialId,
    prfSalt: toBase64Url(prfSalt),
  });
}

/** Opens the secret of a history with any of its passkeys, in one prompt. */
export async function unwrapWithPasskey(
  wrappedKeys: readonly WrappedKey[],
  authenticator: PasskeyAuthenticator,
  rpId: string,
): Promise<Uint8Array> {
  if (wrappedKeys.length === 0) {
    throw new SyncError('WRONG_KEY', 'The history has no passkey.');
  }
  const result = await readPrf(
    authenticator,
    rpId,
    wrappedKeys.map((key) => ({
      credentialId: key.credentialId,
      prfSalt: fromBase64Url(key.prfSalt),
    })),
  );
  return unwrapWith(wrappedKeys, result.credentialId, requirePrf(result.prfOutput));
}

/**
 * On a device that knows no history yet: one prompt in which the user picks any passkey of this
 * domain. It gives the store ID of the history and the PRF output that unwraps its secret, so the
 * device can pull the backup and open it. Throws WRONG_KEY for a passkey of no history.
 */
export async function findWithPasskey(
  authenticator: PasskeyAuthenticator,
  rpId: string,
): Promise<FoundPasskey> {
  const result = await authenticator.get({
    rpId,
    challenge: randomBytes(PASSKEY.challengeBytes),
    allowCredentials: [],
    userVerification: 'required',
    timeout: PASSKEY.timeoutMs,
    extensions: { prf: { eval: { first: await passkeyPrfSalt() } } },
  });
  if (result.userHandle?.length !== FORMAT.storeIdBytes) {
    throw new SyncError('WRONG_KEY', 'This passkey belongs to no history.');
  }
  return {
    storeId: toHex(result.userHandle),
    credentialId: result.credentialId,
    prfOutput: requirePrf(result.prfOutput),
  };
}

/** Opens the secret of a history with a passkey that `findWithPasskey` found. */
export async function unwrapFoundPasskey(
  wrappedKeys: readonly WrappedKey[],
  found: FoundPasskey,
): Promise<Uint8Array> {
  return unwrapWith(wrappedKeys, found.credentialId, found.prfOutput);
}

async function unwrapWith(
  wrappedKeys: readonly WrappedKey[],
  credentialId: string,
  prfOutput: Uint8Array,
): Promise<Uint8Array> {
  const wrapped = wrappedKeys.find((key) => key.credentialId === credentialId);
  if (wrapped === undefined) {
    throw new SyncError('WRONG_KEY', 'The chosen passkey does not belong to this history.');
  }
  return unwrapSecret(wrapped, prfOutput);
}

/** The input of the PRF, the same for every passkey (see FORMAT.prfSaltBytes). */
async function passkeyPrfSalt(): Promise<Uint8Array<ArrayBuffer>> {
  return sha256(utf8(FORMAT.labels.passkeyPrf));
}

function creationOptions(
  account: PasskeyAccount,
  userHandle: Uint8Array<ArrayBuffer>,
  prfSalt: Uint8Array<ArrayBuffer>,
): PublicKeyCredentialCreationOptions {
  return {
    rp: { id: account.rpId, name: account.rpName },
    user: { id: userHandle, name: account.userName, displayName: account.userName },
    challenge: randomBytes(PASSKEY.challengeBytes),
    pubKeyCredParams: PASSKEY.algorithms.map((alg) => ({ type: 'public-key', alg })),
    authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    timeout: PASSKEY.timeoutMs,
    extensions: { prf: { eval: { first: prfSalt } } },
  };
}

/** Asks the authenticator for the PRF output of one of the passkeys, each with its own salt. */
async function readPrf(
  authenticator: PasskeyAuthenticator,
  rpId: string,
  passkeys: { credentialId: string; prfSalt: Uint8Array<ArrayBuffer> }[],
): Promise<PasskeyResult> {
  return authenticator.get({
    rpId,
    challenge: randomBytes(PASSKEY.challengeBytes),
    allowCredentials: passkeys.map(({ credentialId }) => ({
      type: 'public-key',
      id: fromBase64Url(credentialId),
    })),
    userVerification: 'required',
    timeout: PASSKEY.timeoutMs,
    extensions: {
      prf: {
        evalByCredential: Object.fromEntries(
          passkeys.map(({ credentialId, prfSalt }) => [credentialId, { first: prfSalt }]),
        ),
      },
    },
  });
}

function requirePrf(output: Uint8Array | undefined): Uint8Array {
  if (output?.length !== FORMAT.prfOutputBytes) {
    throw new SyncError('PRF_UNSUPPORTED', 'The passkey gave no PRF output.');
  }
  return output;
}

/** Runs a ceremony; a closed prompt or a timeout becomes PASSKEY_CANCELLED. */
async function ceremony(run: () => Promise<Credential | null>): Promise<PublicKeyCredential> {
  let credential: Credential | null;
  try {
    credential = await run();
  } catch (error) {
    if (error instanceof DOMException && error.name === 'NotAllowedError') {
      throw new SyncError('PASSKEY_CANCELLED', 'The passkey prompt was closed.', { cause: error });
    }
    throw error;
  }
  if (!(credential instanceof PublicKeyCredential)) {
    throw new SyncError('PASSKEY_CANCELLED', 'No passkey was chosen.');
  }
  return credential;
}

function toResult(credential: PublicKeyCredential): PasskeyResult {
  const prf = credential.getClientExtensionResults().prf;
  const first = prf?.results?.first;
  const { response } = credential;
  const userHandle =
    response instanceof AuthenticatorAssertionResponse ? response.userHandle : null;
  return {
    credentialId: toBase64Url(new Uint8Array(credential.rawId)),
    prfOutput: first === undefined ? undefined : bufferBytes(first),
    prfEnabled: prf?.enabled,
    userHandle: userHandle === null ? undefined : new Uint8Array(userHandle).slice(),
  };
}

function bufferBytes(source: BufferSource): Uint8Array {
  return ArrayBuffer.isView(source)
    ? new Uint8Array(source.buffer, source.byteOffset, source.byteLength).slice()
    : new Uint8Array(source).slice();
}
