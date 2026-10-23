import { FORMAT, PASSKEY } from './config/format.js';
import { SyncError } from './errors.js';
import { fromBase64Url, randomBytes, toBase64Url } from './lib/bytes.js';
import { unwrapSecret, wrapSecret, type WrappedKey } from './wrap.js';

/** What one WebAuthn ceremony gives back: the credential, and the PRF output when there is one. */
export interface PasskeyResult {
  /** The raw ID of the credential, base64url. */
  credentialId: string;
  prfOutput: Uint8Array | undefined;
  /** From registration only: whether the authenticator supports the PRF at all. */
  prfEnabled: boolean | undefined;
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
 * Registers a passkey and wraps the secret of a history with its PRF. Some authenticators return
 * the PRF output at registration; for the others, one more prompt reads it. Throws PRF_UNSUPPORTED
 * when the passkey cannot give one: the user then needs the recovery code.
 */
export async function addPasskey(
  secret: Uint8Array,
  authenticator: PasskeyAuthenticator,
  account: PasskeyAccount,
): Promise<WrappedKey> {
  const prfSalt = randomBytes(FORMAT.prfSaltBytes);
  const created = await authenticator.create(creationOptions(account, prfSalt));
  if (created.prfEnabled === false) {
    throw new SyncError('PRF_UNSUPPORTED', 'This passkey cannot derive keys (no PRF support).');
  }
  const prfOutput =
    created.prfOutput ??
    (await readPrf(authenticator, account.rpId, [{ credentialId: created.credentialId, prfSalt }]))
      .prfOutput;
  return wrapSecret(secret, requirePrf(prfOutput), 'passkey', {
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
  const passkeys = wrappedKeys.filter((key) => key.kind === 'passkey');
  if (passkeys.length === 0) {
    throw new SyncError('WRONG_KEY', 'The history has no passkey.');
  }
  const result = await readPrf(
    authenticator,
    rpId,
    passkeys.map((key) => ({
      credentialId: key.credentialId,
      prfSalt: fromBase64Url(key.prfSalt),
    })),
  );
  const wrapped = passkeys.find((key) => key.credentialId === result.credentialId);
  if (wrapped === undefined) {
    throw new SyncError('PASSKEY_CANCELLED', 'The chosen passkey does not belong to this history.');
  }
  return unwrapSecret(wrapped, requirePrf(result.prfOutput));
}

function creationOptions(
  account: PasskeyAccount,
  prfSalt: Uint8Array<ArrayBuffer>,
): PublicKeyCredentialCreationOptions {
  return {
    rp: { id: account.rpId, name: account.rpName },
    user: {
      id: randomBytes(PASSKEY.userIdBytes),
      name: account.userName,
      displayName: account.userName,
    },
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
  return {
    credentialId: toBase64Url(new Uint8Array(credential.rawId)),
    prfOutput: first === undefined ? undefined : bufferBytes(first),
    prfEnabled: prf?.enabled,
  };
}

function bufferBytes(source: BufferSource): Uint8Array {
  return ArrayBuffer.isView(source)
    ? new Uint8Array(source.buffer, source.byteOffset, source.byteLength).slice()
    : new Uint8Array(source).slice();
}
