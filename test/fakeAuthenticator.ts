import { SyncError } from '../src/errors.js';
import type { PasskeyAuthenticator, PasskeyResult } from '../src/passkey.js';
import { concatBytes, ownBytes, randomBytes, sha256, toBase64Url, utf8 } from '../src/lib/bytes.js';

/** How the fake authenticator behaves, as real authenticators differ. */
export interface FakeOptions {
  /** Whether the authenticator supports the PRF (CTAP2 hmac-secret) at all. */
  prfSupported: boolean;
  /** Whether it returns the PRF output already at registration. */
  prfAtCreation: boolean;
}

interface FakeCredential {
  secret: Uint8Array;
  userHandle: Uint8Array;
}

function bytesOf(source: BufferSource): Uint8Array {
  return ArrayBuffer.isView(source)
    ? new Uint8Array(source.buffer, source.byteOffset, source.byteLength)
    : new Uint8Array(source);
}

/**
 * An authenticator in memory. Its PRF is what browsers and CTAP2 do: the browser hashes the input
 * with the prefix "WebAuthn PRF" and a zero byte, and the authenticator returns the HMAC-SHA-256 of
 * that hash under a secret of the credential. A sign-in with no allowed credentials offers every
 * passkey, as a discoverable credential does, and the user picks the one named by `choose`, or else
 * the newest.
 */
export class FakeAuthenticator implements PasskeyAuthenticator {
  readonly calls: ('create' | 'get')[] = [];
  private readonly credentials = new Map<string, FakeCredential>();
  private chosen: string | undefined;

  constructor(private readonly options: FakeOptions) {}

  /** The credential that the user picks in the next sign-in without allowed credentials. */
  choose(credentialId: string): void {
    this.chosen = credentialId;
  }

  /** The user handle that a credential keeps, as the passkey manager stores it. */
  userHandleOf(credentialId: string): Uint8Array | undefined {
    return this.credentials.get(credentialId)?.userHandle;
  }

  async create(options: PublicKeyCredentialCreationOptions): Promise<PasskeyResult> {
    this.calls.push('create');
    const credentialId = toBase64Url(randomBytes(16));
    const secret = randomBytes(32);
    this.credentials.set(credentialId, { secret, userHandle: bytesOf(options.user.id).slice() });
    const input = options.extensions?.prf?.eval?.first;
    const giveOutput =
      this.options.prfSupported && this.options.prfAtCreation && input !== undefined;
    return {
      credentialId,
      prfOutput: giveOutput ? await prf(secret, bytesOf(input)) : undefined,
      prfEnabled: this.options.prfSupported,
      userHandle: undefined,
    };
  }

  async get(options: PublicKeyCredentialRequestOptions): Promise<PasskeyResult> {
    this.calls.push('get');
    const allowed = (options.allowCredentials ?? []).map((credential) =>
      toBase64Url(bytesOf(credential.id)),
    );
    const credentialId =
      allowed.length === 0
        ? (this.chosen ?? [...this.credentials.keys()].at(-1))
        : allowed.find((id) => this.credentials.has(id));
    const credential = credentialId === undefined ? undefined : this.credentials.get(credentialId);
    if (credentialId === undefined || credential === undefined) {
      throw new SyncError('PASSKEY_CANCELLED', 'No passkey of this authenticator was allowed.');
    }
    const prfInputs = options.extensions?.prf;
    const input = prfInputs?.evalByCredential?.[credentialId]?.first ?? prfInputs?.eval?.first;
    return {
      credentialId,
      prfOutput:
        this.options.prfSupported && input !== undefined
          ? await prf(credential.secret, bytesOf(input))
          : undefined,
      prfEnabled: undefined,
      userHandle: credential.userHandle,
    };
  }
}

async function prf(secret: Uint8Array, input: Uint8Array): Promise<Uint8Array> {
  const salt = await sha256(concatBytes(utf8('WebAuthn PRF'), new Uint8Array(1), input));
  const key = await crypto.subtle.importKey(
    'raw',
    ownBytes(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, salt));
}
