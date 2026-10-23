import { describe, expect, it } from 'vitest';
import { SyncError } from '../src/errors.js';
import { newHistorySecret } from '../src/keys.js';
import { toHex } from '../src/lib/bytes.js';
import { addPasskey, unwrapWithPasskey } from '../src/passkey.js';
import { wrapWithRecoveryCode } from '../src/recovery.js';
import { newRecoveryCode } from '../src/recovery.js';
import { FakeAuthenticator } from './fakeAuthenticator.js';

const ACCOUNT = { rpId: 'chat.thinkr.sh', rpName: 'Thinkr', userName: 'Thinkr history' };

async function rejectsWith(promise: Promise<unknown>, code: string): Promise<void> {
  const error = await promise.then(
    () => undefined,
    (caught: unknown) => caught,
  );
  expect(error).toBeInstanceOf(SyncError);
  expect((error as SyncError).code).toBe(code);
}

describe('passkeys', () => {
  it('wrap the secret in one prompt when the PRF answers at registration', async () => {
    const authenticator = new FakeAuthenticator({ prfSupported: true, prfAtCreation: true });
    const secret = newHistorySecret();
    const wrapped = await addPasskey(secret, authenticator, ACCOUNT);
    expect(authenticator.calls).toEqual(['create']);
    expect(wrapped.kind).toBe('passkey');
    expect(toHex(await unwrapWithPasskey([wrapped], authenticator, ACCOUNT.rpId))).toBe(
      toHex(secret),
    );
  });

  it('take a second prompt when the PRF answers only on sign-in', async () => {
    const authenticator = new FakeAuthenticator({ prfSupported: true, prfAtCreation: false });
    const secret = newHistorySecret();
    const wrapped = await addPasskey(secret, authenticator, ACCOUNT);
    expect(authenticator.calls).toEqual(['create', 'get']);
    expect(toHex(await unwrapWithPasskey([wrapped], authenticator, ACCOUNT.rpId))).toBe(
      toHex(secret),
    );
  });

  it('report an authenticator without the PRF', async () => {
    const authenticator = new FakeAuthenticator({ prfSupported: false, prfAtCreation: false });
    await rejectsWith(addPasskey(newHistorySecret(), authenticator, ACCOUNT), 'PRF_UNSUPPORTED');
  });

  it('open with whichever passkey of the history the user picks', async () => {
    const phone = new FakeAuthenticator({ prfSupported: true, prfAtCreation: true });
    const laptop = new FakeAuthenticator({ prfSupported: true, prfAtCreation: false });
    const secret = newHistorySecret();
    const keys = [
      await wrapWithRecoveryCode(secret, newRecoveryCode()),
      await addPasskey(secret, phone, ACCOUNT),
      await addPasskey(secret, laptop, ACCOUNT),
    ];
    expect(toHex(await unwrapWithPasskey(keys, laptop, ACCOUNT.rpId))).toBe(toHex(secret));
    expect(toHex(await unwrapWithPasskey(keys, phone, ACCOUNT.rpId))).toBe(toHex(secret));
  });

  it('do not open a history with a passkey of another authenticator', async () => {
    const owner = new FakeAuthenticator({ prfSupported: true, prfAtCreation: true });
    const stranger = new FakeAuthenticator({ prfSupported: true, prfAtCreation: true });
    const wrapped = await addPasskey(newHistorySecret(), owner, ACCOUNT);
    await rejectsWith(unwrapWithPasskey([wrapped], stranger, ACCOUNT.rpId), 'PASSKEY_CANCELLED');
  });

  it('bind the wrapped key to its passkey', async () => {
    const authenticator = new FakeAuthenticator({ prfSupported: true, prfAtCreation: true });
    const first = await addPasskey(newHistorySecret(), authenticator, ACCOUNT);
    const second = await addPasskey(newHistorySecret(), authenticator, ACCOUNT);
    const swapped = { ...first, credentialId: second.credentialId, prfSalt: second.prfSalt };
    await rejectsWith(unwrapWithPasskey([swapped], authenticator, ACCOUNT.rpId), 'WRONG_KEY');
  });

  it('say so when the history has no passkey', async () => {
    const authenticator = new FakeAuthenticator({ prfSupported: true, prfAtCreation: true });
    const recovery = await wrapWithRecoveryCode(newHistorySecret(), newRecoveryCode());
    await rejectsWith(unwrapWithPasskey([recovery], authenticator, ACCOUNT.rpId), 'WRONG_KEY');
  });
});
