import { describe, expect, it } from 'vitest';
import { SyncError } from '../src/errors.js';
import { deriveHistoryKeys, newHistorySecret } from '../src/keys.js';
import { randomBytes, toHex } from '../src/lib/bytes.js';
import {
  addPasskey,
  findWithPasskey,
  unwrapFoundPasskey,
  unwrapWithPasskey,
} from '../src/passkey.js';
import { FakeAuthenticator } from './fakeAuthenticator.js';

const ACCOUNT = { rpId: 'chat.thinkr.sh', rpName: 'Thinkr', userName: 'Thinkr backup' };

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

  it('name the store of their history in the user handle', async () => {
    const authenticator = new FakeAuthenticator({ prfSupported: true, prfAtCreation: true });
    const secret = newHistorySecret();
    const wrapped = await addPasskey(secret, authenticator, ACCOUNT);
    const userHandle = authenticator.userHandleOf(wrapped.credentialId);
    expect(userHandle && toHex(userHandle)).toBe((await deriveHistoryKeys(secret)).storeId);
  });

  it('find their history on a new device in one prompt', async () => {
    const authenticator = new FakeAuthenticator({ prfSupported: true, prfAtCreation: true });
    const secret = newHistorySecret();
    const wrapped = await addPasskey(secret, authenticator, ACCOUNT);
    const found = await findWithPasskey(authenticator, ACCOUNT.rpId);
    expect(authenticator.calls).toEqual(['create', 'get']);
    expect(found.storeId).toBe((await deriveHistoryKeys(secret)).storeId);
    expect(toHex(await unwrapFoundPasskey([wrapped], found))).toBe(toHex(secret));
  });

  it('refuse a passkey that names no history', async () => {
    const authenticator = new FakeAuthenticator({ prfSupported: true, prfAtCreation: true });
    await authenticator.create({
      rp: { id: ACCOUNT.rpId, name: ACCOUNT.rpName },
      user: { id: randomBytes(16), name: 'Other', displayName: 'Other' },
      challenge: randomBytes(32),
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    });
    await rejectsWith(findWithPasskey(authenticator, ACCOUNT.rpId), 'WRONG_KEY');
  });

  it('open with whichever passkey of the history the user picks', async () => {
    const phone = new FakeAuthenticator({ prfSupported: true, prfAtCreation: true });
    const laptop = new FakeAuthenticator({ prfSupported: true, prfAtCreation: false });
    const secret = newHistorySecret();
    const keys = [
      await addPasskey(secret, phone, ACCOUNT),
      await addPasskey(secret, laptop, ACCOUNT),
    ];
    expect(toHex(await unwrapWithPasskey(keys, laptop, ACCOUNT.rpId))).toBe(toHex(secret));
    expect(toHex(await unwrapWithPasskey(keys, phone, ACCOUNT.rpId))).toBe(toHex(secret));
    const found = await findWithPasskey(laptop, ACCOUNT.rpId);
    expect(toHex(await unwrapFoundPasskey(keys, found))).toBe(toHex(secret));
  });

  it('do not open a history with a passkey of another authenticator', async () => {
    const owner = new FakeAuthenticator({ prfSupported: true, prfAtCreation: true });
    const stranger = new FakeAuthenticator({ prfSupported: true, prfAtCreation: true });
    const wrapped = await addPasskey(newHistorySecret(), owner, ACCOUNT);
    await rejectsWith(unwrapWithPasskey([wrapped], stranger, ACCOUNT.rpId), 'PASSKEY_CANCELLED');
    await addPasskey(newHistorySecret(), stranger, ACCOUNT);
    const found = await findWithPasskey(stranger, ACCOUNT.rpId);
    await rejectsWith(unwrapFoundPasskey([wrapped], found), 'WRONG_KEY');
  });

  it('bind the wrapped key to its passkey', async () => {
    const authenticator = new FakeAuthenticator({ prfSupported: true, prfAtCreation: true });
    const first = await addPasskey(newHistorySecret(), authenticator, ACCOUNT);
    const second = await addPasskey(newHistorySecret(), authenticator, ACCOUNT);
    const swapped = { ...first, credentialId: second.credentialId, prfSalt: second.prfSalt };
    await rejectsWith(unwrapWithPasskey([swapped], authenticator, ACCOUNT.rpId), 'WRONG_KEY');
  });

  it('fail when a byte of the wrapped key changes', async () => {
    const authenticator = new FakeAuthenticator({ prfSupported: true, prfAtCreation: true });
    const wrapped = await addPasskey(newHistorySecret(), authenticator, ACCOUNT);
    const flipped = wrapped.ciphertext.startsWith('A')
      ? `B${wrapped.ciphertext.slice(1)}`
      : `A${wrapped.ciphertext.slice(1)}`;
    await rejectsWith(
      unwrapWithPasskey([{ ...wrapped, ciphertext: flipped }], authenticator, ACCOUNT.rpId),
      'WRONG_KEY',
    );
  });

  it('say so when the history has no passkey', async () => {
    const authenticator = new FakeAuthenticator({ prfSupported: true, prfAtCreation: true });
    await rejectsWith(unwrapWithPasskey([], authenticator, ACCOUNT.rpId), 'WRONG_KEY');
  });
});
