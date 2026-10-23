import { describe, expect, it } from 'vitest';
import { SyncError } from '../src/errors.js';
import { deriveHistoryKeys, newHistorySecret } from '../src/keys.js';
import {
  newRecoveryCode,
  parseRecoveryCode,
  unwrapWithRecoveryCode,
  wrapWithRecoveryCode,
} from '../src/recovery.js';
import { toHex } from '../src/lib/bytes.js';

async function rejectsWith(promise: Promise<unknown>, code: string): Promise<void> {
  const error = await promise.then(
    () => undefined,
    (caught: unknown) => caught,
  );
  expect(error).toBeInstanceOf(SyncError);
  expect((error as SyncError).code).toBe(code);
}

describe('history keys', () => {
  it('derive the same store ID and write token from the same secret', async () => {
    const secret = newHistorySecret();
    const [a, b] = await Promise.all([deriveHistoryKeys(secret), deriveHistoryKeys(secret)]);
    expect(a.storeId).toMatch(/^[0-9a-f]{64}$/);
    expect(a.storeId).toBe(b.storeId);
    expect(a.writeToken).toBe(b.writeToken);
    expect(a.storeId).not.toBe(a.writeToken);
  });

  it('differ between two histories', async () => {
    const [a, b] = await Promise.all([
      deriveHistoryKeys(newHistorySecret()),
      deriveHistoryKeys(newHistorySecret()),
    ]);
    expect(a.storeId).not.toBe(b.storeId);
  });

  it('refuse a secret of the wrong length', async () => {
    await rejectsWith(deriveHistoryKeys(new Uint8Array(16)), 'INVALID_DATA');
  });
});

describe('recovery code', () => {
  it('has 8 groups of 4 characters of Crockford base32', () => {
    expect(newRecoveryCode()).toMatch(/^([0-9A-HJKMNP-TV-Z]{4}-){7}[0-9A-HJKMNP-TV-Z]{4}$/);
  });

  it('reads back as typed by hand: any case, spaces, and lookalike letters', () => {
    const code = newRecoveryCode();
    const typed = code.toLowerCase().replaceAll('-', ' ').replaceAll('0', 'o').replaceAll('1', 'l');
    expect(toHex(parseRecoveryCode(typed))).toBe(toHex(parseRecoveryCode(code)));
  });

  it('opens the secret it wrapped, and no other code does', async () => {
    const secret = newHistorySecret();
    const code = newRecoveryCode();
    const wrapped = await wrapWithRecoveryCode(secret, code);
    expect(toHex(await unwrapWithRecoveryCode([wrapped], code))).toBe(toHex(secret));
    await rejectsWith(unwrapWithRecoveryCode([wrapped], newRecoveryCode()), 'WRONG_KEY');
  });

  it('rejects a code of the wrong length or with a stray character', async () => {
    const wrapped = await wrapWithRecoveryCode(newHistorySecret(), newRecoveryCode());
    await rejectsWith(unwrapWithRecoveryCode([wrapped], 'ABCD-EFGH'), 'WRONG_KEY');
    await rejectsWith(
      unwrapWithRecoveryCode([wrapped], `U${newRecoveryCode().slice(1)}`),
      'WRONG_KEY',
    );
  });

  it('fails when a byte of the wrapped key changes', async () => {
    const code = newRecoveryCode();
    const wrapped = await wrapWithRecoveryCode(newHistorySecret(), code);
    const flipped = wrapped.ciphertext.startsWith('A')
      ? `B${wrapped.ciphertext.slice(1)}`
      : `A${wrapped.ciphertext.slice(1)}`;
    await rejectsWith(
      unwrapWithRecoveryCode([{ ...wrapped, ciphertext: flipped }], code),
      'WRONG_KEY',
    );
  });
});
