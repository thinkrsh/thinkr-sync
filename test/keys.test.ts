import { describe, expect, it } from 'vitest';
import { SyncError } from '../src/errors.js';
import { deriveHistoryKeys, newHistorySecret } from '../src/keys.js';
import {
  historySecretFromRecoveryCode,
  newRecoveryCode,
  parseRecoveryCode,
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

  it('gives the same history on every device, and another code another one', async () => {
    const code = newRecoveryCode();
    const typed = code.toLowerCase().replaceAll('-', ' ');
    const [secret, again, other] = await Promise.all([
      historySecretFromRecoveryCode(code),
      historySecretFromRecoveryCode(typed),
      historySecretFromRecoveryCode(newRecoveryCode()),
    ]);
    expect(secret).toHaveLength(32);
    expect(toHex(again)).toBe(toHex(secret));
    expect(toHex(other)).not.toBe(toHex(secret));
    const keys = await deriveHistoryKeys(secret);
    expect((await deriveHistoryKeys(again)).storeId).toBe(keys.storeId);
  });

  it('rejects a code of the wrong length or with a stray character', async () => {
    await rejectsWith(historySecretFromRecoveryCode('ABCD-EFGH'), 'WRONG_KEY');
    await rejectsWith(historySecretFromRecoveryCode(`U${newRecoveryCode().slice(1)}`), 'WRONG_KEY');
  });
});
