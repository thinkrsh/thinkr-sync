import { describe, expect, it } from 'vitest';
import { openBackup, parseBackup, sealBackup, type BackupContent } from '../src/backup.js';
import { SyncError } from '../src/errors.js';
import { deriveHistoryKeys, newHistorySecret, type HistoryKeys } from '../src/keys.js';
import { openRecord, sealRecord } from '../src/records.js';
import { newRecoveryCode, wrapWithRecoveryCode } from '../src/recovery.js';

const CHAT = {
  id: 'chat-1',
  title: 'Tax questions',
  messages: [{ role: 'user', content: 'MARKER-PLAINTEXT' }],
};

async function keys(): Promise<HistoryKeys> {
  return deriveHistoryKeys(newHistorySecret());
}

async function rejectsWith(promise: Promise<unknown>, code: string): Promise<void> {
  const error = await promise.then(
    () => undefined,
    (caught: unknown) => caught,
  );
  expect(error).toBeInstanceOf(SyncError);
  expect((error as SyncError).code).toBe(code);
}

function content(revision: number): BackupContent {
  return {
    revision,
    createdAt: '2026-10-23T12:00:00.000Z',
    records: [{ id: CHAT.id, value: CHAT }],
  };
}

describe('records', () => {
  it('open to the value they sealed, with nothing readable at rest', async () => {
    const history = await keys();
    const sealed = await sealRecord(history, CHAT.id, CHAT);
    expect(JSON.stringify(sealed)).not.toContain('MARKER');
    expect(JSON.stringify(sealed)).not.toContain('Tax');
    expect(await openRecord(history, sealed)).toEqual(CHAT);
  });

  it('do not open under another history', async () => {
    const sealed = await sealRecord(await keys(), CHAT.id, CHAT);
    await rejectsWith(openRecord(await keys(), sealed), 'INVALID_DATA');
  });

  it('cannot pass for another chat', async () => {
    const history = await keys();
    const sealed = await sealRecord(history, CHAT.id, CHAT);
    await rejectsWith(openRecord(history, { ...sealed, id: 'chat-2' }), 'INVALID_DATA');
  });

  it('fail when a byte changes', async () => {
    const history = await keys();
    const sealed = await sealRecord(history, CHAT.id, CHAT);
    const ciphertext = sealed.ciphertext.startsWith('A')
      ? `B${sealed.ciphertext.slice(1)}`
      : `A${sealed.ciphertext.slice(1)}`;
    await rejectsWith(openRecord(history, { ...sealed, ciphertext }), 'INVALID_DATA');
  });

  it('reject stored data of another shape', async () => {
    await rejectsWith(openRecord(await keys(), CHAT), 'INVALID_DATA');
  });
});

describe('backups', () => {
  it('open to the chats they hold, with the wrapped keys readable', async () => {
    const history = await keys();
    const wrapped = await wrapWithRecoveryCode(newHistorySecret(), newRecoveryCode());
    const backup = await sealBackup(history, [wrapped], content(3));
    expect(JSON.stringify(backup)).not.toContain('MARKER');
    expect(parseBackup(JSON.parse(JSON.stringify(backup))).keys).toEqual([wrapped]);
    expect(await openBackup(history, backup)).toEqual(content(3));
  });

  it('compress repeated text before sealing', async () => {
    const history = await keys();
    const long = { ...CHAT, messages: Array.from({ length: 200 }, () => CHAT.messages[0]) };
    const backup = await sealBackup(history, [], {
      ...content(1),
      records: [{ id: CHAT.id, value: long }],
    });
    expect(backup.ciphertext.length).toBeLessThan(JSON.stringify(long).length / 4);
  });

  it('refuse an older revision than the device saw: a rollback', async () => {
    const history = await keys();
    const backup = await sealBackup(history, [], content(4));
    expect((await openBackup(history, backup, 4)).revision).toBe(4);
    await rejectsWith(openBackup(history, backup, 5), 'ROLLBACK');
  });

  it('do not open under another history', async () => {
    const backup = await sealBackup(await keys(), [], content(1));
    await rejectsWith(openBackup(await keys(), backup), 'INVALID_DATA');
  });

  it('reject an envelope of another shape', async () => {
    await rejectsWith(openBackup(await keys(), { v: 1, format: 'other' }), 'INVALID_DATA');
  });
});
