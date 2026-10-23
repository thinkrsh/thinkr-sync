import { describe, expect, it } from 'vitest';
import { openBackup, sealBackup, type Backup } from '../src/backup.js';
import { SYNC_SERVER } from '../src/config/server.js';
import { SyncError } from '../src/errors.js';
import { deriveHistoryKeys, newHistorySecret, type HistoryKeys } from '../src/keys.js';
import { toHex } from '../src/lib/bytes.js';
import { addPasskey, unwrapWithPasskey } from '../src/passkey.js';
import { openRecord, sealRecord } from '../src/records.js';
import { newRecoveryCode, unwrapWithRecoveryCode, wrapWithRecoveryCode } from '../src/recovery.js';
import { createSyncClient } from '../src/sync/client.js';
import { handleSyncRequest, memoryStore, type SyncStore } from '../src/sync/server.js';
import { FakeAuthenticator } from './fakeAuthenticator.js';

const BASE_URL = 'https://chat.example/api/sync';
const ACCOUNT = { rpId: 'chat.example', rpName: 'Thinkr', userName: 'Thinkr history' };

/** A fetch that answers from the reference handler, as a server would. */
function serverFetch(store: SyncStore): typeof fetch {
  return (input, init) => handleSyncRequest(new Request(input, init), store);
}

async function rejectsWith(promise: Promise<unknown>, code: string): Promise<void> {
  const error = await promise.then(
    () => undefined,
    (caught: unknown) => caught,
  );
  expect(error).toBeInstanceOf(SyncError);
  expect((error as SyncError).code).toBe(code);
}

async function backupOf(keys: HistoryKeys, revision: number): Promise<Backup> {
  return sealBackup(keys, [], { revision, createdAt: '2026-10-23T12:00:00.000Z', records: [] });
}

describe('sync', () => {
  it('moves a history to a new device, with only ciphertext on the server', async () => {
    const store = memoryStore();
    const phone = new FakeAuthenticator({ prfSupported: true, prfAtCreation: true });
    const secret = newHistorySecret();
    const code = newRecoveryCode();
    const wrappedKeys = [
      await wrapWithRecoveryCode(secret, code),
      await addPasskey(secret, phone, ACCOUNT),
    ];
    const deviceA = await deriveHistoryKeys(secret);
    const chat = { id: 'chat-1', messages: [{ role: 'user', content: 'MARKER-PLAINTEXT' }] };
    const backup = await sealBackup(deviceA, wrappedKeys, {
      revision: 1,
      createdAt: '2026-10-23T12:00:00.000Z',
      records: [{ id: chat.id, value: chat }],
    });
    await createSyncClient({ baseUrl: BASE_URL, keys: deviceA, fetch: serverFetch(store) }).push(
      backup,
      undefined,
    );
    expect((await store.get(deviceA.storeId))?.body).not.toContain('MARKER');

    const storeIdFromCode = (
      await deriveHistoryKeys(await unwrapWithRecoveryCode(wrappedKeys, code))
    ).storeId;
    const deviceB = await deriveHistoryKeys(await unwrapWithRecoveryCode(wrappedKeys, code));
    expect(deviceB.storeId).toBe(storeIdFromCode);
    const pulled = await createSyncClient({
      baseUrl: BASE_URL,
      keys: deviceB,
      fetch: serverFetch(store),
    }).pull();
    expect(pulled).toBeDefined();
    const opened = await openBackup(deviceB, pulled?.backup);
    expect(opened.records[0]?.value).toEqual(chat);
    const viaPasskey = await unwrapWithPasskey(pulled?.backup.keys ?? [], phone, ACCOUNT.rpId);
    expect(toHex(viaPasskey)).toBe(toHex(secret));
    const record = await sealRecord(deviceB, chat.id, chat);
    expect(await openRecord(deviceA, record)).toEqual(chat);
  });

  it('pushes over the last pull, and refuses a push from a stale pull', async () => {
    const keys = await deriveHistoryKeys(newHistorySecret());
    const client = createSyncClient({ baseUrl: BASE_URL, keys, fetch: serverFetch(memoryStore()) });
    expect(await client.pull()).toBeUndefined();
    const first = await client.push(await backupOf(keys, 1), undefined);
    const second = await client.push(await backupOf(keys, 2), first);
    expect(second).not.toBe(first);
    await rejectsWith(client.push(await backupOf(keys, 3), first), 'CONFLICT');
    await rejectsWith(client.push(await backupOf(keys, 3), undefined), 'CONFLICT');
    const pulled = await client.pull();
    expect(pulled?.etag).toBe(second);
    expect((await openBackup(keys, pulled?.backup)).revision).toBe(2);
  });

  it('deletes a backup', async () => {
    const keys = await deriveHistoryKeys(newHistorySecret());
    const client = createSyncClient({ baseUrl: BASE_URL, keys, fetch: serverFetch(memoryStore()) });
    await client.push(await backupOf(keys, 1), undefined);
    await client.remove();
    expect(await client.pull()).toBeUndefined();
  });
});

describe('the reference sync server', () => {
  async function put(
    store: SyncStore,
    keys: HistoryKeys,
    body: string,
    headers: Record<string, string>,
  ): Promise<number> {
    const request = new Request(`${BASE_URL}/${keys.storeId}`, { method: 'PUT', body, headers });
    return (await handleSyncRequest(request, store)).status;
  }

  it('refuses a write without the write token, or with another one', async () => {
    const store = memoryStore();
    const keys = await deriveHistoryKeys(newHistorySecret());
    const body = JSON.stringify(await backupOf(keys, 1));
    expect(await put(store, keys, body, { 'If-None-Match': '*' })).toBe(401);
    expect(
      await put(store, keys, body, {
        Authorization: `Bearer ${keys.writeToken}`,
        'If-None-Match': '*',
      }),
    ).toBe(201);
    const etag = (await store.get(keys.storeId))?.etag ?? '';
    const other = await deriveHistoryKeys(newHistorySecret());
    expect(
      await put(store, keys, body, {
        Authorization: `Bearer ${other.writeToken}`,
        'If-Match': etag,
      }),
    ).toBe(403);
  });

  it('asks for the tag before it overwrites a backup', async () => {
    const store = memoryStore();
    const keys = await deriveHistoryKeys(newHistorySecret());
    const body = JSON.stringify(await backupOf(keys, 1));
    const auth = { Authorization: `Bearer ${keys.writeToken}` };
    expect(await put(store, keys, body, auth)).toBe(201);
    expect(await put(store, keys, body, auth)).toBe(428);
  });

  it('refuses a body that is not a backup, or that is too large', async () => {
    const store = memoryStore();
    const keys = await deriveHistoryKeys(newHistorySecret());
    const auth = { Authorization: `Bearer ${keys.writeToken}`, 'If-None-Match': '*' };
    expect(await put(store, keys, '{"chats":["plain"]}', auth)).toBe(400);
    expect(await put(store, keys, 'x'.repeat(SYNC_SERVER.maxBackupBytes + 1), auth)).toBe(413);
  });

  it('answers 404 for a path that is not a store ID', async () => {
    const response = await handleSyncRequest(new Request(`${BASE_URL}/not-a-store`), memoryStore());
    expect(response.status).toBe(404);
  });
});
