import { describe, expect, it } from 'vitest';
import { openBackup, sealBackup, type Backup } from '../src/backup.js';
import { SYNC_SERVER } from '../src/config/server.js';
import { SyncError } from '../src/errors.js';
import { deriveHistoryKeys, newHistorySecret, type HistoryKeys } from '../src/keys.js';
import { toHex } from '../src/lib/bytes.js';
import { addPasskey, findWithPasskey, unwrapFoundPasskey } from '../src/passkey.js';
import { openRecord, sealRecord } from '../src/records.js';
import { historySecretFromRecoveryCode, newRecoveryCode } from '../src/recovery.js';
import { createSyncClient, fetchBackup, type PullResult } from '../src/sync/client.js';
import { handleSyncRequest, memoryStore, type SyncStore } from '../src/sync/server.js';
import { FakeAuthenticator } from './fakeAuthenticator.js';

const BASE_URL = 'https://chat.example/api/sync';
const ACCOUNT = { rpId: 'chat.example', rpName: 'Thinkr', userName: 'Thinkr backup' };

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

function foundBackup(result: PullResult): Backup | undefined {
  return result.status === 'found' ? result.backup : undefined;
}

describe('sync', () => {
  it('moves a history to a new device, with only ciphertext on the server', async () => {
    const store = memoryStore();
    const phone = new FakeAuthenticator({ prfSupported: true, prfAtCreation: true });
    const code = newRecoveryCode();
    const secret = await historySecretFromRecoveryCode(code);
    const wrappedKeys = [await addPasskey(secret, phone, ACCOUNT)];
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

    // A new device with the recovery code alone: the code names the backup and opens it.
    const deviceB = await deriveHistoryKeys(await historySecretFromRecoveryCode(code));
    expect(deviceB.storeId).toBe(deviceA.storeId);
    const pulled = await createSyncClient({
      baseUrl: BASE_URL,
      keys: deviceB,
      fetch: serverFetch(store),
    }).pull();
    expect(pulled.status).toBe('found');
    const opened = await openBackup(deviceB, foundBackup(pulled));
    expect(opened.records[0]?.value).toEqual(chat);
    const record = await sealRecord(deviceB, chat.id, chat);
    expect(await openRecord(deviceA, record)).toEqual(chat);

    // A new device with the passkey alone: one prompt finds the backup and unwraps its secret.
    const found = await findWithPasskey(phone, ACCOUNT.rpId);
    const fetched = await fetchBackup({
      baseUrl: BASE_URL,
      storeId: found.storeId,
      fetch: serverFetch(store),
    });
    const viaPasskey = await unwrapFoundPasskey(fetched?.backup.keys ?? [], found);
    expect(toHex(viaPasskey)).toBe(toHex(secret));
    const deviceC = await deriveHistoryKeys(viaPasskey);
    expect((await openBackup(deviceC, fetched?.backup)).records[0]?.value).toEqual(chat);
  });

  it('pushes over the last pull, and refuses a push from a stale pull', async () => {
    const keys = await deriveHistoryKeys(newHistorySecret());
    const client = createSyncClient({ baseUrl: BASE_URL, keys, fetch: serverFetch(memoryStore()) });
    expect(await client.pull()).toEqual({ status: 'missing' });
    const first = await client.push(await backupOf(keys, 1), undefined);
    const second = await client.push(await backupOf(keys, 2), first);
    expect(second).not.toBe(first);
    await rejectsWith(client.push(await backupOf(keys, 3), first), 'CONFLICT');
    await rejectsWith(client.push(await backupOf(keys, 3), undefined), 'CONFLICT');
    const pulled = await client.pull();
    expect(pulled.status === 'found' && pulled.etag).toBe(second);
    expect((await openBackup(keys, foundBackup(pulled))).revision).toBe(2);
  });

  it('sends a backup again only when it changed since the tag the device names', async () => {
    const keys = await deriveHistoryKeys(newHistorySecret());
    const client = createSyncClient({ baseUrl: BASE_URL, keys, fetch: serverFetch(memoryStore()) });
    const first = await client.push(await backupOf(keys, 1), undefined);
    expect(await client.pull(first)).toEqual({ status: 'unchanged' });
    await client.push(await backupOf(keys, 2), first);
    const pulled = await client.pull(first);
    expect((await openBackup(keys, foundBackup(pulled))).revision).toBe(2);
  });

  it('reports the status of an answer that it cannot use', async () => {
    const keys = await deriveHistoryKeys(newHistorySecret());
    const tooLarge: typeof fetch = () => Promise.resolve(new Response(null, { status: 413 }));
    const client = createSyncClient({ baseUrl: BASE_URL, keys, fetch: tooLarge });
    const error = await client.push(await backupOf(keys, 1), undefined).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(SyncError);
    expect((error as SyncError).code).toBe('SERVER');
    expect((error as SyncError).status).toBe(413);
  });

  it('deletes a backup', async () => {
    const keys = await deriveHistoryKeys(newHistorySecret());
    const client = createSyncClient({ baseUrl: BASE_URL, keys, fetch: serverFetch(memoryStore()) });
    await client.push(await backupOf(keys, 1), undefined);
    await client.remove();
    expect(await client.pull()).toEqual({ status: 'missing' });
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

  it('knows its tag in the forms that a proxy in between gives it', async () => {
    const store = memoryStore();
    const keys = await deriveHistoryKeys(newHistorySecret());
    const auth = { Authorization: `Bearer ${keys.writeToken}` };
    expect(await put(store, keys, JSON.stringify(await backupOf(keys, 1)), auth)).toBe(201);
    const etag = (await store.get(keys.storeId))?.etag ?? '';
    const pulled = await handleSyncRequest(
      new Request(`${BASE_URL}/${keys.storeId}`, { headers: { 'If-None-Match': `W/${etag}` } }),
      store,
    );
    expect(pulled.status).toBe(304);
    const body = JSON.stringify(await backupOf(keys, 2));
    const gzipped = etag.replace(/"$/, '-gzip"');
    expect(await put(store, keys, body, { ...auth, 'If-Match': gzipped })).toBe(200);
  });

  it('answers 404 for a path that is not a store ID', async () => {
    const response = await handleSyncRequest(new Request(`${BASE_URL}/not-a-store`), memoryStore());
    expect(response.status).toBe(404);
  });
});
