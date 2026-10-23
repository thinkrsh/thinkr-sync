import { SYNC_SERVER } from '../config/server.js';
import { parseBackup } from '../backup.js';
import { bytesEqual, concatBytes, sha256, toHex, utf8 } from '../lib/bytes.js';

/** A backup as the server keeps it: the body, its tag, and the hash of the write token. */
export interface StoredBackup {
  body: string;
  etag: string;
  tokenHash: string;
}

/**
 * Where the server keeps backups. `putIf` must be atomic: it writes only while the current tag is
 * `expected` (undefined: no backup yet), and says whether it wrote.
 */
export interface SyncStore {
  get(storeId: string): Promise<StoredBackup | undefined>;
  putIf(storeId: string, value: StoredBackup, expected: string | undefined): Promise<boolean>;
  delete(storeId: string): Promise<void>;
}

/** A store in memory, for tests and for a single process. */
export function memoryStore(): SyncStore {
  const backups = new Map<string, StoredBackup>();
  return {
    get: (storeId) => Promise.resolve(backups.get(storeId)),
    putIf(storeId, value, expected) {
      if (backups.get(storeId)?.etag !== expected) return Promise.resolve(false);
      backups.set(storeId, value);
      return Promise.resolve(true);
    },
    delete(storeId) {
      backups.delete(storeId);
      return Promise.resolve();
    },
  };
}

const STATUS = {
  ok: 200,
  created: 201,
  noContent: 204,
  badRequest: 400,
  unauthorized: 401,
  forbidden: 403,
  notFound: 404,
  methodNotAllowed: 405,
  preconditionFailed: 412,
  payloadTooLarge: 413,
  preconditionRequired: 428,
} as const;

/**
 * The reference handler of the sync protocol, on the Fetch API, so any server can mount it. The
 * last segment of the path is the store ID. It reads no content: it checks the shape of a backup,
 * the write token, and the tag, and it logs nothing.
 */
export async function handleSyncRequest(request: Request, store: SyncStore): Promise<Response> {
  const storeId = new URL(request.url).pathname.split('/').pop() ?? '';
  if (!SYNC_SERVER.storeIdPattern.test(storeId)) {
    return status(STATUS.notFound);
  }
  switch (request.method) {
    case 'GET':
      return getBackup(store, storeId);
    case 'PUT':
      return putBackup(request, store, storeId);
    case 'DELETE':
      return deleteBackup(request, store, storeId);
    default:
      return status(STATUS.methodNotAllowed);
  }
}

async function getBackup(store: SyncStore, storeId: string): Promise<Response> {
  const stored = await store.get(storeId);
  if (stored === undefined) return status(STATUS.notFound);
  return new Response(stored.body, {
    status: STATUS.ok,
    headers: {
      'Content-Type': SYNC_SERVER.backupMediaType,
      ETag: stored.etag,
      'Cache-Control': 'no-store',
    },
  });
}

async function putBackup(request: Request, store: SyncStore, storeId: string): Promise<Response> {
  const tokenHash = await writeTokenHash(request);
  if (tokenHash === undefined) return status(STATUS.unauthorized);
  const body = await readLimited(request);
  if (body === undefined) return status(STATUS.payloadTooLarge);
  if (!isBackup(body)) return status(STATUS.badRequest);
  const current = await store.get(storeId);
  if (current !== undefined && !sameHash(current.tokenHash, tokenHash)) {
    return status(STATUS.forbidden);
  }
  const expected = request.headers.get('If-Match') ?? undefined;
  const createOnly = request.headers.get('If-None-Match') === '*';
  if (current !== undefined && expected === undefined) {
    return status(createOnly ? STATUS.preconditionFailed : STATUS.preconditionRequired);
  }
  if (current === undefined && expected !== undefined) {
    return status(STATUS.preconditionFailed);
  }
  const etag = `"${toHex(await sha256(utf8(body)))}"`;
  const written = await store.putIf(
    storeId,
    { body, etag, tokenHash },
    current === undefined ? undefined : expected,
  );
  if (!written) return status(STATUS.preconditionFailed);
  return new Response(null, {
    status: current === undefined ? STATUS.created : STATUS.ok,
    headers: { ETag: etag },
  });
}

async function deleteBackup(
  request: Request,
  store: SyncStore,
  storeId: string,
): Promise<Response> {
  const tokenHash = await writeTokenHash(request);
  if (tokenHash === undefined) return status(STATUS.unauthorized);
  const current = await store.get(storeId);
  if (current === undefined) return status(STATUS.notFound);
  if (!sameHash(current.tokenHash, tokenHash)) return status(STATUS.forbidden);
  await store.delete(storeId);
  return status(STATUS.noContent);
}

/** The SHA-256 of the bearer token, or undefined when the request carries none of the right shape. */
async function writeTokenHash(request: Request): Promise<string | undefined> {
  const token = /^Bearer (\S+)$/.exec(request.headers.get('Authorization') ?? '')?.[1];
  if (token === undefined || !SYNC_SERVER.writeTokenPattern.test(token)) return undefined;
  return toHex(await sha256(utf8(token)));
}

function sameHash(a: string, b: string): boolean {
  return bytesEqual(utf8(a), utf8(b));
}

/** The body as text, read as a stream, or undefined once it passes the limit. */
async function readLimited(request: Request): Promise<string | undefined> {
  if (Number(request.headers.get('Content-Length') ?? '0') > SYNC_SERVER.maxBackupBytes) {
    return undefined;
  }
  const chunks: Uint8Array[] = [];
  let total = 0;
  const reader = request.body?.getReader();
  for (;;) {
    const next = await reader?.read();
    if (next === undefined || next.done) break;
    total += next.value.length;
    if (total > SYNC_SERVER.maxBackupBytes) {
      await reader?.cancel();
      return undefined;
    }
    chunks.push(next.value);
  }
  return new TextDecoder().decode(concatBytes(...chunks));
}

function isBackup(body: string): boolean {
  try {
    parseBackup(JSON.parse(body));
    return true;
  } catch {
    // Any parse failure means a malformed backup; the caller answers 400.
    return false;
  }
}

function status(code: number): Response {
  return new Response(null, { status: code });
}
