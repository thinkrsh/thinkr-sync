import { SYNC_SERVER } from '../config/server.js';
import { SyncError } from '../errors.js';
import type { HistoryKeys } from '../keys.js';
import { parseBackup, type Backup } from '../backup.js';

export interface SyncClientOptions {
  /** The address of the sync server; each backup lives at `<baseUrl>/<storeId>`. */
  baseUrl: string;
  keys: HistoryKeys;
  fetch?: typeof fetch;
}

/** A backup from the server, with the tag that the next push must name. */
export interface PulledBackup {
  backup: Backup;
  etag: string;
}

/**
 * What a pull found: no backup, the backup that the device already has (the tag it named still
 * matches), or a backup to open.
 */
export type PullResult =
  { status: 'missing' } | { status: 'unchanged' } | ({ status: 'found' } & PulledBackup);

export interface SyncClient {
  /**
   * The backup on the server. With the tag of the last pull or push, the server answers
   * `unchanged` instead of sending the same backup again.
   */
  pull(knownEtag?: string): Promise<PullResult>;
  /**
   * Sends a backup. Give the tag of the last pull, or undefined for the first backup. Throws
   * CONFLICT when another device changed the backup since; pull, merge, and push again.
   */
  push(backup: Backup, etag: string | undefined): Promise<string>;
  /** Deletes the backup from the server. */
  remove(): Promise<void>;
}

const HTTP = {
  ok: 200,
  created: 201,
  noContent: 204,
  notModified: 304,
  notFound: 404,
  preconditionFailed: 412,
};

/** A client of the sync protocol: plain HTTP, with ciphertext only in the bodies. */
export function createSyncClient(options: SyncClientOptions): SyncClient {
  const send = options.fetch ?? globalThis.fetch.bind(globalThis);
  const url = storeUrl(options.baseUrl, options.keys.storeId);
  const authorization = `Bearer ${options.keys.writeToken}`;
  return {
    pull: (knownEtag) => get(send, url, knownEtag),
    async push(backup, etag) {
      const response = await send(url, {
        method: 'PUT',
        headers: {
          Authorization: authorization,
          'Content-Type': SYNC_SERVER.backupMediaType,
          ...(etag === undefined ? { 'If-None-Match': '*' } : { 'If-Match': etag }),
        },
        body: JSON.stringify(backup),
      });
      if (response.status === HTTP.preconditionFailed) {
        throw new SyncError('CONFLICT', 'The backup changed on the server since the last pull.');
      }
      expectStatus(response, [HTTP.ok, HTTP.created]);
      return requireEtag(response);
    },
    async remove() {
      const response = await send(url, {
        method: 'DELETE',
        headers: { Authorization: authorization },
      });
      expectStatus(response, [HTTP.noContent, HTTP.notFound]);
    },
  };
}

/**
 * Pulls the backup of a store ID before the device holds its keys: a new device does this with the
 * store ID of a passkey (`findWithPasskey`), then opens the wrapped keys of the backup.
 */
export async function fetchBackup(options: {
  baseUrl: string;
  storeId: string;
  fetch?: typeof fetch;
}): Promise<PulledBackup | undefined> {
  const send = options.fetch ?? globalThis.fetch.bind(globalThis);
  const result = await get(send, storeUrl(options.baseUrl, options.storeId), undefined);
  return result.status === 'found' ? { backup: result.backup, etag: result.etag } : undefined;
}

async function get(
  send: typeof fetch,
  url: string,
  knownEtag: string | undefined,
): Promise<PullResult> {
  const response = await send(url, {
    method: 'GET',
    cache: 'no-store',
    ...(knownEtag === undefined ? {} : { headers: { 'If-None-Match': knownEtag } }),
  });
  if (response.status === HTTP.notFound) return { status: 'missing' };
  if (response.status === HTTP.notModified) return { status: 'unchanged' };
  expectStatus(response, [HTTP.ok]);
  return {
    status: 'found',
    backup: parseBackup(await response.json()),
    etag: requireEtag(response),
  };
}

function storeUrl(baseUrl: string, storeId: string): string {
  const base = baseUrl.endsWith('/') ? baseUrl : `${baseUrl}/`;
  return new URL(storeId, base).href;
}

function expectStatus(response: Response, allowed: number[]): void {
  if (!allowed.includes(response.status)) {
    throw new SyncError('SERVER', `The sync server answered ${String(response.status)}.`, {
      status: response.status,
    });
  }
}

function requireEtag(response: Response): string {
  const etag = response.headers.get('ETag');
  if (etag === null) {
    throw new SyncError('SERVER', 'The sync server sent no ETag.');
  }
  return etag;
}
