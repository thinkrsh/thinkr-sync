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

export interface SyncClient {
  /** The backup on the server, or undefined when there is none yet. */
  pull(): Promise<PulledBackup | undefined>;
  /**
   * Sends a backup. Give the tag of the last pull, or undefined for the first backup. Throws
   * CONFLICT when another device changed the backup since; pull, merge, and push again.
   */
  push(backup: Backup, etag: string | undefined): Promise<string>;
  /** Deletes the backup from the server. */
  remove(): Promise<void>;
}

const HTTP = { ok: 200, created: 201, noContent: 204, notFound: 404, preconditionFailed: 412 };

/** A client of the sync protocol: plain HTTP, with ciphertext only in the bodies. */
export function createSyncClient(options: SyncClientOptions): SyncClient {
  const send = options.fetch ?? globalThis.fetch.bind(globalThis);
  const url = new URL(options.keys.storeId, ensureSlash(options.baseUrl)).href;
  const authorization = `Bearer ${options.keys.writeToken}`;
  return {
    async pull() {
      const response = await send(url, { method: 'GET', cache: 'no-store' });
      if (response.status === HTTP.notFound) return undefined;
      expectStatus(response, [HTTP.ok]);
      return { backup: parseBackup(await response.json()), etag: requireEtag(response) };
    },
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

function ensureSlash(base: string): string {
  return base.endsWith('/') ? base : `${base}/`;
}

function expectStatus(response: Response, allowed: number[]): void {
  if (!allowed.includes(response.status)) {
    throw new SyncError('SERVER', `The sync server answered ${String(response.status)}.`);
  }
}

function requireEtag(response: Response): string {
  const etag = response.headers.get('ETag');
  if (etag === null) {
    throw new SyncError('SERVER', 'The sync server sent no ETag.');
  }
  return etag;
}
