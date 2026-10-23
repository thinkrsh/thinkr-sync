export { openBackup, parseBackup, sealBackup } from './backup.js';
export type { Backup, BackupContent, BackupRecord } from './backup.js';
export { SYNC_ERROR_CODES, SyncError } from './errors.js';
export type { SyncErrorCode } from './errors.js';
export { deriveHistoryKeys, newHistorySecret } from './keys.js';
export type { HistoryKeys } from './keys.js';
export { addPasskey, browserAuthenticator, unwrapWithPasskey } from './passkey.js';
export type { PasskeyAccount, PasskeyAuthenticator, PasskeyResult } from './passkey.js';
export { openRecord, sealRecord } from './records.js';
export type { SealedRecord } from './records.js';
export {
  newRecoveryCode,
  parseRecoveryCode,
  unwrapWithRecoveryCode,
  wrapWithRecoveryCode,
} from './recovery.js';
export { createSyncClient } from './sync/client.js';
export type { PulledBackup, SyncClient, SyncClientOptions } from './sync/client.js';
export { handleSyncRequest, memoryStore } from './sync/server.js';
export type { StoredBackup, SyncStore } from './sync/server.js';
export { parseWrappedKey } from './wrap.js';
export type { WrapKind, WrappedKey } from './wrap.js';
