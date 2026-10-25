export { openBackup, parseBackup, sealBackup } from './backup.js';
export type { Backup, BackupContent, BackupRecord } from './backup.js';
export { SYNC_ERROR_CODES, SyncError } from './errors.js';
export type { SyncErrorCode } from './errors.js';
export { deriveHistoryKeys, newHistorySecret } from './keys.js';
export type { HistoryKeys } from './keys.js';
export {
  addPasskey,
  browserAuthenticator,
  findWithPasskey,
  unwrapFoundPasskey,
  unwrapWithPasskey,
} from './passkey.js';
export type {
  FoundPasskey,
  PasskeyAccount,
  PasskeyAuthenticator,
  PasskeyResult,
} from './passkey.js';
export { openRecord, sealRecord } from './records.js';
export type { SealedRecord } from './records.js';
export { historySecretFromRecoveryCode, newRecoveryCode, parseRecoveryCode } from './recovery.js';
export { createSyncClient, fetchBackup } from './sync/client.js';
export type { PulledBackup, PullResult, SyncClient, SyncClientOptions } from './sync/client.js';
export { handleSyncRequest, memoryStore } from './sync/server.js';
export type { StoredBackup, SyncStore } from './sync/server.js';
export { parseWrappedKey } from './wrap.js';
export type { WrapKind, WrappedKey } from './wrap.js';
