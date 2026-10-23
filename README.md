# Thinkr sync

This package encrypts the chat history of Thinkr on the device, with a key that
only the user holds. A passkey or a recovery code unlocks the key. The package
also syncs the history between devices as ciphertext, so the server never reads
a chat.

The readers are developers and auditors who want to know how the history of
Thinkr stays private. The package has no runtime dependency: it uses only the
Web Crypto API and WebAuthn of the platform.

## How the keys work

This section explains which keys exist and what each key protects.

- **The history secret:** 256 random bits, made on the device. Every other key
  derives from it with HKDF-SHA-256, each with a label of its own.
- **The record key:** AES-256-GCM. It seals each chat that the device stores.
  The ID of the chat is bound into the seal, so a stored chat cannot pass for
  another one.
- **The backup key:** AES-256-GCM. It seals the backup that the server keeps.
- **The store ID and the write token:** the name of the backup on the server,
  and the token that lets the history change or delete it. Neither reveals
  anything about the chats.

The device never stores the history secret in the clear. It stores the secret
wrapped:

- **By a passkey:** the PRF extension of WebAuthn derives a key from the
  passkey and a random salt. That key wraps the secret. A history can have
  several passkeys.
- **By a recovery code:** 160 random bits, shown once to the user as 32
  characters of Crockford base32 in groups of 4. It opens the history when no
  passkey is at hand.

## Use the library

This section shows the four tasks of an app: set up a history, store chats,
sync, and unlock on a new device.

To set up a history, make a secret and wrap it with a passkey and a recovery
code:

```ts
import {
  addPasskey,
  browserAuthenticator,
  deriveHistoryKeys,
  newHistorySecret,
  newRecoveryCode,
  wrapWithRecoveryCode,
} from '@thinkr/sync';

const secret = newHistorySecret();
const recoveryCode = newRecoveryCode(); // Show it to the user once.
const wrappedKeys = [
  await addPasskey(secret, browserAuthenticator(), {
    rpId: 'chat.thinkr.sh',
    rpName: 'Thinkr',
    userName: 'Thinkr history',
  }),
  await wrapWithRecoveryCode(secret, recoveryCode),
];
const keys = await deriveHistoryKeys(secret);
```

To store a chat, seal it, and open it when the app reads it back:

```ts
const sealed = await sealRecord(keys, chat.id, chat);
const value = await openRecord(keys, sealed); // Check it against your schema.
```

To sync, seal a backup and push it with the tag of the last pull:

```ts
const client = createSyncClient({ baseUrl: 'https://chat.thinkr.sh/api/sync', keys });
const backup = await sealBackup(keys, wrappedKeys, { revision, createdAt, records });
const etag = await client.push(backup, lastEtag);
```

To unlock on a new device, pull the backup of the store ID. The user opens it
with a passkey or the recovery code:

```ts
const secret = await unwrapWithPasskey(backup.keys, browserAuthenticator(), 'chat.thinkr.sh');
const content = await openBackup(await deriveHistoryKeys(secret), backup, lastRevision);
```

A new device does not know the store ID yet. It reads the wrapped keys from a
backup file that the user exports, or from the server under a store ID that the
user brings over.

## The sync protocol

This section lists the requests of the sync protocol. Each backup lives at
`<base URL>/<store ID>`, and the bodies hold ciphertext only.

| Request              | Headers                             | Answers                                        |
| -------------------- | ----------------------------------- | ---------------------------------------------- |
| `GET /<store ID>`    | None                                | `200` with the backup and its `ETag`, or `404` |
| `PUT /<store ID>`    | The write token, and a precondition | `201` or `200` with the new `ETag`             |
| `DELETE /<store ID>` | The write token                     | `204`, or `404`                                |

The write token travels as `Authorization: Bearer <write token>`. A push names
`If-None-Match: *` for the first backup, or `If-Match: <ETag>` for every later
one. The server refuses a push with these answers:

- `401`: the push carries no write token.
- `403`: the push carries the write token of another history.
- `412`: the backup changed since the last pull.
- `413`: the backup is larger than 32 MiB.
- `428`: the push names no tag for a backup that exists.

`handleSyncRequest` is the reference server, on the Fetch API. It takes a
`SyncStore`, whose `putIf` must write atomically. `memoryStore` serves tests and
one process.

## What the server learns

This section states what a sync server can and cannot learn.

- It learns the store ID, the size and the time of each backup, and the network
  address of each request.
- It cannot read a chat, a title, or the number of chats: the backup is one
  sealed blob.
- It cannot change a backup without the device noticing: AES-256-GCM
  authenticates every byte.
- It cannot serve an old backup as new: each backup carries a revision inside
  the seal, and `openBackup` refuses one lower than the last revision the device
  saw.
- It can delete a backup, or refuse to serve one. Keep the backup file as well.

## Limits

This section lists what the package does not do.

- The support for the PRF extension differs between browsers and passkey
  managers. Without it, `addPasskey` fails with `PRF_UNSUPPORTED`, and the
  recovery code still opens the history.
- A user who loses every passkey and the recovery code loses the history. No
  one can recover it, by design.
- The app of Thinkr does not use the package yet.

## Development

This section lists the commands for work on the package.

- To run the formatter, the linter, the type checker, and the tests, run
  `npm run check`.
- The tests use an authenticator in memory that computes the PRF as CTAP2 does.
  On 23 Oct 2026 the passkey flow also passed in Chrome 155, with a virtual
  authenticator that supports the PRF.

## License

The Apache License 2.0. The full text is in `LICENSE`.
