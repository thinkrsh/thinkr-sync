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

- **The recovery code:** 160 random bits, shown once to the user as 32
  characters of Crockford base32 in groups of 4.
- **The history secret:** 256 bits, derived from the recovery code with
  HKDF-SHA-256. The same code gives the same secret on every device, so the
  code alone names the backup and opens it. A history without a recovery code
  can start from 256 random bits instead.
- **The record key:** AES-256-GCM. It seals each chat that the device stores.
  The ID of the chat is bound into the seal, so a stored chat cannot pass for
  another one.
- **The backup key:** AES-256-GCM. It seals the backup that the server keeps.
- **The store ID and the write token:** the name of the backup on the server,
  and the token that lets the history change or delete it. Neither reveals
  anything about the chats.

Every key derives from the history secret with HKDF-SHA-256, each with a label
of its own.

A passkey opens the history too. The PRF extension of WebAuthn derives a key
from the passkey, and that key wraps the history secret. The wrapped keys travel
in each backup, readable, since they open nothing without the passkey.

- The user handle of each passkey is the store ID of its history.
- The input of the PRF is the same for every passkey: the SHA-256 of a label.

A new device can therefore ask for the passkey and its PRF in one prompt, read
the store ID from the user handle, pull the backup, and unwrap the secret.

The package stores nothing. The app decides where the secret lives: the chat
app of Thinkr keeps it in the storage of the browser, next to its vouchers, so
that the backup runs without a prompt.

## Use the library

This section shows the tasks of an app: set up a history, back it up, and open
it on a new device.

To set up a history, make a recovery code, take the secret from it, and wrap the
secret with a passkey:

```ts
import {
  addPasskey,
  browserAuthenticator,
  deriveHistoryKeys,
  historySecretFromRecoveryCode,
  newRecoveryCode,
} from '@thinkr/sync';

const recoveryCode = newRecoveryCode(); // Show it to the user once.
const secret = await historySecretFromRecoveryCode(recoveryCode);
const wrappedKeys = [
  await addPasskey(secret, browserAuthenticator(), {
    rpId: 'chat.thinkr.sh',
    rpName: 'Thinkr',
    userName: 'Thinkr backup',
  }),
];
const keys = await deriveHistoryKeys(secret);
```

To store a chat on the device, seal it, and open it when the app reads it back:

```ts
const sealed = await sealRecord(keys, chat.id, chat);
const value = await openRecord(keys, sealed); // Check it against your schema.
```

To back up, seal the records and push them with the tag of the last pull or
push. A pull with that tag answers `unchanged` when no other device pushed:

```ts
const client = createSyncClient({ baseUrl: 'https://chat.thinkr.sh/api/sync', keys });
const backup = await sealBackup(keys, wrappedKeys, { revision, createdAt, records });
const etag = await client.push(backup, lastEtag);
const pulled = await client.pull(etag); // 'missing', 'unchanged', or 'found'.
```

To open the history on a new device with a passkey alone, find the passkey,
fetch its backup, and unwrap the secret:

```ts
const found = await findWithPasskey(browserAuthenticator(), 'chat.thinkr.sh');
const fetched = await fetchBackup({ baseUrl, storeId: found.storeId });
const secret = await unwrapFoundPasskey(fetched.backup.keys, found);
const content = await openBackup(await deriveHistoryKeys(secret), fetched.backup);
```

With the recovery code alone, take the secret from the code, and pull with the
keys that derive from it.

## The sync protocol

This section lists the requests of the sync protocol. Each backup lives at
`<base URL>/<store ID>`, and the bodies hold ciphertext only.

| Request              | Headers                             | Answers                                               |
| -------------------- | ----------------------------------- | ----------------------------------------------------- |
| `GET /<store ID>`    | Optionally `If-None-Match: <ETag>`  | `200` with the backup and its `ETag`, `304`, or `404` |
| `PUT /<store ID>`    | The write token, and a precondition | `201` or `200` with the new `ETag`                    |
| `DELETE /<store ID>` | The write token                     | `204`, or `404`                                       |

A `GET` that names the tag of the stored backup gets `304` and no body. The
server compares only the hash inside a tag, since a proxy in between that
compresses an answer may change its tag to `W/"<hash>"` or `"<hash>-gzip"`. The
write token travels as `Authorization: Bearer <write token>`. A push names
`If-None-Match: *` for the first backup, or `If-Match: <ETag>` for every later
one. The server refuses a push with these answers:

- `401`: the push carries no write token.
- `403`: the push carries the write token of another history.
- `412`: the backup changed since the last pull.
- `413`: the backup is larger than 32 MiB.
- `428`: the push names no tag for a backup that exists.

A `SyncError` of the code `SERVER` carries the HTTP status of the answer.

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
- It can delete a backup, or refuse to serve one.

## Limits

This section lists what the package does not do.

- The support for the PRF extension differs between browsers and passkey
  managers. Without it, `addPasskey` fails with `PRF_UNSUPPORTED`, and the
  recovery code still opens the history.
- A user who loses every passkey and the recovery code loses the history. No
  one can recover it, by design.
- A new recovery code means a new secret, so a new backup: the code cannot
  change while the backup stays.

## Development

This section lists the commands for work on the package.

- To run the formatter, the linter, the type checker, and the tests, run
  `npm run check`.
- The tests use an authenticator in memory that computes the PRF as CTAP2 does,
  with discoverable passkeys that return their user handle. On 23 Oct 2026 the
  chat app of Thinkr also passed the whole flow in Chrome, with a virtual
  authenticator that supports the PRF: turn on, restore with the passkey after
  the site data was cleared, and restore with the recovery code on another
  browser.

## License

The Apache License 2.0. The full text is in `LICENSE`.
