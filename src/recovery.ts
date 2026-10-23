import { RECOVERY_CODE } from './config/format.js';
import { SyncError } from './errors.js';
import { randomBytes } from './lib/bytes.js';
import { unwrapSecret, wrapSecret, type WrappedKey } from './wrap.js';

const BITS_PER_CHARACTER = 5;
const CODE_LENGTH = Math.ceil((RECOVERY_CODE.bytes * 8) / BITS_PER_CHARACTER);

/** Characters that people misread for another one, as Crockford base32 reads them. */
const LOOKALIKES: Readonly<Record<string, string>> = { O: '0', I: '1', L: '1' };

/**
 * A new recovery code: 160 random bits, such as `7KQ2-M9XA-...`. Show it to the user once; the
 * history keeps only the key that it wraps.
 */
export function newRecoveryCode(): string {
  return formatCode(encode(randomBytes(RECOVERY_CODE.bytes)));
}

/** Wraps the secret of a history with a recovery code. */
export async function wrapWithRecoveryCode(secret: Uint8Array, code: string): Promise<WrappedKey> {
  return wrapSecret(secret, parseRecoveryCode(code), 'recovery', { credentialId: '', prfSalt: '' });
}

/** Opens the secret of a history with a recovery code; throws WRONG_KEY for another code. */
export async function unwrapWithRecoveryCode(
  wrappedKeys: readonly WrappedKey[],
  code: string,
): Promise<Uint8Array> {
  const material = parseRecoveryCode(code);
  for (const wrapped of wrappedKeys.filter((key) => key.kind === 'recovery')) {
    try {
      return await unwrapSecret(wrapped, material);
    } catch (error) {
      if (!(error instanceof SyncError && error.code === 'WRONG_KEY')) throw error;
    }
  }
  throw new SyncError('WRONG_KEY', 'This recovery code does not open the history.');
}

/**
 * The bytes of a recovery code as a person types it: any case, with or without dashes and spaces,
 * with O read as 0 and I or L as 1. Throws WRONG_KEY for a code of the wrong shape.
 */
export function parseRecoveryCode(code: string): Uint8Array {
  const characters = Array.from(code.toUpperCase().replace(/[\s-]/g, '')).map(
    (character) => LOOKALIKES[character] ?? character,
  );
  if (characters.length !== CODE_LENGTH) {
    throw new SyncError('WRONG_KEY', `A recovery code has ${String(CODE_LENGTH)} characters.`);
  }
  const bytes = new Uint8Array(RECOVERY_CODE.bytes);
  let buffer = 0;
  let bits = 0;
  let index = 0;
  for (const character of characters) {
    const value = RECOVERY_CODE.alphabet.indexOf(character);
    if (value < 0) {
      throw new SyncError('WRONG_KEY', `The character ${character} is not in a recovery code.`);
    }
    buffer = ((buffer << BITS_PER_CHARACTER) | value) & 0xffff;
    bits += BITS_PER_CHARACTER;
    if (bits >= 8) {
      bits -= 8;
      bytes[index++] = (buffer >> bits) & 0xff;
    }
  }
  return bytes;
}

function encode(bytes: Uint8Array): string {
  let text = '';
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = ((buffer << 8) | byte) & 0xffff;
    bits += 8;
    while (bits >= BITS_PER_CHARACTER) {
      bits -= BITS_PER_CHARACTER;
      text += RECOVERY_CODE.alphabet[(buffer >> bits) & 0b11111] ?? '';
    }
  }
  return text;
}

function formatCode(text: string): string {
  const groups = text.match(new RegExp(`.{1,${String(RECOVERY_CODE.groupLength)}}`, 'g')) ?? [];
  return groups.join(RECOVERY_CODE.separator);
}
