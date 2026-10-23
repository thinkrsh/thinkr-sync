import { FORMAT } from './config/format.js';
import { concatBytes, ownBytes, randomBytes, utf8 } from './lib/bytes.js';

/** AES-256-GCM ciphertext with its nonce. */
export interface Sealed {
  nonce: Uint8Array;
  ciphertext: Uint8Array;
}

const AES_KEY_BITS = 256;
const NO_SALT = new Uint8Array(0);

/** HKDF-SHA-256 of a secret, with an empty salt and the label as info (RFC 5869). */
export async function deriveBytes(
  secret: Uint8Array,
  label: string,
  length: number,
): Promise<Uint8Array<ArrayBuffer>> {
  const material = await crypto.subtle.importKey('raw', ownBytes(secret), 'HKDF', false, [
    'deriveBits',
  ]);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: NO_SALT, info: utf8(label) },
    material,
    length * 8,
  );
  return new Uint8Array(bits);
}

/** An AES-256-GCM key derived from a secret for one purpose; it never leaves WebCrypto. */
export async function deriveAesKey(secret: Uint8Array, label: string): Promise<CryptoKey> {
  const bytes = await deriveBytes(secret, label, AES_KEY_BITS / 8);
  return crypto.subtle.importKey('raw', bytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

/** The associated data of a seal: the label, a zero byte, then the context. */
function associatedData(label: string, context: string): Uint8Array<ArrayBuffer> {
  return concatBytes(utf8(label), new Uint8Array(1), utf8(context));
}

/** Seals bytes with a fresh random nonce, bound to a label and a context. */
export async function seal(
  key: CryptoKey,
  plaintext: Uint8Array,
  label: string,
  context: string,
): Promise<Sealed> {
  const nonce = randomBytes(FORMAT.aesNonceBytes);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: associatedData(label, context) },
    key,
    ownBytes(plaintext),
  );
  return { nonce, ciphertext: new Uint8Array(ciphertext) };
}

/** Opens a seal, or returns undefined when the key, the label, the context, or a byte differs. */
export async function open(
  key: CryptoKey,
  sealed: Sealed,
  label: string,
  context: string,
): Promise<Uint8Array | undefined> {
  if (sealed.nonce.length !== FORMAT.aesNonceBytes) return undefined;
  try {
    const plaintext = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: ownBytes(sealed.nonce),
        additionalData: associatedData(label, context),
      },
      key,
      ownBytes(sealed.ciphertext),
    );
    return new Uint8Array(plaintext);
  } catch {
    // A failed AES-GCM check carries no detail worth keeping; the caller turns it into an error.
    return undefined;
  }
}
