const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

/** The UTF-8 bytes of a text. */
export function utf8(text: string): Uint8Array<ArrayBuffer> {
  return encoder.encode(text);
}

/** The text of UTF-8 bytes; throws on bytes that are not UTF-8. */
export function fromUtf8(bytes: Uint8Array): string {
  return decoder.decode(bytes);
}

/** Cryptographically random bytes. */
export function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(length));
}

/** A copy of the bytes over a plain ArrayBuffer, the form that WebCrypto takes. */
export function ownBytes(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(bytes);
}

/** One array with the bytes of every part, in order. */
export function concatBytes(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const result = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

/** True when both arrays hold the same bytes, in time that does not depend on where they differ. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i++) {
    difference |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return difference === 0;
}

/** Lowercase hex of a byte array. */
export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

/** URL-safe base64 without padding, the form of WebAuthn credential IDs. */
export function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

/** Bytes of URL-safe base64, with or without padding; throws on any other character. */
export function fromBase64Url(text: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]*={0,2}$/.test(text)) {
    throw new Error('Not URL-safe base64.');
  }
  const binary = atob(text.replaceAll('-', '+').replaceAll('_', '/'));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

/** The SHA-256 of the bytes. */
export async function sha256(bytes: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', ownBytes(bytes)));
}

/** The bytes of a stream through a CompressionStream or DecompressionStream. */
export async function transform(
  bytes: Uint8Array,
  stream: CompressionStream | DecompressionStream,
): Promise<Uint8Array<ArrayBuffer>> {
  const output = new Blob([ownBytes(bytes)]).stream().pipeThrough(stream);
  return new Uint8Array(await new Response(output).arrayBuffer());
}
