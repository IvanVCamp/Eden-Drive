// src/utils/cryptoPasswordUtils.js
// Utilities for password hashing/splitting and HKDF->AES key derivation.
// Uses Web Crypto API (window.crypto.subtle).
//
// Exported functions:
// - sha256Bytes(password) -> Uint8Array
// - bytesToHex(u8) -> string
// - hexToBytes(hex) -> Uint8Array
// - splitHashBytes(hashBytes) -> { firstHalf: Uint8Array, secondHalf: Uint8Array }
// - getPasswordHashPart(password) -> hex string (first half)  <-- use to send to server
// - deriveAesKeyFromSecondHalf(secondHalfBytes, { saltBase64?, info? }) -> { aesKey, saltBase64 }
// - deriveAesKeyFromPassword(password, { saltBase64?, info? }) -> { aesKey, saltBase64, passwordHashPartHex }
// - encryptWithAesGcm(aesKey, plaintextBytes) -> { ciphertextBase64, ivBase64 }
// - decryptWithAesGcm(aesKey, ciphertextBase64, ivBase64) -> ArrayBuffer (plaintext bytes)
// - decryptPrivateKeyWithPassword(encryptedPrivateKeyBase64, ivBase64, hkdfSaltBase64, password) -> base64 pkcs8

/* eslint-disable no-console */

function arrayBufferToBase64(buffer) {
  let binary = "";
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

export async function sha256Bytes(password) {
  const enc = new TextEncoder();
  const data = enc.encode(password);
  const hash = await window.crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(hash); // 32 bytes
}

export function bytesToHex(u8) {
  return Array.from(u8).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function hexToBytes(hex) {
  if (hex.length % 2 !== 0) throw new Error("Invalid hex");
  const len = hex.length / 2;
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

export function splitHashBytes(hashBytes) {
  if (!(hashBytes instanceof Uint8Array) || hashBytes.length !== 32) {
    throw new Error("hashBytes must be Uint8Array length 32");
  }
  const firstHalf = hashBytes.slice(0, 16);
  const secondHalf = hashBytes.slice(16, 32);
  return { firstHalf, secondHalf };
}

/**
 * Returns the hex string of the first half of SHA-256(password).
 * Use this to send to the server for verification (passwordHashPart).
 */
export async function getPasswordHashPart(password) {
  const hashBytes = await sha256Bytes(password); // 32 bytes
  const { firstHalf } = splitHashBytes(hashBytes);
  return bytesToHex(firstHalf);
}

/**
 * Derive an AES-GCM 256-bit CryptoKey using HKDF from `secondHalfBytes`.
 * - secondHalfBytes: Uint8Array (16 bytes) - typically the second half of SHA-256(password)
 * - options:
 *    - saltBase64: optional Base64 salt. If omitted, a random 16-byte salt is generated and returned.
 *    - info: optional string (defaults to "private-key-encryption")
 *
 * Returns { aesKey, saltBase64 } where aesKey is a CryptoKey usable for AES-GCM encrypt/decrypt.
 */
export async function deriveAesKeyFromSecondHalf(secondHalfBytes, options = {}) {
  if (!(secondHalfBytes instanceof Uint8Array) || secondHalfBytes.length === 0) {
    throw new Error("secondHalfBytes must be a Uint8Array");
  }

  const info = options.info ? new TextEncoder().encode(options.info) : new TextEncoder().encode("private-key-encryption");

  let salt;
  if (options.saltBase64) {
    // decode provided salt
    const sbuf = base64ToArrayBuffer(options.saltBase64);
    salt = new Uint8Array(sbuf);
  } else {
    // generate a random 16-byte salt (128-bit) - store it because HKDF requires it for deterministic key derivation
    salt = window.crypto.getRandomValues(new Uint8Array(16));
  }

  const ikm = await window.crypto.subtle.importKey("raw", secondHalfBytes, "HKDF", false, ["deriveKey"]);

  const derivedKey = await window.crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt,
      info,
    },
    ikm,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );

  return { aesKey: derivedKey, saltBase64: arrayBufferToBase64(salt.buffer) };
}

/**
 * Convenience: derive AES key directly from password.
 * Returns { aesKey, saltBase64, passwordHashPartHex }.
 * - If options.saltBase64 provided, uses it (=> deterministic derive); otherwise returns a generated saltBase64.
 */
export async function deriveAesKeyFromPassword(password, options = {}) {
  const hash = await sha256Bytes(password); // 32 bytes
  const { firstHalf, secondHalf } = splitHashBytes(hash);

  const { aesKey, saltBase64 } = await deriveAesKeyFromSecondHalf(secondHalf, {
    saltBase64: options.saltBase64,
    info: options.info,
  });

  return {
    aesKey,
    saltBase64,
    passwordHashPartHex: bytesToHex(firstHalf),
  };
}

/**
 * AES-GCM encrypt helper
 * - aesKey: CryptoKey (AES-GCM)
 * - plaintextBytes: ArrayBuffer or Uint8Array
 * Returns { ciphertextBase64, ivBase64 }
 */
export async function encryptWithAesGcm(aesKey, plaintextBytes) {
  const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 96-bit iv recommended for GCM
  const pt = plaintextBytes instanceof ArrayBuffer ? plaintextBytes : plaintextBytes.buffer ? plaintextBytes.buffer : new Uint8Array(plaintextBytes).buffer;

  const ct = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, pt);
  return { ciphertextBase64: arrayBufferToBase64(ct), ivBase64: arrayBufferToBase64(iv.buffer) };
}

/**
 * AES-GCM decrypt helper
 * - aesKey: CryptoKey
 * - ciphertextBase64: base64
 * - ivBase64: base64
 * Returns ArrayBuffer plaintext
 */
export async function decryptWithAesGcm(aesKey, ciphertextBase64, ivBase64) {
  const ctBuf = base64ToArrayBuffer(ciphertextBase64);
  const ivBuf = base64ToArrayBuffer(ivBase64);
  const iv = new Uint8Array(ivBuf);
  const plain = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, ctBuf);
  return plain; // ArrayBuffer
}

export async function decryptPrivateKeyWithPassword(encryptedPrivateKeyBase64, ivBase64, hkdfSaltBase64, password) {
  // 1) derive AES key from password using the same scheme (second half + HKDF with provided salt)
  const hash = await sha256Bytes(password);
  const { secondHalf } = splitHashBytes(hash);

  const { aesKey } = await deriveAesKeyFromSecondHalf(secondHalf, { saltBase64: hkdfSaltBase64, info: "private-key-encryption" });

  // 2) decrypt AES-GCM ciphertext -> returns ArrayBuffer of PKCS8 bytes
  const decryptedBuffer = await decryptWithAesGcm(aesKey, encryptedPrivateKeyBase64, ivBase64);

  // 3) return base64 of PKCS8
  return arrayBufferToBase64(decryptedBuffer);
}

export default {
  sha256Bytes,
  bytesToHex,
  splitHashBytes,
  getPasswordHashPart,
  deriveAesKeyFromSecondHalf,
  deriveAesKeyFromPassword,
  encryptWithAesGcm,
  decryptWithAesGcm,
  decryptPrivateKeyWithPassword,
};
