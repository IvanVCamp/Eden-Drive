// src/utils/cryptoUtils.js
// Utilities for RSA key generation, export, encryption of private key, and helper functions.
// Uses Web Crypto API

function arrayBufferToBase64(buffer) {
  let binary = "";
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) binary += String.fromCharCode(bytes[i]);
  return window.btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binary = window.atob(base64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function chunkString(str, size) {
  const numChunks = Math.ceil(str.length / size);
  const chunks = new Array(numChunks);
  for (let i = 0, o = 0; i < numChunks; ++i, o += size) {
    chunks[i] = str.substr(o, size);
  }
  return chunks;
}

/* ----------------- Hash / HKDF helpers ----------------- */
export async function sha256Bytes(str) {
  const enc = new TextEncoder();
  const data = enc.encode(str);
  const hashBuffer = await window.crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(hashBuffer);
}

export function toHex(u8) {
  return Array.from(u8).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function splitInHalf(u8) {
  const half = u8.length / 2;
  return [u8.slice(0, half), u8.slice(half)];
}

export async function hkdfExpandToAes256(keyMaterialBytes, info = new Uint8Array([]), salt = null) {
  const ikm = await window.crypto.subtle.importKey("raw", keyMaterialBytes, "HKDF", false, ["deriveKey"]);
  const hkdfSalt = salt || window.crypto.getRandomValues(new Uint8Array(16));
  const derivedKey = await window.crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: hkdfSalt, info },
    ikm,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
  return { derivedKey, salt: hkdfSalt };
}

/* ----------------- RSA key generation & export ----------------- */
export async function generateRSAKeyPair(modulusLength = 2048) {
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );
  return keyPair;
}

export async function exportPublicKeyToPEM(publicKey) {
  const spki = await window.crypto.subtle.exportKey("spki", publicKey);
  const b64 = arrayBufferToBase64(spki);
  return "-----BEGIN PUBLIC KEY-----\n" + chunkString(b64, 64).join("\n") + "\n-----END PUBLIC KEY-----";
}

export async function exportPrivateKeyToPKCS8(privateKey) {
  const pkcs8 = await window.crypto.subtle.exportKey("pkcs8", privateKey);
  return arrayBufferToBase64(pkcs8);
}

/* ----------------- AES-GCM encrypt of private key ----------------- */
export async function encryptPrivateKeyWithAesGcm(aesKey, base64Pkcs8) {
  const binaryString = window.atob(base64Pkcs8);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);

  const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV
  const ciphertext = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, bytes);
  return {
    ciphertextBase64: arrayBufferToBase64(ciphertext),
    ivBase64: arrayBufferToBase64(iv.buffer),
  };
}

/* ----------------- High level: generate keys and encrypt private key ----------------- */
/**
 * generateAndEncryptRSAKeys(username, password)
 * - Generates RSA keypair locally
 * - Derives AES key from second half of sha256(password) via HKDF
 * - Encrypts private key PKCS8 with AES-GCM
 * Returns:
 * {
 *   payload: { username, passwordHashPart, publicKeyPEM, encryptedPrivateKey, encryptionMetadata },
 *   privateKeyBase64 // plaintext PKCS8 base64 (returned to allow immediate import in client)
 * }
 */
export async function generateAndEncryptRSAKeys(username, password) {
  // 1) sha256(password)
  const hashBytes = await sha256Bytes(password);
  const [firstHalf, secondHalf] = splitInHalf(hashBytes); // Uint8Array(16), Uint8Array(16)

  // 2) derive AES key from secondHalf with HKDF (use random salt)
  const hkdfInfo = new TextEncoder().encode("private-key-encryption");
  const { derivedKey, salt } = await hkdfExpandToAes256(secondHalf, hkdfInfo, null);

  // 3) generate RSA pair
  const rsaPair = await generateRSAKeyPair();

  // 4) export keys
  const publicKeyPEM = await exportPublicKeyToPEM(rsaPair.publicKey);
  const privateKeyBase64PKCS8 = await exportPrivateKeyToPKCS8(rsaPair.privateKey);

  // 5) encrypt private key with derivedKey
  const encrypted = await encryptPrivateKeyWithAesGcm(derivedKey, privateKeyBase64PKCS8);

  // 6) build payload
  const payload = {
    username,
    // Store first half as hex string to align with spec
    passwordHashPart: toHex(firstHalf),
    publicKeyPEM,
    encryptedPrivateKey: encrypted.ciphertextBase64,
    encryptionMetadata: {
      iv: encrypted.ivBase64,
      hkdfSalt: arrayBufferToBase64(salt.buffer),
      hkdfInfo: "private-key-encryption",
    },
  };

  return { payload, privateKeyBase64: privateKeyBase64PKCS8 };
}

/* ----------------- Exports ----------------- */
export default {
  sha256Bytes,
  toHex,
  splitInHalf,
  hkdfExpandToAes256,
  generateRSAKeyPair,
  exportPublicKeyToPEM,
  exportPrivateKeyToPKCS8,
  encryptPrivateKeyWithAesGcm,
  generateAndEncryptRSAKeys,
};
