// src/utils/cryptoPasswordUtils.js
// Decrypts a private key encrypted with AES-GCM + HKDF from password (from FRONT-001 scheme)

function base64ToArrayBuffer(b64) {
  const bin = window.atob(b64);
  const len = bin.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

function arrayBufferToBase64(buf) {
  let bin = "";
  const bytes = new Uint8Array(buf);
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return window.btoa(bin);
}

export async function decryptPrivateKeyWithPassword(
  encryptedPrivateKeyBase64,
  ivBase64,
  hkdfSaltBase64,
  password
) {
  const iv = new Uint8Array(base64ToArrayBuffer(ivBase64));
  const salt = new Uint8Array(base64ToArrayBuffer(hkdfSaltBase64));
  const info = new TextEncoder().encode("private-key-encryption");

  const passwordBytes = new TextEncoder().encode(password);
  const baseKey = await window.crypto.subtle.importKey("raw", passwordBytes, "HKDF", false, ["deriveKey"]);

  const aesKey = await window.crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info },
    baseKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["decrypt"]
  );

  const encrypted = base64ToArrayBuffer(encryptedPrivateKeyBase64);
  const decrypted = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, encrypted);

  return arrayBufferToBase64(decrypted); // PKCS8 base64 private key
}
