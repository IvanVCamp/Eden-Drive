// src/utils/cryptoUtils.js

// --- Utilidades base64 ---
export function arrayBufferToBase64(buffer) {
  let binary = "";
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

export function base64ToArrayBuffer(base64) {
  const binary = window.atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

export function sanitizeBase64(str) {
  if (!str) return "";
  return str.replace(/[^A-Za-z0-9+/=]/g, "");
}

// --- Hash y HKDF ---
export async function sha256Bytes(str) {
  const enc = new TextEncoder();
  const data = enc.encode(str);
  const hashBuffer = await window.crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(hashBuffer);
}

export async function deriveAesKeyFromPassword(password) {
  const hash = await sha256Bytes(password);
  const secondHalf = hash.slice(16); // última mitad
  const hkdfInfo = new TextEncoder().encode("private-key-encryption");
  const hkdfSalt = window.crypto.getRandomValues(new Uint8Array(32));

  const ikm = await window.crypto.subtle.importKey("raw", secondHalf, "HKDF", false, ["deriveKey"]);

  const aesKey = await window.crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: hkdfSalt,
      info: hkdfInfo,
    },
    ikm,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );

  return { aesKey, hkdfSalt };
}

export async function deriveAesKeyFromPasswordForDecryption(password, hkdfSaltBase64) {
  const hash = await sha256Bytes(password);
  const secondHalf = hash.slice(16);
  const hkdfInfo = new TextEncoder().encode("private-key-encryption");
  const hkdfSalt = new Uint8Array(base64ToArrayBuffer(hkdfSaltBase64));

  const ikm = await window.crypto.subtle.importKey("raw", secondHalf, "HKDF", false, ["deriveKey"]);

  return await window.crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: hkdfSalt,
      info: hkdfInfo,
    },
    ikm,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

// --- RSA ---
export async function generateRSAKeyPair() {
  return await window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );
}

export async function exportPublicKeyToPEM(publicKey) {
  const spki = await window.crypto.subtle.exportKey("spki", publicKey);
  const b64 = arrayBufferToBase64(spki);
  const chunks = b64.match(/.{1,64}/g) || [];
  return `-----BEGIN PUBLIC KEY-----\n${chunks.join("\n")}\n-----END PUBLIC KEY-----`;
}

export async function exportPrivateKeyToPKCS8(privateKey) {
  const pkcs8 = await window.crypto.subtle.exportKey("pkcs8", privateKey);
  return arrayBufferToBase64(pkcs8);
}

// --- AES ---
export async function encryptPrivateKeyWithAesGcm(aesKey, base64Pkcs8) {
  const cleanPkcs8 = sanitizeBase64(base64Pkcs8);
  const binaryString = window.atob(cleanPkcs8);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);

  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, bytes);

  return {
    ciphertextBase64: sanitizeBase64(arrayBufferToBase64(ciphertext)),
    ivBase64: sanitizeBase64(arrayBufferToBase64(iv.buffer)),
  };
}

export async function decryptPrivateKeyWithAesGcm(password, encryptedBase64, ivBase64, hkdfSaltBase64) {
  const aesKey = await deriveAesKeyFromPasswordForDecryption(password, hkdfSaltBase64);

  const plaintext = await window.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: base64ToArrayBuffer(ivBase64),
    },
    aesKey,
    base64ToArrayBuffer(encryptedBase64)
  );

  return arrayBufferToBase64(plaintext);
}

// --- Función principal unificada ---
export async function generateAndEncryptRSAKeys(username, newPassword) {
  const hash = await sha256Bytes(newPassword);
  const firstHalf = hash.slice(0, 16);

  const { aesKey, hkdfSalt } = await deriveAesKeyFromPassword(newPassword);
  const rsaPair = await generateRSAKeyPair();
  const publicKeyPEM = await exportPublicKeyToPEM(rsaPair.publicKey);
  const privateKeyBase64PKCS8 = await exportPrivateKeyToPKCS8(rsaPair.privateKey);

  const encrypted = await encryptPrivateKeyWithAesGcm(aesKey, privateKeyBase64PKCS8);

  return {
    username,
    passwordHashPart: Array.from(firstHalf)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(""),
    publicKeyPEM,
    encryptedPrivateKey: sanitizeBase64(encrypted.ciphertextBase64),
    encryptionMetadata: {
      iv: sanitizeBase64(encrypted.ivBase64),
      hkdfSalt: sanitizeBase64(arrayBufferToBase64(hkdfSalt.buffer)),
      hkdfInfo: "private-key-encryption",
    },
  };
}
