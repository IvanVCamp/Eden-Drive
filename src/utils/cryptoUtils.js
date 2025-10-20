// cryptoUtils.js
// Módulo utilitario de criptografía asimétrica/simétrica (RSA + AES + HKDF)
// Usado en FRONT-002, pero también reutilizable por FRONT-001 y FRONT-005

function arrayBufferToBase64(buffer) {
  let binary = '';
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

export async function sha256Bytes(str) {
  const enc = new TextEncoder();
  const data = enc.encode(str);
  const hashBuffer = await window.crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(hashBuffer);
}

export async function deriveAesKeyFromPassword(password) {
  const hash = await sha256Bytes(password);
  const [firstHalf, secondHalf] = [hash.slice(0, 16), hash.slice(16)];

  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const ikm = await window.crypto.subtle.importKey("raw", secondHalf, "HKDF", false, ["deriveKey"]);
  const derivedKey = await window.crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt,
      info: new TextEncoder().encode("private-key-encryption"),
    },
    ikm,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
  return { derivedKey, salt, firstHalf };
}

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
  return (
    "-----BEGIN PUBLIC KEY-----\n" +
    b64.match(/.{1,64}/g).join("\n") +
    "\n-----END PUBLIC KEY-----"
  );
}

export async function exportPrivateKeyToPKCS8(privateKey) {
  const pkcs8 = await window.crypto.subtle.exportKey("pkcs8", privateKey);
  return arrayBufferToBase64(pkcs8);
}

export async function encryptPrivateKey(aesKey, privateKeyBase64) {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const plaintext = base64ToArrayBuffer(privateKeyBase64);
  const ciphertext = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, plaintext);
  return {
    ciphertextBase64: arrayBufferToBase64(ciphertext),
    ivBase64: arrayBufferToBase64(iv.buffer),
  };
}

export async function decryptPrivateKey(aesKey, ciphertextBase64, ivBase64) {
  const ciphertext = base64ToArrayBuffer(ciphertextBase64);
  const iv = new Uint8Array(base64ToArrayBuffer(ivBase64));
  const decrypted = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, ciphertext);
  return arrayBufferToBase64(decrypted);
}

export async function generateAndEncryptRSAKeys(username, password) {
  const { derivedKey, salt, firstHalf } = await deriveAesKeyFromPassword(password);
  const rsaPair = await generateRSAKeyPair();
  const publicKeyPEM = await exportPublicKeyToPEM(rsaPair.publicKey);
  const privateKeyBase64 = await exportPrivateKeyToPKCS8(rsaPair.privateKey);
  const encrypted = await encryptPrivateKey(derivedKey, privateKeyBase64);

  return {
    username,
    passwordHashPart: Array.from(firstHalf)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(""),
    publicKeyPEM,
    encryptedPrivateKey: encrypted.ciphertextBase64,
    encryptionMetadata: {
      iv: encrypted.ivBase64,
      hkdfSalt: arrayBufferToBase64(salt.buffer),
      hkdfInfo: "private-key-encryption",
    },
  };
}
