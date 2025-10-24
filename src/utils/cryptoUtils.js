// --- UTILIDADES BÁSICAS ---
export async function sha256Bytes(str) {
  const enc = new TextEncoder();
  const data = enc.encode(str);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(hashBuffer);
}

export function splitInHalf(u8) {
  const half = u8.length / 2;
  return [u8.slice(0, half), u8.slice(half)];
}

export function arrayBufferToBase64(buffer) {
  let binary = "";
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

export function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

export function base64ToBytes(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function toHex(u8) {
  return Array.from(u8).map((b) => b.toString(16).padStart(2, "0")).join("");
}

// --- DERIVACIÓN DE CLAVES ---
export async function deriveHalfHashFromPassword(password) {
  const hash = await sha256Bytes(password);
  const [, secondHalf] = splitInHalf(hash);
  return secondHalf;
}

export async function hkdfExpandToAes256(keyMaterialBytes, info, salt) {
  const ikm = await crypto.subtle.importKey("raw", keyMaterialBytes, "HKDF", false, ["deriveKey"]);
  const hkdfSalt = salt || new Uint8Array(32);
  const derivedKey = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: hkdfSalt, info },
    ikm,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
  return { derivedKey, salt: hkdfSalt };
}

export async function deriveAesKeyFromPasswordHalf(password, saltBase64) {
  const hashBytes = await sha256Bytes(password);
  const [, secondHalf] = splitInHalf(hashBytes);
  const salt = saltBase64 ? base64ToArrayBuffer(saltBase64) : new Uint8Array(32);
  const ikm = await crypto.subtle.importKey("raw", secondHalf, "HKDF", false, ["deriveKey"]);
  const aesKey = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt,
      info: new TextEncoder().encode("private-key-encryption")
    },
    ikm,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
  return { aesKey };
}

// --- RSA ---
export async function generateRSAKeyPair() {
  return crypto.subtle.generateKey(
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
  const spki = await crypto.subtle.exportKey("spki", publicKey);
  const b64 = arrayBufferToBase64(spki);
  return "-----BEGIN PUBLIC KEY-----\n" + b64.match(/.{1,64}/g).join("\n") + "\n-----END PUBLIC KEY-----";
}

export async function exportPrivateKeyToPKCS8(privateKey) {
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", privateKey);
  return arrayBufferToBase64(pkcs8);
}

export async function importPrivateKeyFromPkcs8Base64(pkcs8Base64) {
  const keyData = base64ToArrayBuffer(pkcs8Base64);
  return crypto.subtle.importKey(
    "pkcs8",
    keyData,
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["decrypt"]
  );
}

// --- CIFRADO / DESCIFRADO AES-GCM ---
export async function encryptPrivateKeyWithAesGcm(aesKey, base64Pkcs8) {
  const binaryString = atob(base64Pkcs8);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, bytes);
  return {
    ciphertextBase64: arrayBufferToBase64(ciphertext),
    ivBase64: arrayBufferToBase64(iv.buffer),
  };
}

export async function decryptPrivateKeyWithPassword(encryptedBase64, ivBase64, saltBase64, keyMaterialBytes) {
  try {
    const iv = base64ToBytes(ivBase64);
    const salt = base64ToBytes(saltBase64);
    const info = new TextEncoder().encode("private-key-encryption");
    const ikm = await crypto.subtle.importKey("raw", keyMaterialBytes, "HKDF", false, ["deriveKey"]);
    const aesKey = await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt, info },
      ikm,
      { name: "AES-GCM", length: 256 },
      true,
      ["decrypt"]
    );
    const ciphertext = base64ToBytes(encryptedBase64);
    const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, ciphertext);
    return arrayBufferToBase64(decrypted);
  } catch (err) {
    console.error("Error descifrando la clave privada:", err);
    return null;
  }
}

export async function decryptPrivateKeyAesGcm(aesKey, encryptedBase64, ivBase64) {
  const iv = new Uint8Array(atob(ivBase64).split("").map((c) => c.charCodeAt(0)));
  const ciphertext = base64ToArrayBuffer(encryptedBase64);
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, ciphertext);
  return arrayBufferToBase64(decrypted);
}

// --- FUNCIÓN COMPLETA DE GENERACIÓN Y CIFRADO DE CLAVES ---
export async function generateAndEncryptRSAKeys(username, password) {
  const hashBytes = await sha256Bytes(password);
  const [firstHalf, secondHalf] = splitInHalf(hashBytes);
  const hkdfInfo = new TextEncoder().encode("private-key-encryption");
  const { derivedKey, salt } = await hkdfExpandToAes256(secondHalf, hkdfInfo, null);
  const rsaPair = await generateRSAKeyPair();
  const publicKeyPEM = await exportPublicKeyToPEM(rsaPair.publicKey);
  const privateKeyBase64PKCS8 = await exportPrivateKeyToPKCS8(rsaPair.privateKey);
  const encrypted = await encryptPrivateKeyWithAesGcm(derivedKey, privateKeyBase64PKCS8);

  return {
    username,
    passwordHashPart: toHex(firstHalf),
    publicKeyPEM,
    encryptedPrivateKey: encrypted.ciphertextBase64,
    encryptionMetadata: {
      iv: encrypted.ivBase64,
      hkdfSalt: arrayBufferToBase64(salt.buffer),
      hkdfInfo: "private-key-encryption",
    },
  };
}
