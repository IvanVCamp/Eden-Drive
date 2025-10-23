// src/context/AuthContext.jsx
import React, { createContext, useContext, useEffect, useState } from "react";
import { getPasswordHashPart, decryptPrivateKeyWithPassword } from "../utils/cryptoPasswordUtils";
import { importPrivateKeyFromPkcs8Base64 } from "../utils/fileCryptoUtils";

const AuthContext = createContext(null);

export function useAuth() {
  return useContext(AuthContext);
}

function readUsersFromStorage() {
  const raw = localStorage.getItem("app_users_v1");
  if (!raw) return {};
  try {
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

function writeUsersToStorage(obj) {
  localStorage.setItem("app_users_v1", JSON.stringify(obj));
}

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null); // { username, publicKeyPEM, privateKeyCryptoKey }
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    // Optionally: restore session from sessionStorage (not implemented by default)
  }, []);

  async function registerUser(payload) {
    // payload: { username, passwordHashPart, publicKeyPEM, encryptedPrivateKey, encryptionMetadata }
    const users = readUsersFromStorage();
    users[payload.username] = payload;
    writeUsersToStorage(users);
    return true;
  }

  async function login(username, password) {
    setLoading(true);
    try {
      const users = readUsersFromStorage();
      const stored = users[username];
      if (!stored) {
        throw new Error("Usuario no encontrado");
      }
      // compute passwordHashPart
      const clientHashPart = await decryptPrivateKeyWithPassword(password); // hex
      if (clientHashPart !== stored.passwordHashPart) {
        throw new Error("Contraseña incorrecta");
      }
      // decrypt private key (returns pkcs8 base64)
      const { encryptedPrivateKey, encryptionMetadata, publicKeyPEM } = stored;
      const pkcs8Base64 = await decryptPrivateKeyWithPassword(
        encryptedPrivateKey,
        encryptionMetadata.iv,
        encryptionMetadata.hkdfSalt,
        password
      );
      // import private key to CryptoKey
      const privateKeyCryptoKey = await importPrivateKeyFromPkcs8Base64(pkcs8Base64);
      // set user state
      setUser({ username, publicKeyPEM, privateKeyCryptoKey, pkcs8Base64 });
      return { ok: true };
    } catch (err) {
      console.error("login error:", err);
      return { ok: false, error: err.message || String(err) };
    } finally {
      setLoading(false);
    }
  }

  async function logout() {
    setUser(null);
  }

  const value = { user, loading, registerUser, login, logout };
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
