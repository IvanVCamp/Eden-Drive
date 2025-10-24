import React, { createContext, useContext, useState } from "react";
import {
  importPrivateKeyFromPkcs8Base64,
  decryptPrivateKeyAesGcm,
  deriveAesKeyFromPasswordHalf,
} from "../utils/cryptoUtils";

const AuthContext = createContext();

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);

  async function registerUser(payload) {
    localStorage.setItem(`user-${payload.username}`, JSON.stringify(payload));
  }

  async function login(username, password) {
    const stored = localStorage.getItem(`user-${username}`);
    if (!stored) return false;

    const userData = JSON.parse(stored);

    try {
      // Derivar clave AES desde la segunda mitad del hash SHA-256 de la contraseña
      const { aesKey } = await deriveAesKeyFromPasswordHalf(password, userData.encryptionMetadata.hkdfSalt);

      // Descifrar la clave privada almacenada
      const privateKeyBase64 = await decryptPrivateKeyAesGcm(
        aesKey,
        userData.encryptedPrivateKey,
        userData.encryptionMetadata.iv
      );

      // Importar la clave privada en formato CryptoKey
      const privateKeyCryptoKey = await importPrivateKeyFromPkcs8Base64(privateKeyBase64);

      const finalUser = {
        username: userData.username,
        publicKeyPEM: userData.publicKeyPEM,
        privateKeyCryptoKey,
      };

      setUser(finalUser);
      return true;
    } catch (err) {
      console.error("Error al descifrar clave privada:", err);
      return false;
    }
  }

  function logout() {
    setUser(null);
  }

  return (
    <AuthContext.Provider value={{ user, login, logout, registerUser }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
