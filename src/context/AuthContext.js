// src/context/AuthContext.jsx
import React, { createContext, useState, useContext } from "react";
import {
  decryptPrivateKeyWithAesGcm,
  sanitizeBase64,
} from "../utils/cryptoUtils";

const AuthContext = createContext();
export const useAuth = () => useContext(AuthContext);

export function AuthProvider({ children }) {
  const [currentUser, setCurrentUser] = useState(null);

  async function registerUser(userPayload) {
    const users = JSON.parse(localStorage.getItem("app_users_v1") || "{}");
    users[userPayload.username] = userPayload;
    localStorage.setItem("app_users_v1", JSON.stringify(users));
    setCurrentUser(userPayload);
  }

  async function login(username, password) {
    const users = JSON.parse(localStorage.getItem("app_users_v1") || "{}");
    const stored = users[username];
    if (!stored) throw new Error("Usuario no encontrado.");

    try {
      const pkcs8Base64 = await decryptPrivateKeyWithAesGcm(
        password,
        sanitizeBase64(stored.encryptedPrivateKey),
        sanitizeBase64(stored.encryptionMetadata.iv),
        sanitizeBase64(stored.encryptionMetadata.hkdfSalt)
      );

      setCurrentUser({
        username,
        privateKey: pkcs8Base64,
        publicKey: stored.publicKeyPEM,
      });

      return true;
    } catch (err) {
      console.error("Error al descifrar clave privada:", err);
      throw new Error("Contraseña incorrecta o datos corruptos.");
    }
  }

  function logout() {
    setCurrentUser(null);
  }

  return (
    <AuthContext.Provider value={{ currentUser, registerUser, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}
