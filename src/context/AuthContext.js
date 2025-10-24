import React, { createContext, useContext, useState } from "react";
import {
  decryptPrivateKeyWithPassword,
  importPrivateKeyFromBase64,
  deriveHalfHashFromPassword
} from "../utils/cryptoUtils";

const AuthContext = createContext();
export const useAuth = () => useContext(AuthContext);

export function AuthProvider({ children }) {
  const [currentUser, setCurrentUser] = useState(null);
  const [privateKey, setPrivateKey] = useState(null);

  async function registerUser(payload) {
    const stored = JSON.parse(localStorage.getItem("app_users_v1") || "{}");
    stored[payload.username] = payload;
    localStorage.setItem("app_users_v1", JSON.stringify(stored));
  }

  async function login(username, password) {
    try {
      const allUsers = JSON.parse(localStorage.getItem("app_users_v1") || "{}");
      const userData = allUsers[username];
      if (!userData) throw new Error("Usuario no encontrado");

      const { encryptedPrivateKey, encryptionMetadata } = userData;
      const { iv, hkdfSalt } = encryptionMetadata;

      // Derivar la segunda mitad del hash de la contraseña igual que en el registro
      const half = await deriveHalfHashFromPassword(password);

      const pkcs8Base64 = await decryptPrivateKeyWithPassword(
        encryptedPrivateKey,
        iv,
        hkdfSalt,
        half
      );

      if (!pkcs8Base64) throw new Error("Fallo al descifrar clave privada");

      const privateKeyObj = await importPrivateKeyFromBase64(pkcs8Base64);

      setCurrentUser({ username, publicKeyPEM: userData.publicKeyPEM });
      setPrivateKey(privateKeyObj);
      return true;
    } catch (err) {
      console.error("Error en login():", err);
      setCurrentUser(null);
      setPrivateKey(null);
      return false;
    }
  }

  function logout() {
    setCurrentUser(null);
    setPrivateKey(null);
  }

  const value = {
    currentUser,
    privateKey,
    registerUser,
    login,
    logout
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
