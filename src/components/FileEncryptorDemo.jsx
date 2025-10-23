import React, { useState } from "react";
import { useAuth } from "../context/AuthContext";
import {
  encryptFileWithAesGcm,
  exportAesKeyRawBase64,
  importPublicKeyFromPem,
  encryptAesKeyWithPublicKey,
  packageEncryptedPayload,
  downloadJsonAsFile,
  importPrivateKeyFromPkcs8Base64,
  decryptAesKeyWithPrivateKey,
  importAesKeyFromRawBase64,
  decryptFileWithAesGcm,
} from "../utils/fileCryptoUtils";

/**
 * FileCryptoDemo now uses authenticated user keys when available:
 * - If a user is logged in, their publicKeyPEM is available as auth.user.publicKeyPEM
 * - auth.user.privateKeyCryptoKey is available to decrypt AES keys when needed
 *
 * The UI lets you:
 * - Choose file
 * - Choose recipients: by default it shows the current user as recipient (so you can encrypt to yourself)
 * - Click Encrypt -> JSON package is generated and offered for download
 * - Decrypt: uses auth.user.privateKeyCryptoKey to decrypt AES key and file
 */

export default function FileCryptoDemo() {
  const auth = useAuth();
  const [file, setFile] = useState(null);
  const [otherRecipientPem, setOtherRecipientPem] = useState("");
  const [pkg, setPkg] = useState(null);
  const [working, setWorking] = useState(false);
  const [message, setMessage] = useState("");

  async function handleEncrypt() {
    if (!file) {
      setMessage("Selecciona un archivo primero.");
      return;
    }

    setWorking(true);
    setMessage("");
    try {
      // 1) encrypt file with random AES key
      const fileMeta = await encryptFileWithAesGcm(file);
      const aesRawBase64 = await exportAesKeyRawBase64(fileMeta.aesKey);

      // 2) build recipients list: include auth.user if present
      const recipients = [];
      if (auth.user && auth.user.publicKeyPEM) {
        const pub = await importPublicKeyFromPem(auth.user.publicKeyPEM);
        const encAes = await encryptAesKeyWithPublicKey(aesRawBase64, pub);
        recipients.push({ id: auth.user.username, encryptedAesKeyBase64: encAes, publicKeyPEM: auth.user.publicKeyPEM });
      }

      // 3) optionally add another recipient provided via textarea
      if (otherRecipientPem && otherRecipientPem.trim()) {
        try {
          const pub2 = await importPublicKeyFromPem(otherRecipientPem.trim());
          const enc2 = await encryptAesKeyWithPublicKey(aesRawBase64, pub2);
          recipients.push({ id: "other", encryptedAesKeyBase64: enc2, publicKeyPEM: otherRecipientPem.trim() });
        } catch (err) {
          console.warn("Invalid extra recipient PEM", err);
        }
      }

      // 4) remove AES key from memory reference
      fileMeta.aesKey = null;

      // 5) package
      const packaged = packageEncryptedPayload(fileMeta, recipients);
      setPkg(packaged);

      // 6) download
      downloadJsonAsFile(packaged, `${file.name}.encrypted.json`);
      setMessage("Archivo cifrado correctamente. Paquete descargado.");
    } catch (err) {
      console.error(err);
      setMessage("Error durante el cifrado: " + err.message);
    } finally {
      setWorking(false);
    }
  }

  async function handleDecryptFromPackage() {
    setMessage("");
    if (!pkg) {
      setMessage("No hay paquete cargado. Primero cifra o pega un paquete JSON.");
      return;
    }
    if (!auth.user || !auth.user.privateKeyCryptoKey) {
      setMessage("No estás autenticado o tu clave privada no está disponible en memoria para descifrar.");
      return;
    }
    setWorking(true);
    try {
      // find recipient entry we can decrypt
      let found = null;
      for (const r of pkg.recipients) {
        if (r.encryptedAesKeyBase64) {
          try {
            const aesRawBase64 = await decryptAesKeyWithPrivateKey(r.encryptedAesKeyBase64, auth.user.privateKeyCryptoKey);
            found = { aesRawBase64, recipientId: r.id };
            break;
          } catch (err) {
            // ignore if can't decrypt with this private key
          }
        }
      }
      if (!found) {
        setMessage("No se pudo descifrar la clave AES con la clave privada actual.");
        setWorking(false);
        return;
      }
      const aesKey = await importAesKeyFromRawBase64(found.aesRawBase64);
      const fileBuf = await decryptFileWithAesGcm(pkg.file.ciphertextBase64, pkg.file.ivBase64, aesKey);
      const blob = new Blob([fileBuf], { type: pkg.file.mimeType || "application/octet-stream" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = pkg.file.filename || "download.bin";
      document.body.appendChild(a);
      a.click();
      a.remove();
      setMessage(`Descifrado correcto como '${found.recipientId}'. Descarga iniciada.`);
    } catch (err) {
      console.error(err);
      setMessage("Error durante el descifrado: " + err.message);
    } finally {
      setWorking(false);
    }
  }

  return (
    <div className="min-h-screen bg-gray-50 p-6 flex flex-col items-center gap-6">
      <div className="max-w-3xl w-full bg-white p-6 rounded-lg shadow">
        <h2 className="text-xl font-semibold mb-4">FRONT-007 — Cifrado de archivos con manejo automático de claves</h2>

        <div className="mb-4 text-sm text-gray-600">
          {auth.user ? (
            <div>
              <p>Autenticado como <strong>{auth.user.username}</strong>.</p>
              <p className="text-xs">Clave pública cargada automáticamente desde tu cuenta.</p>
            </div>
          ) : (
            <p>No estás autenticado: el cifrado aún funciona pero no se usará clave privada pública guardada.</p>
          )}
        </div>

        <div className="space-y-3">
          <input type="file" onChange={(e) => setFile(e.target.files?.[0] || null)} />
          <textarea value={otherRecipientPem} onChange={(e) => setOtherRecipientPem(e.target.value)} className="w-full border p-2 rounded text-xs" rows={4} placeholder="(Opcional) clave pública PEM extra para otro destinatario"></textarea>

          <div className="flex gap-2">
            <button onClick={handleEncrypt} disabled={working} className="px-4 py-2 bg-indigo-600 text-white rounded">{working ? "Procesando..." : "Cifrar archivo"}</button>
            <button onClick={handleDecryptFromPackage} disabled={working || !pkg} className="px-4 py-2 bg-emerald-600 text-white rounded">{working ? "Procesando..." : "Descifrar paquete (si eres destinatario)"}</button>
          </div>

          {message && <p className="text-sm mt-2">{message}</p>}
          {pkg && <pre className="mt-3 max-h-60 overflow-auto text-xs bg-gray-50 p-2 rounded">{JSON.stringify(pkg, null, 2)}</pre>}
        </div>
      </div>
    </div>
  );
}
