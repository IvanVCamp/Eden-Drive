import React, { useState } from "react";
import { useAuth } from "../context/AuthContext";
import {
  encryptFileWithAesGcm,
  exportAesKeyRawBase64,
  importPublicKeyFromPem,
  encryptAesKeyWithPublicKey,
  packageEncryptedPayload,
  downloadJsonAsFile,
  importAesKeyFromRawBase64,
  decryptAesKeyWithPrivateKey,
  decryptFileWithAesGcm,
} from "../utils/fileCryptoUtils";
import { UploadCloud, Download, ShieldCheck } from "lucide-react";

export default function FileCryptoDemo() {
  const auth = useAuth();
  const [file, setFile] = useState(null);
  const [pkg, setPkg] = useState(null);
  const [message, setMessage] = useState("");
  const [working, setWorking] = useState(false);

  async function handleEncrypt() {
    if (!file) {
      setMessage("Selecciona un archivo primero.");
      return;
    }
    setWorking(true);
    try {
      const meta = await encryptFileWithAesGcm(file);
      const aesRaw = await exportAesKeyRawBase64(meta.aesKey);

      const recipients = [];
      if (auth.user && auth.user.publicKeyPEM) {
        const pub = await importPublicKeyFromPem(auth.user.publicKeyPEM);
        const enc = await encryptAesKeyWithPublicKey(aesRaw, pub);
        recipients.push({ id: auth.user.username, encryptedAesKeyBase64: enc, publicKeyPEM: auth.user.publicKeyPEM });
      }

      meta.aesKey = null;
      const packaged = packageEncryptedPayload(meta, recipients);
      setPkg(packaged);
      downloadJsonAsFile(packaged, `${file.name}.encrypted.json`);
      setMessage("Archivo cifrado y descargado correctamente.");
    } catch (err) {
      setMessage("Error en el proceso: " + err.message);
    } finally {
      setWorking(false);
    }
  }

  async function handleDecryptFromPackage() {
    if (!pkg) {
      setMessage("Carga un paquete JSON cifrado primero.");
      return;
    }
    if (!auth.user || !auth.user.privateKeyCryptoKey) {
      setMessage("No estás autenticado o tu clave privada no está disponible.");
      return;
    }
    setWorking(true);
    try {
      let found = null;
      for (const r of pkg.recipients) {
        try {
          const aesRawBase64 = await decryptAesKeyWithPrivateKey(r.encryptedAesKeyBase64, auth.user.privateKeyCryptoKey);
          found = aesRawBase64;
          break;
        } catch {}
      }
      if (!found) {
        setMessage("No se pudo descifrar la clave AES.");
        return;
      }
      const aesKey = await importAesKeyFromRawBase64(found);
      const fileBuf = await decryptFileWithAesGcm(pkg.file.ciphertextBase64, pkg.file.ivBase64, aesKey);
      const blob = new Blob([fileBuf], { type: pkg.file.mimeType || "application/octet-stream" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = pkg.file.filename || "archivo_descifrado";
      a.click();
      setMessage("Descifrado y descarga completados.");
    } catch (err) {
      setMessage("Error: " + err.message);
    } finally {
      setWorking(false);
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex flex-col items-center p-10">
      <div className="max-w-3xl w-full bg-white rounded-3xl shadow-2xl p-8 border border-indigo-100">
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-2xl font-bold text-gray-800">Mi Nube Segura</h1>
          <ShieldCheck className="text-indigo-600" size={32} />
        </div>

        {auth.user && (
          <div className="mb-6 bg-indigo-50 border border-indigo-100 rounded-xl p-4 text-sm text-gray-700">
            Sesión activa como <strong>{auth.user.username}</strong>
          </div>
        )}

        <div className="space-y-6">
          <div className="flex flex-col items-center justify-center border-2 border-dashed border-indigo-300 rounded-2xl p-6 hover:bg-indigo-50 transition">
            <UploadCloud size={40} className="text-indigo-500 mb-3" />
            <input
              type="file"
              onChange={(e) => setFile(e.target.files?.[0] || null)}
              className="w-full text-sm text-gray-700 cursor-pointer"
            />
          </div>

          <div className="flex justify-center gap-4">
            <button
              onClick={handleEncrypt}
              disabled={working}
              className="flex items-center gap-2 px-6 py-3 bg-indigo-600 text-white font-semibold rounded-xl shadow hover:bg-indigo-700 transition disabled:opacity-60"
            >
              <UploadCloud size={18} /> Cifrar archivo
            </button>
            <button
              onClick={handleDecryptFromPackage}
              disabled={working || !pkg}
              className="flex items-center gap-2 px-6 py-3 bg-emerald-600 text-white font-semibold rounded-xl shadow hover:bg-emerald-700 transition disabled:opacity-60"
            >
              <Download size={18} /> Descifrar paquete
            </button>
          </div>

          {message && <p className="text-center text-sm text-gray-700 mt-4">{message}</p>}

          {pkg && (
            <div className="mt-6 bg-gray-50 rounded-xl border border-gray-200 p-4 max-h-64 overflow-auto text-xs text-gray-700">
              <p className="font-semibold mb-2 text-indigo-600">Vista previa del paquete cifrado:</p>
              <pre>{JSON.stringify(pkg, null, 2)}</pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
