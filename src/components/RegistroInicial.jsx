import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { generateAndEncryptRSAKeys } from "../utils/cryptoUtils";
import { useAuth } from "../context/AuthContext";

export default function FirstLoginChangePassword() {
  const navigate = useNavigate();
  const auth = useAuth();

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [isFirstLogin, setIsFirstLogin] = useState(false);
  const [showChangeModal, setShowChangeModal] = useState(false);

  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [validationErrors, setValidationErrors] = useState([]);
  const [statusMessage, setStatusMessage] = useState("");
  const [processing, setProcessing] = useState(false);

  const [resultPayload, setResultPayload] = useState(null);

  function validatePasswordRules(pwd) {
    const errors = [];
    if (pwd.length < 12) errors.push("La contraseña debe tener al menos 12 caracteres.");
    if (!/[A-Z]/.test(pwd)) errors.push("Debe contener al menos una letra mayúscula.");
    if (!/[a-z]/.test(pwd)) errors.push("Debe contener al menos una letra minúscula.");
    if (!/\d/.test(pwd)) errors.push("Debe contener al menos un número.");
    if (!/[!@#$%^&*(),.?\":{}|<>]/.test(pwd)) errors.push("Debe contener al menos un carácter especial.");
    return errors;
  }

  async function mockLogin(username, password) {
    const INITIAL_PASSWORD = "TempPass123!";
    if (password === INITIAL_PASSWORD) return { ok: true, firstLogin: true };
    // if user exists in localStorage treat as ok
    const usersRaw = localStorage.getItem("app_users_v1");
    if (usersRaw) {
      const users = JSON.parse(usersRaw);
      if (users[username]) return { ok: true, firstLogin: false };
    }
    // otherwise allow (for demo) as non-first login
    return { ok: true, firstLogin: false };
  }

  async function handleLogin(e) {
    e.preventDefault();
    setStatusMessage("");
    setProcessing(true);
    try {
      const res = await mockLogin(username, password);
      if (!res.ok) {
        setStatusMessage("Credenciales incorrectas");
        setProcessing(false);
        return;
      }
      if (res.firstLogin) {
        setIsFirstLogin(true);
        setShowChangeModal(true);
        setProcessing(false);
        return;
      }
      // try real login using AuthContext (will verify hash and decrypt private key)
      const r = await auth.login(username, password);
      if (!r.ok) {
        setStatusMessage("Login fallido: " + (r.error || "credenciales incorrectas"));
        setProcessing(false);
        return;
      }
      // success -> navigate to file crypto
      navigate("/file-crypto");
    } catch (err) {
      console.error(err);
      setStatusMessage("Error en el login");
    } finally {
      setProcessing(false);
    }
  }

  async function handleChangePasswordSubmit(e) {
    e.preventDefault();
    setValidationErrors([]);
    setStatusMessage("");

    const errors = validatePasswordRules(newPassword);
    if (newPassword !== confirmPassword) errors.push("Las contraseñas no coinciden.");
    if (errors.length > 0) {
      setValidationErrors(errors);
      return;
    }

    setProcessing(true);
    try {
      const { payload, privateKeyBase64 } = await generateAndEncryptRSAKeys(username, newPassword);

      // Register user in AuthContext (which stores in localStorage)
      await auth.registerUser(payload);

      // Immediately login the user using new password (this will decrypt and import private key)
      const r = await auth.login(username, newPassword);
      if (!r.ok) {
        setStatusMessage("Registro completado pero login automático falló: " + (r.error || ""));
      } else {
        // redirect to file-crypto
        navigate("/file-crypto");
      }

      setResultPayload(payload);
      setShowChangeModal(false);
      setIsFirstLogin(false);
    } catch (err) {
      console.error(err);
      setStatusMessage("Error durante el proceso de cambio de contraseña.");
    } finally {
      setProcessing(false);
    }
  }

  return (
    <div className="min-h-screen bg-slate-50 flex items-center justify-center p-6">
      <div className="max-w-md w-full bg-white rounded-2xl shadow-lg p-6">
        <h2 className="text-2xl font-semibold mb-4">Iniciar sesión</h2>
        <form onSubmit={handleLogin} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700">Usuario</label>
            <input value={username} onChange={(e) => setUsername(e.target.value)} className="mt-1 block w-full rounded-md border-gray-300 shadow-sm p-2" placeholder="correo@empresa.com" required />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Contraseña</label>
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} className="mt-1 block w-full rounded-md border-gray-300 shadow-sm p-2" placeholder="Contraseña" required />
            <p className="text-xs text-gray-500 mt-1">Si es tu primer acceso usa la contraseña temporal.</p>
          </div>
          <div>
            <button type="submit" disabled={processing} className="w-full py-2 px-4 rounded-xl bg-indigo-600 text-white font-medium hover:bg-indigo-700 disabled:opacity-60">
              {processing ? "Procesando..." : "Entrar"}
            </button>
          </div>
        </form>

        {statusMessage && <p className="mt-4 text-sm text-green-700">{statusMessage}</p>}

        {resultPayload && (
          <div className="mt-4 p-3 bg-gray-50 rounded-lg border">
            <h3 className="text-sm font-medium">Payload a enviar al servidor (demo)</h3>
            <pre className="mt-2 text-xs break-words max-h-48 overflow-auto">{JSON.stringify(resultPayload, null, 2)}</pre>
          </div>
        )}

        {showChangeModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
            <div className="w-full max-w-lg bg-white rounded-2xl p-6 shadow-2xl">
              <h3 className="text-xl font-semibold mb-2">Primer acceso — Cambia tu contraseña</h3>
              <p className="text-sm text-gray-600 mb-4">Por seguridad debes cambiar la contraseña temporal y generar tus claves RSA.</p>

              <form onSubmit={handleChangePasswordSubmit} className="space-y-3">
                <div>
                  <label className="block text-sm font-medium">Nueva contraseña</label>
                  <input type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} className="mt-1 block w-full rounded-md border-gray-300 shadow-sm p-2" placeholder="Nueva contraseña segura" required />
                </div>
                <div>
                  <label className="block text-sm font-medium">Confirmar contraseña</label>
                  <input type="password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} className="mt-1 block w-full rounded-md border-gray-300 shadow-sm p-2" placeholder="Repite la contraseña" required />
                </div>

                {validationErrors.length > 0 && <ul className="text-sm text-red-600 list-disc pl-5">{validationErrors.map((err, i) => <li key={i}>{err}</li>)}</ul>}

                <div className="flex gap-2 justify-end">
                  <button type="button" onClick={() => { setShowChangeModal(false); setValidationErrors([]); }} className="px-4 py-2 rounded-lg border">Cancelar</button>
                  <button type="submit" disabled={processing} className="px-4 py-2 rounded-lg bg-indigo-600 text-white disabled:opacity-60">{processing ? "Generando claves..." : "Cambiar y Generar claves"}</button>
                </div>
              </form>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
