// src/components/FirstLoginChangePassword.jsx
import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { generateAndEncryptRSAKeys } from "../utils/cryptoUtils";
import { useAuth } from "../context/AuthContext";

export default function FirstLoginChangePassword() {
  const navigate = useNavigate();
  const { registerUser, login } = useAuth();

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [isFirstLogin, setIsFirstLogin] = useState(false);
  const [showChangeModal, setShowChangeModal] = useState(false);
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [validationErrors, setValidationErrors] = useState([]);
  const [statusMessage, setStatusMessage] = useState("");
  const [processing, setProcessing] = useState(false);

  function validatePasswordRules(pwd) {
    const errors = [];
    if (pwd.length < 12) errors.push("La contraseña debe tener al menos 12 caracteres.");
    if (!/[A-Z]/.test(pwd)) errors.push("Debe contener al menos una letra mayúscula.");
    if (!/[a-z]/.test(pwd)) errors.push("Debe contener al menos una letra minúscula.");
    if (!/\d/.test(pwd)) errors.push("Debe contener al menos un número.");
    if (!/[!@#$%^&*(),.?\":{}|<>]/.test(pwd))
      errors.push("Debe contener al menos un carácter especial.");
    return errors;
  }

  async function mockLogin(username, password) {
    const INITIAL_PASSWORD = "TempPass123!";
    if (password === INITIAL_PASSWORD) return { ok: true, firstLogin: true };
    // Cualquier otra contraseña válida simula login correcto
    return { ok: true, firstLogin: false };
  }

  async function handleLogin(e) {
    e.preventDefault();
    setProcessing(true);
    setStatusMessage("");

    try {
      const res = await mockLogin(username, password);
      if (!res.ok) {
        setStatusMessage("Credenciales incorrectas");
        return;
      }

      if (res.firstLogin) {
        setIsFirstLogin(true);
        setShowChangeModal(true);
      } else {
        setStatusMessage("Login correcto. Cargando módulo de cifrado...");
        const ok = await login(username, password);
        if (ok) {
          console.log("✅ Login completado, navegando...");
          navigate("/file-crypto", { state: { username } });
        } else {
          console.warn("⚠️ Login no retornó true");
        }
      }
    } catch (err) {
      console.error("❌ Error en handleLogin:", err);
      setStatusMessage("Error en el login.");
    } finally {
      setProcessing(false);
    }
  }

  async function handleChangePasswordSubmit(e) {
    e.preventDefault();
    setValidationErrors([]);
    const errors = validatePasswordRules(newPassword);
    if (newPassword !== confirmPassword) errors.push("Las contraseñas no coinciden.");
    if (errors.length > 0) {
      setValidationErrors(errors);
      return;
    }

    setProcessing(true);
    try {
      const payload = await generateAndEncryptRSAKeys(username, newPassword);
      await registerUser(payload);
      setStatusMessage("Registro completado. Iniciando sesión automática...");

      const ok = await login(username, newPassword);
      if (ok) {
        console.log("✅ Registro + login exitoso, navegando...");
        navigate("/file-crypto", { state: { username } });
      }
    } catch (err) {
      console.error("❌ Error durante registro/login:", err);
      setStatusMessage("Error durante el proceso de registro o login.");
    } finally {
      setProcessing(false);
      setShowChangeModal(false);
    }
  }

  return (
    <div className="min-h-screen bg-slate-50 flex items-center justify-center p-6">
      <div className="max-w-md w-full bg-white rounded-2xl shadow-lg p-6">
        <h2 className="text-2xl font-semibold mb-4">Iniciar sesión</h2>

        <form onSubmit={handleLogin} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700">Usuario</label>
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="mt-1 block w-full rounded-md border-gray-300 shadow-sm p-2"
              placeholder="correo@empresa.com"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700">Contraseña</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="mt-1 block w-full rounded-md border-gray-300 shadow-sm p-2"
              placeholder="Contraseña"
              required
            />
            <p className="text-xs text-gray-500 mt-1">
              Si es tu primer acceso usa la contraseña temporal.
            </p>
          </div>

          <button
            type="submit"
            disabled={processing}
            className="w-full py-2 px-4 rounded-xl bg-indigo-600 text-white font-medium hover:bg-indigo-700 disabled:opacity-60"
          >
            {processing ? "Procesando..." : "Entrar"}
          </button>
        </form>

        {statusMessage && <p className="mt-4 text-sm text-green-700">{statusMessage}</p>}

        {showChangeModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
            <div className="w-full max-w-lg bg-white rounded-2xl p-6 shadow-2xl">
              <h3 className="text-xl font-semibold mb-2">Primer acceso — Cambia tu contraseña</h3>
              <p className="text-sm text-gray-600 mb-4">
                Por seguridad debes cambiar la contraseña temporal y generar tus claves RSA.
              </p>

              <form onSubmit={handleChangePasswordSubmit} className="space-y-3">
                <div>
                  <label className="block text-sm font-medium">Nueva contraseña</label>
                  <input
                    type="password"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm p-2"
                    placeholder="Nueva contraseña segura"
                    required
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium">Confirmar contraseña</label>
                  <input
                    type="password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm p-2"
                    placeholder="Repite la contraseña"
                    required
                  />
                </div>

                {validationErrors.length > 0 && (
                  <ul className="text-sm text-red-600 list-disc pl-5">
                    {validationErrors.map((err, i) => (
                      <li key={i}>{err}</li>
                    ))}
                  </ul>
                )}

                <div className="flex gap-2 justify-end">
                  <button
                    type="button"
                    onClick={() => setShowChangeModal(false)}
                    className="px-4 py-2 rounded-lg border"
                  >
                    Cancelar
                  </button>
                  <button
                    type="submit"
                    disabled={processing}
                    className="px-4 py-2 rounded-lg bg-indigo-600 text-white disabled:opacity-60"
                  >
                    {processing ? "Generando claves..." : "Cambiar y Generar claves"}
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
