import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { generateAndEncryptRSAKeys } from "../utils/cryptoUtils";
import { useAuth } from "../context/AuthContext";
import { Lock, LogIn } from "lucide-react";

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
    if (pwd.length < 12) errors.push("Debe tener al menos 12 caracteres.");
    if (!/[A-Z]/.test(pwd)) errors.push("Debe incluir una letra mayúscula.");
    if (!/[a-z]/.test(pwd)) errors.push("Debe incluir una letra minúscula.");
    if (!/\d/.test(pwd)) errors.push("Debe incluir un número.");
    if (!/[!@#$%^&*(),.?\":{}|<>]/.test(pwd))
      errors.push("Debe incluir un carácter especial.");
    return errors;
  }

  async function mockLogin(username, password) {
    const INITIAL_PASSWORD = "TempPass123!";
    if (password === INITIAL_PASSWORD) return { ok: true, firstLogin: true };
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
        const ok = await login(username, password);
        if (ok) navigate("/file-crypto", { state: { username } });
        else setStatusMessage("Error durante el inicio de sesión. Comprueba tus datos.");
      }
    } catch {
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
      const ok = await login(username, newPassword);
      if (ok) navigate("/file-crypto", { state: { username } });
      else setStatusMessage("Error durante el registro o login.");
    } catch {
      setStatusMessage("Error durante el proceso de registro o login.");
    } finally {
      setProcessing(false);
      setShowChangeModal(false);
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-indigo-100 via-white to-blue-100 flex items-center justify-center p-6">
      <div className="max-w-md w-full bg-white/90 backdrop-blur-md border border-indigo-100 rounded-3xl shadow-2xl p-8">
        <div className="flex items-center justify-center mb-6">
          <div className="bg-indigo-600 text-white p-3 rounded-full shadow-md">
            <LogIn size={28} />
          </div>
        </div>

        <h2 className="text-2xl font-bold text-center text-gray-800 mb-6">Acceso Seguro</h2>
        <form onSubmit={handleLogin} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-600">Usuario</label>
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="mt-1 w-full p-3 border border-gray-300 rounded-xl shadow-sm focus:ring-2 focus:ring-indigo-400 focus:border-indigo-400 outline-none"
              placeholder="usuario@correo.com"
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-600">Contraseña</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="mt-1 w-full p-3 border border-gray-300 rounded-xl shadow-sm focus:ring-2 focus:ring-indigo-400 focus:border-indigo-400 outline-none"
              placeholder="••••••••"
              required
            />
            <p className="text-xs text-gray-500 mt-1">
              Usa tu contraseña temporal si es tu primer acceso.
            </p>
          </div>
          <button
            type="submit"
            disabled={processing}
            className="w-full py-3 rounded-xl bg-indigo-600 text-white font-semibold hover:bg-indigo-700 transition disabled:opacity-60"
          >
            {processing ? "Procesando..." : "Entrar"}
          </button>
        </form>
        {statusMessage && (
          <p className="mt-4 text-center text-sm text-red-600">{statusMessage}</p>
        )}

        {showChangeModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
            <div className="w-full max-w-lg bg-white rounded-2xl p-8 shadow-2xl">
              <div className="flex items-center mb-4 gap-3">
                <Lock className="text-indigo-600" size={24} />
                <h3 className="text-lg font-semibold text-gray-800">
                  Primer acceso — Cambia tu contraseña
                </h3>
              </div>
              <form onSubmit={handleChangePasswordSubmit} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-600">Nueva contraseña</label>
                  <input
                    type="password"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    className="mt-1 w-full p-3 border border-gray-300 rounded-xl shadow-sm focus:ring-2 focus:ring-indigo-400 focus:border-indigo-400 outline-none"
                    placeholder="Nueva contraseña segura"
                    required
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-600">Confirmar contraseña</label>
                  <input
                    type="password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    className="mt-1 w-full p-3 border border-gray-300 rounded-xl shadow-sm focus:ring-2 focus:ring-indigo-400 focus:border-indigo-400 outline-none"
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
                <div className="flex justify-end gap-3 mt-4">
                  <button
                    type="button"
                    onClick={() => setShowChangeModal(false)}
                    className="px-4 py-2 rounded-lg border text-gray-700 hover:bg-gray-100 transition"
                  >
                    Cancelar
                  </button>
                  <button
                    type="submit"
                    disabled={processing}
                    className="px-4 py-2 rounded-lg bg-indigo-600 text-white font-medium hover:bg-indigo-700 transition disabled:opacity-60"
                  >
                    {processing ? "Generando..." : "Confirmar"}
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
