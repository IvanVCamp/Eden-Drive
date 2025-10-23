import React from "react";
import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom";
import FirstLoginChangePassword from "./components/RegistroInicial";
import FileCryptoDemo from "./components/FileEncryptorDemo";
import { AuthProvider, useAuth } from "./context/AuthContext";

function PrivateRoute({ children }) {
  const { user } = useAuth();
  return user ? children : <Navigate to="/" replace />;
}

export default function App() {
  return (
    <AuthProvider>
      <Router>
        <Routes>
          <Route path="/" element={<FirstLoginChangePassword />} />
          <Route path="/file-crypto" element={<PrivateRoute><FileCryptoDemo /></PrivateRoute>} />
        </Routes>
      </Router>
    </AuthProvider>
  );
}
