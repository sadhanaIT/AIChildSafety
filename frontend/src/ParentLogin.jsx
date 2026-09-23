import React, { useState } from 'react';

export default function ParentLogin({ onLoginSuccess }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [errorMsg, setErrorMsg] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const response = await fetch("http://localhost:8000/api/v1/profile/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password })
      });

      if (response.ok) {
        sessionStorage.setItem("parent_auth", "true");
        sessionStorage.setItem("parent_email", email);
        onLoginSuccess();
      } else {
        setErrorMsg("Invalid email or password. Default is parent@example.com / 1234");
      }
    } catch (err) {
      setErrorMsg("Failed to connect to the backend server.");
    }
  };

  return (
    <div style={{ maxWidth: 400, margin: "80px auto", padding: 30, background: "#fff", borderRadius: 8, boxShadow: "0 4px 12px rgba(0,0,0,0.1)", textAlign: "center" }}>
      <h2>Guardian Sign-In</h2>
      <p style={{ color: "#666", fontSize: 14, marginBottom: 20 }}>Sign in with your email and password to access controls.</p>
      <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: 14 }}>
        <input
          type="email"
          placeholder="Email Address"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
          style={{ padding: 10, borderRadius: 4, border: "1px solid #ccc", fontSize: 15 }}
        />
        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          style={{ padding: 10, borderRadius: 4, border: "1px solid #ccc", fontSize: 15 }}
        />
        <button type="submit" style={{ padding: 10, background: "#0066cc", color: "#fff", border: "none", borderRadius: 4, fontWeight: "bold", cursor: "pointer", fontSize: 15 }}>
          Sign In
        </button>
        {errorMsg && <span style={{ color: "#dc2626", fontSize: 13, marginTop: 4 }}>{errorMsg}</span>}
      </form>
    </div>
  );
}