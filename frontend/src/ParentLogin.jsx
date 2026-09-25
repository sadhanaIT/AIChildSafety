import React, { useState } from "react";

const API_BASE_URL = "http://127.0.0.1:8000";

export default function ParentLogin({
  onLoginSuccess,
}) {
  const [password, setPassword] = useState("");
  const [errorMsg, setErrorMsg] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (event) => {
    event.preventDefault();

    const enteredPassword = password.trim();

    if (!enteredPassword) {
      setErrorMsg("Please enter your password.");
      return;
    }

    if (loading) {
      return;
    }

    try {
      setLoading(true);
      setErrorMsg("");

      const response = await fetch(
        `${API_BASE_URL}/api/v1/profile/verify-password`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Accept: "application/json",
          },
          body: JSON.stringify({
            password: enteredPassword,
          }),
        }
      );

      let data = null;

      try {
        data = await response.json();
      } catch {
        data = null;
      }

      console.log(
        "Parent login response:",
        response.status,
        data
      );

      if (response.ok) {
        sessionStorage.setItem(
          "parent_auth",
          "true"
        );

        setPassword("");
        setErrorMsg("");

        if (
          typeof onLoginSuccess ===
          "function"
        ) {
          onLoginSuccess();
        }

        return;
      }

      if (response.status === 401) {
        setErrorMsg(
          data?.detail ||
            "Incorrect password."
        );
        return;
      }

      if (response.status >= 500) {
        setErrorMsg(
          "The backend server encountered an error. Check the PyCharm terminal."
        );
        return;
      }

      setErrorMsg(
        data?.detail ||
          data?.message ||
          `Login failed (HTTP ${response.status}).`
      );
    } catch (error) {
      console.error(
        "Parent login network error:",
        error
      );

      setErrorMsg(
        "Cannot reach the backend server. Make sure FastAPI is running on port 8000."
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        maxWidth: 400,
        margin: "80px auto",
        padding: 30,
        background: "#fff",
        borderRadius: 8,
        boxShadow:
          "0 4px 12px rgba(0,0,0,0.1)",
        textAlign: "center",
      }}
    >
      <h2>Guardian Sign-In</h2>

      <p
        style={{
          color: "#666",
          fontSize: 14,
          lineHeight: 1.5,
          marginBottom: 20,
        }}
      >
        Enter your guardian password to
        access safety controls and
        analytics.
      </p>

      <form
        onSubmit={handleSubmit}
        style={{
          display: "flex",
          flexDirection: "column",
          gap: 14,
        }}
      >
        <input
          type="password"
          placeholder="Enter Password"
          value={password}
          onChange={(event) =>
            setPassword(event.target.value)
          }
          required
          autoComplete="current-password"
          disabled={loading}
          style={{
            padding: 10,
            borderRadius: 4,
            border: "1px solid #ccc",
            fontSize: 15,
          }}
        />

        <button
          type="submit"
          disabled={loading}
          style={{
            padding: 10,
            background: loading
              ? "#8bb8e8"
              : "#0066cc",
            color: "#fff",
            border: "none",
            borderRadius: 4,
            fontWeight: "bold",
            cursor: loading
              ? "not-allowed"
              : "pointer",
            fontSize: 15,
          }}
        >
          {loading
            ? "Signing In..."
            : "Sign In"}
        </button>

        {errorMsg && (
          <span
            style={{
              color: "#dc2626",
              fontSize: 13,
              marginTop: 4,
              lineHeight: 1.4,
            }}
          >
            {errorMsg}
          </span>
        )}
      </form>
    </div>
  );
}