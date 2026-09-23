import React, { useState, useEffect } from 'react';

export default function ParentDashboard() {
  const [isAuthenticated, setIsAuthenticated] = useState(
    sessionStorage.getItem("parent_auth") === "true"
  );
  const [passwordInput, setPasswordInput] = useState("");
  const [errorMsg, setErrorMsg] = useState("");

  const [metrics, setMetrics] = useState({
    total_interactions: 0,
    warnings_count: 0,
    blocked_count: 0,
    recent_alerts: []
  });

  const fetchDashboardData = async () => {
    try {
      const response = await fetch("http://localhost:8000/dashboard/metrics");
      if (response.ok) {
        const data = await response.json();
        setMetrics(data);
      }
    } catch (error) {
      console.error("Failed to load dashboard data:", error);
    }
  };

  useEffect(() => {
    if (isAuthenticated) {
      fetchDashboardData();
      // Poll every 5 seconds to update the feed in real-time
      const interval = setInterval(fetchDashboardData, 5000);
      return () => clearInterval(interval);
    }
  }, [isAuthenticated]);

  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const response = await fetch("http://localhost:8000/api/v1/profile/verify-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: passwordInput })
      });

      if (response.ok) {
        sessionStorage.setItem("parent_auth", "true");
        setIsAuthenticated(true);
        setErrorMsg("");
      } else {
        setErrorMsg("Incorrect password. Default is 1234.");
      }
    } catch (err) {
      setErrorMsg("Failed to connect to backend server.");
    }
  };

  if (!isAuthenticated) {
    return (
      <div style={{ maxWidth: 400, margin: "80px auto", padding: 30, background: "#fff", borderRadius: 8, boxShadow: "0 4px 12px rgba(0,0,0,0.1)", textAlign: "center" }}>
        <h2>Parent Access Required</h2>
        <p style={{ color: "#666", fontSize: 14 }}>Please enter your guardian password to view analytics and rules.</p>
        <form onSubmit={handleLogin} style={{ display: "flex", flexDirection: "column", gap: 12, marginTop: 20 }}>
          <input
            type="password"
            placeholder="Enter Password"
            value={passwordInput}
            onChange={(e) => setPasswordInput(e.target.value)}
            style={{ padding: 10, borderRadius: 4, border: "1px solid #ccc", fontSize: 16 }}
          />
          <button type="submit" style={{ padding: 10, background: "#0066cc", color: "#fff", border: "none", borderRadius: 4, fontWeight: "bold", cursor: "pointer" }}>
            Unlock Dashboard
          </button>
          {errorMsg && <span style={{ color: "#dc2626", fontSize: 13 }}>{errorMsg}</span>}
        </form>
      </div>
    );
  }

  return (
    <div style={{ maxWidth: 800, margin: "0 auto", padding: 20 }}>
      <h2>Parent Safety Analytics</h2>
      <p style={{ color: "#666" }}>
        Real-time monitoring of child-AI interactions, emotion tracking, and risk filters.
      </p>

      {/* Metric Cards */}
      <div style={{ display: "flex", gap: 16, margin: "24px 0" }}>
        <div style={{ flex: 1, padding: 16, background: "#f8f9fa", borderRadius: 8 }}>
          <div>Total Interactions</div>
          <h2 style={{ color: "#0066cc", margin: "8px 0 0" }}>{metrics.total_interactions}</h2>
        </div>
        <div style={{ flex: 1, padding: 16, background: "#f8f9fa", borderRadius: 8 }}>
          <div>Warnings Triggered</div>
          <h2 style={{ color: "#d97706", margin: "8px 0 0" }}>{metrics.warnings_count}</h2>
        </div>
        <div style={{ flex: 1, padding: 16, background: "#f8f9fa", borderRadius: 8 }}>
          <div>Blocked Content</div>
          <h2 style={{ color: "#dc2626", margin: "8px 0 0" }}>{metrics.blocked_count}</h2>
        </div>
      </div>

      {/* Live Alerts Audit Table */}
      <h3>Live Safety Alerts (5 Most Recent)</h3>
      <table style={{ width: "100%", borderCollapse: "collapse", marginTop: 12 }}>
        <thead>
          <tr style={{ borderBottom: "2px solid #eee", textAlign: "left" }}>
            <th style={{ padding: 8 }}>Timestamp</th>
            <th style={{ padding: 8 }}>Child Input</th>
            <th style={{ padding: 8 }}>Detected Emotion</th>
            <th style={{ padding: 8 }}>Safety Status</th>
          </tr>
        </thead>
        <tbody>
          {metrics.recent_alerts.length === 0 ? (
            <tr>
              <td colSpan="4" style={{ padding: 16, textAlign: "center", color: "#888" }}>
                No safety alerts recorded yet.
              </td>
            </tr>
          ) : (
            metrics.recent_alerts.map((alert) => (
              <tr key={alert.id} style={{ borderBottom: "1px solid #f0f0f0" }}>
                <td style={{ padding: 8 }}>{alert.timestamp}</td>
                <td style={{ padding: 8 }}>{alert.child_input}</td>
                <td style={{ padding: 8 }}>
                  <span style={{ background: "#eef2ff", padding: "2px 8px", borderRadius: 4 }}>
                    {alert.detected_emotion}
                  </span>
                </td>
                <td style={{ padding: 8 }}>
                  <span
                    style={{
                      fontWeight: "bold",
                      color: alert.safety_status === "BLOCK" ? "#dc2626" : "#d97706"
                    }}
                  >
                    {alert.safety_status}
                  </span>
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}