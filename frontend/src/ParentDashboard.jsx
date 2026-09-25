import React, { useCallback, useEffect, useState } from "react";

const API_BASE_URL = "http://localhost:8000";

export default function ParentDashboard() {
  const [isAuthenticated, setIsAuthenticated] = useState(
    sessionStorage.getItem("parent_auth") === "true"
  );

  const [passwordInput, setPasswordInput] = useState("");
  const [errorMsg, setErrorMsg] = useState("");
  const [loading, setLoading] = useState(false);
  const [metricsLoading, setMetricsLoading] = useState(false);

  const [metrics, setMetrics] = useState({
    total_interactions: 0,
    warnings_count: 0,
    blocked_count: 0,
    recent_alerts: [],
  });

  // ==========================================================
  // FETCH DASHBOARD DATA
  // ==========================================================

  const fetchDashboardData = useCallback(async () => {
    if (!isAuthenticated) {
      return;
    }

    try {
      setMetricsLoading(true);

      const response = await fetch(
        `${API_BASE_URL}/dashboard/metrics`,
        {
          method: "GET",
          headers: {
            Accept: "application/json",
          },
        }
      );

      if (!response.ok) {
        throw new Error(
          `Dashboard request failed with status ${response.status}`
        );
      }

      const data = await response.json();

      setMetrics({
        total_interactions: Number(data.total_interactions) || 0,
        warnings_count: Number(data.warnings_count) || 0,
        blocked_count: Number(data.blocked_count) || 0,
        recent_alerts: Array.isArray(data.recent_alerts)
          ? data.recent_alerts
          : [],
      });
    } catch (error) {
      console.error(
        "Failed to load dashboard data:",
        error
      );
    } finally {
      setMetricsLoading(false);
    }
  }, [isAuthenticated]);

  // ==========================================================
  // INITIAL LOAD + REAL-TIME POLLING
  // ==========================================================

  useEffect(() => {
    if (!isAuthenticated) {
      return undefined;
    }

    fetchDashboardData();

    // Update dashboard every 5 seconds.
    const interval = setInterval(
      fetchDashboardData,
      5000
    );

    return () => {
      clearInterval(interval);
    };
  }, [isAuthenticated, fetchDashboardData]);

  // ==========================================================
  // PARENT LOGIN
  // ==========================================================

  const handleLogin = async (event) => {
    event.preventDefault();

    const password = passwordInput.trim();

    if (!password) {
      setErrorMsg("Please enter your password.");
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
            password,
          }),
        }
      );

      if (!response.ok) {
        let message = "Incorrect password.";

        try {
          const errorData = await response.json();

          if (errorData?.detail) {
            message = String(errorData.detail);
          }
        } catch {
          // Keep default error message.
        }

        setErrorMsg(message);
        return;
      }

      sessionStorage.setItem(
        "parent_auth",
        "true"
      );

      setIsAuthenticated(true);
      setPasswordInput("");
      setErrorMsg("");
    } catch (error) {
      console.error(
        "Parent login failed:",
        error
      );

      setErrorMsg(
        "Failed to connect to the backend server."
      );
    } finally {
      setLoading(false);
    }
  };

  // ==========================================================
  // LOGOUT
  // ==========================================================

  const handleLogout = () => {
    sessionStorage.removeItem("parent_auth");
    sessionStorage.removeItem("parent_email");

    setIsAuthenticated(false);
    setPasswordInput("");
    setErrorMsg("");

    setMetrics({
      total_interactions: 0,
      warnings_count: 0,
      blocked_count: 0,
      recent_alerts: [],
    });
  };

  // ==========================================================
  // LOGIN SCREEN
  // ==========================================================

  if (!isAuthenticated) {
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
        <h2>Parent Access Required</h2>

        <p
          style={{
            color: "#666",
            fontSize: 14,
            lineHeight: 1.5,
          }}
        >
          Please enter your guardian password
          to view analytics and safety alerts.
        </p>

        <form
          onSubmit={handleLogin}
          style={{
            display: "flex",
            flexDirection: "column",
            gap: 12,
            marginTop: 20,
          }}
        >
          <input
            type="password"
            placeholder="Enter Password"
            value={passwordInput}
            onChange={(event) =>
              setPasswordInput(
                event.target.value
              )
            }
            autoComplete="current-password"
            disabled={loading}
            style={{
              padding: 10,
              borderRadius: 4,
              border:
                "1px solid #ccc",
              fontSize: 16,
              outline: "none",
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
            }}
          >
            {loading
              ? "Verifying..."
              : "Unlock Dashboard"}
          </button>

          {errorMsg && (
            <span
              style={{
                color: "#dc2626",
                fontSize: 13,
              }}
            >
              {errorMsg}
            </span>
          )}
        </form>
      </div>
    );
  }

  // ==========================================================
  // DASHBOARD
  // ==========================================================

  return (
    <div
      style={{
        maxWidth: 800,
        margin: "0 auto",
        padding: 20,
      }}
    >
      {/* Header */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "flex-start",
          gap: 20,
          flexWrap: "wrap",
        }}
      >
        <div>
          <h2 style={{ marginBottom: 8 }}>
            Parent Safety Analytics
          </h2>

          <p
            style={{
              color: "#666",
              marginTop: 0,
              lineHeight: 1.5,
            }}
          >
            Real-time monitoring of
            child-AI interactions, emotion
            tracking, and safety filters.
          </p>
        </div>

        <button
          type="button"
          onClick={handleLogout}
          style={{
            padding: "8px 14px",
            background: "#fff",
            color: "#dc2626",
            border:
              "1px solid #dc2626",
            borderRadius: 4,
            fontWeight: "bold",
            cursor: "pointer",
          }}
        >
          Logout
        </button>
      </div>

      {/* Metric Cards */}
      <div
        style={{
          display: "flex",
          gap: 16,
          margin: "24px 0",
          flexWrap: "wrap",
        }}
      >
        <div
          style={{
            flex: 1,
            minWidth: 180,
            padding: 16,
            background: "#f8f9fa",
            borderRadius: 8,
          }}
        >
          <div>Total Interactions</div>

          <h2
            style={{
              color: "#0066cc",
              margin: "8px 0 0",
            }}
          >
            {metrics.total_interactions}
          </h2>
        </div>

        <div
          style={{
            flex: 1,
            minWidth: 180,
            padding: 16,
            background: "#f8f9fa",
            borderRadius: 8,
          }}
        >
          <div>Warnings Triggered</div>

          <h2
            style={{
              color: "#d97706",
              margin: "8px 0 0",
            }}
          >
            {metrics.warnings_count}
          </h2>
        </div>

        <div
          style={{
            flex: 1,
            minWidth: 180,
            padding: 16,
            background: "#f8f9fa",
            borderRadius: 8,
          }}
        >
          <div>Blocked Content</div>

          <h2
            style={{
              color: "#dc2626",
              margin: "8px 0 0",
            }}
          >
            {metrics.blocked_count}
          </h2>
        </div>
      </div>

      {/* Live Alerts */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: 12,
          gap: 10,
        }}
      >
        <h3 style={{ margin: 0 }}>
          Live Safety Alerts
        </h3>

        <button
          type="button"
          onClick={fetchDashboardData}
          disabled={metricsLoading}
          style={{
            padding: "6px 10px",
            background: "#fff",
            border: "1px solid #ccc",
            borderRadius: 4,
            cursor: metricsLoading
              ? "not-allowed"
              : "pointer",
            color: "#444",
          }}
        >
          {metricsLoading
            ? "Refreshing..."
            : "Refresh"}
        </button>
      </div>

      <p
        style={{
          color: "#888",
          fontSize: 13,
          marginTop: 0,
        }}
      >
        Showing the 5 most recent WARN and
        BLOCK events.
      </p>

      <div
        style={{
          overflowX: "auto",
        }}
      >
        <table
          style={{
            width: "100%",
            borderCollapse: "collapse",
            marginTop: 12,
            minWidth: 650,
          }}
        >
          <thead>
            <tr
              style={{
                borderBottom:
                  "2px solid #eee",
                textAlign: "left",
              }}
            >
              <th style={{ padding: 8 }}>
                Timestamp
              </th>

              <th style={{ padding: 8 }}>
                Child Input
              </th>

              <th style={{ padding: 8 }}>
                Detected Emotion
              </th>

              <th style={{ padding: 8 }}>
                Safety Status
              </th>

              <th style={{ padding: 8 }}>
                Risk
              </th>
            </tr>
          </thead>

          <tbody>
            {metrics.recent_alerts.length ===
            0 ? (
              <tr>
                <td
                  colSpan="5"
                  style={{
                    padding: 16,
                    textAlign: "center",
                    color: "#888",
                  }}
                >
                  No safety alerts recorded
                  yet.
                </td>
              </tr>
            ) : (
              metrics.recent_alerts.map(
                (alert) => {
                  const status =
                    String(
                      alert.safety_status ||
                        ""
                    ).toUpperCase();

                  const risk =
                    Number(
                      alert.risk_score
                    );

                  return (
                    <tr
                      key={alert.id}
                      style={{
                        borderBottom:
                          "1px solid #f0f0f0",
                      }}
                    >
                      <td
                        style={{
                          padding: 8,
                        }}
                      >
                        {alert.timestamp ||
                          "--"}
                      </td>

                      <td
                        style={{
                          padding: 8,
                          maxWidth: 300,
                          wordBreak:
                            "break-word",
                        }}
                      >
                        {alert.child_input ||
                          "[IMAGE UPLOAD]"}
                      </td>

                      <td
                        style={{
                          padding: 8,
                        }}
                      >
                        <span
                          style={{
                            background:
                              "#eef2ff",
                            padding:
                              "2px 8px",
                            borderRadius: 4,
                          }}
                        >
                          {alert.detected_emotion ||
                            "neutral"}
                        </span>
                      </td>

                      <td
                        style={{
                          padding: 8,
                        }}
                      >
                        <span
                          style={{
                            fontWeight:
                              "bold",
                            color:
                              status ===
                              "BLOCK"
                                ? "#dc2626"
                                : "#d97706",
                          }}
                        >
                          {status || "WARN"}
                        </span>
                      </td>

                      <td
                        style={{
                          padding: 8,
                          fontWeight:
                            "600",
                        }}
                      >
                        {Number.isFinite(risk)
                          ? risk.toFixed(3)
                          : "0.000"}
                      </td>
                    </tr>
                  );
                }
              )
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}