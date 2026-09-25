import React, {
  useCallback,
  useEffect,
  useState,
} from "react";

const API_BASE_URL = "http://localhost:8000";

const DEFAULT_PROFILE_NAME =
  "Child Companion Profile";

const DEFAULT_SENSITIVITY =
  "High (Strict PII & Toxicity Block)";

const DEFAULT_NOTIFICATIONS_ENABLED = true;

export default function Profile() {
  // ==========================================================
  // PROFILE STATE
  // ==========================================================

  const [profileName, setProfileName] = useState(
    DEFAULT_PROFILE_NAME
  );

  const [sensitivity, setSensitivity] = useState(
    DEFAULT_SENSITIVITY
  );

  const [notificationsEnabled, setNotificationsEnabled] =
    useState(
      DEFAULT_NOTIFICATIONS_ENABLED
    );

  // ==========================================================
  // BROWSER LOCK STATE
  // ==========================================================

  const [isBrowserLocked, setIsBrowserLocked] =
    useState(true);

  const [browserLockLoading, setBrowserLockLoading] =
    useState(false);

  // ==========================================================
  // CUSTOM RULES
  // ==========================================================

  const [restrictedWords, setRestrictedWords] =
    useState([]);

  const [newWord, setNewWord] = useState("");

  // ==========================================================
  // UI STATE
  // ==========================================================

  const [loadingProfile, setLoadingProfile] =
    useState(true);

  const [saving, setSaving] = useState(false);

  const [savedMessage, setSavedMessage] =
    useState(false);

  const [actionMessage, setActionMessage] =
    useState("");

  const [errorMessage, setErrorMessage] =
    useState("");

  // ==========================================================
  // LOAD PROFILE SETTINGS
  // ==========================================================

  const fetchProfileSettings = useCallback(
    async () => {
      try {
        setLoadingProfile(true);
        setErrorMessage("");

        const response = await fetch(
          `${API_BASE_URL}/api/v1/profile/rules`,
          {
            method: "GET",
            headers: {
              Accept: "application/json",
            },
          }
        );

        if (!response.ok) {
          throw new Error(
            `Profile request failed with status ${response.status}`
          );
        }

        const data = await response.json();

        // ----------------------------------------------------
        // Keywords
        // ----------------------------------------------------

        if (Array.isArray(data.keywords)) {
          const uniqueKeywords = [
            ...new Set(
              data.keywords
                .map((word) =>
                  String(word)
                    .trim()
                    .toLowerCase()
                )
                .filter(Boolean)
            ),
          ];

          setRestrictedWords(
            uniqueKeywords
          );
        } else {
          setRestrictedWords([]);
        }

        // ----------------------------------------------------
        // Profile name
        // ----------------------------------------------------

        if (
          typeof data.profile_name ===
            "string" &&
          data.profile_name.trim()
        ) {
          setProfileName(
            data.profile_name
          );
        }

        // ----------------------------------------------------
        // Sensitivity
        // ----------------------------------------------------

        if (
          typeof data.sensitivity ===
            "string" &&
          data.sensitivity.trim()
        ) {
          setSensitivity(
            data.sensitivity
          );
        }

        // ----------------------------------------------------
        // Notifications
        // ----------------------------------------------------

        if (
          typeof data.notifications_enabled ===
          "boolean"
        ) {
          setNotificationsEnabled(
            data.notifications_enabled
          );
        }
      } catch (error) {
        console.error(
          "Failed to load profile settings:",
          error
        );

        setErrorMessage(
          "Failed to load profile settings from the backend."
        );
      } finally {
        setLoadingProfile(false);
      }
    },
    []
  );

  // ==========================================================
  // INITIAL LOAD
  // ==========================================================

  useEffect(() => {
    fetchProfileSettings();
  }, [fetchProfileSettings]);

  // ==========================================================
  // ADD CUSTOM RULE
  // ==========================================================

  const handleAddWord = (event) => {
    event.preventDefault();

    const normalizedWord = newWord
      .trim()
      .toLowerCase();

    if (!normalizedWord) {
      return;
    }

    const alreadyExists =
      restrictedWords.some(
        (word) =>
          String(word)
            .trim()
            .toLowerCase() ===
          normalizedWord
      );

    if (alreadyExists) {
      setNewWord("");
      return;
    }

    setRestrictedWords(
      (previousWords) => [
        ...previousWords,
        normalizedWord,
      ]
    );

    setNewWord("");
    setSavedMessage(false);
    setErrorMessage("");
  };

  // ==========================================================
  // REMOVE CUSTOM RULE
  // ==========================================================

  const handleRemoveWord = (
    wordToRemove
  ) => {
    setRestrictedWords(
      (previousWords) =>
        previousWords.filter(
          (word) =>
            word !== wordToRemove
        )
    );

    setSavedMessage(false);
    setErrorMessage("");
  };

  // ==========================================================
  // BROWSER SAFETY LOCK
  // ==========================================================

  const handleToggleBrowserLock =
    async (lockState) => {
      if (browserLockLoading) {
        return;
      }

      const endpoint = lockState
        ? "enforce-browser-locks"
        : "unlock-browser-locks";

      try {
        setBrowserLockLoading(true);
        setActionMessage("");
        setErrorMessage("");

        const response = await fetch(
          `${API_BASE_URL}/api/v1/profile/${endpoint}`,
          {
            method: "POST",
            headers: {
              Accept: "application/json",
            },
          }
        );

        let data = {};

        try {
          data = await response.json();
        } catch {
          data = {};
        }

        if (!response.ok) {
          throw new Error(
            data?.message ||
              data?.detail ||
              `Browser lock request failed with status ${response.status}`
          );
        }

        // ----------------------------------------------------
        // Only update local state when backend succeeds.
        // ----------------------------------------------------

        if (
          data?.status === "success"
        ) {
          setIsBrowserLocked(
            lockState
          );
        }

        setActionMessage(
          data?.message ||
            (
              lockState
                ? "Browser safety locks successfully enforced."
                : "Browser safety locks successfully removed."
            )
        );

        window.setTimeout(() => {
          setActionMessage("");
        }, 4000);
      } catch (error) {
        console.error(
          "Browser safety lock request failed:",
          error
        );

        setActionMessage(
          error?.message ||
            "Error communicating with the backend."
        );
      } finally {
        setBrowserLockLoading(false);
      }
    };

  // ==========================================================
  // SAVE PROFILE
  // ==========================================================

  const handleSave = async (
    event
  ) => {
    event.preventDefault();

    if (saving) {
      return;
    }

    try {
      setSaving(true);
      setSavedMessage(false);
      setErrorMessage("");

      // ------------------------------------------------------
      // Normalize keywords before sending.
      // ------------------------------------------------------

      const cleanedKeywords = [
        ...new Set(
          restrictedWords
            .map((word) =>
              String(word)
                .trim()
                .toLowerCase()
            )
            .filter(Boolean)
        ),
      ];

      const response = await fetch(
        `${API_BASE_URL}/api/v1/profile/rules`,
        {
          method: "POST",
          headers: {
            "Content-Type":
              "application/json",
            Accept: "application/json",
          },
          body: JSON.stringify({
            profile_name:
              profileName.trim() ||
              DEFAULT_PROFILE_NAME,

            sensitivity:
              sensitivity.trim() ||
              DEFAULT_SENSITIVITY,

            notifications_enabled:
              Boolean(
                notificationsEnabled
              ),

            keywords:
              cleanedKeywords,
          }),
        }
      );

      let data = {};

      try {
        data = await response.json();
      } catch {
        data = {};
      }

      if (!response.ok) {
        throw new Error(
          data?.detail ||
            data?.message ||
            `Save request failed with status ${response.status}`
        );
      }

      // ------------------------------------------------------
      // Update local state with normalized values.
      // ------------------------------------------------------

      setRestrictedWords(
        cleanedKeywords
      );

      setProfileName(
        profileName.trim() ||
          DEFAULT_PROFILE_NAME
      );

      setSensitivity(
        sensitivity.trim() ||
          DEFAULT_SENSITIVITY
      );

      setSavedMessage(true);

      window.setTimeout(() => {
        setSavedMessage(false);
      }, 3000);
    } catch (error) {
      console.error(
        "Failed to save profile configuration:",
        error
      );

      setErrorMessage(
        error?.message ||
          "Failed to save profile configuration."
      );
    } finally {
      setSaving(false);
    }
  };

  // ==========================================================
  // LOADING STATE
  // ==========================================================

  if (loadingProfile) {
    return (
      <div
        style={{
          flex: 1,
          overflowY: "auto",
          padding: "32px",
          background:
            "linear-gradient(135deg, #fdfbfd 0%, #f3eef8 100%)",
          boxSizing: "border-box",
          minHeight: "100%",
        }}
      >
        <div
          style={{
            maxWidth: "750px",
            margin: "0 auto",
          }}
        >
          <div
            style={{
              background: "#ffffff",
              padding: "28px",
              borderRadius: "14px",
              border:
                "1px solid #eadef5",
              color: "#7a6e93",
              textAlign: "center",
            }}
          >
            Loading profile settings...
          </div>
        </div>
      </div>
    );
  }

  // ==========================================================
  // MAIN PROFILE UI
  // ==========================================================

  return (
    <div
      style={{
        flex: 1,
        overflowY: "auto",
        padding: "32px",
        background:
          "linear-gradient(135deg, #fdfbfd 0%, #f3eef8 100%)",
        boxSizing: "border-box",
        minHeight: "100%",
      }}
    >
      <div
        style={{
          maxWidth: "750px",
          margin: "0 auto",
        }}
      >
        {/* ==================================================
            PAGE HEADER
            ================================================== */}

        <h1
          style={{
            color: "#2d2640",
            marginBottom: "6px",
            fontSize: "24px",
            fontWeight: "700",
          }}
        >
          User & Device Profile
        </h1>

        <p
          style={{
            color: "#7a6e93",
            marginBottom: "24px",
            fontSize: "14px",
            lineHeight: "1.5",
          }}
        >
          Configure child safety thresholds,
          emergency settings, and custom
          restricted topic filters.
        </p>

        {/* ==================================================
            ERROR MESSAGE
            ================================================== */}

        {errorMessage && (
          <div
            style={{
              background: "#fef2f2",
              color: "#b91c1c",
              padding: "12px 18px",
              borderRadius: "10px",
              marginBottom: "20px",
              border:
                "1px solid #fecaca",
              fontWeight: "600",
              fontSize: "13px",
            }}
          >
            ⚠️ {errorMessage}
          </div>
        )}

        {/* ==================================================
            SAVE SUCCESS MESSAGE
            ================================================== */}

        {savedMessage && (
          <div
            style={{
              background: "#e6f7ed",
              color: "#1e7e34",
              padding: "12px 18px",
              borderRadius: "10px",
              marginBottom: "20px",
              border:
                "1px solid #c3e6cb",
              fontWeight: "600",
              fontSize: "13px",
            }}
          >
            ✓ Profile settings and
            filters synced with backend
            successfully!
          </div>
        )}

        {/* ==================================================
            BROWSER ACTION MESSAGE
            ================================================== */}

        {actionMessage && (
          <div
            style={{
              background: "#f3eef8",
              color: "#64587a",
              padding: "12px 18px",
              borderRadius: "10px",
              marginBottom: "20px",
              border:
                "1px solid #ded0f1",
              fontWeight: "600",
              fontSize: "13px",
            }}
          >
            ℹ️ {actionMessage}
          </div>
        )}

        {/* ==================================================
            BROWSER SAFETY LOCKS
            ================================================== */}

        <div
          style={{
            background: "#ffffff",
            padding: "20px 24px",
            borderRadius: "14px",
            boxShadow:
              "0 4px 15px rgba(116, 90, 158, 0.04)",
            marginBottom: "20px",
            border:
              "1px solid #eadef5",
            display: "flex",
            justifyContent:
              "space-between",
            alignItems: "center",
            gap: "20px",
            flexWrap: "wrap",
          }}
        >
          <div>
            <h4
              style={{
                margin: "0 0 4px 0",
                color: "#2d2640",
                fontSize: "15px",
                fontWeight: "600",
              }}
            >
              System Browser Safety
              Locks
            </h4>

            <p
              style={{
                margin: 0,
                color: "#7a6e93",
                fontSize: "13px",
                lineHeight: "1.4",
              }}
            >
              Enforce strict SafeSearch
              and YouTube Restricted
              Mode.
            </p>
          </div>

          <button
            type="button"
            disabled={
              browserLockLoading
            }
            onClick={() =>
              handleToggleBrowserLock(
                !isBrowserLocked
              )
            }
            style={{
              background:
                browserLockLoading
                  ? "#9ca3af"
                  : isBrowserLocked
                  ? "#ef4444"
                  : "#10b981",
              color: "#fff",
              border: "none",
              padding: "10px 16px",
              borderRadius: "8px",
              fontWeight: "bold",
              fontSize: "13px",
              cursor:
                browserLockLoading
                  ? "not-allowed"
                  : "pointer",
              transition:
                "all 0.2s",
            }}
          >
            {browserLockLoading
              ? "Updating..."
              : isBrowserLocked
              ? "🔓 Unlock Browser"
              : "🔒 Lock Browser"}
          </button>
        </div>

        {/* ==================================================
            PROFILE FORM
            ================================================== */}

        <form
          onSubmit={handleSave}
          style={{
            background: "#ffffff",
            padding: "28px",
            borderRadius: "14px",
            boxShadow:
              "0 4px 15px rgba(116, 90, 158, 0.04)",
            border:
              "1px solid #eadef5",
          }}
        >
          {/* =================================================
              SECTION HEADER
              ================================================= */}

          <h3
            style={{
              marginTop: "0",
              color: "#2d2640",
              borderBottom:
                "1px solid #f2ecfb",
              paddingBottom: "12px",
              marginBottom: "20px",
              fontSize: "16px",
              fontWeight: "600",
            }}
          >
            Guardian & Safety
            Configuration
          </h3>

          {/* =================================================
              PROFILE NAME
              ================================================= */}

          <div
            style={{
              marginBottom: "20px",
            }}
          >
            <label
              style={{
                display: "block",
                fontWeight: "600",
                color: "#2d2640",
                marginBottom: "8px",
                fontSize: "13px",
              }}
            >
              Profile Name
            </label>

            <input
              type="text"
              value={profileName}
              maxLength={100}
              onChange={(event) => {
                setProfileName(
                  event.target.value
                );
                setSavedMessage(false);
              }}
              style={{
                width: "100%",
                padding:
                  "12px 14px",
                borderRadius: "8px",
                border:
                  "1px solid #ded0f1",
                fontSize: "14px",
                boxSizing:
                  "border-box",
                background:
                  "#fcfbfe",
                color: "#2d2640",
                outline: "none",
              }}
            />
          </div>

          {/* =================================================
              SENSITIVITY
              ================================================= */}

          <div
            style={{
              marginBottom: "20px",
            }}
          >
            <label
              style={{
                display: "block",
                fontWeight: "600",
                color: "#2d2640",
                marginBottom: "8px",
                fontSize: "13px",
              }}
            >
              Safety Sensitivity
              Level
            </label>

            <select
              value={sensitivity}
              onChange={(event) => {
                setSensitivity(
                  event.target.value
                );
                setSavedMessage(false);
              }}
              style={{
                width: "100%",
                padding:
                  "12px 14px",
                borderRadius: "8px",
                border:
                  "1px solid #ded0f1",
                fontSize: "14px",
                background:
                  "#fcfbfe",
                color: "#2d2640",
                boxSizing:
                  "border-box",
                outline: "none",
                cursor: "pointer",
              }}
            >
              <option>
                High (Strict PII & Toxicity
                Block)
              </option>

              <option>
                Medium (Balanced Protection)
              </option>

              <option>
                Low (Minimal Filtering)
              </option>
            </select>
          </div>

          {/* =================================================
              CUSTOM KEYWORDS
              ================================================= */}

          <div
            style={{
              marginBottom: "20px",
              background: "#fcfbfe",
              padding: "18px",
              borderRadius: "10px",
              border:
                "1px solid #f2ecfb",
            }}
          >
            <label
              style={{
                display: "block",
                fontWeight: "600",
                color: "#2d2640",
                marginBottom: "4px",
                fontSize: "13px",
              }}
            >
              Custom Blocked
              Keywords & Topics
            </label>

            <p
              style={{
                color: "#7a6e93",
                fontSize: "13px",
                marginBottom: "12px",
                marginTop: "0",
                lineHeight: "1.5",
              }}
            >
              These terms are saved
              to the backend database
              and can trigger guardian
              warnings during safety
              checks.
            </p>

            {/* Add Rule */}
            <div
              style={{
                display: "flex",
                gap: "10px",
                marginBottom: "12px",
              }}
            >
              <input
                type="text"
                value={newWord}
                maxLength={100}
                onChange={(event) =>
                  setNewWord(
                    event.target.value
                  )
                }
                onKeyDown={(event) => {
                  if (
                    event.key ===
                    "Enter"
                  ) {
                    handleAddWord(event);
                  }
                }}
                placeholder="e.g. bullying, secrets"
                style={{
                  flex: 1,
                  padding:
                    "10px 14px",
                  borderRadius: "8px",
                  border:
                    "1px solid #ded0f1",
                  fontSize: "13px",
                  background:
                    "#ffffff",
                  color: "#2d2640",
                  outline: "none",
                  minWidth: 0,
                }}
              />

              <button
                type="button"
                onClick={handleAddWord}
                disabled={
                  !newWord.trim()
                }
                style={{
                  background:
                    newWord.trim()
                      ? "#10b981"
                      : "#9ca3af",
                  color: "#fff",
                  border: "none",
                  padding:
                    "10px 16px",
                  borderRadius: "8px",
                  fontWeight: "600",
                  fontSize: "13px",
                  cursor:
                    newWord.trim()
                      ? "pointer"
                      : "not-allowed",
                  whiteSpace:
                    "nowrap",
                }}
              >
                Add Rule
              </button>
            </div>

            {/* Existing Rules */}
            <div
              style={{
                display: "flex",
                flexWrap: "wrap",
                gap: "8px",
              }}
            >
              {restrictedWords.length ===
              0 ? (
                <span
                  style={{
                    color: "#998eab",
                    fontSize: "13px",
                  }}
                >
                  No custom rules
                  added yet.
                </span>
              ) : (
                restrictedWords.map(
                  (word) => (
                    <span
                      key={word}
                      style={{
                        background:
                          "#f0eaf8",
                        color:
                          "#7c58cc",
                        padding:
                          "4px 12px",
                        borderRadius:
                          "20px",
                        fontSize: "13px",
                        display:
                          "flex",
                        alignItems:
                          "center",
                        gap: "6px",
                        border:
                          "1px solid #ded0f1",
                        fontWeight:
                          "500",
                      }}
                    >
                      {word}

                      <button
                        type="button"
                        aria-label={`Remove ${word}`}
                        onClick={() =>
                          handleRemoveWord(
                            word
                          )
                        }
                        style={{
                          background:
                            "transparent",
                          border: "none",
                          cursor:
                            "pointer",
                          color:
                            "#ef4444",
                          fontWeight:
                            "bold",
                          fontSize:
                            "14px",
                          padding: 0,
                          lineHeight: 1,
                        }}
                      >
                        ×
                      </button>
                    </span>
                  )
                )
              )}
            </div>
          </div>

          {/* =================================================
              NOTIFICATIONS
              ================================================= */}

          <div
            style={{
              marginBottom: "24px",
              display: "flex",
              alignItems: "center",
              gap: "10px",
            }}
          >
            <input
              type="checkbox"
              id="notif"
              checked={
                notificationsEnabled
              }
              onChange={(event) => {
                setNotificationsEnabled(
                  event.target.checked
                );
                setSavedMessage(false);
              }}
              style={{
                width: "16px",
                height: "16px",
                cursor: "pointer",
                accentColor:
                  "#8c63d4",
              }}
            />

            <label
              htmlFor="notif"
              style={{
                color: "#2d2640",
                fontSize: "13px",
                cursor: "pointer",
                fontWeight: "500",
              }}
            >
              Send instant guardian
              warning notifications
              on high-risk detection
            </label>
          </div>

          {/* =================================================
              SAVE BUTTON
              ================================================= */}

          <button
            type="submit"
            disabled={saving}
            style={{
              background: saving
                ? "#9f83d2"
                : "linear-gradient(135deg, #8c63d4 0%, #6e44b8 100%)",
              color: "#fff",
              border: "none",
              padding:
                "12px 24px",
              borderRadius: "8px",
              fontWeight: "bold",
              fontSize: "14px",
              cursor: saving
                ? "not-allowed"
                : "pointer",
              boxShadow:
                "0 4px 15px rgba(140, 99, 212, 0.3)",
            }}
          >
            {saving
              ? "Saving..."
              : "Save Changes"}
          </button>
        </form>
      </div>
    </div>
  );
}