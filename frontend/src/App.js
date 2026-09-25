import React, {
  useState,
  useRef,
  useEffect,
  useCallback
} from "react";

import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

import "./App.css";
import ParentDashboard from "./ParentDashboard";
import Profile from "./Profile";


/* ==========================================================
   API CONFIGURATION
   ========================================================== */

const API_BASE_URL =
  "http://localhost:8000";


/* ==========================================================
   SUPPORTED IMAGE TYPES
   ========================================================== */

const ALLOWED_IMAGE_TYPES = new Set([
  "image/jpeg",
  "image/jpg",
  "image/png",
  "image/webp"
]);


/* ==========================================================
   APP
   ========================================================== */

function App() {

  // ========================================================
  // NAVIGATION TAB STATE
  // ========================================================

  const [activeTab, setActiveTab] =
    useState("chat");


  // ========================================================
  // PARENT AUTHENTICATION
  // ========================================================

  const [
    isAuthenticated,
    setIsAuthenticated
  ] = useState(
    sessionStorage.getItem(
      "parent_auth"
    ) === "true"
  );

  const [
    passwordInput,
    setPasswordInput
  ] = useState("");

  const [
    errorMsg,
    setErrorMsg
  ] = useState("");

  const [
    authLoading,
    setAuthLoading
  ] = useState(false);


  // ========================================================
  // CHAT STATE
  // ========================================================

  const [
    message,
    setMessage
  ] = useState("");

  const [
    selectedFile,
    setSelectedFile
  ] = useState(null);

  const [
    chatLog,
    setChatLog
  ] = useState([]);

  const [
    loading,
    setLoading
  ] = useState(false);


  // ========================================================
  // AGE GROUP
  // ========================================================

  const [ageGroup] =
    useState("general");


  // ========================================================
  // REFS
  // ========================================================

  const chatEndRef =
    useRef(null);

  const fileInputRef =
    useRef(null);


  // ========================================================
  // PARENT LOGIN
  // ========================================================

  const handleLogin = async (event) => {

    event.preventDefault();

    const password =
      passwordInput.trim();

    if (!password) {

      setErrorMsg(
        "Please enter your password."
      );

      return;
    }

    if (authLoading) {
      return;
    }

    try {

      setAuthLoading(true);
      setErrorMsg("");

      const response =
        await fetch(
          `${API_BASE_URL}/api/v1/profile/verify-password`,
          {
            method: "POST",

            headers: {
              "Content-Type":
                "application/json",

              Accept:
                "application/json"
            },

            body: JSON.stringify({
              password
            })
          }
        );

      let data = null;

      try {

        data =
          await response.json();

      } catch {

        data = null;

      }

      if (!response.ok) {

        setErrorMsg(
          data?.detail ||
          "Incorrect password."
        );

        return;
      }

      sessionStorage.setItem(
        "parent_auth",
        "true"
      );

      setIsAuthenticated(
        true
      );

      setPasswordInput("");
      setErrorMsg("");

    } catch (error) {

      console.error(
        "Parent authentication error:",
        error
      );

      setErrorMsg(
        "Cannot reach the backend server. Make sure FastAPI is running on port 8000."
      );

    } finally {

      setAuthLoading(false);

    }
  };


  // ========================================================
  // PASSWORD GATE
  // ========================================================

  const renderPasswordGate = () => (

    <div className="password-gate">

      <h2>
        Parent Access Required
      </h2>

      <p>
        Please enter your guardian password
        to view analytics and safety rules.
      </p>

      <form
        onSubmit={handleLogin}
        className="password-form"
      >

        <input
          type="password"
          placeholder="Enter password"
          value={passwordInput}
          onChange={(event) =>
            setPasswordInput(
              event.target.value
            )
          }
          disabled={authLoading}
          autoComplete="current-password"
        />

        <button
          type="submit"
          disabled={authLoading}
        >
          {authLoading
            ? "Verifying..."
            : "Unlock Dashboard"}
        </button>

        {errorMsg && (

          <span className="auth-error">
            {errorMsg}
          </span>

        )}

      </form>

    </div>

  );


  // ========================================================
  // AUTO SCROLL
  // ========================================================

  useEffect(() => {

    chatEndRef.current?.scrollIntoView({
      behavior: "smooth"
    });

  }, [
    chatLog,
    loading
  ]);


  // ========================================================
  // BUILD CONVERSATION CONTEXT
  // ========================================================

  const buildConversationContext =
    useCallback(() => {

      if (
        chatLog.length === 0
      ) {

        return "";

      }

      return chatLog
        .slice(-10)
        .map((chat) => {

          const speaker =
            chat.sender === "child"
              ? "User"
              : "Assistant";

          return `${speaker}: ${
            chat.text || ""
          }`;

        })
        .join("\n");

    }, [chatLog]);


  // ========================================================
  // SEND MESSAGE
  // ========================================================

  const sendMessage = async (
    event
  ) => {

    event.preventDefault();

    if (
      !message.trim() &&
      !selectedFile
    ) {

      return;

    }

    if (loading) {
      return;
    }


    // ======================================================
    // PRESERVE CURRENT VALUES
    // ======================================================

    const currentMessage =
      message.trim();

    const currentFile =
      selectedFile;


    // ======================================================
    // CREATE IMAGE PREVIEW
    // ======================================================

    const imagePreview =
      currentFile
        ? URL.createObjectURL(
            currentFile
          )
        : null;


    // ======================================================
    // BUILD PREVIOUS CONTEXT
    // ======================================================

    const previousContext =
      buildConversationContext();


    // ======================================================
    // ADD USER MESSAGE IMMEDIATELY
    // ======================================================

    setChatLog(
      (previous) => [

        ...previous,

        {
          sender: "child",

          text:
            currentMessage,

          image:
            imagePreview,

          fileName:
            currentFile
              ? currentFile.name
              : null
        }

      ]
    );


    // ======================================================
    // CLEAR INPUT
    // ======================================================

    setMessage("");
    setSelectedFile(null);

    if (fileInputRef.current) {

      fileInputRef.current.value =
        "";

    }

    setLoading(true);


    try {

      // ====================================================
      // BUILD FORM DATA
      // ====================================================

      const formData =
        new FormData();

      formData.append(
        "message",
        currentMessage
      );

      formData.append(
        "age_group",
        ageGroup
      );

      formData.append(
        "conversation_context",
        previousContext
      );

      if (currentFile) {

        formData.append(
          "file",
          currentFile,
          currentFile.name
        );

      }


      // ====================================================
      // API REQUEST
      // ====================================================

      const response =
        await fetch(
          `${API_BASE_URL}/api/v1/chat`,
          {
            method: "POST",
            body: formData
          }
        );


      // ====================================================
      // READ JSON RESPONSE
      // ====================================================

      let data = null;

      try {

        data =
          await response.json();

      } catch {

        throw new Error(
          "Backend returned an invalid response."
        );

      }


      // ====================================================
      // HTTP ERROR
      // ====================================================

      if (!response.ok) {

        throw new Error(
          data?.detail ||
          "Safety service request failed."
        );

      }


      // ====================================================
      // ADD ASSISTANT RESPONSE
      // ====================================================

      setChatLog(
        (previous) => [

          ...previous,

          {
            sender: "ai",

            text:
              data.response ||
              "I couldn't generate a response right now.",

            status:
              data.status ||
              "ALLOW",

            risk:
              typeof data.risk_score ===
              "number"
                ? data.risk_score
                : 0,

            warning:
              data.warning ||
              null,

            reason:
              data.reason ||
              null,

            emotion:
              data.emotion ||
              "neutral",

            emotionConfidence:
              typeof data.emotion_confidence ===
              "number"
                ? data.emotion_confidence
                : 0,

            emotionConfidenceLevel:
              data.emotion_confidence_level ||
              "UNKNOWN",

            pii:
              Array.isArray(
                data.pii_details
              )
                ? data.pii_details
                : [],

            imageRisk:
              typeof data.image_risk ===
              "number"
                ? data.image_risk
                : 0,

            imageTags:
              Array.isArray(
                data.image_tags
              )
                ? data.image_tags
                : [],

            imageStatus:
              data.image_status ||
              "ALLOW",

            imageCategory:
              data.image_category ||
              "not_analyzed",

            imagePiiDetected:
              Boolean(
                data.image_pii_detected
              ),

            imagePii:
              Array.isArray(
                data.image_pii
              )
                ? data.image_pii
                : [],

            llmCalled:
              Boolean(
                data.llm_called
              ),

            logId:
              data.log_id ||
              null
          }

        ]
      );

    } catch (error) {

      console.error(
        "SafeLayer service error:",
        error
      );

      setChatLog(
        (previous) => [

          ...previous,

          {
            sender: "ai",

            text:
              error?.message ||
              "I'm having trouble connecting to the safety service right now. Please try again later.",

            status:
              "ERROR",

            risk:
              null,

            emotion:
              "neutral",

            pii: [],

            imageRisk:
              0,

            imageTags: []

          }

        ]
      );

    } finally {

      setLoading(false);

    }
  };


  // ========================================================
  // STATUS CLASS
  // ========================================================

  const getStatusClass =
    (status) => {

      switch (
        String(status)
          .toUpperCase()
      ) {

        case "ALLOW":
          return "status-allow";

        case "WARN":
          return "status-warn";

        case "BLOCK":
        case "BLOCKED":
          return "status-block";

        case "ERROR":
          return "status-error";

        default:
          return "";

      }

    };


  // ========================================================
  // FILE SELECTION
  // ========================================================

  const handleFileChange =
    (event) => {

      const file =
        event.target.files?.[0];

      if (!file) {
        return;
      }


      // ====================================================
      // IMAGE TYPE CHECK
      // ====================================================

      if (
        !ALLOWED_IMAGE_TYPES.has(
          file.type
        )
      ) {

        alert(
          "Please select a JPG, PNG, or WEBP image."
        );

        event.target.value =
          "";

        return;

      }


      // ====================================================
      // IMAGE SIZE CHECK
      // ====================================================

      const maxSize =
        10 * 1024 * 1024;

      if (
        file.size >
        maxSize
      ) {

        alert(
          "Image is too large. Maximum size is 10 MB."
        );

        event.target.value =
          "";

        return;

      }


      setSelectedFile(
        file
      );

    };


  // ========================================================
  // REMOVE SELECTED FILE
  // ========================================================

  const removeSelectedFile =
    () => {

      setSelectedFile(
        null
      );

      if (
        fileInputRef.current
      ) {

        fileInputRef.current.value =
          "";

      }

    };


  // ========================================================
  // LOGOUT
  // ========================================================

  const handleLogout = () => {

    sessionStorage.removeItem(
      "parent_auth"
    );

    sessionStorage.removeItem(
      "parent_email"
    );

    setIsAuthenticated(
      false
    );

    setPasswordInput("");
    setErrorMsg("");

  };


  // ========================================================
  // RENDER
  // ========================================================

  return (

    <div className="app-container">

      {/* ==================================================
          NAVIGATION
          ================================================== */}

      <nav>

        <h3>
          SafeLayer Platform
        </h3>

        <button
          type="button"
          onClick={() =>
            setActiveTab("chat")
          }
          className={
            activeTab === "chat"
              ? "nav-active"
              : ""
          }
        >
          Child Chat
        </button>

        <button
          type="button"
          onClick={() =>
            setActiveTab(
              "dashboard"
            )
          }
          className={
            activeTab ===
            "dashboard"
              ? "nav-active"
              : ""
          }
        >
          Parent Dashboard
        </button>

        <button
          type="button"
          onClick={() =>
            setActiveTab(
              "profile"
            )
          }
          className={
            activeTab ===
            "profile"
              ? "nav-active"
              : ""
          }
        >
          Profile
        </button>

        {isAuthenticated && (

          <button
            type="button"
            onClick={handleLogout}
            className="nav-logout"
          >
            Logout
          </button>

        )}

      </nav>


      {/* ==================================================
          PARENT DASHBOARD
          ================================================== */}

      {activeTab ===
      "dashboard" ? (

        isAuthenticated
          ? (
            <ParentDashboard />
          )
          : (
            renderPasswordGate()
          )

      ) : activeTab ===
        "profile" ? (

        isAuthenticated
          ? (
            <Profile />
          )
          : (
            renderPasswordGate()
          )

      ) : (

        <>
          {/* ================================================
              HEADER
              ================================================= */}

          <header className="app-header">

            <h2>
              SafeLayer
            </h2>

            <p>
              A universal safety layer
              for secure AI interactions.
            </p>

          </header>


          {/* ================================================
              CHAT WINDOW
              ================================================= */}

          <main
            className="chat-window"
          >

            {chatLog.length ===
              0 && (

              <div className="welcome-message">

                <h3>
                  Welcome to SafeLayer
                </h3>

                <p>
                  Ask questions, explore
                  ideas, learn, or get help
                  with everyday tasks.
                </p>

              </div>

            )}


            {chatLog.map(
              (chat, index) => (

              <div
                key={index}
                className={`message ${chat.sender}`}
              >

                {/* =========================================
                    SENDER
                    ========================================= */}

                <strong className="message-sender">

                  {chat.sender ===
                  "child"
                    ? "You"
                    : "Assistant"}

                  :

                </strong>


                {/* =========================================
                    USER MESSAGE
                    ========================================= */}

                {chat.sender ===
                  "child" &&
                  chat.text && (

                  <p className="message-text">
                    {chat.text}
                  </p>

                )}


                {/* =========================================
                    ASSISTANT MARKDOWN
                    ========================================= */}

                {chat.sender ===
                  "ai" &&
                  chat.text && (

                  <div className="markdown-response">

                    <ReactMarkdown
                      remarkPlugins={[
                        remarkGfm
                      ]}
                      components={{
                        a: ({
                          children,
                          ...props
                        }) => (

                          <a
                            {...props}
                            target="_blank"
                            rel="noopener noreferrer"
                          >
                            {children}
                          </a>

                        )
                      }}
                    >
                      {chat.text}
                    </ReactMarkdown>

                  </div>

                )}


                {/* =========================================
                    UPLOADED IMAGE
                    ========================================= */}

                {chat.image && (

                  <img
                    src={chat.image}
                    alt="Uploaded by user"
                    className="uploaded-image"
                  />

                )}


                {/* =========================================
                    FILE NAME
                    ========================================= */}

                {chat.fileName && (

                  <div className="file-name">

                    📎 {chat.fileName}

                  </div>

                )}


                {/* =========================================
                    SAFETY METADATA
                    ========================================= */}

                {chat.sender ===
                  "ai" && (

                  <div className="safety-meta">

                    <div className="safety-top-row">

                      {chat.status && (

                        <span
                          className={
                            getStatusClass(
                              chat.status
                            )
                          }
                        >

                          Status:{" "}
                          {chat.status}

                          {chat.risk !==
                            null &&
                            ` | Risk: ${chat.risk}`}

                        </span>

                      )}


                      {chat.emotion && (

                        <span className="emotion-badge">

                          🧠 Emotion:{" "}

                          <strong>
                            {chat.emotion}
                          </strong>

                        </span>

                      )}

                    </div>





                    {/* =====================================
                        IMAGE RISK
                        ===================================== */}

                    {chat.imageRisk >
                      0 && (

                      <div className="image-risk">

                        🖼️ Image Risk Score:{" "}

                        {chat.imageRisk}

                      </div>

                    )}


                    {/* =====================================
                        IMAGE STATUS
                        ===================================== */}

                    {chat.imageStatus &&
                      chat.imageStatus !==
                        "ALLOW" && (

                      <div className="metadata-detail">

                        Image status:{" "}

                        <strong>
                          {
                            chat.imageStatus
                          }
                        </strong>

                      </div>

                    )}


                    {/* =====================================
                        WARNING
                        ===================================== */}

                    {chat.warning && (

                      <div className="warning-message">

                        ⚠️{" "}
                        {chat.warning}

                      </div>

                    )}


                    {/* =====================================
                        SAFETY REASON
                        ===================================== */}

                    {chat.reason &&
                      chat.status !==
                        "ALLOW" && (

                      <div className="reason-message">

                        <strong>
                          Safety reason:
                        </strong>{" "}

                        {chat.reason}

                      </div>

                    )}


                    {/* =====================================
                        TEXT PII
                        ===================================== */}

                    {chat.pii &&
                      chat.pii.length > 0 && (

                      <div className="pii-warning">

                        <strong>
                          ⚠️ Sensitive information detected
                        </strong>

                        <ul>

                          {chat.pii.map(
                            (
                              item,
                              piiIndex
                            ) => (

                              <li
                                key={
                                  piiIndex
                                }
                              >

                                {item.type ||
                                  "Sensitive information"}

                              </li>

                            )
                          )}

                        </ul>

                      </div>

                    )}


                    {/* =====================================
                        IMAGE PII
                        ===================================== */}

                    {chat.imagePiiDetected &&
                      chat.imagePii &&
                      chat.imagePii.length >
                        0 && (

                      <div className="pii-warning image-pii-warning">

                        <strong>
                          🖼️ Sensitive information
                          detected in image
                        </strong>

                        <ul>

                          {chat.imagePii.map(
                            (
                              item,
                              piiIndex
                            ) => (

                              <li
                                key={
                                  piiIndex
                                }
                              >

                                {item.type ||
                                  "Sensitive image information"}

                              </li>

                            )
                          )}

                        </ul>

                      </div>

                    )}


                    {/* =====================================
                        EXTERNAL AI STATUS
                        ===================================== */}

                    {chat.status !==
                      "ERROR" &&
                      typeof chat.llmCalled ===
                        "boolean" && (

                      <div className="metadata-detail">

                        External AI response:{" "}

                        {chat.llmCalled
                          ? "Processed"
                          : "Not called"}

                      </div>

                    )}

                  </div>

                )}

              </div>

            ) )}


            {/* ==============================================
                LOADING
                ============================================== */}

            {loading && (

              <div className="loading-indicator">

                <span className="loading-dot">
                  ●
                </span>

                Safety Layer is analyzing
                your message...

              </div>

            )}


            <div
              ref={chatEndRef}
            />

          </main>


          {/* =================================================
              INPUT AREA
              ================================================= */}

          <footer className="input-area">

            <input
              ref={fileInputRef}
              id="file-upload"
              type="file"
              accept=".jpg,.jpeg,.png,.webp,image/jpeg,image/png,image/webp"
              onChange={
                handleFileChange
              }
              disabled={loading}
              className="hidden-file-input"
            />


            <label
              htmlFor="file-upload"
              className="attach-button"
            >

              📷{" "}

              {selectedFile
                ? "Image selected"
                : "Attach Image"}

            </label>


            {selectedFile && (

              <button
                type="button"
                className="remove-file-button"
                onClick={
                  removeSelectedFile
                }
                disabled={loading}
                aria-label="Remove selected image"
              >
                ×
              </button>

            )}


            <form
              className="message-form"
              onSubmit={
                sendMessage
              }
            >

              <input
                type="text"
                value={message}
                onChange={(
                  event
                ) =>
                  setMessage(
                    event.target.value
                  )
                }
                placeholder="Ask me anything..."
                disabled={loading}
                autoComplete="off"
              />


              <button
                type="submit"
                className="send-btn"
                disabled={
                  loading ||
                  (
                    !message.trim() &&
                    !selectedFile
                  )
                }
              >

                {loading
                  ? "..."
                  : "Send"}

              </button>

            </form>

          </footer>

        </>

      )}

    </div>
  );
}


export default App;