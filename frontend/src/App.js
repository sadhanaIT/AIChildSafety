import React, {
  useState,
  useRef,
  useEffect
} from "react";

import "./App.css";
import ParentDashboard from "./ParentDashboard";
import Profile from "./Profile";


function App() {

  // ==========================================================
  // NAVIGATION TAB STATE
  // ==========================================================
  const [activeTab, setActiveTab] = useState("chat");

  // ==========================================================
  // STATE
  // ==========================================================

  const [message, setMessage] = useState("");

  const [selectedFile, setSelectedFile] =
    useState(null);

  const [chatLog, setChatLog] =
    useState([]);

  const [loading, setLoading] =
    useState(false);

  // General-purpose platform
  const [ageGroup] =
    useState("general");

  const chatEndRef =
    useRef(null);


  // ==========================================================
  // AUTO SCROLL
  // ==========================================================

  useEffect(() => {

    chatEndRef.current?.scrollIntoView({
      behavior: "smooth"
    });

  }, [chatLog, loading]);


  // ==========================================================
  // BUILD CONVERSATION CONTEXT
  // ==========================================================

  const buildConversationContext = () => {

    if (chatLog.length === 0) {
      return "";
    }

    return chatLog
      .slice(-10)
      .map((chat) => {

        const speaker =
          chat.sender === "child"
            ? "User"
            : "Assistant";

        return `${speaker}: ${chat.text || ""}`;

      })
      .join("\n");
  };


  // ==========================================================
  // SEND MESSAGE
  // ==========================================================

  const sendMessage = async (event) => {

    event.preventDefault();

    // ----------------------------------------------
    // Prevent empty requests
    // ----------------------------------------------

    if (
      !message.trim() &&
      !selectedFile
    ) {
      return;
    }

    if (loading) {
      return;
    }

    // ----------------------------------------------
    // Preserve current values
    // ----------------------------------------------

    const currentMessage =
      message.trim();

    const currentFile =
      selectedFile;

    // ----------------------------------------------
    // Create local image preview
    // ----------------------------------------------

    const imagePreview =
      currentFile
        ? URL.createObjectURL(currentFile)
        : null;

    // ----------------------------------------------
    // Build context BEFORE adding current message
    // ----------------------------------------------

    const previousContext =
      buildConversationContext();

    // ----------------------------------------------
    // Add user message immediately
    //
    // "child" is intentionally retained as the
    // internal CSS class for compatibility with
    // the existing App.css.
    // ----------------------------------------------

    setChatLog((previous) => [

      ...previous,

      {
        sender: "child",

        text: currentMessage,

        image: imagePreview,

        fileName:
          currentFile
            ? currentFile.name
            : null
      }

    ]);

    // ----------------------------------------------
    // Clear input
    // ----------------------------------------------

    setMessage("");

    setSelectedFile(null);

    setLoading(true);


    try {

      // ==================================================
      // FORM DATA
      // ==================================================

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
          currentFile
        );

      }


      // ==================================================
      // API REQUEST
      // ==================================================

      const response =
        await fetch(
          "http://127.0.0.1:8000/api/v1/chat",
          {
            method: "POST",
            body: formData
          }
        );


      // ==================================================
      // READ RESPONSE
      // ==================================================

      let data;

      try {

        data =
          await response.json();

      } catch (jsonError) {

        throw new Error(
          "Backend returned an invalid response."
        );

      }


      // ==================================================
      // HTTP ERROR
      // ==================================================

      if (!response.ok) {

        throw new Error(
          data?.detail ||
          "Safety service request failed."
        );

      }


      // ==================================================
      // ASSISTANT RESPONSE
      // ==================================================

      setChatLog((previous) => [

        ...previous,

        {
          sender: "ai",

          text:
            data.response ||
            "I couldn't generate a response right now.",

          status:
            data.status || "ALLOW",

          risk:
            typeof data.risk_score === "number"
              ? data.risk_score
              : 0,

          warning:
            data.warning || null,

          emotion:
            data.emotion || "neutral",

          pii:
            Array.isArray(data.pii_details)
              ? data.pii_details
              : [],

          imageRisk:
            typeof data.image_risk === "number"
              ? data.image_risk
              : 0,

          imageTags:
            Array.isArray(data.image_tags)
              ? data.image_tags
              : [],

          logId:
            data.log_id || null
        }

      ]);

    } catch (error) {

      console.error(
        "SafeLayer service error:",
        error
      );


      // ==================================================
      // SHOW ERROR IN CHAT
      // ==================================================

      setChatLog((previous) => [

        ...previous,

        {
          sender: "ai",

          text:
            "I'm having trouble connecting to the safety service right now. Please try again later.",

          status: "ERROR",

          risk: null,

          emotion: "neutral",

          pii: [],

          imageRisk: 0
        }

      ]);

    } finally {

      setLoading(false);

    }
  };


  // ==========================================================
  // STATUS CLASS
  // ==========================================================

  const getStatusClass = (status) => {

    switch (status) {

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


  // ==========================================================
  // HANDLE FILE
  // ==========================================================

  const handleFileChange = (event) => {

    const file =
      event.target.files?.[0];

    if (!file) {
      return;
    }

    if (!file.type.startsWith("image/")) {

      alert(
        "Please select an image file."
      );

      event.target.value = "";

      return;
    }

    setSelectedFile(file);

  };


  // ==========================================================
  // REMOVE SELECTED FILE
  // ==========================================================

  const removeSelectedFile = () => {

    setSelectedFile(null);

  };


  // ==========================================================
  // RENDER
  // ==========================================================

  return (

    <div className="app-container">

      {/* ====================================================
          TOP NAVIGATION TABS
      ==================================================== */}
      <nav style={{ background: '#1a1a1a', padding: '12px 25px', display: 'flex', gap: '15px', alignItems: 'center', borderBottom: '1px solid #333' }}>
        <h3 style={{ color: '#fff', margin: 0, marginRight: '15px', fontSize: '16px' }}>SafeLayer Platform</h3>
        <button
          onClick={() => setActiveTab('chat')}
          style={{
            background: activeTab === 'chat' ? '#007bff' : 'transparent',
            color: '#fff',
            border: 'none',
            padding: '6px 14px',
            borderRadius: '6px',
            cursor: 'pointer',
            fontWeight: '600'
          }}
        >
          Child Chat
        </button>
        <button
          onClick={() => setActiveTab('dashboard')}
          style={{
            background: activeTab === 'dashboard' ? '#007bff' : 'transparent',
            color: '#fff',
            border: 'none',
            padding: '6px 14px',
            borderRadius: '6px',
            cursor: 'pointer',
            fontWeight: '600'
          }}
        >
          Parent Dashboard
        </button>
        <button
          onClick={() => setActiveTab('profile')}
          style={{
            background: activeTab === 'profile' ? '#007bff' : 'transparent',
            color: '#fff',
            border: 'none',
            padding: '6px 14px',
            borderRadius: '6px',
            cursor: 'pointer',
            fontWeight: '600'
          }}
        >
          Profile
        </button>
      </nav>

      {activeTab === 'dashboard' ? (
        <ParentDashboard />
      ) : activeTab === 'profile' ? (
        <Profile />
      ) : (
        <>
          {/* ====================================================
              HEADER
          ==================================================== */}

          <header className="app-header">

            <h2>
              SafeLayer
            </h2>

            <p>
              A universal safety layer for secure AI interactions.
            </p>

          </header>


          {/* ====================================================
              CHAT
          ==================================================== */}

          <main className="chat-window">

            {chatLog.length === 0 && (

              <div className="welcome-message">

                <h3>
                  Welcome to SafeLayer
                </h3>

                <p>
                  Ask questions, explore ideas, learn,
                  or get help with everyday tasks.
                </p>

              </div>

            )}


            {chatLog.map((chat, index) => (

              <div
                key={index}
                className={`message ${chat.sender}`}
              >

                <strong>
                  {chat.sender === "child"
                    ? "You"
                    : "Assistant"}
                  :
                </strong>


                {/* ==============================================
                    TEXT
                ============================================== */}

                {chat.text && (

                  <p className="message-text">
                    {chat.text}
                  </p>

                )}


                {/* ==============================================
                    IMAGE
                ============================================== */}

                {chat.image && (

                  <img
                    src={chat.image}
                    alt="Uploaded by user"
                    className="uploaded-image"
                  />

                )}


                {/* ==============================================
                    FILE NAME
                ============================================== */}

                {chat.fileName && (

                  <div className="file-name">
                    📎 {chat.fileName}
                  </div>

                )}


                {/* ==============================================
                    SAFETY INFORMATION
                ============================================== */}

                {chat.sender === "ai" && (

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

                          Status: {chat.status}

                          {chat.risk !== null &&
                            ` | Risk: ${chat.risk}`}

                        </span>

                      )}


                      {chat.emotion && (

                        <span className="emotion-badge">

                          🧠 Emotion:

                          <strong>
                            {chat.emotion}
                          </strong>

                        </span>

                      )}

                    </div>


                    {/* ==========================================
                        IMAGE RISK
                    ========================================== */}

                    {chat.imageRisk > 0 && (

                      <div className="image-risk">

                        🖼️ Image Risk Score:

                        {" "}

                        {chat.imageRisk}

                      </div>

                    )}


                    {/* ==========================================
                        WARNING
                    ========================================== */}

                    {chat.warning && (

                      <div className="warning-message">

                        ⚠️ {chat.warning}

                      </div>

                    )}


                    {/* ==========================================
                        PII
                    ========================================== */}

                    {chat.pii &&
                      chat.pii.length > 0 && (

                        <div className="pii-warning">

                          <strong>
                            ⚠️ Sensitive information detected
                          </strong>

                          <ul>

                            {chat.pii.map(
                              (item, piiIndex) => (

                                <li key={piiIndex}>

                                  {item.type ||
                                    "Sensitive information"}

                                </li>

                              )
                            )}

                          </ul>

                        </div>

                      )}

                  </div>

                )}

              </div>

            ))}


            {/* ==================================================
                LOADING
            ================================================== */}

            {loading && (

              <div className="loading-indicator">

                <span className="loading-dot">
                  ●
                </span>

                Safety Layer is analyzing your
                message...

              </div>

            )}


            <div ref={chatEndRef} />

          </main>


          {/* ====================================================
              INPUT AREA
          ==================================================== */}

          <footer className="input-area">

            <input
              id="file-upload"
              type="file"
              accept="image/*"
              onChange={handleFileChange}
              disabled={loading}
              className="hidden-file-input"
            />


            <label
              htmlFor="file-upload"
              className="attach-button"
            >

              📷

              {selectedFile
                ? " Image selected"
                : " Attach Image"}

            </label>


            {selectedFile && (

              <button
                type="button"
                className="remove-file-button"
                onClick={removeSelectedFile}
                disabled={loading}
              >
                ×
              </button>

            )}


            <form
              className="message-form"
              onSubmit={sendMessage}
            >

              <input
                type="text"
                value={message}
                onChange={(event) =>
                  setMessage(event.target.value)
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