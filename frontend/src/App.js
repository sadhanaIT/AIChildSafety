import React, { useState, useRef, useEffect } from 'react';
import './App.css';

function App() {
  const [message, setMessage] = useState('');
  const [selectedFile, setSelectedFile] = useState(null);
  const [chatLog, setChatLog] = useState([]);
  const [loading, setLoading] = useState(false);
  const chatEndRef = useRef(null);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [chatLog]);

  const sendMessage = async (e) => {
    e.preventDefault();
    if (!message.trim() && !selectedFile) return;

    const userMessage = message;
    const currentFile = selectedFile;

    setMessage('');
    setSelectedFile(null);

    // Add child message/image to log immediately
    setChatLog(prev => [...prev, {
      sender: 'child',
      text: userMessage,
      image: currentFile ? URL.createObjectURL(currentFile) : null
    }]);
    setLoading(true);

    try {
      const formData = new FormData();
      formData.append('message', userMessage);
      formData.append('age_group', 'pre_teen');
      if (currentFile) {
        formData.append('file', currentFile);
      }

      const response = await fetch('http://127.0.0.1:8000/api/v1/chat', {
        method: 'POST',
        body: formData // Sending FormData for multipart file upload
      });

      const data = await response.json();

      setChatLog(prev => [
        ...prev,
        {
          sender: 'ai',
          text: data.response,
          status: data.status,
          risk: data.risk_score,
          warning: data.warning,
          emotion: data.emotion,
          pii: data.pii_details || [],
          imageRisk: data.image_risk
        }
      ]);
    } catch (error) {
      console.error('Error connecting to safety backend:', error);
      setChatLog(prev => [...prev, { sender: 'ai', text: 'Oops! I seem to be disconnected from my safety sensors.' }]);
    } finally {
      setLoading(false);
    }
  };

  const getStatusClass = (status) => {
    switch (status) {
      case 'ALLOW': return 'status-allow';
      case 'WARN': return 'status-warn';
      case 'BLOCK': return 'status-block';
      default: return '';
    }
  };

  return (
    <div className="app-container">
      <header>
        <h2>KiddieSafe AI</h2>
        <p>Your friendly, monitored AI companion with Multimodal Safety.</p>
      </header>

      <main className="chat-window">
        {chatLog.map((chat, index) => (
          <div key={index} className={`message ${chat.sender}`}>
            <strong>{chat.sender === 'child' ? 'You' : 'KiddieSafe AI'}:</strong>
            {chat.text && <p>{chat.text}</p>}
            {chat.image && <img src={chat.image} alt="Uploaded by child" style={{ maxWidth: '200px', borderRadius: '10px', marginTop: '5px' }} />}

            {chat.sender === 'ai' && (chat.status || chat.emotion) && (
              <div className="safety-meta">
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                  <span className={getStatusClass(chat.status)}>
                    Status: {chat.status} | Risk: {chat.risk}
                  </span>
                  <span style={{ background: '#e0e7ff', color: '#3730a3', padding: '2px 6px', borderRadius: '4px', fontSize: '0.85em' }}>
                    🧠 Emotion: <strong>{chat.emotion || 'neutral'}</strong>
                  </span>
                </div>
                {chat.imageRisk > 0 && <p style={{ fontSize: '0.85em', color: '#475569' }}>🖼️ Image Risk Score: {chat.imageRisk}</p>}
                {chat.warning && <p style={{ color: '#ca8a04', margin: '5px 0 0' }}>⚠️ {chat.warning}</p>}

                {chat.pii && chat.pii.length > 0 && (
                  <div className="pii-badge">
                    <strong>⚠️ Sensitive Info Detected:</strong>
                    <ul style={{ margin: '5px 0 0', paddingLeft: '15px' }}>
                      {chat.pii.map((item, i) => (
                        <li key={i}>{item.text} ({item.type})</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
        {loading && <div className="loading-indicator">Safety Engine is analyzing message and image...</div>}
        <div ref={chatEndRef} />
      </main>

      <footer className="input-area">
        <input
          type="file"
          accept="image/*"
          onChange={(e) => setSelectedFile(e.target.files[0])}
          style={{ display: 'none' }}
          id="file-upload"
        />
        <label htmlFor="file-upload" style={{ cursor: 'pointer', background: '#e2e8f0', padding: '10px 15px', borderRadius: '20px', fontSize: '0.9em' }}>
          📷 {selectedFile ? selectedFile.name : 'Attach Image'}
        </label>

        <input
          type="text"
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          placeholder="Ask me about animals, space, or upload a picture!"
          disabled={loading}
        />
        <button type="submit" className="send-btn" onClick={sendMessage} disabled={loading || (!message.trim() && !selectedFile)}>
          Send
        </button>
      </footer>
    </div>
  );
}

export default App;