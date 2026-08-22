import React, { useState, useRef, useEffect } from 'react';
import './App.css';

function App() {
  const [message, setMessage] = useState('');
  const [chatLog, setChatLog] = useState([]);
  const [loading, setLoading] = useState(false);
  const chatEndRef = useRef(null);

  // Auto-scroll to bottom whenever chatLog updates
  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [chatLog]);

  const sendMessage = async (e) => {
    e.preventDefault();
    if (!message.trim()) return;

    const userMessage = message;
    setMessage('');
    // Add child message immediately
    setChatLog(prev => [...prev, { sender: 'child', text: userMessage }]);
    setLoading(true);

    try {
      const response = await fetch('http://127.0.0.1:8000/api/v1/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: userMessage, age_group: 'pre_teen' })
      });

      const data = await response.json();

      // Add AI response and safety data safely with fallback array
      setChatLog(prev => [
        ...prev,
        {
          sender: 'ai',
          text: data.response,
          status: data.status,
          risk: data.risk_score,
          warning: data.warning,
          pii: data.pii_details || []
        }
      ]);
    } catch (error) {
      console.error('Error connecting to safety backend:', error);
      setChatLog(prev => [...prev, { sender: 'ai', text: 'Oops! I seem to be disconnected from my safety sensors.' }]);
    } finally {
      setLoading(false);
    }
  };

  // Helper to determine CSS class based on status
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
        <p>Your friendly, monitored AI companion.</p>
      </header>

      <main className="chat-window">
        {chatLog.map((chat, index) => (
          <div key={index} className={`message ${chat.sender}`}>
            <strong>{chat.sender === 'child' ? 'You' : 'KiddieSafe AI'}:</strong>
            <p>{chat.text}</p>

            {/* Safety Meta Information Card with Safe Optional Chaining */}
            {chat.sender === 'ai' && (chat.status || (chat.pii && chat.pii.length > 0)) && (
              <div className="safety-meta">
                <span className={getStatusClass(chat.status)}>
                  Status: {chat.status} | Risk: {chat.risk}
                </span>
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
        {loading && <div className="loading-indicator">KiddieSafe is thinking...</div>}
        <div ref={chatEndRef} />
      </main>

      <footer className="input-area">
        <input
          type="text"
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          placeholder="Ask me about animals, space, or stories!"
          disabled={loading}
        />
        <button type="submit" className="send-btn" onClick={sendMessage} disabled={loading || !message.trim()}>
          Send
        </button>
      </footer>
    </div>
  );
}

export default App;