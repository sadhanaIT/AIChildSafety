import React, { useState } from 'react';
import './App.css';

function App() {
  const [inputMessage, setInputMessage] = useState('');
  const [chatHistory, setChatHistory] = useState([]);
  const [loading, setLoading] = useState(false);

  const handleSendMessage = async () => {
    if (!inputMessage.trim()) return;

    const userMsg = { sender: 'child', text: inputMessage };
    setChatHistory((prev) => [...prev, userMsg]);
    setLoading(true);

    try {
      // API call connecting directly to FastAPI Safety Middleware
      const response = await fetch('http://localhost:8000/api/v1/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          child_id: 'child_user_01',
          message: inputMessage,
          target_llm: 'chatgpt',
        }),
      });

      const data = await response.json();

      const systemMsg = {
        sender: 'ai',
        text: data.response,
        decision: data.decision,
        riskScore: data.risk_score,
      };

      setChatHistory((prev) => [...prev, systemMsg]);
    } catch (error) {
      console.error('Error connecting to Safety Backend:', error);
    } finally {
      setInputMessage('');
      setLoading(false);
    }
  };

  return (
    <div className="chat-container">
      <h2>Child AI Companion (Safety Monitored)</h2>
      <div className="chat-box">
        {chatHistory.map((msg, index) => (
          <div key={index} className={`message ${msg.sender}`}>
            <p>{msg.text}</p>
            {msg.decision && (
              <span className={`badge ${msg.decision.toLowerCase()}`}>
                Status: {msg.decision} | Risk: {msg.riskScore}
              </span>
            )}
          </div>
        ))}
        {loading && <p>Safety Engine inspecting message...</p>}
      </div>
      <div className="input-box">
        <input
          type="text"
          value={inputMessage}
          onChange={(e) => setInputMessage(e.target.value)}
          placeholder="Ask AI anything..."
          onKeyPress={(e) => e.key === 'Enter' && handleSendMessage()}
        />
        <button onClick={handleSendMessage}>Send</button>
      </div>
    </div>
  );
}

export default App;