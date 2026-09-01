import React, { useState, useEffect } from 'react';

export default function Profile() {
  const [profileName, setProfileName] = useState('Child Companion Profile');
  const [sensitivity, setSensitivity] = useState('High (Strict PII & Toxicity Block)');
  const [notificationsEnabled, setNotificationsEnabled] = useState(true);
  const [isBrowserLocked, setIsBrowserLocked] = useState(true);

  const [restrictedWords, setRestrictedWords] = useState([]);
  const [newWord, setNewWord] = useState('');
  const [savedMessage, setSavedMessage] = useState(false);
  const [actionMessage, setActionMessage] = useState('');

  // Fetch rules and profile settings from backend on load
  useEffect(() => {
    fetch('http://localhost:8000/api/v1/profile/rules')
      .then(res => res.json())
      .then(data => {
        if (data.keywords) {
          setRestrictedWords(data.keywords);
        }
        if (data.profile_name) setProfileName(data.profile_name);
        if (data.sensitivity) setSensitivity(data.sensitivity);
        if (data.notifications_enabled !== undefined) setNotificationsEnabled(data.notifications_enabled);
      })
      .catch(err => console.log("Failed to load custom rules", err));
  }, []);

  const handleAddWord = (e) => {
    e.preventDefault();
    if (newWord.trim() && !restrictedWords.includes(newWord.trim().toLowerCase())) {
      setRestrictedWords([...restrictedWords, newWord.trim().toLowerCase()]);
      setNewWord('');
    }
  };

  const handleRemoveWord = (wordToRemove) => {
    setRestrictedWords(restrictedWords.filter(word => word !== wordToRemove));
  };

  const handleToggleBrowserLock = async (lockState) => {
    const endpoint = lockState ? 'enforce-browser-locks' : 'unlock-browser-locks';
    try {
      const res = await fetch(`http://localhost:8000/api/v1/profile/${endpoint}`, {
        method: 'POST'
      });
      const data = await res.json();
      setIsBrowserLocked(lockState);
      setActionMessage(data.message);
      setTimeout(() => setActionMessage(''), 4000);
    } catch (err) {
      setActionMessage("Error communicating with backend.");
      setTimeout(() => setActionMessage(''), 4000);
    }
  };

  const handleSave = async (e) => {
    e.preventDefault();
    try {
      await fetch('http://localhost:8000/api/v1/profile/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          profile_name: profileName,
          sensitivity: sensitivity,
          notifications_enabled: notificationsEnabled,
          keywords: restrictedWords
        })
      });
      setSavedMessage(true);
      setTimeout(() => setSavedMessage(false), 3000);
    } catch (err) {
      console.error("Failed to save profile configuration", err);
    }
  };

  return (
    <div style={{ padding: '20px 30px', fontFamily: 'Inter, sans-serif', background: '#f8f9fa', boxSizing: 'border-box' }}>
      <div style={{ maxWidth: '750px', margin: '0 auto' }}>

        <h1 style={{ color: '#1a1a1a', marginBottom: '4px', fontSize: '22px' }}>User & Device Profile</h1>
        <p style={{ color: '#666', marginBottom: '20px', fontSize: '13px' }}>
          Configure child safety thresholds, emergency settings, and custom restricted topic filters.
        </p>

        {savedMessage && (
          <div style={{ background: '#d4edda', color: '#155724', padding: '10px 16px', borderRadius: '6px', marginBottom: '15px', border: '1px solid #c3e6cb', fontWeight: '500', fontSize: '13px' }}>
            ✓ Profile settings and filters synced with backend successfully!
          </div>
        )}

        {actionMessage && (
          <div style={{ background: '#e2e3e5', color: '#383d41', padding: '10px 16px', borderRadius: '6px', marginBottom: '15px', border: '1px solid #d6d8db', fontWeight: '500', fontSize: '13px' }}>
            ℹ️ {actionMessage}
          </div>
        )}

        <div style={{ background: '#fff', padding: '16px 20px', borderRadius: '10px', boxShadow: '0 2px 8px rgba(0,0,0,0.04)', marginBottom: '20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <h4 style={{ margin: '0 0 4px 0', color: '#333', fontSize: '14px' }}>System Browser Safety Locks</h4>
            <p style={{ margin: 0, color: '#666', fontSize: '12px' }}>Enforce strict SafeSearch and YouTube Restricted Mode.</p>
          </div>
          <button
            type="button"
            onClick={() => handleToggleBrowserLock(!isBrowserLocked)}
            style={{
              background: isBrowserLocked ? '#dc3545' : '#28a745',
              color: '#fff', border: 'none', padding: '8px 14px', borderRadius: '6px', fontWeight: 'bold', fontSize: '12px', cursor: 'pointer'
            }}
          >
            {isBrowserLocked ? '🔓 Unlock Browser' : '🔒 Lock Browser'}
          </button>
        </div>

        <form onSubmit={handleSave} style={{ background: '#fff', padding: '24px', borderRadius: '10px', boxShadow: '0 2px 8px rgba(0,0,0,0.04)' }}>

          <h3 style={{ marginTop: '0', color: '#333', borderBottom: '1px solid #eee', paddingBottom: '10px', marginBottom: '16px', fontSize: '16px' }}>
            Guardian & Safety Configuration
          </h3>

          <div style={{ marginBottom: '16px' }}>
            <label style={{ display: 'block', fontWeight: '600', color: '#444', marginBottom: '6px', fontSize: '13px' }}>Profile Name</label>
            <input
              type="text"
              value={profileName}
              onChange={(e) => setProfileName(e.target.value)}
              style={{ width: '100%', padding: '9px 12px', borderRadius: '6px', border: '1px solid #ccc', fontSize: '13px', boxSizing: 'border-box' }}
            />
          </div>

          <div style={{ marginBottom: '16px' }}>
            <label style={{ display: 'block', fontWeight: '600', color: '#444', marginBottom: '6px', fontSize: '13px' }}>Safety Sensitivity Level</label>
            <select
              value={sensitivity}
              onChange={(e) => setSensitivity(e.target.value)}
              style={{ width: '100%', padding: '9px 12px', borderRadius: '6px', border: '1px solid #ccc', fontSize: '13px', background: '#fff', boxSizing: 'border-box' }}
            >
              <option>High (Strict PII & Toxicity Block)</option>
              <option>Medium (Balanced Protection)</option>
              <option>Low (Minimal Filtering)</option>
            </select>
          </div>

          <div style={{ marginBottom: '18px', background: '#fdfdfe', padding: '14px', borderRadius: '6px', border: '1px solid #eaeaea' }}>
            <label style={{ display: 'block', fontWeight: '600', color: '#333', marginBottom: '4px', fontSize: '13px' }}>
              Custom Blocked Keywords & Topics
            </label>
            <p style={{ color: '#666', fontSize: '12px', marginBottom: '10px', marginTop: '0' }}>
              These terms are saved to the backend database and will instantly block matching chat inputs.
            </p>

            <div style={{ display: 'flex', gap: '8px', marginBottom: '10px' }}>
              <input
                type="text"
                value={newWord}
                onChange={(e) => setNewWord(e.target.value)}
                placeholder="e.g. bullying, secrets"
                style={{ flex: 1, padding: '7px 10px', borderRadius: '6px', border: '1px solid #ccc', fontSize: '12px' }}
              />
              <button
                type="button"
                onClick={handleAddWord}
                style={{ background: '#28a745', color: '#fff', border: 'none', padding: '7px 14px', borderRadius: '6px', fontWeight: '600', fontSize: '12px', cursor: 'pointer' }}
              >
                Add Rule
              </button>
            </div>

            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
              {restrictedWords.map((word, idx) => (
                <span key={idx} style={{ background: '#e9ecef', color: '#333', padding: '3px 8px', borderRadius: '15px', fontSize: '12px', display: 'flex', alignItems: 'center', gap: '5px', border: '1px solid #dee2e6' }}>
                  {word}
                  <button
                    type="button"
                    onClick={() => handleRemoveWord(word)}
                    style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: '#dc3545', fontWeight: 'bold', fontSize: '13px', padding: 0 }}
                  >
                    ×
                  </button>
                </span>
              ))}
            </div>
          </div>

          <div style={{ marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <input
              type="checkbox"
              id="notif"
              checked={notificationsEnabled}
              onChange={(e) => setNotificationsEnabled(e.target.checked)}
              style={{ width: '15px', height: '15px', cursor: 'pointer' }}
            />
            <label htmlFor="notif" style={{ color: '#444', fontSize: '13px', cursor: 'pointer', fontWeight: '500' }}>
              Send instant guardian warning notifications on high-risk detection
            </label>
          </div>

          <button
            type="submit"
            style={{ background: '#007bff', color: '#fff', border: 'none', padding: '9px 18px', borderRadius: '6px', fontWeight: 'bold', fontSize: '13px', cursor: 'pointer' }}
          >
            Save Changes
          </button>

        </form>
      </div>
    </div>
  );
}