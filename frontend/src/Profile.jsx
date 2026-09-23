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
    <div style={{ flex: 1, overflowY: 'auto', padding: '32px', background: 'linear-gradient(135deg, #fdfbfd 0%, #f3eef8 100%)', boxSizing: 'border-box' }}>
      <div style={{ maxWidth: '750px', margin: '0 auto' }}>

        <h1 style={{ color: '#2d2640', marginBottom: '6px', fontSize: '24px', fontWeight: '700' }}>User & Device Profile</h1>
        <p style={{ color: '#7a6e93', marginBottom: '24px', fontSize: '14px' }}>
          Configure child safety thresholds, emergency settings, and custom restricted topic filters.
        </p>

        {savedMessage && (
          <div style={{ background: '#e6f7ed', color: '#1e7e34', padding: '12px 18px', borderRadius: '10px', marginBottom: '20px', border: '1px solid #c3e6cb', fontWeight: '600', fontSize: '13px' }}>
            ✓ Profile settings and filters synced with backend successfully!
          </div>
        )}

        {actionMessage && (
          <div style={{ background: '#f3eef8', color: '#64587a', padding: '12px 18px', borderRadius: '10px', marginBottom: '20px', border: '1px solid #ded0f1', fontWeight: '600', fontSize: '13px' }}>
            ℹ️ {actionMessage}
          </div>
        )}

        <div style={{ background: '#ffffff', padding: '20px 24px', borderRadius: '14px', boxShadow: '0 4px 15px rgba(116, 90, 158, 0.04)', marginBottom: '20px', border: '1px solid #eadef5', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <h4 style={{ margin: '0 0 4px 0', color: '#2d2640', fontSize: '15px', fontWeight: '600' }}>System Browser Safety Locks</h4>
            <p style={{ margin: 0, color: '#7a6e93', fontSize: '13px' }}>Enforce strict SafeSearch and YouTube Restricted Mode.</p>
          </div>
          <button
            type="button"
            onClick={() => handleToggleBrowserLock(!isBrowserLocked)}
            style={{
              background: isBrowserLocked ? '#ef4444' : '#10b981',
              color: '#fff', border: 'none', padding: '10px 16px', borderRadius: '8px', fontWeight: 'bold', fontSize: '13px', cursor: 'pointer', transition: 'all 0.2s'
            }}
          >
            {isBrowserLocked ? '🔓 Unlock Browser' : '🔒 Lock Browser'}
          </button>
        </div>

        <form onSubmit={handleSave} style={{ background: '#ffffff', padding: '28px', borderRadius: '14px', boxShadow: '0 4px 15px rgba(116, 90, 158, 0.04)', border: '1px solid #eadef5' }}>

          <h3 style={{ marginTop: '0', color: '#2d2640', borderBottom: '1px solid #f2ecfb', paddingBottom: '12px', marginBottom: '20px', fontSize: '16px', fontWeight: '600' }}>
            Guardian & Safety Configuration
          </h3>

          <div style={{ marginBottom: '20px' }}>
            <label style={{ display: 'block', fontWeight: '600', color: '#2d2640', marginBottom: '8px', fontSize: '13px' }}>Profile Name</label>
            <input
              type="text"
              value={profileName}
              onChange={(e) => setProfileName(e.target.value)}
              style={{ width: '100%', padding: '12px 14px', borderRadius: '8px', border: '1px solid #ded0f1', fontSize: '14px', boxSizing: 'border-box', background: '#fcfbfe', color: '#2d2640', outline: 'none' }}
            />
          </div>

          <div style={{ marginBottom: '20px' }}>
            <label style={{ display: 'block', fontWeight: '600', color: '#2d2640', marginBottom: '8px', fontSize: '13px' }}>Safety Sensitivity Level</label>
            <select
              value={sensitivity}
              onChange={(e) => setSensitivity(e.target.value)}
              style={{ width: '100%', padding: '12px 14px', borderRadius: '8px', border: '1px solid #ded0f1', fontSize: '14px', background: '#fcfbfe', color: '#2d2640', boxSizing: 'border-box', outline: 'none' }}
            >
              <option>High (Strict PII & Toxicity Block)</option>
              <option>Medium (Balanced Protection)</option>
              <option>Low (Minimal Filtering)</option>
            </select>
          </div>

          <div style={{ marginBottom: '20px', background: '#fcfbfe', padding: '18px', borderRadius: '10px', border: '1px solid #f2ecfb' }}>
            <label style={{ display: 'block', fontWeight: '600', color: '#2d2640', marginBottom: '4px', fontSize: '13px' }}>
              Custom Blocked Keywords & Topics
            </label>
            <p style={{ color: '#7a6e93', fontSize: '13px', marginBottom: '12px', marginTop: '0' }}>
              These terms are saved to the backend database and will instantly trigger warnings for parent review.
            </p>

            <div style={{ display: 'flex', gap: '10px', marginBottom: '12px' }}>
              <input
                type="text"
                value={newWord}
                onChange={(e) => setNewWord(e.target.value)}
                placeholder="e.g. bullying, secrets"
                style={{ flex: 1, padding: '10px 14px', borderRadius: '8px', border: '1px solid #ded0f1', fontSize: '13px', background: '#ffffff', color: '#2d2640', outline: 'none' }}
              />
              <button
                type="button"
                onClick={handleAddWord}
                style={{ background: '#10b981', color: '#fff', border: 'none', padding: '10px 16px', borderRadius: '8px', fontWeight: '600', fontSize: '13px', cursor: 'pointer' }}
              >
                Add Rule
              </button>
            </div>

            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
              {restrictedWords.map((word, idx) => (
                <span key={idx} style={{ background: '#f0eaf8', color: '#7c58cc', padding: '4px 12px', borderRadius: '20px', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '6px', border: '1px solid #ded0f1', fontWeight: '500' }}>
                  {word}
                  <button
                    type="button"
                    onClick={() => handleRemoveWord(word)}
                    style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: '#ef4444', fontWeight: 'bold', fontSize: '14px', padding: 0 }}
                  >
                    ×
                  </button>
                </span>
              ))}
            </div>
          </div>

          <div style={{ marginBottom: '24px', display: 'flex', alignItems: 'center', gap: '10px' }}>
            <input
              type="checkbox"
              id="notif"
              checked={notificationsEnabled}
              onChange={(e) => setNotificationsEnabled(e.target.checked)}
              style={{ width: '16px', height: '16px', cursor: 'pointer', accentColor: '#8c63d4' }}
            />
            <label htmlFor="notif" style={{ color: '#2d2640', fontSize: '13px', cursor: 'pointer', fontWeight: '500' }}>
              Send instant guardian warning notifications on high-risk detection
            </label>
          </div>

          <button
            type="submit"
            style={{ background: 'linear-gradient(135deg, #8c63d4 0%, #6e44b8 100%)', color: '#fff', border: 'none', padding: '12px 24px', borderRadius: '8px', fontWeight: 'bold', fontSize: '14px', cursor: 'pointer', boxShadow: '0 4px 15px rgba(140, 99, 212, 0.3)' }}
          >
            Save Changes
          </button>

        </form>
      </div>
    </div>
  );
}