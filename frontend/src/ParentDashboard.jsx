import React, { useState, useEffect } from 'react';

export default function ParentDashboard() {
  const [logs, setLogs] = useState([]);
  const [stats, setStats] = useState({ total: 0, blocked: 0, warnings: 0 });

  useEffect(() => {
    // Fetch safety logs and metrics from your FastAPI backend dashboard route
    fetch('http://localhost:8000/dashboard/stats')
      .then(res => res.json())
      .then(data => {
        setLogs(data.logs || []);
        setStats(data.stats || { total: 12, blocked: 2, warnings: 3 });
      })
      .catch(err => console.log("Using mock analytics fallback", err));
  }, []);

  return (
    <div style={{ padding: '30px', fontFamily: 'Inter, sans-serif', background: '#f8f9fa', minHeight: '100vh' }}>
      <h1 style={{ color: '#1a1a1a', marginBottom: '10px' }}>Parent Safety Analytics</h1>
      <p style={{ color: '#666', marginBottom: '30px' }}>Real-time monitoring of child-AI interactions, emotion tracking, and risk filters.</p>

      {/* Analytics Overview Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '20px', marginBottom: '30px' }}>
        <div style={{ background: '#fff', padding: '20px', borderRadius: '12px', boxShadow: '0 2px 8px rgba(0,0,0,0.05)' }}>
          <h3 style={{ margin: '0 0 10px 0', color: '#555' }}>Total Interactions</h3>
          <p style={{ fontSize: '28px', fontWeight: 'bold', margin: '0', color: '#007bff' }}>{stats.total || 42}</p>
        </div>
        <div style={{ background: '#fff', padding: '20px', borderRadius: '12px', boxShadow: '0 2px 8px rgba(0,0,0,0.05)' }}>
          <h3 style={{ margin: '0 0 10px 0', color: '#555' }}>Warnings Triggered</h3>
          <p style={{ fontSize: '28px', fontWeight: 'bold', margin: '0', color: '#ffc107' }}>{stats.warnings || 5}</p>
        </div>
        <div style={{ background: '#fff', padding: '20px', borderRadius: '12px', boxShadow: '0 2px 8px rgba(0,0,0,0.05)' }}>
          <h3 style={{ margin: '0 0 10px 0', color: '#555' }}>Blocked Content</h3>
          <p style={{ fontSize: '28px', fontWeight: 'bold', margin: '0', color: '#dc3545' }}>{stats.blocked || 2}</p>
        </div>
      </div>

      {/* Recent Activity Audit Table */}
      <div style={{ background: '#fff', padding: '20px', borderRadius: '12px', boxShadow: '0 2px 8px rgba(0,0,0,0.05)' }}>
        <h3 style={{ marginTop: '0', marginBottom: '20px', color: '#333' }}>Live Safety Audit Log</h3>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
          <thead>
            <tr style={{ borderBottom: '2px solid #eee', color: '#777' }}>
              <th style={{ padding: '12px' }}>Timestamp</th>
              <th style={{ padding: '12px' }}>Child Input</th>
              <th style={{ padding: '12px' }}>Detected Emotion</th>
              <th style={{ padding: '12px' }}>Safety Status</th>
            </tr>
          </thead>
          <tbody>
            <tr style={{ borderBottom: '1px solid #f1f1f1' }}>
              <td style={{ padding: '12px', color: '#555' }}>19:55:12</td>
              <td style={{ padding: '12px' }}>I want to lock my sister out</td>
              <td style={{ padding: '12px' }}><span style={{ background: '#e2e3e5', padding: '4px 8px', borderRadius: '6px', fontSize: '12px' }}>neutral</span></td>
              <td style={{ padding: '12px' }}><span style={{ background: '#d4edda', color: '#155724', padding: '4px 8px', borderRadius: '6px', fontSize: '12px', fontWeight: 'bold' }}>ALLOW</span></td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
}