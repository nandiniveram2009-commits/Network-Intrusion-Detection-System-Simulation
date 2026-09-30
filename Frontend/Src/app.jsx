import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';

function App() {
  const [stats, setStats] = useState({ total_flows: 0, normal_flows: 0, suspicious_flows: 0, open_alerts: 0, critical_alerts: 0, average_risk_score: 0 });
  const [alerts, setAlerts] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [newNote, setNewNote] = useState('');

  const fetchData = async () => {
    try {
      const statsRes = await axios.get('http://localhost:5000/api/dashboard/stats');
      setStats(statsRes.data);
      const alertsRes = await axios.get('http://localhost:5000/api/alerts');
      setAlerts(alertsRes.data);
    } catch (err) {
      console.error("Dashboard connection error:", err);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 3000);
    return () => clearInterval(interval);
  }, []);

  const updateStatus = async (alertId, status) => {
    await axios.put(`http://localhost:5000/api/alerts/${alertId}/status`, { status });
    fetchData();
    if (selectedAlert && selectedAlert.alert_id === alertId) {
      setSelectedAlert({ ...selectedAlert, status });
    }
  };

  const addNote = async (alertId) => {
    if (!newNote) return;
    await axios.post(`http://localhost:5000/api/alerts/${alertId}/notes`, { note: newNote });
    setNewNote('');
    const res = await axios.get(`http://localhost:5000/api/alerts/${alertId}`);
    setSelectedAlert(res.data);
  };

  const selectAlertDetail = async (alertId) => {
    const res = await axios.get(`http://localhost:5000/api/alerts/${alertId}`);
    setSelectedAlert(res.data);
  };

  return (
    <div className="soc-container">
      <header className="soc-header">
        <h1>🛡️ Network Intrusion Detection System (IDS) | SOC Operations</h1>
        <p>Defensive Security Monitoring & Incident Triage Dashboard</p>
      </header>

      <div className="stats-grid">
        <div className="card"><h3>Total Flows</h3><p>{stats.total_flows}</p></div>
        <div className="card normal"><h3>Normal Traffic</h3><p>{stats.normal_flows}</p></div>
        <div className="card warning"><h3>Suspicious Traffic</h3><p>{stats.suspicious_flows}</p></div>
        <div className="card alert"><h3>Open Alerts</h3><p>{stats.open_alerts}</p></div>
        <div className="card critical"><h3>Critical Alerts</h3><p>{stats.critical_alerts}</p></div>
        <div className="card"><h3>Avg Risk Score</h3><p>{stats.average_risk_score} / 100</p></div>
      </div>

      <div className="main-workspace">
        <div className="alert-queue">
          <h2>Active Security Alert Queue</h2>
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Source IP</th>
                <th>Destination</th>
                <th>Alert Type</th>
                <th>Severity</th>
                <th>Risk</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map(alt => (
                <tr key={alt.alert_id} onClick={() => selectAlertDetail(alt.alert_id)} className={selectedAlert?.alert_id === alt.alert_id ? 'selected' : ''}>
                  <td>{new Date(alt.created_at).toLocaleTimeString()}</td>
                  <td><code>{alt.source_ip}</code></td>
                  <td><code>{alt.destination_ip}:{alt.destination_port}</code></td>
                  <td>{alt.alert_type}</td>
                  <td><span className={`badge ${alt.severity.toLowerCase()}`}>{alt.severity}</span></td>
                  <td><strong>{alt.risk_score}</strong></td>
                  <td><span className={`status ${alt.status.toLowerCase()}`}>{alt.status}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {selectedAlert && (
          <div className="investigation-panel">
            <h2>Incident Triage: {selectedAlert.alert_id}</h2>
            <div className="detail-group">
              <p><strong>Rule Triggered:</strong> {selectedAlert.alert_type} ({selectedAlert.rule_id})</p>
              <p><strong>Source:</strong> <code>{selectedAlert.source_ip}</code> → <strong>Destination:</strong> <code>{selectedAlert.destination_ip}:{selectedAlert.destination_port}</code></p>
              <p><strong>Risk Score:</strong> {selectedAlert.risk_score} / 100</p>
              <p><strong>Description:</strong> {selectedAlert.description}</p>
            </div>

            <div className="workflow-actions">
              <label>Update Status: </label>
              <button onClick={() => updateStatus(selectedAlert.alert_id, "INVESTIGATING")}>Investigate</button>
              <button onClick={() => updateStatus(selectedAlert.alert_id, "RESOLVED")}>Resolve</button>
              <button onClick={() => updateStatus(selectedAlert.alert_id, "FALSE_POSITIVE")}>False Positive</button>
            </div>

            <div className="notes-section">
              <h3>Analyst Notes & Investigation Trail</h3>
              <ul>
                {selectedAlert.notes?.map((n, idx) => (
                  <li key={idx}>[{new Date(n.created_at).toLocaleTimeString()}] {n.note}</li>
                ))}
              </ul>
              <input type="text" placeholder="Add triage observation..." value={newNote} onChange={(e) => setNewNote(e.target.value)} />
              <button onClick={() => addNote(selectedAlert.alert_id)}>Add Note</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
