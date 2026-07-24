import React, { useState, useEffect } from 'react';
import ThreatFeed from './components/ThreatFeed';
import CodeScanner from './components/CodeScanner';
import RepoScans from './components/RepoScans';
import DastScanner from './components/DastScanner';
import StatsPanel from './components/StatsPanel';
import { useWebSocket } from './services/websocket';
import { fetchEvents, fetchStats } from './services/api';

function App() {
  const [activeTab, setActiveTab] = useState('feed');
  const [events, setEvents] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  const ws = useWebSocket(process.env.REACT_APP_WS_URL || 'ws://localhost:3000/ws');

  useEffect(() => {
    loadInitialData();
  }, []);

  useEffect(() => {
    if (ws) {
      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.type === 'new_event') {
          setEvents(prev => [data.data, ...prev].slice(0, 200));
        }
      };
    }
  }, [ws]);

  const loadInitialData = async () => {
    try {
      const [eventsData, statsData] = await Promise.all([
        fetchEvents(),
        fetchStats()
      ]);
      setEvents(eventsData);
      setStats(statsData);
    } catch (error) {
      console.error('Failed to load data:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="app">
      <header className="header">
        <div className="header-content">
          <h1>
            <span className="logo">🛡️</span>
            SentinelAI
          </h1>
          <p className="subtitle">Security Monitoring Platform</p>
        </div>
      </header>

      <main className="main">
        <nav className="tabs">
          <button className={`tab ${activeTab === 'feed' ? 'active' : ''}`}
            onClick={() => setActiveTab('feed')}>
            Threat Feed
          </button>
          <button className={`tab ${activeTab === 'scanner' ? 'active' : ''}`}
            onClick={() => setActiveTab('scanner')}>
            Code Scanner
          </button>
          <button className={`tab ${activeTab === 'repo-scans' ? 'active' : ''}`}
            onClick={() => setActiveTab('repo-scans')}>
            Repo Scans
          </button>
          <button className={`tab ${activeTab === 'dast' ? 'active' : ''}`}
            onClick={() => setActiveTab('dast')}>
            DAST Scanner
          </button>
          <button className={`tab ${activeTab === 'stats' ? 'active' : ''}`}
            onClick={() => setActiveTab('stats')}>
            Statistics
          </button>
        </nav>

        <div className="content">
          {loading ? (
            <div className="loading">Loading...</div>
          ) : (
            <>
              {activeTab === 'feed' && <ThreatFeed events={events} />}
              {activeTab === 'scanner' && <CodeScanner />}
              {activeTab === 'repo-scans' && <RepoScans />}
              {activeTab === 'dast' && <DastScanner />}
              {activeTab === 'stats' && <StatsPanel stats={stats} events={events} />}
            </>
          )}
        </div>
      </main>
    </div>
  );
}

export default App;
