import React, { useState, useEffect } from 'react';
import ThreatFeedSidebar from './components/ThreatFeedSidebar';
import UnifiedScanner from './components/UnifiedScanner';
import StatsBar from './components/StatsBar';
import { useWebSocket } from './services/websocket';
import { fetchEvents, fetchStats } from './services/api';

function App() {
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
          setEvents(prev => {
            const incoming = data.data;
            const id = incoming?._id;
            if (id && prev.some(e => e._id === id)) return prev;
            return [incoming, ...prev].slice(0, 200);
          });
        }
      };
    }
  }, [ws]);

  const loadInitialData = async () => {
    try {
      const clearedAt = localStorage.getItem('sentinel_feed_cleared_at');
      const params = clearedAt ? { since: clearedAt } : {};
      const [eventsData, statsData] = await Promise.all([
        fetchEvents(params),
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

  const clearEvents = () => {
    localStorage.setItem('sentinel_feed_cleared_at', new Date().toISOString());
    setEvents([]);
  };

  return (
    <div className="app-layout">
      <aside className="sidebar">
        <div className="sidebar-header">
          <h1 className="sidebar-brand">
            <span className="brand-icon">🛡️</span>
            SentinelAI
          </h1>
          <p className="sidebar-subtitle">Security Monitor</p>
        </div>
        <ThreatFeedSidebar events={events} onClear={clearEvents} />
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="topbar-left">
            <h2 className="topbar-title">Security Scanner</h2>
          </div>
          <div className="topbar-right">
            <span className={`ws-status ${ws ? 'connected' : ''}`}>
              <span className="ws-dot" />
              {ws ? 'Live' : 'Offline'}
            </span>
          </div>
        </header>

        {loading ? (
          <div className="loading-full">
            <div className="loading-spinner" />
            <span>Loading...</span>
          </div>
        ) : (
          <div className="main-scroll">
            <StatsBar events={events} />
            <UnifiedScanner />
          </div>
        )}
      </main>
    </div>
  );
}

export default App;
