import React from 'react';
import { Shield, Trash2, AlertTriangle, Info } from 'lucide-react';
import FindingCard from './FindingCard';

const getSeverityIcon = (severity) => {
  switch (severity) {
    case 'critical':
    case 'high':
      return <AlertTriangle className="feed-severity-icon" style={{ color: severity === 'critical' ? '#ef4444' : '#f97316' }} />;
    case 'medium':
      return <AlertTriangle className="feed-severity-icon" style={{ color: '#eab308' }} />;
    default:
      return <Info className="feed-severity-icon" style={{ color: '#64748b' }} />;
  }
};

const ThreatFeedSidebar = ({ events, onClear }) => {
  return (
    <div className="sidebar-feed">
      <div className="sidebar-feed-header">
        <h2 className="sidebar-feed-title">
          <Shield className="icon-sm" /> Threat Feed
        </h2>
        {events.length > 0 && (
          <button onClick={onClear} className="clear-btn">
            <Trash2 className="icon-xs" /> Clear
          </button>
        )}
      </div>

      {events.length > 0 && (
        <div className="sidebar-feed-count">
          {events.length} event{events.length !== 1 ? 's' : ''}
        </div>
      )}

      <div className="sidebar-feed-list">
        {events.length === 0 ? (
          <div className="sidebar-feed-empty">
            <Shield className="icon" />
            <p>No threats yet</p>
          </div>
        ) : (
          events.map((event, index) => (
            <div key={`${event._id || ''}-${index}`} className="sidebar-feed-item">
              <div className="feed-item-header">
                {getSeverityIcon(event.severity)}
                <span className="feed-item-type">{(event.event_type || '').replace('_', ' ')}</span>
                <span className={`feed-item-severity ${event.severity}`}>{event.severity}</span>
              </div>
              <div className="feed-item-prediction">
                {(event.prediction || '').replace(/_/g, ' ')}
              </div>
              {event.explanation?.what && (
                <div className="feed-item-what">{event.explanation.what}</div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default ThreatFeedSidebar;
