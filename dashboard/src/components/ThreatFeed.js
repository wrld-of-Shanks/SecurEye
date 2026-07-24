import React from 'react';
import { AlertTriangle, Shield, Info, CheckCircle } from 'lucide-react';

const ThreatFeed = ({ events }) => {
  const getSeverityIcon = (severity) => {
    switch (severity) {
      case 'critical':
      case 'high':
        return <AlertTriangle className="icon critical" />;
      case 'medium':
        return <Shield className="icon medium" />;
      case 'low':
        return <Info className="icon low" />;
      default:
        return <CheckCircle className="icon info" />;
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical':
        return '#ef4444';
      case 'high':
        return '#f97316';
      case 'medium':
        return '#eab308';
      case 'low':
        return '#3b82f6';
      default:
        return '#6b7280';
    }
  };

  const formatTimestamp = (timestamp) => {
    return new Date(timestamp).toLocaleString();
  };

  return (
    <div className="threat-feed">
      <h2>Live Threat Feed</h2>
      
      {events.length === 0 ? (
        <div className="no-events">
          <Shield className="icon" />
          <p>No threats detected yet. Waiting for incoming events...</p>
        </div>
      ) : (
        <div className="events-list">
          {events.map((event, index) => (
            <div
              key={event._id || index}
              className={`event-card ${event.severity}`}
            >
              <div className="event-header">
                <div className="event-icon">
                  {getSeverityIcon(event.severity)}
                </div>
                <div className="event-info">
                  <span className="event-type">{event.event_type}</span>
                  <span className="event-time">
                    {formatTimestamp(event.timestamp)}
                  </span>
                </div>
                <div
                  className="severity-badge"
                  style={{ backgroundColor: getSeverityColor(event.severity) }}
                >
                  {event.severity}
                </div>
              </div>
              
              <div className="event-body">
                <div className="prediction">
                  <strong>Prediction:</strong> {event.prediction}
                </div>
                <div className="confidence">
                  <strong>Confidence:</strong> 
                  <span className="confidence-value">
                    {(event.confidence * 100).toFixed(1)}%
                  </span>
                </div>
                <div className="status">
                  <strong>Status:</strong> {event.status}
                </div>
              </div>
              
              {event.explanation && (
                <div className="event-explanation">
                  <strong>Details:</strong>
                  <pre>{JSON.stringify(event.explanation, null, 2)}</pre>
                </div>
              )}
              
              {event.suggested_fix && (
                <div className="event-fix">
                  <strong>Suggested Fix:</strong>
                  <pre>{event.suggested_fix}</pre>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default ThreatFeed;
