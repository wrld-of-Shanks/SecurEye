import React from 'react';
import { AlertTriangle, Shield, Info, CheckCircle, MapPin, BookOpen, Wrench, MessageCircle } from 'lucide-react';

const getSeverityColor = (severity) => {
  switch (severity) {
    case 'critical': return '#ef4444';
    case 'high': return '#f97316';
    case 'medium': return '#eab308';
    case 'low': return '#3b82f6';
    default: return '#6b7280';
  }
};

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

const formatTimestamp = (ts) => ts ? new Date(ts).toLocaleString() : null;

const FindingCard = ({ event, showType = true, showFile = false }) => {
  const exp = event.explanation || {};
  const rem = exp.remediation || {};

  return (
    <div className={`event-card ${event.severity}`}>
      <div className="event-header">
        <div className="event-icon">
          {getSeverityIcon(event.severity)}
        </div>
        <div className="event-info">
          <span className="event-type">
            {showType && <span className={`event-type-badge ${event.event_type}`}>{event.event_type}</span>}
            {' '}{event.prediction}
          </span>
          <span className="event-time">
            {event.file_path && <span className="file-badge">{event.file_path}</span>}
            {event.line_range?.start && ` L${event.line_range.start}-${event.line_range.end}`}
            {event.mode && !event.file_path && <span className={`mode-badge ${event.mode}`}>{event.mode}</span>}
            {!event.file_path && !event.mode && event.timestamp && ` ${formatTimestamp(event.timestamp)}`}
          </span>
        </div>
        <div className="severity-badge" style={{ backgroundColor: getSeverityColor(event.severity) }}>
          {event.severity}
        </div>
      </div>

      <div className="event-body">
        <div>
          <strong>Confidence:</strong>
          <span className="confidence-value"> {(event.confidence * 100).toFixed(1)}%</span>
        </div>
        <div><strong>Status:</strong> {event.status}</div>
        {exp.reference?.cwe && exp.reference.cwe !== 'N/A' && (
          <div><strong>Ref:</strong> <span className="cwe-ref">{exp.reference.cwe}</span>
            {exp.reference.owasp && exp.reference.owasp !== 'N/A' && (
              <span className="owasp-ref"> / {exp.reference.owasp}</span>
            )}
          </div>
        )}
      </div>

      {exp.what && (
        <div className="explanation-section">
          <h4><AlertTriangle className="icon-sm" /> What</h4>
          <p>{exp.what}</p>
        </div>
      )}

      {exp.why_it_matters && (
        <div className="explanation-section">
          <h4><MessageCircle className="icon-sm" /> Why it matters</h4>
          <p>{exp.why_it_matters}</p>
        </div>
      )}

      {exp.location && (
        <div className="explanation-section">
          <h4><MapPin className="icon-sm" /> Where</h4>
          <pre className="location-pre">{exp.location}</pre>
        </div>
      )}

      {exp.confidence_note && (
        <div className="explanation-section confidence-note-section">
          <h4><BookOpen className="icon-sm" /> Confidence</h4>
          <p className="confidence-note-text">{exp.confidence_note}</p>
        </div>
      )}

      {rem.guidance && (
        <div className="explanation-section">
          <h4><Wrench className="icon-sm" /> How to fix</h4>
          <p>{rem.guidance}</p>
          {rem.suggested_code_fix && (
            <div className="fix-section">
              <strong>Suggested code fix:</strong>
              <pre className="fix-code">{rem.suggested_code_fix}</pre>
              <p className="fix-disclaimer">This is a suggested fix and should be reviewed before applying.</p>
            </div>
          )}
        </div>
      )}

      {event.suggested_fix && !rem.suggested_code_fix && (
        <div className="explanation-section">
          <h4><Wrench className="icon-sm" /> Suggested Fix</h4>
          <pre className="fix-code">{event.suggested_fix}</pre>
          <p className="fix-disclaimer">This is a suggested fix and should be reviewed before applying.</p>
        </div>
      )}
    </div>
  );
};

export default FindingCard;
