import React from 'react';
import { Shield } from 'lucide-react';
import FindingCard from './FindingCard';

const ThreatFeed = ({ events }) => {
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
            <FindingCard key={event._id || index} event={event} />
          ))}
        </div>
      )}
    </div>
  );
};

export default ThreatFeed;
