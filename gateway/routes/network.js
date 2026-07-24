const express = require('express');
const router = express.Router();
const Event = require('../../shared/schema/event');

module.exports = function(networkService, triageEngine, wss) {
  router.post('/analyze', async (req, res) => {
    try {
      const response = await fetch(`${networkService}/predict`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(req.body)
      });
      
      const result = await response.json();
      
      const triageResult = triageEngine.classify(result.confidence, result);
      
      const event = new Event({
        event_type: 'network',
        source: req.body.source || 'unknown',
        prediction: result.prediction,
        confidence: result.confidence,
        severity: triageResult.severity,
        status: triageResult.status,
        explanation: result.explanation || null,
        raw_features: req.body
      });
      
      await event.save();
      
      broadcastEvent(wss, event);
      
      res.json({
        event_id: event._id,
        prediction: result.prediction,
        confidence: result.confidence,
        anomaly_score: result.anomaly_score,
        severity: triageResult.severity,
        status: triageResult.status,
        explanation: result.explanation
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  return router;
};

function broadcastEvent(wss, event) {
  const message = JSON.stringify({
    type: 'new_event',
    data: event
  });
  
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(message);
    }
  });
}
