const express = require('express');
const router = express.Router();
const Event = require('../../shared/schema/event');

module.exports = function(codeService, triageEngine, wss) {
  router.post('/scan', async (req, res) => {
    try {
      const response = await fetch(`${codeService}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: req.body.code })
      });
      
      const result = await response.json();
      
      const triageResult = triageEngine.classify(result.confidence, result);
      
      const event = new Event({
        event_type: 'code',
        source: req.body.source || 'manual_scan',
        prediction: result.prediction,
        confidence: result.confidence,
        severity: triageResult.severity,
        status: triageResult.status,
        explanation: result.explanation,
        suggested_fix: result.suggested_fix || null,
        raw_features: { code: req.body.code }
      });
      
      await event.save();
      
      broadcastEvent(wss, event);
      
      res.json({
        event_id: event._id,
        prediction: result.prediction,
        confidence: result.confidence,
        severity: triageResult.severity,
        status: triageResult.status,
        explanation: result.explanation,
        suggested_fix: result.suggested_fix,
        top_predictions: result.top_predictions
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
