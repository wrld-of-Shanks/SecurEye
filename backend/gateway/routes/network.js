const express = require('express');
const WebSocket = require('ws');
const router = express.Router();
const Event = require('../../shared/schema/event');
const { validate, networkAnalyzeSchema } = require('../../shared/utils/validation');
const { scanLimiter } = require('../../shared/middleware/rateLimiter');
const { createChildLogger } = require('../../shared/utils/logger');

const log = createChildLogger('network-route');

module.exports = function(networkService, triageEngine, wss) {
  router.post('/analyze', scanLimiter, validate(networkAnalyzeSchema), async (req, res) => {
    try {
      const response = await fetch(`${networkService}/predict`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(req.body),
        signal: AbortSignal.timeout(30000)
      });

      const result = await response.json();

      if (!response.ok) {
        log.error({ status: response.status, requestId: req.id }, 'Network service error');
        return res.status(502).json({ error: 'Network service unavailable' });
      }

      const triageResult = triageEngine.classify(result.confidence, result);

      const event = new Event({
        event_type: 'network',
        source: req.body.source || 'unknown',
        prediction: result.prediction,
        confidence: result.confidence,
        certainty_type: 'inferred',
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
        certainty_type: 'inferred',
        anomaly_score: result.anomaly_score,
        severity: triageResult.severity,
        status: triageResult.status,
        explanation: result.explanation
      });
    } catch (err) {
      log.error({ err, requestId: req.id }, 'Network analysis failed');
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  return router;
};

function broadcastEvent(wss, event) {
  const message = JSON.stringify({ type: 'new_event', data: event });
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(message);
    }
  });
}
