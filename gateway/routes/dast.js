const express = require('express');
const WebSocket = require('ws');
const router = express.Router();
const Event = require('../../shared/schema/event');
const AuthorizedTarget = require('../../shared/schema/authorizedTarget');
const { validate, dastScanSchema, authorizedTargetSchema } = require('../../shared/utils/validation');
const { dastLimiter } = require('../../shared/middleware/rateLimiter');
const { createChildLogger } = require('../../shared/utils/logger');

const log = createChildLogger('dast-route');

function extractHost(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

async function isAuthorized(targetUrl) {
  const host = extractHost(targetUrl);
  if (!host) return false;
  const localHosts = ['localhost', '127.0.0.1', '0.0.0.0'];
  if (localHosts.includes(host)) return true;
  const record = await AuthorizedTarget.findOne({ target: host });
  return !!record;
}

module.exports = function(dastService, triageEngine, wss) {
  router.post('/scan', dastLimiter, validate(dastScanSchema), async (req, res) => {
    const { target_url, mode, verbose_evidence } = req.body;

    if (mode === 'active') {
      const authorized = await isAuthorized(target_url);
      if (!authorized) {
        log.warn({ target_url, requestId: req.id }, 'Active scan rejected: target not authorized');
        return res.status(403).json({
          error: 'Target not authorized for active scanning',
          message: 'Add the target host to the authorized targets list before running active scans'
        });
      }
    }

    try {
      const response = await fetch(`${dastService}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_url, mode, verbose_evidence }),
        signal: AbortSignal.timeout(120000)
      });

      const result = await response.json();

      if (!response.ok) {
        log.error({ status: response.status, requestId: req.id }, 'DAST service error');
        return res.status(502).json({ error: result.error || 'DAST service unavailable' });
      }

      const savedFindings = [];
      for (const finding of (result.findings || [])) {
        const certaintyType = finding.certainty_type || finding.explanation?.certainty_type || 'inferred';

        let triageResult;
        if (certaintyType === 'confirmed') {
          triageResult = triageEngine.classifyConfirmed(finding.severity || 'medium');
        } else {
          triageResult = triageEngine.classify(finding.confidence, finding);
        }

        const event = new Event({
          event_type: 'dast',
          source: target_url,
          prediction: finding.check_name,
          confidence: certaintyType === 'confirmed' ? null : finding.confidence,
          certainty_type: certaintyType,
          severity: triageResult.severity,
          status: triageResult.status,
          explanation: finding.explanation || null,
          mode,
          evidence: verbose_evidence && finding.evidence ? finding.evidence : null,
          raw_features: { target_url, mode }
        });

        await event.save();
        savedFindings.push(event);
        broadcastEvent(wss, event);
      }

      res.json({
        target_url,
        mode,
        finding_count: savedFindings.length,
        findings: savedFindings.map(f => ({
          event_id: f._id,
          prediction: f.prediction,
          confidence: f.confidence,
          certainty_type: f.certainty_type,
          severity: f.severity,
          status: f.status,
          explanation: f.explanation
        }))
      });
    } catch (err) {
      log.error({ err, requestId: req.id }, 'DAST scan failed');
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  router.get('/authorized-targets', async (req, res) => {
    try {
      const targets = await AuthorizedTarget.find().sort({ added_at: -1 });
      res.json(targets);
    } catch (err) {
      log.error({ err, requestId: req.id }, 'Failed to fetch authorized targets');
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  router.post('/authorized-targets', validate(authorizedTargetSchema), async (req, res) => {
    try {
      const { target, note } = req.body;
      const record = await AuthorizedTarget.findOneAndUpdate(
        { target },
        { target, note: note || '', added_at: new Date() },
        { upsert: true, new: true }
      );
      res.status(201).json(record);
    } catch (err) {
      log.error({ err, requestId: req.id }, 'Failed to add authorized target');
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  router.delete('/authorized-targets/:target', async (req, res) => {
    try {
      await AuthorizedTarget.findOneAndDelete({ target: req.params.target });
      res.json({ deleted: true });
    } catch (err) {
      log.error({ err, requestId: req.id }, 'Failed to delete authorized target');
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
