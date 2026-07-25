const express = require('express');
const WebSocket = require('ws');
const router = express.Router();
const Event = require('../../shared/schema/event');
const { createChildLogger } = require('../../shared/utils/logger');

const log = createChildLogger('repo-scan-route');

const savedJobs = new Set();

module.exports = function (codeService, triageEngine, wss) {
  router.get('/scan-repo', async (req, res) => {
    try {
      const response = await fetch(`${codeService}/repo-scan`, {
        signal: AbortSignal.timeout(5000)
      });

      const result = await response.json();
      res.status(response.status).json(result);
    } catch (err) {
      log.error({ err, requestId: req.id }, 'Failed to fetch scan jobs');
      res.status(502).json({ error: 'Code service unavailable' });
    }
  });

  router.post('/scan-repo', async (req, res) => {
    const { repo_url } = req.body;
    if (!repo_url) {
      return res.status(400).json({ error: 'repo_url is required' });
    }

    try {
      const response = await fetch(`${codeService}/repo-scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repo_url }),
        signal: AbortSignal.timeout(15000)
      });

      const result = await response.json();
      res.status(response.status).json(result);
    } catch (err) {
      log.error({ err, requestId: req.id }, 'Failed to start repo scan');
      res.status(502).json({ error: 'Code service unavailable' });
    }
  });

  router.get('/scan-repo/:jobId', async (req, res) => {
    try {
      const response = await fetch(`${codeService}/repo-scan/${req.params.jobId}`, {
        signal: AbortSignal.timeout(5000)
      });

      const result = await response.json();

      if (response.ok && result.status === 'completed' && result.findings && !savedJobs.has(req.params.jobId)) {
        const allFindings = [];
        for (const [filePath, fileFindings] of Object.entries(result.findings)) {
          for (const f of fileFindings) {
            allFindings.push(f);
          }
        }
        if (allFindings.length > 0) {
          savedJobs.add(req.params.jobId);
          await saveRepoFindings(allFindings, result.repo_url, triageEngine, wss, req.params.jobId);
        }
      }

      res.status(response.status).json(result);
    } catch (err) {
      log.error({ err, requestId: req.id }, 'Failed to fetch repo scan status');
      res.status(502).json({ error: 'Code service unavailable' });
    }
  });

  return router;
};

async function saveRepoFindings(findings, repoUrl, triageEngine, wss, jobId) {
  for (const finding of findings) {
    try {
      const explanation = finding.explanation || {};
      const severity = finding.severity || 'medium';
      const triageResult = triageEngine.classifyConfirmed(severity);

      const event = new Event({
        event_type: 'scan_repo',
        source: repoUrl || 'repo_scan',
        prediction: finding.prediction || finding.check_name || 'vulnerability',
        confidence: finding.confidence ?? null,
        certainty_type: 'inferred',
        severity: triageResult.severity,
        status: triageResult.status,
        explanation: {
          what: explanation.what || finding.message || '',
          why_it_matters: explanation.why_it_matters || '',
          location: explanation.location || finding.location || finding.file_path || '',
          reference: explanation.reference || { cwe: finding.cwe || null, owasp: finding.owasp || null },
          remediation: explanation.remediation || { guidance: finding.remediation || finding.suggested_fix || '', suggested_code_fix: null },
          certainty_type: 'inferred',
          confidence_note: explanation.confidence_note || ''
        },
        suggested_fix: finding.suggested_fix || null,
        file_path: finding.file_path || null,
        line_range: finding.line_range || { start: null, end: null },
        raw_features: { repo_url: repoUrl, file_path: finding.file_path }
      });

      await event.save();
      broadcastEvent(wss, event);
    } catch (err) {
      log.error({ err, jobId }, 'Failed to save repo scan finding');
    }
  }
}

function broadcastEvent(wss, event) {
  const message = JSON.stringify({ type: 'new_event', data: event });
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(message);
    }
  });
}
