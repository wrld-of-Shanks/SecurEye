const crypto = require('crypto');
const { createChildLogger } = require('../utils/logger');

const log = createChildLogger('auth');

function apiKeyAuth(req, res, next) {
  const apiKey = req.headers['x-api-key'] || req.query.api_key;
  const validKey = process.env.API_KEY || 'sentinelai-dev-key-change-in-production';

  if (!apiKey) {
    log.warn({ requestId: req.id }, 'Missing API key');
    return res.status(401).json({ error: 'API key required' });
  }

  if (apiKey.length !== validKey.length || !crypto.timingSafeEqual(Buffer.from(apiKey), Buffer.from(validKey))) {
    log.warn({ requestId: req.id }, 'Invalid API key');
    return res.status(403).json({ error: 'Invalid API key' });
  }

  next();
}

module.exports = { apiKeyAuth };
