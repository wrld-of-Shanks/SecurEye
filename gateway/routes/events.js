const express = require('express');
const router = express.Router();
const Event = require('../../shared/schema/event');
const { validate, paginationSchema } = require('../../utils/validation');
const { createChildLogger } = require('../../utils/logger');

const log = createChildLogger('events-route');

router.get('/', validate(paginationSchema, 'query'), async (req, res) => {
  try {
    const { event_type, status, limit = 50, page = 1 } = req.query;
    const query = {};
    if (event_type) query.event_type = event_type;
    if (status) query.status = status;

    const skip = (page - 1) * limit;
    const [events, total] = await Promise.all([
      Event.find(query).sort({ timestamp: -1 }).skip(skip).limit(limit),
      Event.countDocuments(query)
    ]);

    res.json({ events, total, page, limit });
  } catch (err) {
    log.error({ err, requestId: req.id }, 'Failed to fetch events');
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/:id', async (req, res) => {
  try {
    const event = await Event.findById(req.params.id);
    if (!event) return res.status(404).json({ error: 'Event not found' });
    res.json(event);
  } catch (err) {
    log.error({ err, requestId: req.id }, 'Failed to fetch event');
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/stats/summary', async (req, res) => {
  try {
    const stats = await Event.aggregate([
      {
        $group: {
          _id: { event_type: '$event_type', status: '$status' },
          count: { $sum: 1 },
          avg_confidence: { $avg: '$confidence' }
        }
      }
    ]);
    res.json(stats);
  } catch (err) {
    log.error({ err, requestId: req.id }, 'Failed to fetch stats');
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
