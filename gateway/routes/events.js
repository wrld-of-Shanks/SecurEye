const express = require('express');
const router = express.Router();
const Event = require('../../shared/schema/event');

router.get('/', async (req, res) => {
  try {
    const { event_type, status, limit = 50 } = req.query;
    const query = {};
    if (event_type) query.event_type = event_type;
    if (status) query.status = status;
    
    const events = await Event.find(query)
      .sort({ timestamp: -1 })
      .limit(parseInt(limit));
    
    res.json(events);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/:id', async (req, res) => {
  try {
    const event = await Event.findById(req.params.id);
    if (!event) return res.status(404).json({ error: 'Event not found' });
    res.json(event);
  } catch (err) {
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
