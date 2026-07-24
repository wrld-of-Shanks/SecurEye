const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const cors = require('cors');
const mongoose = require('mongoose');
require('dotenv').config();

const eventRoutes = require('./routes/events');
const networkRoutes = require('./routes/network');
const codeRoutes = require('./routes/code');
const { TriageEngine } = require('../shared/triage/engine');
const Event = require('../shared/schema/event');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = process.env.GATEWAY_PORT || 3000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/sentinelai';
const NETWORK_SERVICE = process.env.NETWORK_SERVICE || 'http://localhost:5001';
const CODE_SERVICE = process.env.CODE_SERVICE || 'http://localhost:5002';

app.use(cors());
app.use(express.json());

const triageEngine = new TriageEngine();

mongoose.connect(MONGO_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

app.use('/api/events', eventRoutes);
app.use('/api/network', networkRoutes(NETWORK_SERVICE, triageEngine, wss));
app.use('/api/code', codeRoutes(CODE_SERVICE, triageEngine, wss));

wss.on('connection', (ws) => {
  console.log('Client connected to WebSocket');
  ws.on('close', () => console.log('Client disconnected'));
});

app.set('wss', wss);

server.listen(PORT, () => {
  console.log(`Gateway running on port ${PORT}`);
});

module.exports = { app, server, wss };
