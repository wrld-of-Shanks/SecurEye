import axios from 'axios';

const API_BASE = process.env.REACT_APP_API_BASE || 'http://localhost:3000';

const api = axios.create({
  baseURL: API_BASE,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json'
  }
});

export const fetchEvents = async (params = {}) => {
  try {
    const response = await api.get('/api/events', { params });
    return response.data;
  } catch (error) {
    console.error('Failed to fetch events:', error);
    throw error;
  }
};

export const fetchEventById = async (id) => {
  try {
    const response = await api.get(`/api/events/${id}`);
    return response.data;
  } catch (error) {
    console.error('Failed to fetch event:', error);
    throw error;
  }
};

export const fetchStats = async () => {
  try {
    const response = await api.get('/api/events/stats/summary');
    return response.data;
  } catch (error) {
    console.error('Failed to fetch stats:', error);
    throw error;
  }
};

export const analyzeNetwork = async (data) => {
  try {
    const response = await api.post('/api/network/analyze', data);
    return response.data;
  } catch (error) {
    console.error('Failed to analyze network:', error);
    throw error;
  }
};

export const scanCode = async (code) => {
  try {
    const response = await api.post('/api/code/scan', { code });
    return response.data;
  } catch (error) {
    console.error('Failed to scan code:', error);
    throw error;
  }
};

export default api;
