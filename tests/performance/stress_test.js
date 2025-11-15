// k6 Stress Testing Script for OryxID
// Tests system behavior under extreme load
// Run with: k6 run tests/performance/stress_test.js

import http from 'k6/http';
import { check, sleep } from 'k6';
import encoding from 'k6/encoding';

export const options = {
  stages: [
    { duration: '2m', target: 100 },   // Ramp up to 100 users
    { duration: '5m', target: 100 },   // Stay at 100
    { duration: '2m', target: 200 },   // Spike to 200 users
    { duration: '5m', target: 200 },   // Stay at 200
    { duration: '2m', target: 300 },   // Spike to 300 users
    { duration: '5m', target: 300 },   // Stay at 300
    { duration: '5m', target: 0 },     // Ramp down
  ],
  thresholds: {
    http_req_duration: ['p(99)<2000'], // 99% < 2s under stress
    http_req_failed: ['rate<0.05'],    // Failed requests < 5% under stress
  },
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const CLIENT_ID = __ENV.CLIENT_ID || 'test-client-id';
const CLIENT_SECRET = __ENV.CLIENT_SECRET || 'test-secret';
const credentials = encoding.b64encode(`${CLIENT_ID}:${CLIENT_SECRET}`);

export default function () {
  // Stress test primarily the token endpoint as it's most resource-intensive
  const payload = {
    grant_type: 'client_credentials',
    scope: 'openid profile email',
  };

  const params = {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': `Basic ${credentials}`,
    },
  };

  const res = http.post(
    `${BASE_URL}/oauth/token`,
    Object.keys(payload).map(key => `${key}=${encodeURIComponent(payload[key])}`).join('&'),
    params
  );

  check(res, {
    'status is 200 or 429': (r) => r.status === 200 || r.status === 429, // Accept rate limiting
    'response time < 2s': (r) => r.timings.duration < 2000,
  });

  sleep(0.1); // Minimal think time to maximize load
}
