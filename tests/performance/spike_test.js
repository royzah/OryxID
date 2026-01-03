// k6 Spike Testing Script for OryxID
// Tests system response to sudden traffic spikes
// Run with: k6 run tests/performance/spike_test.js

import http from 'k6/http';
import { check } from 'k6';
import encoding from 'k6/encoding';

export const options = {
  stages: [
    { duration: '10s', target: 10 },    // Low baseline
    { duration: '30s', target: 10 },    // Stable baseline
    { duration: '10s', target: 500 },   // Spike to 500 users
    { duration: '3m', target: 500 },    // Sustained spike
    { duration: '10s', target: 10 },    // Drop back to baseline
    { duration: '3m', target: 10 },     // Recovery period
  ],
  thresholds: {
    http_req_duration: ['p(95)<3000'], // 95% < 3s during spike
    http_req_failed: ['rate<0.1'],     // Failed requests < 10% during spike
  },
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const CLIENT_ID = __ENV.CLIENT_ID || 'test-client-id';
const CLIENT_SECRET = __ENV.CLIENT_SECRET || 'test-secret';
const credentials = encoding.b64encode(`${CLIENT_ID}:${CLIENT_SECRET}`);

export default function () {
  const payload = {
    grant_type: 'client_credentials',
    scope: 'openid',
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
    'status is 200': (r) => r.status === 200,
    'has access_token': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.access_token !== undefined;
      } catch (e) {
        return false;
      }
    },
  });
}
