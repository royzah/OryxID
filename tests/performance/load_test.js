// k6 Performance Testing Script for OryxID
// Run with: k6 run tests/performance/load_test.js

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';
import encoding from 'k6/encoding';

// Custom metrics
const errorRate = new Rate('errors');
const tokenDuration = new Trend('token_request_duration');
const discoveryDuration = new Trend('discovery_duration');
const successfulTokens = new Counter('successful_tokens');

// Test configuration
export const options = {
  stages: [
    { duration: '30s', target: 10 },   // Ramp up to 10 users
    { duration: '1m', target: 50 },    // Ramp up to 50 users
    { duration: '2m', target: 100 },   // Ramp up to 100 users
    { duration: '2m', target: 100 },   // Stay at 100 users
    { duration: '1m', target: 0 },     // Ramp down to 0 users
  ],
  thresholds: {
    http_req_duration: ['p(95)<500', 'p(99)<1000'], // 95% < 500ms, 99% < 1s
    errors: ['rate<0.1'],                            // Error rate < 10%
    http_req_failed: ['rate<0.01'],                 // Failed requests < 1%
  },
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const CLIENT_ID = __ENV.CLIENT_ID || 'test-client-id';
const CLIENT_SECRET = __ENV.CLIENT_SECRET || 'test-secret';

// Encode credentials for Basic Auth
const credentials = encoding.b64encode(`${CLIENT_ID}:${CLIENT_SECRET}`);

export function setup() {
  // Verify server is accessible
  const res = http.get(`${BASE_URL}/.well-known/openid-configuration`);
  check(res, {
    'setup: server is accessible': (r) => r.status === 200,
  });

  return { baseURL: BASE_URL };
}

export default function (data) {
  const scenarios = [
    testTokenEndpoint,
    testDiscoveryEndpoint,
    testJWKSEndpoint,
    testIntrospectionEndpoint,
    testPAREndpoint,
  ];

  // Randomly select a scenario to execute
  const scenario = scenarios[Math.floor(Math.random() * scenarios.length)];
  scenario(data.baseURL);

  sleep(1); // Think time between requests
}

function testTokenEndpoint(baseURL) {
  const payload = {
    grant_type: 'client_credentials',
    scope: 'openid profile',
  };

  const params = {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': `Basic ${credentials}`,
    },
    tags: { name: 'TokenEndpoint' },
  };

  const res = http.post(
    `${baseURL}/oauth/token`,
    Object.keys(payload).map(key => `${key}=${encodeURIComponent(payload[key])}`).join('&'),
    params
  );

  const success = check(res, {
    'token: status is 200': (r) => r.status === 200,
    'token: has access_token': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.access_token !== undefined;
      } catch (e) {
        return false;
      }
    },
    'token: has token_type': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.token_type === 'Bearer';
      } catch (e) {
        return false;
      }
    },
    'token: response time < 500ms': (r) => r.timings.duration < 500,
  });

  tokenDuration.add(res.timings.duration);
  errorRate.add(!success);
  if (success) {
    successfulTokens.add(1);
  }
}

function testDiscoveryEndpoint(baseURL) {
  const params = {
    tags: { name: 'DiscoveryEndpoint' },
  };

  const res = http.get(`${baseURL}/.well-known/openid-configuration`, params);

  const success = check(res, {
    'discovery: status is 200': (r) => r.status === 200,
    'discovery: has issuer': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.issuer !== undefined;
      } catch (e) {
        return false;
      }
    },
    'discovery: has token_endpoint': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.token_endpoint !== undefined;
      } catch (e) {
        return false;
      }
    },
    'discovery: response time < 100ms': (r) => r.timings.duration < 100,
  });

  discoveryDuration.add(res.timings.duration);
  errorRate.add(!success);
}

function testJWKSEndpoint(baseURL) {
  const params = {
    tags: { name: 'JWKSEndpoint' },
  };

  const res = http.get(`${baseURL}/.well-known/jwks.json`, params);

  check(res, {
    'jwks: status is 200': (r) => r.status === 200,
    'jwks: has keys array': (r) => {
      try {
        const body = JSON.parse(r.body);
        return Array.isArray(body.keys) && body.keys.length > 0;
      } catch (e) {
        return false;
      }
    },
    'jwks: response time < 100ms': (r) => r.timings.duration < 100,
  });
}

function testIntrospectionEndpoint(baseURL) {
  // First get a token
  const tokenPayload = {
    grant_type: 'client_credentials',
    scope: 'openid',
  };

  const tokenParams = {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': `Basic ${credentials}`,
    },
  };

  const tokenRes = http.post(
    `${baseURL}/oauth/token`,
    Object.keys(tokenPayload).map(key => `${key}=${encodeURIComponent(tokenPayload[key])}`).join('&'),
    tokenParams
  );

  if (tokenRes.status === 200) {
    const tokenBody = JSON.parse(tokenRes.body);
    const accessToken = tokenBody.access_token;

    // Introspect the token
    const introspectPayload = {
      token: accessToken,
    };

    const introspectParams = {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${credentials}`,
      },
      tags: { name: 'IntrospectionEndpoint' },
    };

    const res = http.post(
      `${baseURL}/oauth/introspect`,
      Object.keys(introspectPayload).map(key => `${key}=${encodeURIComponent(introspectPayload[key])}`).join('&'),
      introspectParams
    );

    check(res, {
      'introspection: status is 200': (r) => r.status === 200,
      'introspection: token is active': (r) => {
        try {
          const body = JSON.parse(r.body);
          return body.active === true;
        } catch (e) {
          return false;
        }
      },
      'introspection: response time < 300ms': (r) => r.timings.duration < 300,
    });
  }
}

function testPAREndpoint(baseURL) {
  const payload = {
    response_type: 'code',
    redirect_uri: 'https://example.com/callback',
    scope: 'openid profile',
    code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
    code_challenge_method: 'S256',
    state: `state-${Date.now()}`,
    nonce: `nonce-${Date.now()}`,
  };

  const params = {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': `Basic ${credentials}`,
    },
    tags: { name: 'PAREndpoint' },
  };

  const res = http.post(
    `${baseURL}/oauth/par`,
    Object.keys(payload).map(key => `${key}=${encodeURIComponent(payload[key])}`).join('&'),
    params
  );

  check(res, {
    'par: status is 201': (r) => r.status === 201,
    'par: has request_uri': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.request_uri !== undefined;
      } catch (e) {
        return false;
      }
    },
    'par: has expires_in': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.expires_in === 90;
      } catch (e) {
        return false;
      }
    },
    'par: response time < 400ms': (r) => r.timings.duration < 400,
  });
}

export function handleSummary(data) {
  return {
    'stdout': textSummary(data, { indent: ' ', enableColors: true }),
    'summary.json': JSON.stringify(data),
  };
}

function textSummary(data, { indent = '', enableColors = false } = {}) {
  const rate = (metric) => {
    if (metric.values.rate !== undefined) {
      return (metric.values.rate * 100).toFixed(2) + '%';
    }
    return 'N/A';
  };

  const duration = (metric) => {
    if (metric.values.avg !== undefined) {
      return `avg=${metric.values.avg.toFixed(2)}ms p95=${metric.values['p(95)'].toFixed(2)}ms`;
    }
    return 'N/A';
  };

  return `
${indent}✓ Metrics Summary:
${indent}  Requests: ${data.metrics.http_reqs?.values.count || 0}
${indent}  Failed: ${rate(data.metrics.http_req_failed || {})}
${indent}  Duration: ${duration(data.metrics.http_req_duration || {})}
${indent}  Custom Metrics:
${indent}    Error Rate: ${rate(data.metrics.errors || {})}
${indent}    Successful Tokens: ${data.metrics.successful_tokens?.values.count || 0}
${indent}    Token Duration: ${duration(data.metrics.token_request_duration || {})}
${indent}    Discovery Duration: ${duration(data.metrics.discovery_duration || {})}
`;
}
