import { test, expect } from '@playwright/test';

test.describe('OAuth Authorization Flow', () => {
  test('should complete authorization code flow', async ({ page }) => {
    // Navigate to authorization endpoint with proper parameters
    const authParams = new URLSearchParams({
      response_type: 'code',
      client_id: 'test-client-id',
      redirect_uri: 'https://example.com/callback',
      scope: 'openid profile email',
      state: 'random-state',
      code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
      code_challenge_method: 'S256',
    });

    await page.goto(`/oauth/authorize?${authParams.toString()}`);

    // Should show authorization consent screen
    await expect(page.locator('text=/Authorize|Grant Access/i')).toBeVisible();

    // Check that client name and requested scopes are displayed
    await expect(page.locator('text=/Test Application/i')).toBeVisible();
    await expect(page.locator('text=/openid|profile|email/i')).toBeVisible();
  });

  test('should retrieve OpenID configuration', async ({ page }) => {
    const response = await page.request.get('/.well-known/openid-configuration');

    expect(response.ok()).toBeTruthy();

    const config = await response.json();
    expect(config.issuer).toBeTruthy();
    expect(config.authorization_endpoint).toContain('/oauth/authorize');
    expect(config.token_endpoint).toContain('/oauth/token');
    expect(config.jwks_uri).toContain('/.well-known/jwks.json');
    expect(config.userinfo_endpoint).toContain('/oauth/userinfo');
  });

  test('should retrieve JWKS', async ({ page }) => {
    const response = await page.request.get('/.well-known/jwks.json');

    expect(response.ok()).toBeTruthy();

    const jwks = await response.json();
    expect(jwks.keys).toBeDefined();
    expect(Array.isArray(jwks.keys)).toBeTruthy();
    expect(jwks.keys.length).toBeGreaterThan(0);

    const key = jwks.keys[0];
    expect(key.kty).toBe('RSA');
    expect(key.kid).toBeTruthy();
    expect(key.n).toBeTruthy();
    expect(key.e).toBeTruthy();
  });

  test('should create PAR request', async ({ page }) => {
    const parData = new URLSearchParams({
      response_type: 'code',
      redirect_uri: 'https://example.com/callback',
      scope: 'openid profile',
      code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
      code_challenge_method: 'S256',
      state: 'random-state',
    });

    const clientId = 'test-client-id';
    const clientSecret = 'test-secret';
    const credentials = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');

    const response = await page.request.post('/oauth/par', {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${credentials}`,
      },
      data: parData.toString(),
    });

    expect(response.ok()).toBeTruthy();

    const parResponse = await response.json();
    expect(parResponse.request_uri).toBeTruthy();
    expect(parResponse.request_uri).toContain('urn:ietf:params:oauth:request_uri:');
    expect(parResponse.expires_in).toBe(90);
  });

  test('should obtain access token via client credentials', async ({ page }) => {
    const tokenData = new URLSearchParams({
      grant_type: 'client_credentials',
      scope: 'openid profile',
    });

    const clientId = 'test-client-id';
    const clientSecret = 'test-secret';
    const credentials = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');

    const response = await page.request.post('/oauth/token', {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${credentials}`,
      },
      data: tokenData.toString(),
    });

    expect(response.ok()).toBeTruthy();

    const tokenResponse = await response.json();
    expect(tokenResponse.access_token).toBeTruthy();
    expect(tokenResponse.token_type).toBe('Bearer');
    expect(tokenResponse.expires_in).toBeTruthy();
  });

  test('should introspect token', async ({ page }) => {
    // First get a token
    const tokenData = new URLSearchParams({
      grant_type: 'client_credentials',
      scope: 'openid',
    });

    const clientId = 'test-client-id';
    const clientSecret = 'test-secret';
    const credentials = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');

    const tokenResponse = await page.request.post('/oauth/token', {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${credentials}`,
      },
      data: tokenData.toString(),
    });

    const tokenJson = await tokenResponse.json();
    const accessToken = tokenJson.access_token;

    // Introspect the token
    const introspectData = new URLSearchParams({
      token: accessToken,
    });

    const introspectResponse = await page.request.post('/oauth/introspect', {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${credentials}`,
      },
      data: introspectData.toString(),
    });

    expect(introspectResponse.ok()).toBeTruthy();

    const introspectJson = await introspectResponse.json();
    expect(introspectJson.active).toBe(true);
    expect(introspectJson.client_id).toBe(clientId);
  });

  test('should revoke token', async ({ page }) => {
    // Get a token first
    const tokenData = new URLSearchParams({
      grant_type: 'client_credentials',
      scope: 'openid',
    });

    const clientId = 'test-client-id';
    const clientSecret = 'test-secret';
    const credentials = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');

    const tokenResponse = await page.request.post('/oauth/token', {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${credentials}`,
      },
      data: tokenData.toString(),
    });

    const tokenJson = await tokenResponse.json();
    const accessToken = tokenJson.access_token;

    // Revoke the token
    const revokeData = new URLSearchParams({
      token: accessToken,
      token_type_hint: 'access_token',
    });

    const revokeResponse = await page.request.post('/oauth/revoke', {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${credentials}`,
      },
      data: revokeData.toString(),
    });

    expect(revokeResponse.ok()).toBeTruthy();
  });
});
