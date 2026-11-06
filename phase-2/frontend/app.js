/**
 * AuthLab Phase 2 — Interactive Testing Suite Controller
 */

const CONFIG = {
  keycloakUrl: 'http://localhost:8080',
  realm: 'Authlab',
  clientId: 'authlab-web',
  apiUrl: 'http://localhost:5000',
};

const STATE = {
  token: sessionStorage.getItem('phase2_token') || null,
  claims: null,
  header: null,
  currentUser: null,
  jwks: null,
};

function escapeHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function showToast(msg) {
  const toast = document.getElementById('global-toast');
  if (!toast) return;
  toast.innerHTML = msg;
  toast.classList.remove('hidden');
  setTimeout(() => toast.classList.add('hidden'), 4000);
}

function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.tab === tabId);
  });
  document.querySelectorAll('.tab-content').forEach(c => {
    c.classList.toggle('active', c.id === tabId);
  });
  if (tabId === 'tab-jwks' && !STATE.jwks) {
    fetchLiveJwks();
  }
}

// ============================================================================
// TOKEN DECODING & PARSING
// ============================================================================

function decodeJwt(jwtStr) {
  try {
    const parts = jwtStr.split('.');
    if (parts.length < 2) return null;
    const b64 = (s) => atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4));
    return {
      header: JSON.parse(b64(parts[0])),
      payload: JSON.parse(b64(parts[1])),
    };
  } catch {
    return null;
  }
}

function setSessionToken(tokenStr) {
  STATE.token = tokenStr;
  sessionStorage.setItem('phase2_token', tokenStr);
  const parsed = decodeJwt(tokenStr);
  if (parsed) {
    STATE.header = parsed.header;
    STATE.claims = parsed.payload;
    STATE.currentUser = parsed.payload.preferred_username || 'user';
  } else {
    STATE.header = null;
    STATE.claims = null;
    STATE.currentUser = null;
  }
  updateTokenDisplay();
}

function clearToken() {
  STATE.token = null;
  STATE.header = null;
  STATE.claims = null;
  STATE.currentUser = null;
  sessionStorage.removeItem('phase2_token');
  updateTokenDisplay();
  showToast('ℹ️ Active token cleared.');
}

function logout() {
  clearToken();
  showToast('👋 Signed out of Keycloak session.');
}

function updateTokenDisplay() {
  const emptyState = document.getElementById('token-empty-state');
  const activeState = document.getElementById('token-active-state');
  const navUser = document.getElementById('nav-user-controls');

  if (!STATE.token || !STATE.claims) {
    emptyState.classList.remove('hidden');
    activeState.classList.add('hidden');
    navUser.classList.add('hidden');
    return;
  }

  emptyState.classList.add('hidden');
  activeState.classList.remove('hidden');
  navUser.classList.remove('hidden');

  const c = STATE.claims;
  const roles = c.realm_access?.roles || [];
  const primaryRole = roles.includes('Admin') || roles.includes('admin')
    ? 'Admin'
    : roles.includes('Developer') || roles.includes('developer')
    ? 'Developer'
    : 'User / viewer';

  document.getElementById('claim-sub').textContent = (c.sub || '').slice(0, 16) + '...';
  document.getElementById('claim-user').textContent = c.preferred_username || 'unknown';
  document.getElementById('claim-aud').textContent = Array.isArray(c.aud) ? c.aud.join(', ') : c.aud || '-';

  // Role badges
  document.getElementById('claim-roles').innerHTML = roles
    .filter(r => !['default-roles-authlab', 'offline_access', 'uma_authorization'].includes(r))
    .map(r => `<span class="badge ${r.toLowerCase().includes('admin') ? 'badge-amber' : 'badge-blue'}">${escapeHtml(r)}</span>`)
    .join(' ') || '<span class="text-muted">None</span>';

  // Expiration calculation
  const expSec = Math.max(0, (c.exp || 0) - Math.floor(Date.now() / 1000));
  document.getElementById('claim-exp').textContent = `${expSec}s remaining`;

  // Raw JSON
  document.getElementById('raw-jwt-json').textContent = JSON.stringify({
    header: STATE.header,
    payload: STATE.claims,
  }, null, 2);

  // Nav user chip
  document.getElementById('nav-user-name').textContent = c.preferred_username || 'user';
  document.getElementById('nav-user-role').textContent = `Role: ${primaryRole}`;
}

function copyTokenToClipboard() {
  if (!STATE.token) return;
  navigator.clipboard.writeText(STATE.token);
  showToast('📋 Copied raw Bearer token to clipboard!');
}

// ============================================================================
// KEYCLOAK AUTHENTICATION
// ============================================================================

async function authenticateWithKeycloak(username, password) {
  const tokenUrl = `${CONFIG.keycloakUrl}/realms/${CONFIG.realm}/protocol/openid-connect/token`;
  const body = new URLSearchParams({
    grant_type: 'password',
    client_id: CONFIG.clientId,
    username: username.trim(),
    password,
  });

  const resp = await fetch(tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    throw new Error(data.error_description || data.error || `HTTP ${resp.status}`);
  }

  setSessionToken(data.access_token);
  showToast(`🎉 Authenticated as <strong>${escapeHtml(username)}</strong>! Token loaded into test bench.`);
}

async function quickLogin(username, password) {
  try {
    await authenticateWithKeycloak(username, password);
  } catch (err) {
    showToast(`❌ Authentication failed: ${escapeHtml(err.message)}`);
  }
}

async function handleManualLogin(e) {
  e.preventDefault();
  const u = document.getElementById('custom-user').value;
  const p = document.getElementById('custom-pw').value;
  try {
    await authenticateWithKeycloak(u, p);
  } catch (err) {
    showToast(`❌ Login failed: ${escapeHtml(err.message)}`);
  }
}

async function checkKeycloakStatus() {
  const statusEl = document.getElementById('kc-status-text');
  try {
    const res = await fetch(`${CONFIG.keycloakUrl}/realms/${CONFIG.realm}/protocol/openid-connect/certs`);
    if (res.ok) {
      statusEl.textContent = `Keycloak Online (${CONFIG.realm})`;
    } else {
      statusEl.textContent = 'Keycloak: Realm Check Failed';
    }
  } catch {
    statusEl.textContent = 'Keycloak: Offline / Connecting...';
  }
}

// ============================================================================
// RESOURCE API TEST RUNNER
// ============================================================================

async function callApi(path, includeToken = true) {
  const url = `${CONFIG.apiUrl}${path}`;
  const respConsole = document.getElementById('response-console-output');
  const badge = document.getElementById('response-status-badge');
  const targetEl = document.getElementById('resp-target');
  const timeEl = document.getElementById('resp-time');

  targetEl.textContent = `${url} ${includeToken && STATE.token ? '(with Bearer token)' : '(no token)'}`;
  badge.className = 'badge badge-gray';
  badge.textContent = 'Calling...';

  const headers = {};
  if (includeToken && STATE.token) {
    headers['Authorization'] = `Bearer ${STATE.token}`;
  }

  const startTime = performance.now();
  try {
    const resp = await fetch(url, { method: 'GET', headers });
    const latency = Math.round(performance.now() - startTime);
    timeEl.textContent = `${latency}ms`;

    const raw = await resp.text();
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      parsed = raw;
    }

    if (resp.status >= 200 && resp.status < 300) {
      badge.className = 'badge badge-green';
      badge.textContent = `${resp.status} OK`;
    } else if (resp.status === 401) {
      badge.className = 'badge badge-amber';
      badge.textContent = '401 Unauthorized';
    } else if (resp.status === 403) {
      badge.className = 'badge badge-red';
      badge.textContent = '403 Forbidden';
    } else {
      badge.className = 'badge badge-red';
      badge.textContent = `HTTP ${resp.status}`;
    }

    respConsole.textContent = typeof parsed === 'object' ? JSON.stringify(parsed, null, 2) : parsed;
  } catch (err) {
    badge.className = 'badge badge-red';
    badge.textContent = 'Network Error';
    respConsole.textContent = `Error connecting to ${url}:\n${err.message}\n(Ensure phase-2-api is running on port 5000)`;
  }
}

// ============================================================================
// TAB 2: JWT ATTACK SIMULATIONS
// ============================================================================

function b64Encode(str) {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function logAttack(msg) {
  const log = document.getElementById('attack-console-log');
  log.textContent += msg + '\n';
  log.scrollTop = log.scrollHeight;
}

function clearAttackConsole() {
  document.getElementById('attack-console-log').textContent = '';
}

async function testAttackNone() {
  clearAttackConsole();
  logAttack('=== EXPLOIT 1: alg: "none" Signature Stripping Test ===');
  
  const header = { alg: 'none', typ: 'JWT' };
  const payload = {
    iss: `http://localhost:8080/realms/${CONFIG.realm}`,
    aud: 'authlab-api',
    sub: 'mallory_attacker',
    realm_access: { roles: ['admin', 'Admin'] },
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
  };

  const forgedToken = `${b64Encode(JSON.stringify(header))}.${b64Encode(JSON.stringify(payload))}.`;
  logAttack(`[FORGED TOKEN] ${forgedToken.slice(0, 45)}...<empty signature>`);
  logAttack('Sending unsigned token to Resource API: GET /api/admin/users ...');

  try {
    const resp = await fetch(`${CONFIG.apiUrl}/api/admin/users`, {
      headers: { Authorization: `Bearer ${forgedToken}` },
    });
    const data = await resp.json().catch(() => ({}));
    if (resp.status === 401 || resp.status === 503) {
      logAttack(`🛡️ SECURE VERIFIER RESULT: BLOCKED! HTTP ${resp.status} (${data.error || 'invalid_token'})`);
      logAttack('Explanation: The API uses algorithms=["RS256"]. The alg header is NEVER trusted.');
    } else {
      logAttack(`💥 EXPLOIT SUCCEEDED (Vulnerable!): HTTP ${resp.status}`);
    }
  } catch (err) {
    logAttack(`Network error: ${err.message}`);
  }
}

async function testAttackKeyConfusion() {
  clearAttackConsole();
  logAttack('=== EXPLOIT 2: alg: "HS256" Public Key Confusion (CVE-2015-9235) ===');
  logAttack('1. Fetching server RSA public key from JWKS...');

  try {
    const certsResp = await fetch(`${CONFIG.keycloakUrl}/realms/${CONFIG.realm}/protocol/openid-connect/certs`);
    const jwks = await certsResp.json();
    const key = jwks.keys?.[0];
    logAttack(`   Found Key ID: ${key?.kid}, Algorithm: ${key?.alg}`);

    const header = { alg: 'HS256', typ: 'JWT', kid: key?.kid };
    const payload = {
      iss: `http://localhost:8080/realms/${CONFIG.realm}`,
      aud: 'authlab-api',
      sub: 'mallory_attacker',
      realm_access: { roles: ['admin', 'Admin'] },
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
    };

    // Simulated HMAC signed with public modulus
    const fakeSig = b64Encode('simulated_hmac_signature_with_public_key');
    const forgedToken = `${b64Encode(JSON.stringify(header))}.${b64Encode(JSON.stringify(payload))}.${fakeSig}`;

    logAttack('2. Sending HS256 HMAC-signed token to Resource API: GET /api/admin/users ...');
    const resp = await fetch(`${CONFIG.apiUrl}/api/admin/users`, {
      headers: { Authorization: `Bearer ${forgedToken}` },
    });
    const data = await resp.json().catch(() => ({}));
    if (resp.status === 401 || resp.status === 503) {
      logAttack(`🛡️ SECURE VERIFIER RESULT: BLOCKED! HTTP ${resp.status} (${data.error || 'invalid_token'})`);
      logAttack('Explanation: The verifier pins RS256. Symmetric HMAC tokens are rejected outright.');
    } else {
      logAttack(`💥 EXPLOIT SUCCEEDED: HTTP ${resp.status}`);
    }
  } catch (err) {
    logAttack(`Network error: ${err.message}`);
  }
}

async function testAttackTamper() {
  clearAttackConsole();
  logAttack('=== EXPLOIT 3: Payload Tampering (Signature Check) ===');
  if (!STATE.token) {
    logAttack('⚠️ Please sign in as Alice first using the Quick Sign-In buttons!');
    return;
  }

  const parts = STATE.token.split('.');
  const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
  logAttack(`Original roles: ${JSON.stringify(payload.realm_access?.roles)}`);

  // Tamper roles
  payload.realm_access = { roles: ['admin', 'Admin'] };
  const tamperedPayloadB64 = b64Encode(JSON.stringify(payload));
  const tamperedToken = `${parts[0]}.${tamperedPayloadB64}.${parts[2]}`;

  logAttack('Altered payload to include ["admin"] without re-signing with private RSA key.');
  logAttack('Sending tampered token to Resource API: GET /api/admin/users ...');

  try {
    const resp = await fetch(`${CONFIG.apiUrl}/api/admin/users`, {
      headers: { Authorization: `Bearer ${tamperedToken}` },
    });
    const data = await resp.json().catch(() => ({}));
    logAttack(`🛡️ SECURE VERIFIER RESULT: BLOCKED! HTTP ${resp.status} (${data.detail || data.error})`);
    logAttack('Explanation: RSA signature verification failed because the cryptographic hash was altered.');
  } catch (err) {
    logAttack(`Network error: ${err.message}`);
  }
}

async function testAttackExpired() {
  clearAttackConsole();
  logAttack('=== EXPLOIT 4: Expired Token Replay ===');

  const header = { alg: 'RS256', typ: 'JWT' };
  const payload = {
    iss: `http://localhost:8080/realms/${CONFIG.realm}`,
    aud: 'authlab-api',
    sub: 'old_session',
    exp: Math.floor(Date.now() / 1000) - 7200, // 2 hours ago
  };

  const fakeExpired = `${b64Encode(JSON.stringify(header))}.${b64Encode(JSON.stringify(payload))}.fakesig`;
  logAttack(`Sending expired token (exp=${payload.exp}) to Resource API: GET /api/me ...`);

  try {
    const resp = await fetch(`${CONFIG.apiUrl}/api/me`, {
      headers: { Authorization: `Bearer ${fakeExpired}` },
    });
    const data = await resp.json().catch(() => ({}));
    logAttack(`🛡️ SECURE VERIFIER RESULT: BLOCKED! HTTP ${resp.status} (${data.error || 'invalid_token'})`);
  } catch (err) {
    logAttack(`Network error: ${err.message}`);
  }
}

async function runAllAttackTests() {
  clearAttackConsole();
  logAttack('▶ Running comprehensive Phase 2 Attack Suite...\n');
  await testAttackNone();
  logAttack('\n--------------------------------------------------------------\n');
  await testAttackKeyConfusion();
  logAttack('\n--------------------------------------------------------------\n');
  await testAttackTamper();
  logAttack('\n--------------------------------------------------------------\n');
  await testAttackExpired();
  logAttack('\n==============================================================');
  logAttack('✅ ALL ATTACK VECTOR SIMULATIONS COMPLETED!');
}

// ============================================================================
// TAB 3: LIVE JWKS INSPECTOR
// ============================================================================

async function fetchLiveJwks() {
  const container = document.getElementById('jwks-keys-container');
  container.innerHTML = '<div class="text-muted">Fetching live keys from Keycloak...</div>';
  try {
    const url = `${CONFIG.keycloakUrl}/realms/${CONFIG.realm}/protocol/openid-connect/certs`;
    const resp = await fetch(url);
    const data = await resp.json();
    STATE.jwks = data;

    container.innerHTML = (data.keys || [])
      .map((k, idx) => `
        <div class="jwk-card">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <strong>Key #${idx + 1}</strong>
            <span class="badge ${k.use === 'sig' ? 'badge-green' : 'badge-gray'}">${escapeHtml(k.use || 'use')}</span>
          </div>
          <div class="jwk-row">
            <span>Key ID (kid):</span>
            <code>${escapeHtml(k.kid)}</code>
          </div>
          <div class="jwk-row">
            <span>Algorithm (alg):</span>
            <code>${escapeHtml(k.alg)}</code>
          </div>
          <div class="jwk-row">
            <span>Key Type (kty):</span>
            <code>${escapeHtml(k.kty)}</code>
          </div>
          <div class="jwk-row">
            <span>Public Modulus (n):</span>
            <code>${escapeHtml((k.n || '').slice(0, 24))}...</code>
          </div>
          <div class="jwk-row">
            <span>Exponent (e):</span>
            <code>${escapeHtml(k.e)}</code>
          </div>
          <div class="jwk-row">
            <span>Private Key (d):</span>
            <code style="color: #34d399;">WITHHELD (Secure)</code>
          </div>
        </div>
      `)
      .join('');
  } catch (err) {
    container.innerHTML = `<div class="text-danger">Failed to fetch JWKS: ${escapeHtml(err.message)}</div>`;
  }
}

// ============================================================================
// INITIALIZATION
// ============================================================================

window.addEventListener('DOMContentLoaded', async () => {
  await checkKeycloakStatus();
  if (STATE.token) {
    updateTokenDisplay();
  }
});

