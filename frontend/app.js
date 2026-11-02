/**
 * AuthLab — Interactive Login & Access Security X-Ray
 */

const CONFIG = {
  keycloakUrl: 'http://localhost:8080',
  apiUrl: 'http://localhost:5001',
  realm: 'authlab',
  clientId: 'authlab-web',
};

const STATE = {
  currentUsername: null,
  currentToken: null,
  currentTokenPayload: null,
  currentTargetEndpoint: '/api/admin/users',
  cachedTokens: {},
  knownPasswords: {
    alice: 'alice123',
    bob: 'bob123',
  },
  tokenCountdownTimer: null,
};

// Base64URL helper to decode JWT header and payload
function base64UrlDecode(str) {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  return decodeURIComponent(
    atob(base64)
      .split('')
      .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
      .join('')
  );
}

// Initialization on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  checkSystemHealth();
  // Auto-run initial login check for Alice on /api/admin/users to demonstrate the 403 error immediately
  handleLoginAndAccess();
  // Poll backend audit logs periodically
  setInterval(fetchRecentAuditLog, 2500);
});

// Check health of Keycloak (:8080) and Flask API (:5001)
async function checkSystemHealth() {
  try {
    const kcResp = await fetch(`${CONFIG.keycloakUrl}/realms/${CONFIG.realm}/.well-known/openid-configuration`);
    if (kcResp.ok) {
      document.getElementById('keycloak-status-text').textContent = 'Online (:8080)';
      document.getElementById('keycloak-status-dot').style.backgroundColor = 'var(--success)';
    } else {
      throw new Error();
    }
  } catch (err) {
    document.getElementById('keycloak-status-text').textContent = 'Offline';
    document.getElementById('keycloak-status-dot').style.backgroundColor = 'var(--danger)';
  }

  try {
    const apiResp = await fetch(`${CONFIG.apiUrl}/health`);
    if (apiResp.ok) {
      document.getElementById('api-status-text').textContent = 'Online (:5001)';
      document.getElementById('api-status-dot').style.backgroundColor = 'var(--success)';
    } else {
      throw new Error();
    }
  } catch (err) {
    document.getElementById('api-status-text').textContent = 'Offline';
    document.getElementById('api-status-dot').style.backgroundColor = 'var(--danger)';
  }
}

// Switch between Sign In and Register New User modes
function switchAuthMode(mode) {
  const loginView = document.getElementById('view-login-mode');
  const regView = document.getElementById('view-register-mode');
  const loginTab = document.getElementById('tab-mode-login');
  const regTab = document.getElementById('tab-mode-register');
  const panelIcon = document.getElementById('auth-panel-icon');
  const panelTitle = document.getElementById('auth-panel-title');
  const panelBadge = document.getElementById('auth-panel-badge');

  if (mode === 'register') {
    if (loginView) loginView.style.display = 'none';
    if (regView) regView.style.display = 'block';
    if (loginTab) loginTab.classList.remove('active');
    if (regTab) regTab.classList.add('active');
    if (panelIcon) panelIcon.textContent = '✨';
    if (panelTitle) panelTitle.textContent = 'Register Keycloak User';
    if (panelBadge) {
      panelBadge.textContent = 'Keycloak Admin API';
      panelBadge.style.background = 'rgba(16, 185, 129, 0.15)';
      panelBadge.style.color = '#6ee7b7';
      panelBadge.style.borderColor = 'rgba(16, 185, 129, 0.35)';
    }
  } else {
    if (loginView) loginView.style.display = 'block';
    if (regView) regView.style.display = 'none';
    if (loginTab) loginTab.classList.add('active');
    if (regTab) regTab.classList.remove('active');
    if (panelIcon) panelIcon.textContent = '🔐';
    if (panelTitle) panelTitle.textContent = 'User Login & Access';
    if (panelBadge) {
      panelBadge.textContent = 'Keycloak Direct Grant';
      panelBadge.style.background = 'rgba(99, 102, 241, 0.15)';
      panelBadge.style.color = '#a5b4fc';
      panelBadge.style.borderColor = 'rgba(99, 102, 241, 0.3)';
    }
  }
}

// Add or update a quick-fill button for a newly registered user
function addQuickFillAccount(username, password, role) {
  if (password) {
    STATE.knownPasswords[username] = password;
  }
  const grid = document.getElementById('quick-fill-accounts-grid');
  if (!grid) return;

  const btnId = `btn-quick-${username}`;
  let btn = document.getElementById(btnId);
  const roleLabel = role.charAt(0).toUpperCase() + role.slice(1);
  const icon = role === 'admin' ? '🛡️' : role === 'developer' ? '🧑‍💻' : '👩‍💻';
  const subText = role === 'admin' ? 'Gets 200 on Admin' : 'Gets 403 on Admin';
  const subColor = role === 'admin' ? '#fcd34d' : '#93c5fd';

  if (!btn) {
    btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'quick-fill-btn';
    btn.id = btnId;
    grid.appendChild(btn);
  }

  btn.onclick = () => quickFillCredentials(username, STATE.knownPasswords[username] || password, role);
  btn.innerHTML = `
    <span>${icon}</span>
    <div style="text-align: left;">
      <div style="font-weight: 600;">${escapeHtml(username)} (${escapeHtml(roleLabel)})</div>
      <div style="font-size: 0.7rem; color: ${subColor};">${subText}</div>
    </div>
  `;
}

// Handle Register New User submission via Flask -> Keycloak Admin API
async function handleRegisterUser(event) {
  if (event) event.preventDefault();

  const usernameInput = document.getElementById('reg-username');
  const passwordInput = document.getElementById('reg-password');
  const emailInput = document.getElementById('reg-email');
  const roleSelect = document.getElementById('reg-role');
  const feedbackEl = document.getElementById('register-feedback');
  const submitBtn = document.getElementById('btn-submit-register');
  const submitText = document.getElementById('btn-submit-register-text');

  const username = (usernameInput?.value || '').trim().toLowerCase();
  const password = (passwordInput?.value || '').trim();
  const email = (emailInput?.value || '').trim();
  const role = roleSelect?.value || 'viewer';

  if (submitBtn) submitBtn.disabled = true;
  if (submitText) submitText.textContent = 'Provisioning in Keycloak...';
  if (feedbackEl) {
    feedbackEl.style.display = 'block';
    feedbackEl.style.background = 'rgba(99, 102, 241, 0.12)';
    feedbackEl.style.border = '1px solid rgba(99, 102, 241, 0.3)';
    feedbackEl.style.color = '#c7d2fe';
    feedbackEl.textContent = `Creating user "${username}" in Keycloak realm "${CONFIG.realm}" with role "${role}"...`;
  }

  try {
    const resp = await fetch(`${CONFIG.apiUrl}/api/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, email, role }),
    });

    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      throw new Error(data.detail || data.error || `HTTP ${resp.status}`);
    }

    // Clear any cached token for this username
    delete STATE.cachedTokens[username];

    // Add quick-fill button for the newly registered user
    addQuickFillAccount(username, password, role);

    // Show success message
    if (feedbackEl) {
      feedbackEl.style.background = 'rgba(16, 185, 129, 0.15)';
      feedbackEl.style.border = '1px solid rgba(16, 185, 129, 0.4)';
      feedbackEl.style.color = '#6ee7b7';
      feedbackEl.innerHTML = `
        <strong>✓ Registered in Keycloak!</strong> User <code>${escapeHtml(username)}</code> created with realm role <code>${escapeHtml(role)}</code>. Signing in and running X-Ray...
      `;
    }

    // Clear registration inputs
    if (usernameInput) usernameInput.value = '';
    if (passwordInput) passwordInput.value = '';
    if (emailInput) emailInput.value = '';

    // Automatically populate login form and authenticate as the new user
    setTimeout(() => {
      switchAuthMode('login');
      quickFillCredentials(username, password, role);
    }, 650);

  } catch (err) {
    if (feedbackEl) {
      feedbackEl.style.background = 'rgba(239, 68, 68, 0.15)';
      feedbackEl.style.border = '1px solid rgba(239, 68, 68, 0.4)';
      feedbackEl.style.color = '#fca5a5';
      feedbackEl.innerHTML = `<strong>✗ Registration Failed:</strong> ${escapeHtml(err.message)}`;
    }
  } finally {
    if (submitBtn) submitBtn.disabled = false;
    if (submitText) submitText.textContent = 'Register in Keycloak & Sign In';
  }
}

// Quick fill helper: updates inputs and pill highlights
function quickFillCredentials(username, password, role) {
  const actualPassword = STATE.knownPasswords[username] || password;
  switchAuthMode('login');
  document.getElementById('login-username').value = username;
  document.getElementById('login-password').value = actualPassword;
  document.getElementById('target-endpoint').value = '/api/admin/users';

  document.querySelectorAll('.quick-fill-btn').forEach(btn => btn.classList.remove('active'));
  const activeBtn = document.getElementById(`btn-quick-${username}`);
  if (activeBtn) activeBtn.classList.add('active');

  // Trigger login & access check directly for instant feedback
  handleLoginAndAccess();
}

// One-click helper to sign in as Bob (Admin) and unlock the Admin Console
function unlockAdminAsBob() {
  quickFillCredentials('bob', STATE.knownPasswords.bob || 'bob123', 'admin');
}

// Fetch token directly from Keycloak via Password Grant
async function fetchKeycloakToken(username, password) {
  const tokenEndpoint = `${CONFIG.keycloakUrl}/realms/${CONFIG.realm}/protocol/openid-connect/token`;
  const body = new URLSearchParams({
    grant_type: 'password',
    client_id: CONFIG.clientId,
    username: username,
    password: password,
  });

  const resp = await fetch(tokenEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  if (!resp.ok) {
    const errData = await resp.json().catch(() => ({}));
    throw new Error(errData.error_description || errData.error || `HTTP ${resp.status}`);
  }

  const data = await resp.json();
  return {
    accessToken: data.access_token,
    expiresIn: data.expires_in || 300,
  };
}

// Core Handler: User submits username + password and requests access to endpoint
async function handleLoginAndAccess(event) {
  if (event) event.preventDefault();

  const usernameInput = document.getElementById('login-username');
  const passwordInput = document.getElementById('login-password');
  const endpointSelect = document.getElementById('target-endpoint');
  const submitBtn = document.getElementById('btn-submit-login');
  const submitText = document.getElementById('btn-submit-text');

  const username = usernameInput ? usernameInput.value.trim() : 'alice';
  const password = passwordInput ? passwordInput.value.trim() : 'alice123';
  const targetEndpoint = endpointSelect ? endpointSelect.value : '/api/admin/users';
  STATE.currentTargetEndpoint = targetEndpoint;

  // Visual indication of active request
  if (submitBtn) submitBtn.disabled = true;
  if (submitText) submitText.textContent = 'Authenticating & Requesting...';

  const startTime = performance.now();

  try {
    // 1. Authenticate live with Keycloak (always verify current credentials & enabled status)
    const authResult = await fetchKeycloakToken(username, password);
    const token = authResult.accessToken;
    const expiresIn = authResult.expiresIn;
    STATE.cachedTokens[username] = token;
    STATE.knownPasswords[username] = password;

    STATE.currentToken = token;
    STATE.currentUsername = username;

    // Decode token segments
    const parts = token.split('.');
    const header = JSON.parse(base64UrlDecode(parts[0]));
    const payload = JSON.parse(base64UrlDecode(parts[1]));
    STATE.currentTokenPayload = payload;

    const roles = payload.realm_access?.roles || [];
    const appRoles = roles.filter(r => ['viewer', 'admin', 'developer'].includes(r));
    const primaryRole = appRoles.includes('admin') ? 'admin' : appRoles.includes('viewer') ? 'viewer' : 'custom';

    // Update Session Pill
    updateSessionDisplay(username, appRoles, expiresIn, true);

    // Update Step 1 in Trace
    document.getElementById('trace-step1-user').textContent = username;
    document.getElementById('trace-step1-roles').textContent = JSON.stringify(appRoles.length ? appRoles : ['none']);
    document.getElementById('trace-step1-badge').className = 'xray-step-status status-ok';
    document.getElementById('trace-step1-badge').textContent = '✓ Token Issued';

    // 2. Request Target Resource from Flask API with Bearer token
    const apiTargetUrl = `${CONFIG.apiUrl}${targetEndpoint}`;
    document.getElementById('data-target-url').textContent = `GET ${apiTargetUrl}`;

    const apiResp = await fetch(apiTargetUrl, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    const latency = Math.round(performance.now() - startTime);
    document.getElementById('decision-latency').textContent = `${latency}ms`;

    const responseData = await apiResp.json().catch(async () => ({ text: await apiResp.text() }));
    document.getElementById('verified-live-data').textContent = JSON.stringify(responseData, null, 2);

    // 3. Update Access Decision Banner & X-Ray Trace according to HTTP Status
    evaluateAccessDecision(apiResp.status, username, appRoles, targetEndpoint, header, responseData);

    // 4. Update the bottom matrix for all 4 routes
    await refreshAllEndpoints();
    fetchRecentAuditLog();

  } catch (err) {
    const latency = Math.round(performance.now() - startTime);
    document.getElementById('decision-latency').textContent = `${latency}ms`;

    // Display Authentication Error from Keycloak
    renderKeycloakAuthError(err.message, username);
  } finally {
    if (submitBtn) submitBtn.disabled = false;
    if (submitText) submitText.textContent = 'Login & Request Access';
  }
}

// Update Active Session Pill
function updateSessionDisplay(username, roles, expiresIn, isAuthenticated) {
  const avatar = document.getElementById('session-avatar');
  const userDisplay = document.getElementById('session-username-display');
  const rolesDisplay = document.getElementById('session-roles-display');
  const badge = document.getElementById('session-badge');

  if (!isAuthenticated) {
    avatar.textContent = '🚫';
    userDisplay.textContent = 'Anonymous (No Token)';
    rolesDisplay.textContent = 'roles: none';
    badge.className = 'decision-badge dec-AUTH_ERROR_401';
    badge.textContent = 'UNAUTHENTICATED';
    startCountdown(0);
    return;
  }

  const isAdmin = roles.includes('admin');
  const isDev = roles.includes('developer');
  const roleTitle = isAdmin ? 'Admin' : isDev ? 'Developer' : 'Viewer';
  avatar.textContent = isAdmin ? '🛡️' : isDev ? '🧑‍💻' : '👩‍💻';
  userDisplay.textContent = `${username} (${roleTitle})`;
  rolesDisplay.textContent = `roles: ${JSON.stringify(roles)}`;
  badge.className = 'decision-badge dec-ALLOWED';
  badge.textContent = 'AUTHENTICATED';
  startCountdown(expiresIn);
}

// Evaluate and render the Access Decision and Security X-Ray Trace
function evaluateAccessDecision(status, username, roles, endpoint, header, responseData) {
  const banner = document.getElementById('decision-banner');
  const icon = document.getElementById('decision-icon');
  const statusBadge = document.getElementById('decision-status-badge');
  const headline = document.getElementById('decision-headline');
  const explanation = document.getElementById('decision-explanation');

  const traceStep2Kid = document.getElementById('trace-step2-kid');
  const traceStep2Sig = document.getElementById('trace-step2-sig');
  const traceStep2Exp = document.getElementById('trace-step2-exp');
  const traceStep2Badge = document.getElementById('trace-step2-badge');

  const traceStep3Req = document.getElementById('trace-step3-req');
  const traceStep3Prov = document.getElementById('trace-step3-prov');
  const traceStep3Dec = document.getElementById('trace-step3-dec');
  const traceStep3Badge = document.getElementById('trace-step3-badge');

  // Step 2 details (Flask signature validation)
  traceStep2Kid.textContent = header?.kid || 'cached';
  traceStep2Sig.textContent = 'SHA-256 Valid ✓';
  traceStep2Sig.style.color = 'var(--success)';
  traceStep2Exp.textContent = 'Active ✓';
  traceStep2Badge.className = 'xray-step-status status-ok';
  traceStep2Badge.textContent = '✓ Signature Valid';

  // Determine required role based on endpoint
  let requiredRoleText = 'none';
  if (endpoint === '/api/admin/users') requiredRoleText = 'admin';
  else if (endpoint === '/api/users') requiredRoleText = 'viewer, developer, admin';
  else if (endpoint === '/api/me') requiredRoleText = 'any valid token';

  traceStep3Req.textContent = requiredRoleText;
  traceStep3Prov.textContent = roles.length ? roles.join(', ') : 'none';

  if (status === 403) {
    // 403 FORBIDDEN ERROR
    banner.className = 'xray-decision-banner access-denied';
    icon.textContent = '🚫';
    statusBadge.className = 'decision-code-badge badge-403';
    statusBadge.textContent = 'HTTP 403 FORBIDDEN';
    headline.textContent = 'Access Denied';
    headline.style.color = '#f87171';
    explanation.innerHTML = `
      Authentication succeeded with Keycloak (valid RS256 token signed for <strong>${username}</strong>), 
      but Flask RBAC decorator <code>@require_auth("admin")</code> checked your roles <code>${JSON.stringify(roles)}</code> 
      and <strong>strictly rejected access</strong>.
    `;

    traceStep3Dec.textContent = 'Denied (403)';
    traceStep3Dec.style.color = 'var(--danger)';
    traceStep3Badge.className = 'xray-step-status status-err';
    traceStep3Badge.style.background = 'rgba(239, 68, 68, 0.2)';
    traceStep3Badge.style.color = '#f87171';
    traceStep3Badge.textContent = '✗ Access Denied';

  } else if (status === 200) {
    // 200 OK GRANTED
    banner.className = 'xray-decision-banner access-granted';
    icon.textContent = '✅';
    statusBadge.className = 'decision-code-badge badge-200';
    statusBadge.textContent = 'HTTP 200 OK';
    headline.textContent = 'Access Granted';
    headline.style.color = 'var(--success)';
    explanation.innerHTML = `
      Authentication succeeded with Keycloak and Flask RBAC decorator verified that your role 
      satisfies endpoint permission requirements. <strong>Resource unlocked!</strong>
    `;

    traceStep3Dec.textContent = 'Granted (200)';
    traceStep3Dec.style.color = 'var(--success)';
    traceStep3Badge.className = 'xray-step-status status-ok';
    traceStep3Badge.style.background = 'rgba(16, 185, 129, 0.2)';
    traceStep3Badge.style.color = 'var(--success)';
    traceStep3Badge.textContent = '✓ Access Granted';

  } else if (status === 401) {
    // 401 UNAUTHORIZED
    banner.className = 'xray-decision-banner access-denied';
    icon.textContent = '⚠️';
    statusBadge.className = 'decision-code-badge badge-401';
    statusBadge.textContent = 'HTTP 401 UNAUTHORIZED';
    headline.textContent = 'Authentication Error';
    headline.style.color = 'var(--warning)';
    explanation.innerHTML = `
      Flask API rejected the request: <strong>${responseData.detail || 'Token missing or invalid'}</strong>.
    `;

    traceStep3Dec.textContent = 'Denied (401)';
    traceStep3Dec.style.color = 'var(--warning)';
    traceStep3Badge.className = 'xray-step-status status-err';
    traceStep3Badge.style.background = 'rgba(245, 158, 11, 0.2)';
    traceStep3Badge.style.color = 'var(--warning)';
    traceStep3Badge.textContent = '✗ Unauthenticated';
  }
}

// Render Keycloak Authentication Failure
function renderKeycloakAuthError(errMsg, username) {
  const banner = document.getElementById('decision-banner');
  const icon = document.getElementById('decision-icon');
  const statusBadge = document.getElementById('decision-status-badge');
  const headline = document.getElementById('decision-headline');
  const explanation = document.getElementById('decision-explanation');

  banner.className = 'xray-decision-banner access-denied';
  icon.textContent = '❌';
  statusBadge.className = 'decision-code-badge badge-401';
  statusBadge.textContent = 'KEYCLOAK AUTH FAILED';
  headline.textContent = 'Invalid Credentials';
  headline.style.color = 'var(--danger)';
  explanation.innerHTML = `
    Keycloak identity provider (:8080) rejected login for user <strong>${username}</strong>: 
    <code>${errMsg}</code>. Verify your username and password.
  `;

  document.getElementById('verified-live-data').textContent = JSON.stringify({
    idp_error: 'invalid_grant',
    message: errMsg,
    username: username
  }, null, 2);

  document.getElementById('trace-step1-user').textContent = username;
  document.getElementById('trace-step1-roles').textContent = '—';
  document.getElementById('trace-step1-badge').className = 'xray-step-status status-err';
  document.getElementById('trace-step1-badge').textContent = '✗ Auth Failed';

  STATE.currentToken = null;
  STATE.currentUsername = null;
  STATE.currentTokenPayload = null;
  updateSessionDisplay(username, [], 0, false);
  refreshAllEndpoints();
}

// Test request without a token (Anonymous)
async function testAnonymousAccess() {
  STATE.currentToken = null;
  STATE.currentUsername = null;
  STATE.currentTokenPayload = null;
  clearInterval(STATE.tokenCountdownTimer);

  const endpointSelect = document.getElementById('target-endpoint');
  const targetEndpoint = endpointSelect ? endpointSelect.value : '/api/admin/users';
  STATE.currentTargetEndpoint = targetEndpoint;

  updateSessionDisplay('Anonymous', [], 0, false);

  const startTime = performance.now();
  const apiTargetUrl = `${CONFIG.apiUrl}${targetEndpoint}`;
  document.getElementById('data-target-url').textContent = `GET ${apiTargetUrl} (No Token)`;

  try {
    const apiResp = await fetch(apiTargetUrl);
    const latency = Math.round(performance.now() - startTime);
    document.getElementById('decision-latency').textContent = `${latency}ms`;

    const data = await apiResp.json().catch(async () => ({ text: await apiResp.text() }));
    document.getElementById('verified-live-data').textContent = JSON.stringify(data, null, 2);

    // Update Banner
    const banner = document.getElementById('decision-banner');
    const icon = document.getElementById('decision-icon');
    const statusBadge = document.getElementById('decision-status-badge');
    const headline = document.getElementById('decision-headline');
    const explanation = document.getElementById('decision-explanation');

    if (apiResp.status === 200) {
      banner.className = 'xray-decision-banner access-granted';
      icon.textContent = '✅';
      statusBadge.className = 'decision-code-badge badge-200';
      statusBadge.textContent = 'HTTP 200 OK';
      headline.textContent = 'Public Access Allowed';
      explanation.innerHTML = `This endpoint (<code>/api/public</code>) is completely open and does not require an Authorization token.`;
    } else {
      banner.className = 'xray-decision-banner access-denied';
      icon.textContent = '🚫';
      statusBadge.className = 'decision-code-badge badge-401';
      statusBadge.textContent = 'HTTP 401 UNAUTHORIZED';
      headline.textContent = 'Missing Token';
      explanation.innerHTML = `
        Flask API rejected the request: <strong>${data.detail || 'Send Authorization: Bearer <token>'}</strong>. 
        Authentication is required to access <code>${targetEndpoint}</code>.
      `;
    }

    // Trace update
    document.getElementById('trace-step1-user').textContent = 'none';
    document.getElementById('trace-step1-roles').textContent = '[]';
    document.getElementById('trace-step1-badge').className = 'xray-step-status';
    document.getElementById('trace-step1-badge').textContent = '○ No Token';

    document.getElementById('trace-step2-kid').textContent = 'none';
    document.getElementById('trace-step2-sig').textContent = 'Missing Header';
    document.getElementById('trace-step2-sig').style.color = 'var(--text-muted)';
    document.getElementById('trace-step2-exp').textContent = '—';
    document.getElementById('trace-step2-badge').className = 'xray-step-status';
    document.getElementById('trace-step2-badge').textContent = '○ Missing Header';

    document.getElementById('trace-step3-req').textContent = targetEndpoint === '/api/public' ? 'none' : 'Bearer Token';
    document.getElementById('trace-step3-prov').textContent = 'none';
    document.getElementById('trace-step3-dec').textContent = apiResp.status === 200 ? 'Granted (200)' : 'Denied (401)';
    document.getElementById('trace-step3-badge').className = apiResp.status === 200 ? 'xray-step-status status-ok' : 'xray-step-status status-err';
    document.getElementById('trace-step3-badge').textContent = apiResp.status === 200 ? '✓ Public Open' : '✗ Unauthenticated';

    await refreshAllEndpoints();
    fetchRecentAuditLog();

  } catch (err) {
    document.getElementById('verified-live-data').textContent = `Request failed: ${err.message}`;
  }
}

// Copy cURL command for current request
function copyTraceCurl() {
  const token = STATE.currentToken;
  const endpoint = STATE.currentTargetEndpoint || '/api/admin/users';
  let curl = `curl -i -X GET "http://localhost:5001${endpoint}"`;
  if (token) {
    curl += ` \\\n  -H "Authorization: Bearer ${token}"`;
  }

  navigator.clipboard.writeText(curl).then(() => {
    const btn = event?.currentTarget;
    if (btn) {
      const orig = btn.textContent;
      btn.textContent = '✓ Copied!';
      setTimeout(() => { btn.textContent = orig; }, 1500);
    }
  });
}

// Refresh bottom live matrix for all 4 endpoints
async function refreshAllEndpoints() {
  const token = STATE.currentToken;
  const headers = {};
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  // 1. /api/public
  const pubStart = performance.now();
  fetch(`${CONFIG.apiUrl}/api/public`)
    .then(async r => {
      const data = await r.json().catch(async () => ({ text: await r.text() }));
      const latency = Math.round(performance.now() - pubStart);
      document.getElementById('latency-endpoint-public').textContent = `${latency}ms`;
      document.getElementById('data-endpoint-public').textContent = JSON.stringify(data, null, 2);
    })
    .catch(err => {
      document.getElementById('data-endpoint-public').textContent = `Error: ${err.message}`;
    });

  // 2. /api/me
  const meStart = performance.now();
  const meCard = document.getElementById('card-endpoint-me');
  const meBadge = document.getElementById('badge-endpoint-me');
  const meReason = document.getElementById('xray-reason-me');
  const meDataBox = document.getElementById('data-endpoint-me');
  const meLatency = document.getElementById('latency-endpoint-me');

  fetch(`${CONFIG.apiUrl}/api/me`, { headers })
    .then(async r => {
      const latency = Math.round(performance.now() - meStart);
      meLatency.textContent = `${latency}ms`;
      const data = await r.json().catch(async () => ({ text: await r.text() }));
      meDataBox.textContent = JSON.stringify(data, null, 2);

      if (r.status === 200) {
        meCard.className = 'xray-access-card access-granted';
        meBadge.className = 'access-decision-badge badge-granted';
        meBadge.textContent = 'ACCESS GRANTED (200 OK)';
        meReason.innerHTML = `<strong>X-Ray Decision:</strong> Valid RS256 signature verified against Keycloak JWKS. User identity unpacked.`;
      } else {
        meCard.className = 'xray-access-card access-denied';
        meBadge.className = 'access-decision-badge badge-denied';
        meBadge.textContent = `ACCESS DENIED (${r.status} UNAUTHORIZED)`;
        meReason.innerHTML = `<strong>X-Ray Decision:</strong> Authentication Failure: ${data.detail || 'Missing Authorization Bearer header'}.`;
      }
    })
    .catch(err => {
      meDataBox.textContent = `Error: ${err.message}`;
    });

  // 3. /api/users
  const usersStart = performance.now();
  const usersCard = document.getElementById('card-endpoint-users');
  const usersBadge = document.getElementById('badge-endpoint-users');
  const usersReason = document.getElementById('xray-reason-users');
  const usersDataBox = document.getElementById('data-endpoint-users');
  const usersLatency = document.getElementById('latency-endpoint-users');

  fetch(`${CONFIG.apiUrl}/api/users`, { headers })
    .then(async r => {
      const latency = Math.round(performance.now() - usersStart);
      usersLatency.textContent = `${latency}ms`;
      const data = await r.json().catch(async () => ({ text: await r.text() }));
      usersDataBox.textContent = JSON.stringify(data, null, 2);

      if (r.status === 200) {
        usersCard.className = 'xray-access-card access-granted';
        usersBadge.className = 'access-decision-badge badge-granted';
        usersBadge.textContent = 'ACCESS GRANTED (200 OK)';
        usersReason.innerHTML = `<strong>X-Ray Decision:</strong> Requires role <code>viewer</code>, <code>developer</code>, or <code>admin</code>. Role check passed.`;
      } else {
        usersCard.className = 'xray-access-card access-denied';
        usersBadge.className = 'access-decision-badge badge-denied';
        usersBadge.textContent = `ACCESS DENIED (${r.status} UNAUTHORIZED)`;
        usersReason.innerHTML = `<strong>X-Ray Decision:</strong> Authentication Error: ${data.detail || 'No valid token provided'}.`;
      }
    })
    .catch(err => {
      usersDataBox.textContent = `Error: ${err.message}`;
    });

  // 4. /api/admin/users
  const adminStart = performance.now();
  const adminCard = document.getElementById('card-endpoint-admin');
  const adminBadge = document.getElementById('badge-endpoint-admin');
  const adminReason = document.getElementById('xray-reason-admin');
  const adminDataBox = document.getElementById('data-endpoint-admin');
  const adminLatency = document.getElementById('latency-endpoint-admin');

  fetch(`${CONFIG.apiUrl}/api/admin/users`, { headers })
    .then(async r => {
      const latency = Math.round(performance.now() - adminStart);
      adminLatency.textContent = `${latency}ms`;
      const data = await r.json().catch(async () => ({ text: await r.text() }));
      adminDataBox.textContent = JSON.stringify(data, null, 2);

      const activeUser = STATE.currentUsername || 'User';
      const activeRoles = (STATE.currentTokenPayload?.realm_access?.roles || []).filter(k =>
        ['viewer', 'developer', 'admin'].includes(k)
      );
      const roleStr = activeRoles.length ? activeRoles.join(', ') : 'none';

      if (r.status === 200) {
        adminCard.className = 'xray-access-card access-granted';
        adminBadge.className = 'access-decision-badge badge-granted';
        adminBadge.textContent = 'ACCESS GRANTED (200 OK)';
        adminReason.innerHTML = `<strong>X-Ray Decision:</strong> Verified <strong>${escapeHtml(activeUser)}</strong>'s <code>admin</code> role against <code>@require_auth("admin")</code>. Full admin access unlocked.`;
      } else if (r.status === 403) {
        adminCard.className = 'xray-access-card access-denied';
        adminBadge.className = 'access-decision-badge badge-denied';
        adminBadge.textContent = 'ACCESS DENIED (403 FORBIDDEN)';
        adminReason.innerHTML = `<strong>X-Ray Decision:</strong> Authorization Failure: <strong>${escapeHtml(activeUser)}</strong>'s RS256 signature is valid, but role <code>${escapeHtml(roleStr)}</code> does not satisfy <code>@require_auth("admin")</code>.`;
      } else {
        adminCard.className = 'xray-access-card access-denied';
        adminBadge.className = 'access-decision-badge badge-denied';
        adminBadge.textContent = `ACCESS DENIED (${r.status} UNAUTHORIZED)`;
        adminReason.innerHTML = `<strong>X-Ray Decision:</strong> Authentication Failure: ${data.detail || 'Unauthenticated request'}.`;
      }

      renderAdminConsole(r.status, data, activeUser, roleStr);
    })
    .catch(err => {
      adminDataBox.textContent = `Error: ${err.message}`;
    });
}

// Render the Admin Keycloak User & Password Management Console
function renderAdminConsole(status, data, activeUser, roleStr) {
  const badge = document.getElementById('admin-console-badge');
  const lockedBox = document.getElementById('admin-console-locked');
  const unlockedBox = document.getElementById('admin-console-unlocked');
  const unlockBtn = document.getElementById('btn-unlock-admin-bob');
  const reasonCode = document.getElementById('admin-locked-reason-code');
  const reasonDesc = document.getElementById('admin-locked-reason-desc');
  const tbody = document.getElementById('admin-users-tbody');

  if (!lockedBox || !unlockedBox) return;

  if (status !== 200) {
    lockedBox.style.display = 'flex';
    unlockedBox.style.display = 'none';
    if (unlockBtn) unlockBtn.style.display = 'inline-flex';
    if (badge) {
      badge.className = 'access-decision-badge badge-denied';
      badge.textContent = status === 403 ? 'LOCKED (403 FORBIDDEN)' : 'LOCKED (401 UNAUTHORIZED)';
    }
    if (reasonCode) {
      reasonCode.textContent = status === 403 ? 'HTTP 403 FORBIDDEN' : 'HTTP 401 UNAUTHORIZED';
    }
    if (reasonDesc) {
      reasonDesc.innerHTML = status === 403
        ? `Authenticated as <strong>${escapeHtml(activeUser)}</strong> with role <code>${escapeHtml(roleStr)}</code>, which lacks the <code>admin</code> privilege required to manage Keycloak users and reset passwords.`
        : `No valid Bearer token provided. Authenticate as an <code>admin</code> user (such as <strong>bob</strong>) to manage Keycloak users and reset passwords.`;
    }
    return;
  }

  // Unlocked (Admin session active)
  lockedBox.style.display = 'none';
  unlockedBox.style.display = 'block';
  if (unlockBtn) unlockBtn.style.display = 'none';
  if (badge) {
    badge.className = 'access-decision-badge badge-granted';
    badge.textContent = `UNLOCKED (ADMIN: ${activeUser.toUpperCase()})`;
  }

  const users = data.users || [];
  if (!tbody) return;

  if (users.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="6" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">
          No users found in Keycloak realm.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = users
    .map(u => {
      const uid = escapeHtml(u.id);
      const uname = escapeHtml(u.username);
      const pRole = u.primaryRole || 'viewer';
      const icon = pRole === 'admin' ? '🛡️' : pRole === 'developer' ? '🧑‍💻' : '👩‍💻';
      const statusBadge = u.enabled
        ? `<span class="decision-badge dec-ALLOWED">ENABLED</span>`
        : `<span class="decision-badge dec-DENIED_403">DISABLED</span>`;
      const toggleLabel = u.enabled ? 'Disable Login' : 'Enable Login';
      const knownPw = STATE.knownPasswords[u.username] || '';

      return `
        <tr>
          <td>
            <div style="display: flex; align-items: center; gap: 0.65rem;">
              <span style="font-size: 1.25rem;">${icon}</span>
              <div>
                <div style="font-weight: 600; color: #fff; display: flex; align-items: center; gap: 0.4rem;">
                  <span>${uname}</span>
                  ${
                    u.isBuiltIn
                      ? `<span style="font-size: 0.65rem; padding: 0.1rem 0.4rem; border-radius: 999px; background: rgba(99, 102, 241, 0.15); color: #a5b4fc; border: 1px solid rgba(99, 102, 241, 0.3);">Default</span>`
                      : `<span style="font-size: 0.65rem; padding: 0.1rem 0.4rem; border-radius: 999px; background: rgba(16, 185, 129, 0.15); color: #6ee7b7; border: 1px solid rgba(16, 185, 129, 0.3);">Custom</span>`
                  }
                </div>
                <div style="font-size: 0.74rem; color: var(--text-muted);">${escapeHtml(u.name || '')}</div>
              </div>
            </div>
          </td>
          <td>
            <div style="font-family: var(--font-mono); font-size: 0.78rem; color: #cbd5e1;">${escapeHtml(u.email || '—')}</div>
            <div style="font-family: var(--font-mono); font-size: 0.68rem; color: var(--text-muted);">sub: ${uid.slice(0, 8)}...</div>
          </td>
          <td>
            <div style="display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap;">
              ${statusBadge}
              <button type="button" class="suite-copy-btn" onclick="adminToggleUserStatus('${uid}', '${uname}', ${!u.enabled})" title="Toggle Keycloak login enabled/disabled">
                ${toggleLabel}
              </button>
            </div>
          </td>
          <td>
            <select class="form-input" style="padding: 0.35rem 0.6rem; font-size: 0.78rem; background-color: var(--bg-surface); width: auto;" onchange="adminChangeUserRole('${uid}', '${uname}', this.value)">
              <option value="viewer" ${pRole === 'viewer' ? 'selected' : ''}>viewer</option>
              <option value="developer" ${pRole === 'developer' ? 'selected' : ''}>developer</option>
              <option value="admin" ${pRole === 'admin' ? 'selected' : ''}>admin</option>
            </select>
          </td>
          <td>
            <div style="display: flex; align-items: center; gap: 0.4rem;">
              <input type="password" id="reset-pw-${uid}" class="form-input" placeholder="New password (min 4)" style="padding: 0.35rem 0.65rem; font-size: 0.78rem; width: 165px;">
              <button type="button" class="btn-primary" onclick="adminResetUserPassword('${uid}', '${uname}')" style="padding: 0.38rem 0.75rem; font-size: 0.76rem; white-space: nowrap;">
                🔑 Reset Password
              </button>
            </div>
          </td>
          <td style="text-align: right;">
            <div style="display: inline-flex; align-items: center; gap: 0.4rem;">
              <button type="button" class="suite-copy-btn" onclick="adminTestSignIn('${uname}', '${escapeHtml(knownPw)}', '${pRole}')" title="Fill login form as ${uname} and test access">
                ▶️ Sign In
              </button>
              ${
                !u.isBuiltIn
                  ? `<button type="button" class="suite-copy-btn" onclick="adminDeleteUser('${uid}', '${uname}')" style="color: #fca5a5; border-color: rgba(239, 68, 68, 0.35); background: rgba(239, 68, 68, 0.1);" title="Delete user from Keycloak">
                      🗑️ Delete
                    </button>`
                  : ''
              }
            </div>
          </td>
        </tr>
      `;
    })
    .join('');
}

function showAdminFeedback(messageHtml, isError = false) {
  const box = document.getElementById('admin-action-feedback');
  if (!box) return;
  box.style.display = 'block';
  box.style.background = isError ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.15)';
  box.style.border = isError ? '1px solid rgba(239, 68, 68, 0.4)' : '1px solid rgba(16, 185, 129, 0.4)';
  box.style.color = isError ? '#fca5a5' : '#6ee7b7';
  box.innerHTML = messageHtml;
}

// Admin Action: Reset a user's login password in Keycloak
async function adminResetUserPassword(userId, username) {
  const pwInput = document.getElementById(`reset-pw-${userId}`);
  const newPassword = (pwInput?.value || '').trim();
  if (!newPassword || newPassword.length < 4) {
    showAdminFeedback(`<strong>⚠️ Password Reset:</strong> Enter a new password of at least 4 characters for <code>${escapeHtml(username)}</code>.`, true);
    pwInput?.focus();
    return;
  }

  try {
    const resp = await fetch(`${CONFIG.apiUrl}/api/admin/users/${encodeURIComponent(userId)}/reset-password`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${STATE.currentToken || ''}`,
      },
      body: JSON.stringify({ password: newPassword, temporary: false }),
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      throw new Error(data.detail || data.error || `HTTP ${resp.status}`);
    }

    // Update cached known password and invalidate cached token so next login uses the new password
    STATE.knownPasswords[username] = newPassword;
    delete STATE.cachedTokens[username];
    if (pwInput) pwInput.value = '';

    showAdminFeedback(
      `<strong>✓ Password Reset in Keycloak:</strong> Login password for <code>${escapeHtml(username)}</code> has been updated. Click <strong>▶️ Sign In</strong> on their row (or Quick Fill) to test logging in with the new password.`
    );
    await refreshAllEndpoints();
    fetchRecentAuditLog();
  } catch (err) {
    showAdminFeedback(`<strong>✗ Password Reset Failed:</strong> ${escapeHtml(err.message)}`, true);
  }
}

// Admin Action: Change a user's Keycloak realm role
async function adminChangeUserRole(userId, username, newRole) {
  try {
    const resp = await fetch(`${CONFIG.apiUrl}/api/admin/users/${encodeURIComponent(userId)}/role`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${STATE.currentToken || ''}`,
      },
      body: JSON.stringify({ role: newRole }),
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      throw new Error(data.detail || data.error || `HTTP ${resp.status}`);
    }

    delete STATE.cachedTokens[username];
    if (STATE.knownPasswords[username]) {
      addQuickFillAccount(username, STATE.knownPasswords[username], newRole);
    }

    showAdminFeedback(
      `<strong>✓ Role Updated in Keycloak:</strong> Assigned realm role <code>${escapeHtml(newRole)}</code> to user <code>${escapeHtml(username)}</code>.`
    );
    await refreshAllEndpoints();
    fetchRecentAuditLog();
  } catch (err) {
    showAdminFeedback(`<strong>✗ Role Update Failed:</strong> ${escapeHtml(err.message)}`, true);
  }
}

// Admin Action: Enable or Disable a user's login in Keycloak
async function adminToggleUserStatus(userId, username, enabled) {
  try {
    const resp = await fetch(`${CONFIG.apiUrl}/api/admin/users/${encodeURIComponent(userId)}/status`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${STATE.currentToken || ''}`,
      },
      body: JSON.stringify({ enabled }),
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      throw new Error(data.detail || data.error || `HTTP ${resp.status}`);
    }

    delete STATE.cachedTokens[username];
    showAdminFeedback(
      `<strong>✓ Account Status Updated:</strong> User <code>${escapeHtml(username)}</code> is now <strong>${enabled ? 'ENABLED' : 'DISABLED'}</strong> in Keycloak.`
    );
    await refreshAllEndpoints();
    fetchRecentAuditLog();
  } catch (err) {
    showAdminFeedback(`<strong>✗ Status Update Failed:</strong> ${escapeHtml(err.message)}`, true);
  }
}

// Admin Action: Delete a custom user from Keycloak
async function adminDeleteUser(userId, username) {
  try {
    const resp = await fetch(`${CONFIG.apiUrl}/api/admin/users/${encodeURIComponent(userId)}`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${STATE.currentToken || ''}`,
      },
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      throw new Error(data.detail || data.error || `HTTP ${resp.status}`);
    }

    delete STATE.cachedTokens[username];
    delete STATE.knownPasswords[username];
    const quickBtn = document.getElementById(`btn-quick-${username}`);
    if (quickBtn) quickBtn.remove();

    showAdminFeedback(`<strong>✓ User Deleted:</strong> Removed <code>${escapeHtml(username)}</code> from Keycloak.`);
    await refreshAllEndpoints();
    fetchRecentAuditLog();
  } catch (err) {
    showAdminFeedback(`<strong>✗ Delete Failed:</strong> ${escapeHtml(err.message)}`, true);
  }
}

// Helper to test signing in as a user from the Admin table
function adminTestSignIn(username, fallbackPw, role) {
  const pw = STATE.knownPasswords[username] || fallbackPw || '';
  switchAuthMode('login');
  document.getElementById('login-username').value = username;
  document.getElementById('login-password').value = pw;
  if (pw) {
    quickFillCredentials(username, pw, role);
  } else {
    document.getElementById('login-password').focus();
  }
}

// Fetch latest Backend Audit Log from Flask server
async function fetchRecentAuditLog() {
  const lineEl = document.getElementById('latest-audit-log-line');
  try {
    const resp = await fetch(`${CONFIG.apiUrl}/api/logs`);
    if (!resp.ok) return;
    const data = await resp.json();
    const logs = data.logs || [];
    if (logs.length === 0) {
      lineEl.textContent = 'No audit logs recorded yet.';
      return;
    }
    const latest = logs[0];
    const time = new Date(latest.timestamp).toLocaleTimeString();
    const decColor = (latest.status === 200 || latest.status === 201) ? '#34d399' : latest.status === 403 ? '#f87171' : '#fcd34d';

    lineEl.innerHTML = `
      <span style="color: var(--text-muted); font-weight: 600;">[#${latest.id} @ ${time}]</span>
      <span class="method-badge" style="font-size: 0.68rem;">${latest.method}</span>
      <code style="color: #fff; font-weight: 600;">${latest.endpoint}</code>
      &rarr;
      <strong style="color: ${decColor};">${latest.status} (${latest.decision})</strong>
      | User: <strong style="color: #60a5fa;">${latest.username || 'anonymous'}</strong>
      | Roles: <code style="color: #fcd34d;">${latest.roles ? latest.roles.join(', ') : 'none'}</code>
      <br>
      <span style="color: #94a3b8; font-size: 0.74rem;">&bull; Server Detail: ${escapeHtml(latest.detail)}</span>
    `;
  } catch (e) {
    lineEl.textContent = `Could not fetch Flask audit log: ${e.message}`;
  }
}

// Expiration Countdown
function startCountdown(seconds) {
  clearInterval(STATE.tokenCountdownTimer);
  let remaining = seconds;
  const display = document.getElementById('session-countdown-text');

  if (remaining <= 0) {
    display.textContent = 'No active token';
    display.style.color = 'var(--text-muted)';
    return;
  }

  const update = () => {
    if (remaining <= 0) {
      clearInterval(STATE.tokenCountdownTimer);
      display.textContent = 'Token Expired (0s)';
      display.style.color = 'var(--danger)';
      return;
    }
    const mins = Math.floor(remaining / 60);
    const secs = remaining % 60;
    display.textContent = mins > 0 ? `${mins}m ${secs}s remaining` : `${secs}s remaining`;
    display.style.color = remaining < 30 ? 'var(--danger)' : 'var(--success)';
    remaining -= 1;
  };

  update();
  STATE.tokenCountdownTimer = setInterval(update, 1000);
}

function escapeHtml(str) {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
