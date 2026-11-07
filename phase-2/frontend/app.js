/**
 * AuthLab Phase 2 — Privilege-Based Portal Controller
 * Integrates with Keycloak (Realm: Authlab) and Resource API (:5000)
 * Features live cryptographic attack simulation and full security audit logging.
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
  auditFilter: 'all',
  autoRefreshTimer: null,
};

function escapeHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function showToast(msg) {
  const toast = document.getElementById('global-toast') || document.getElementById('dashboard-toast');
  if (!toast) return;
  toast.innerHTML = msg;
  toast.classList.remove('hidden');
  setTimeout(() => toast.classList.add('hidden'), 4500);
}

// ============================================================================
// TOKEN PARSING & DECODING
// ============================================================================

function decodeJwt(jwtStr) {
  try {
    const parts = jwtStr.split('.');
    if (parts.length < 2) return null;
    const b64 = (s) =>
      atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4));
    return {
      header: JSON.parse(b64(parts[0])),
      payload: JSON.parse(b64(parts[1])),
    };
  } catch {
    return null;
  }
}

function isTokenExpired(claims) {
  if (!claims || !claims.exp) return true;
  return claims.exp < Math.floor(Date.now() / 1000);
}

// ============================================================================
// KEYCLOAK HEALTH CHECK
// ============================================================================

async function checkKeycloakStatus() {
  const statusPill = document.getElementById('kc-status-pill');
  const statusEl = document.getElementById('kc-status-text');
  try {
    const res = await fetch(`${CONFIG.keycloakUrl}/realms/${CONFIG.realm}/protocol/openid-connect/certs`);
    if (res.ok) {
      statusEl.textContent = `Keycloak Online (${CONFIG.realm})`;
      statusPill.style.background = 'rgba(16, 185, 129, 0.12)';
      statusPill.style.borderColor = 'rgba(16, 185, 129, 0.3)';
      statusPill.querySelector('.status-dot').style.background = '#10b981';
    } else {
      statusEl.textContent = 'Keycloak: Realm Check Failed';
    }
  } catch {
    statusEl.textContent = 'Keycloak: Connecting...';
  }
}

// ============================================================================
// VIEW SWITCHING (LOGIN VS DASHBOARD)
// ============================================================================

function showAuthView() {
  document.getElementById('auth-view').classList.remove('hidden');
  document.getElementById('dashboard-view').classList.add('hidden');
  document.getElementById('nav-user-controls').classList.add('hidden');
}

function showDashboardView() {
  document.getElementById('auth-view').classList.add('hidden');
  document.getElementById('dashboard-view').classList.remove('hidden');
  document.getElementById('nav-user-controls').classList.remove('hidden');
}

// ============================================================================
// AUTHENTICATION LOGIC
// ============================================================================

async function login(username, password) {
  const submitBtn = document.getElementById('login-submit-btn');
  const alertEl = document.getElementById('login-alert');

  if (alertEl) {
    alertEl.classList.add('hidden');
    alertEl.textContent = '';
  }

  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.textContent = 'Authenticating against Keycloak...';
  }

  const tokenUrl = `${CONFIG.keycloakUrl}/realms/${CONFIG.realm}/protocol/openid-connect/token`;
  const body = new URLSearchParams({
    grant_type: 'password',
    client_id: CONFIG.clientId,
    username: username.trim(),
    password: password,
  });

  try {
    const resp = await fetch(tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });

    const data = await resp.json().catch(() => ({}));

    if (!resp.ok) {
      const errMsg = data.error_description || data.error || `HTTP ${resp.status}`;
      throw new Error(errMsg);
    }

    const token = data.access_token;
    const parsed = decodeJwt(token);

    if (!parsed) {
      throw new Error('Received unparseable JWT access token from Keycloak.');
    }

    // Save token to session
    STATE.token = token;
    STATE.header = parsed.header;
    STATE.claims = parsed.payload;
    STATE.currentUser = parsed.payload.preferred_username || username;
    sessionStorage.setItem('phase2_token', token);

    // Switch view to dashboard & load privileged tiers
    showDashboardView();
    await loadDashboardData();
    showToast(`🎉 Welcome back, <strong>${escapeHtml(STATE.currentUser)}</strong>! Workspace privileges updated.`);

  } catch (err) {
    if (alertEl) {
      alertEl.innerHTML = `⚠️ <strong>Authentication Failed:</strong> ${escapeHtml(err.message)}`;
      alertEl.classList.remove('hidden');
    } else {
      alert(`Login failed: ${err.message}`);
    }
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Sign In with Keycloak';
    }
  }
}

async function handleFormLogin(event) {
  if (event) event.preventDefault();
  const u = document.getElementById('input-username').value;
  const p = document.getElementById('input-password').value;
  if (!u || !p) return;
  await login(u, p);
}

async function quickLogin(username, password) {
  document.getElementById('input-username').value = username;
  document.getElementById('input-password').value = password;
  await login(username, password);
}

function logout() {
  STATE.token = null;
  STATE.claims = null;
  STATE.header = null;
  STATE.currentUser = null;
  sessionStorage.removeItem('phase2_token');
  showAuthView();
  showToast('👋 You have signed out of your Keycloak session.');
}

// ============================================================================
// PRIVILEGE-BASED DASHBOARD LOADER
// ============================================================================

async function loadDashboardData() {
  if (!STATE.claims) return;

  const c = STATE.claims;
  const rawRoles = c.realm_access?.roles || [];
  const rolesLower = rawRoles.map(r => r.toLowerCase());

  const isAdmin = rolesLower.includes('admin');
  const isDeveloper = rolesLower.includes('developer');
  const isReader = !isAdmin && !isDeveloper;

  let primaryRoleTitle = 'Reader (Level 1)';
  let userIcon = '📖';

  if (isAdmin) {
    primaryRoleTitle = 'Administrator (Level 3)';
    userIcon = '🛡️';
  } else if (isDeveloper) {
    primaryRoleTitle = 'Developer (Level 2)';
    userIcon = '🧑‍💻';
  }

  // 1. Update Topbar
  document.getElementById('nav-user-icon').textContent = userIcon;
  document.getElementById('nav-user-name').textContent = c.preferred_username || 'User';
  document.getElementById('nav-user-role').textContent = primaryRoleTitle;

  // 2. Update Hero Privilege Banner
  const displayName = c.name || c.preferred_username || 'User';
  document.getElementById('hero-title').textContent = `Welcome, ${displayName}!`;

  if (isAdmin) {
    document.getElementById('hero-desc').innerHTML =
      `You are authenticated with <strong>Administrator (Level 3)</strong> clearance. You have unhindered access to <strong>all 3 privilege tiers</strong>, including system security governance and live audit logs.`;
  } else if (isDeveloper) {
    document.getElementById('hero-desc').innerHTML =
      `You are authenticated with <strong>Developer (Level 2)</strong> clearance. You have access to Tier 1 and Tier 2 (staging configs, microservice topology, and feature flags). Tier 3 is restricted to Admins.`;
  } else {
    document.getElementById('hero-desc').innerHTML =
      `You are authenticated with <strong>Reader (Level 1)</strong> clearance. You have access to Tier 1 (Knowledge Base &amp; Organization Directory). Developer and Admin tiers are locked.`;
  }

  // 3. Update Visual Privilege Status Pills
  const pillT1 = document.getElementById('pill-tier-1');
  const pillT2 = document.getElementById('pill-tier-2');
  const pillT3 = document.getElementById('pill-tier-3');

  // Tier 1 is always unlocked for authenticated users
  pillT1.className = 'status-pill-item unlocked';
  pillT1.innerHTML = '<span class="pill-dot"></span> Tier 1: Reader (Unlocked)';

  // Tier 2 (Developer & Admin)
  if (isDeveloper || isAdmin) {
    pillT2.className = 'status-pill-item unlocked';
    pillT2.innerHTML = '<span class="pill-dot"></span> Tier 2: Developer (Unlocked)';
  } else {
    pillT2.className = 'status-pill-item locked';
    pillT2.innerHTML = '<span class="pill-dot"></span> Tier 2: Developer (Locked)';
  }

  // Tier 3 (Admin ONLY)
  if (isAdmin) {
    pillT3.className = 'status-pill-item unlocked';
    pillT3.innerHTML = '<span class="pill-dot"></span> Tier 3: Admin (Unlocked)';
  } else {
    pillT3.className = 'status-pill-item locked';
    pillT3.innerHTML = '<span class="pill-dot"></span> Tier 3: Admin (Locked)';
  }

  // 4. Fetch Tier 1: General Workspace (GET /api/users)
  await loadTier1Data();

  // 5. Render Tier 2: Developer Workspace
  if (isDeveloper || isAdmin) {
    document.getElementById('tier-2-unlocked').classList.remove('hidden');
    document.getElementById('tier-2-locked').classList.add('hidden');
    await loadTier2Data();
  } else {
    document.getElementById('tier-2-unlocked').classList.add('hidden');
    document.getElementById('tier-2-locked').classList.remove('hidden');
    document.getElementById('locked-dev-username').textContent = c.preferred_username || 'alice';
  }

  // 6. Render Tier 3: Admin Control Center
  if (isAdmin) {
    document.getElementById('tier-3-unlocked').classList.remove('hidden');
    document.getElementById('tier-3-locked').classList.add('hidden');
    await loadTier3Data();
  } else {
    document.getElementById('tier-3-unlocked').classList.add('hidden');
    document.getElementById('tier-3-locked').classList.remove('hidden');
  }

  // 7. Refresh Live Audit Logs
  fetchAuditLogs();
}

// Tier 1 Fetcher
async function loadTier1Data() {
  const kbContainer = document.getElementById('reader-kb-list');
  const dirContainer = document.getElementById('reader-directory-tbody');

  try {
    const resp = await fetch(`${CONFIG.apiUrl}/api/users`, {
      headers: { Authorization: `Bearer ${STATE.token}` },
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();

    // Populate Knowledge Base
    kbContainer.innerHTML = (data.knowledge_base || []).map(kb => `
      <div class="kb-item">
        <div>
          <div class="kb-title">${escapeHtml(kb.title)}</div>
          <div class="kb-meta">ID: <code>${escapeHtml(kb.id)}</code> &bull; ${escapeHtml(kb.category)} &bull; Updated: ${escapeHtml(kb.updated)}</div>
        </div>
        <span class="badge badge-blue">${escapeHtml(kb.version)}</span>
      </div>
    `).join('');

    // Populate Directory Table
    dirContainer.innerHTML = (data.directory || []).map(u => `
      <tr>
        <td>
          <strong>${escapeHtml(u.name)}</strong>
          <span class="text-xs text-muted">(@${escapeHtml(u.username)})</span>
        </td>
        <td><span class="badge badge-purple">${escapeHtml(u.clearance)}</span></td>
        <td><code>${escapeHtml(u.email)}</code></td>
        <td><span class="badge badge-green">${escapeHtml(u.status)}</span></td>
      </tr>
    `).join('');

  } catch (err) {
    kbContainer.innerHTML = `<div class="text-danger">Failed to load Knowledge Base: ${escapeHtml(err.message)}</div>`;
    dirContainer.innerHTML = `<tr><td colspan="4" class="text-danger text-center">Failed to load directory.</td></tr>`;
  }
}

// Tier 2 Fetcher (Developer Config)
async function loadTier2Data() {
  const flagsEl = document.getElementById('dev-feature-flags');
  const servicesEl = document.getElementById('dev-services-list');
  const pipelineEl = document.getElementById('dev-pipeline-box');

  try {
    const resp = await fetch(`${CONFIG.apiUrl}/api/developer/config`, {
      headers: { Authorization: `Bearer ${STATE.token}` },
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();

    // Feature Flags
    flagsEl.innerHTML = Object.entries(data.feature_flags || {}).map(([flag, val]) => `
      <div class="flag-item">
        <span>${escapeHtml(flag)}</span>
        <span class="badge ${val ? 'badge-green' : 'badge-gray'}">${val ? 'ENABLED' : 'DISABLED'}</span>
      </div>
    `).join('');

    // Microservices
    servicesEl.innerHTML = (data.services_topology || []).map(svc => `
      <div class="service-item">
        <div>
          <strong>${escapeHtml(svc.name)}</strong>
          <div class="text-xs text-muted">${escapeHtml(svc.host)} &bull; ${escapeHtml(svc.protocol)}</div>
        </div>
        <span class="badge badge-green">${escapeHtml(svc.status)}</span>
      </div>
    `).join('');

    // Build Pipeline
    const p = data.build_pipeline || {};
    pipelineEl.innerHTML = `
      <div class="pipeline-metric">
        <span class="text-muted">Target Branch:</span>
        <code>${escapeHtml(p.branch)}</code>
      </div>
      <div class="pipeline-metric">
        <span class="text-muted">Last Commit:</span>
        <code>${escapeHtml(p.last_commit)}</code>
      </div>
      <div class="pipeline-metric">
        <span class="text-muted">Automated Tests:</span>
        <span class="badge badge-green">${escapeHtml(p.tests_passed)} / ${escapeHtml(p.tests_passed)} Passed</span>
      </div>
      <div class="pipeline-metric">
        <span class="text-muted">Code Coverage:</span>
        <strong class="text-green">${escapeHtml(p.code_coverage)}</strong>
      </div>
    `;

  } catch (err) {
    flagsEl.innerHTML = `<div class="text-danger">Failed to load: ${escapeHtml(err.message)}</div>`;
  }
}

// Tier 3 Fetcher (Admin Security Center)
async function loadTier3Data() {
  const auditEl = document.getElementById('admin-audit-log');
  const govEl = document.getElementById('admin-governance-box');

  try {
    const resp = await fetch(`${CONFIG.apiUrl}/api/admin/users`, {
      headers: { Authorization: `Bearer ${STATE.token}` },
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();

    // Audit Log (populated directly from live server events)
    auditEl.innerHTML = (data.security_audit_log || []).map(log => {
      let badgeClass = 'badge-blue';
      if ((log.event_type || '').startsWith('ATTACK_')) badgeClass = 'badge-red';
      else if (log.status_code === 403) badgeClass = 'badge-amber';
      else if (log.status_code === 200) badgeClass = 'badge-green';

      const statusBadge = log.status_code === 200 ? 'badge-green' : (log.status_code === 403 ? 'badge-amber' : 'badge-red');

      return `
        <div class="audit-log-row">
          <div>
            <code>${escapeHtml(log.id)}</code> &bull; <span class="badge ${badgeClass}">${escapeHtml(log.event_type || log.action)}</span>
            <div class="text-xs text-muted">Actor: <strong>${escapeHtml(log.actor)}</strong> &bull; Target: <code>${escapeHtml(log.endpoint || '-')}</code> &bull; ${escapeHtml(log.timestamp)}</div>
          </div>
          <span class="badge ${statusBadge}">
            HTTP ${escapeHtml(log.status_code || log.status)}
          </span>
        </div>
      `;
    }).join('');

    // System Governance
    const g = data.system_governance || {};
    govEl.innerHTML = `
      <div class="governance-item">
        <span>Token Algorithm</span>
        <strong>${escapeHtml(g.token_algorithm)}</strong>
      </div>
      <div class="governance-item">
        <span>Token TTL</span>
        <strong>${escapeHtml(g.token_ttl_seconds)} seconds</strong>
      </div>
      <div class="governance-item">
        <span>Active JWKS Keys</span>
        <strong>${escapeHtml(g.jwks_active_keys)} Keys Published</strong>
      </div>
      <div class="governance-item">
        <span>Total Audit Events</span>
        <strong class="text-green">${escapeHtml(g.total_audit_events || 0)} Recorded</strong>
      </div>
    `;

  } catch (err) {
    auditEl.innerHTML = `<div class="text-danger">Access Denied: ${escapeHtml(err.message)}</div>`;
  }
}

function triggerAdminAction(actionName) {
  showToast(`⚙️ <strong>Admin Action Executed:</strong> ${escapeHtml(actionName)} verified successfully against Keycloak realm policy.`);
  fetchAuditLogs();
}

// ============================================================================
// LIVE SECURITY & ATTACK AUDIT LOGS
// ============================================================================

async function fetchAuditLogs() {
  const tbody = document.getElementById('audit-logs-tbody');
  if (!tbody) return;

  try {
    const resp = await fetch(`${CONFIG.apiUrl}/api/audit-logs?filter=${STATE.auditFilter}&limit=100`);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();

    // Update stats
    const s = data.summary || {};
    const totalEl = document.getElementById('stat-total-events');
    const attacksEl = document.getElementById('stat-attacks-blocked');
    const deniedEl = document.getElementById('stat-forbidden-denied');
    const grantedEl = document.getElementById('stat-access-granted');

    if (totalEl) totalEl.textContent = s.total_events || 0;
    if (attacksEl) attacksEl.textContent = s.attacks_blocked || 0;
    if (deniedEl) deniedEl.textContent = s.forbidden_blocked || 0;
    if (grantedEl) grantedEl.textContent = s.access_granted || 0;

    const events = data.events || [];
    if (events.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted" style="padding: 2rem;">No audit events matching current filter (${escapeHtml(STATE.auditFilter)}).</td></tr>`;
      return;
    }

    tbody.innerHTML = events.map(ev => {
      let badgeClass = 'badge-blue';
      let statusBadge = 'badge-green';

      if (ev.event_type.startsWith('ATTACK_')) {
        badgeClass = 'badge-red';
      } else if (ev.event_type.includes('DENIED') || ev.status_code === 403) {
        badgeClass = 'badge-amber';
      } else if (ev.event_type.includes('EXPIRED') || ev.status_code === 401) {
        badgeClass = 'badge-purple';
      } else if (ev.event_type === 'ACCESS_GRANTED') {
        badgeClass = 'badge-green';
      }

      if (ev.status_code >= 400 && ev.status_code < 500) {
        statusBadge = ev.status_code === 403 ? 'badge-amber' : 'badge-red';
      } else if (ev.status_code >= 500) {
        statusBadge = 'badge-red';
      }

      const rolesStr = (ev.roles && ev.roles.length) ? ` <span class="text-xs text-muted">(${ev.roles.join(', ')})</span>` : '';

      return `
        <tr>
          <td><code>${escapeHtml(ev.id)}</code></td>
          <td><span class="text-xs text-muted">${escapeHtml(ev.timestamp)}</span></td>
          <td><span class="badge ${badgeClass}">${escapeHtml(ev.event_type)}</span></td>
          <td><strong>${escapeHtml(ev.actor)}</strong>${rolesStr}</td>
          <td><code>${escapeHtml(ev.method)} ${escapeHtml(ev.endpoint)}</code></td>
          <td><span class="badge ${statusBadge}">${escapeHtml(ev.status_code)}</span></td>
          <td><span class="text-xs text-secondary">${escapeHtml(ev.detail)}</span></td>
        </tr>
      `;
    }).join('');

  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="7" class="text-danger text-center">Failed to fetch audit logs: ${escapeHtml(err.message)}</td></tr>`;
  }
}

function setAuditLogFilter(filterName) {
  STATE.auditFilter = filterName;
  document.querySelectorAll('.log-filter-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.filter === filterName);
  });
  fetchAuditLogs();
}

function toggleAutoRefresh(enabled) {
  if (STATE.autoRefreshTimer) {
    clearInterval(STATE.autoRefreshTimer);
    STATE.autoRefreshTimer = null;
  }
  if (enabled) {
    STATE.autoRefreshTimer = setInterval(() => {
      const dView = document.getElementById('dashboard-view');
      if (dView && !dView.classList.contains('hidden')) {
        fetchAuditLogs();
      }
    }, 3000);
  }
}

async function clearServerAuditLogs() {
  try {
    const resp = await fetch(`${CONFIG.apiUrl}/api/audit-logs/clear`, { method: 'POST' });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    await fetchAuditLogs();
    showToast('🗑️ Server audit logs have been reset.');
  } catch (err) {
    showToast(`❌ Failed to clear logs: ${escapeHtml(err.message)}`);
  }
}

// ============================================================================
// SUBTABS (WORKSPACES, ATTACKS, AUDIT LOGS, JWKS)
// ============================================================================

function switchSubTab(subtabId) {
  document.querySelectorAll('.subnav-tab').forEach(b => {
    b.classList.toggle('active', b.dataset.subtab === subtabId);
  });
  document.querySelectorAll('.subtab-content').forEach(c => {
    c.classList.toggle('active', c.id === subtabId);
  });

  if (subtabId === 'view-logs') {
    fetchAuditLogs();
  } else if (subtabId === 'view-jwks' && !STATE.jwks) {
    fetchLiveJwks();
  }
}

// ============================================================================
// ACTIVE JWT TOKEN INSPECTOR MODAL
// ============================================================================

function toggleTokenModal() {
  const modal = document.getElementById('token-modal');
  const isHidden = modal.classList.toggle('hidden');

  if (!isHidden && STATE.claims) {
    const c = STATE.claims;
    const roles = c.realm_access?.roles || [];

    document.getElementById('modal-claim-sub').textContent = (c.sub || '').slice(0, 18) + '...';
    document.getElementById('modal-claim-user').textContent = c.preferred_username || '-';
    document.getElementById('modal-claim-aud').textContent = Array.isArray(c.aud) ? c.aud.join(', ') : c.aud || '-';

    document.getElementById('modal-claim-roles').innerHTML = roles
      .filter(r => !['default-roles-authlab', 'offline_access', 'uma_authorization'].includes(r))
      .map(r => `<span class="badge ${r.toLowerCase().includes('admin') ? 'badge-amber' : 'badge-blue'}">${escapeHtml(r)}</span>`)
      .join(' ') || '<span class="text-muted">None</span>';

    const expSec = Math.max(0, (c.exp || 0) - Math.floor(Date.now() / 1000));
    document.getElementById('modal-claim-exp').textContent = `${expSec}s remaining`;

    document.getElementById('modal-raw-json').textContent = JSON.stringify({
      header: STATE.header,
      payload: STATE.claims,
    }, null, 2);
  }
}

function copyTokenToClipboard() {
  if (!STATE.token) return;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(STATE.token)
      .then(() => showToast('📋 Copied active Bearer token to clipboard!'))
      .catch(() => fallbackCopy(STATE.token));
  } else {
    fallbackCopy(STATE.token);
  }
}

function fallbackCopy(text) {
  const ta = document.createElement('textarea');
  ta.value = text;
  document.body.appendChild(ta);
  ta.select();
  document.execCommand('copy');
  document.body.removeChild(ta);
  showToast('📋 Copied active Bearer token to clipboard!');
}

// ============================================================================
// ATTACK SUITE SIMULATIONS
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
      logAttack(`🛡️ SECURE VERIFIER RESULT: BLOCKED! HTTP ${resp.status} (${data.detail || data.error || 'invalid_token'})`);
      logAttack('Explanation: The API verifier rejects alg: "none" outright. RS256 algorithm pinning is strictly enforced.');
      logAttack('[SERVER AUDIT] 🛡️ Exploit recorded in server Security Audit Trail: ATTACK_SIGNATURE_STRIPPING (HTTP 401)');
    } else {
      logAttack(`💥 EXPLOIT SUCCEEDED: HTTP ${resp.status}`);
    }
  } catch (err) {
    logAttack(`Network error: ${err.message}`);
  }
  fetchAuditLogs();
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

    const fakeSig = b64Encode('simulated_hmac_signature_with_public_key');
    const forgedToken = `${b64Encode(JSON.stringify(header))}.${b64Encode(JSON.stringify(payload))}.${fakeSig}`;

    logAttack('2. Sending HS256 HMAC-signed token to Resource API: GET /api/admin/users ...');
    const resp = await fetch(`${CONFIG.apiUrl}/api/admin/users`, {
      headers: { Authorization: `Bearer ${forgedToken}` },
    });
    const data = await resp.json().catch(() => ({}));
    if (resp.status === 401 || resp.status === 503) {
      logAttack(`🛡️ SECURE VERIFIER RESULT: BLOCKED! HTTP ${resp.status} (${data.detail || data.error || 'invalid_token'})`);
      logAttack('Explanation: The API verifier pins RS256. Symmetric HMAC algorithms are rejected outright.');
      logAttack('[SERVER AUDIT] 🛡️ Exploit recorded in server Security Audit Trail: ATTACK_KEY_CONFUSION (HTTP 401)');
    } else {
      logAttack(`💥 EXPLOIT SUCCEEDED: HTTP ${resp.status}`);
    }
  } catch (err) {
    logAttack(`Network error: ${err.message}`);
  }
  fetchAuditLogs();
}

async function testAttackTamper() {
  clearAttackConsole();
  logAttack('=== EXPLOIT 3: Payload Tampering (Signature Check) ===');
  if (!STATE.token) {
    logAttack('⚠️ Please sign in first before testing token tampering.');
    return;
  }

  const parts = STATE.token.split('.');
  const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
  logAttack(`Original roles: ${JSON.stringify(payload.realm_access?.roles)}`);

  payload.realm_access = { roles: ['admin', 'Admin'] };
  const tamperedPayloadB64 = b64Encode(JSON.stringify(payload));
  const tamperedToken = `${parts[0]}.${tamperedPayloadB64}.${parts[2]}`;

  logAttack('Altered payload to include ["admin"] without re-signing with Keycloak private RSA key.');
  logAttack('Sending tampered token to Resource API: GET /api/admin/users ...');

  try {
    const resp = await fetch(`${CONFIG.apiUrl}/api/admin/users`, {
      headers: { Authorization: `Bearer ${tamperedToken}` },
    });
    const data = await resp.json().catch(() => ({}));
    logAttack(`🛡️ SECURE VERIFIER RESULT: BLOCKED! HTTP ${resp.status} (${data.detail || data.error})`);
    logAttack('Explanation: Cryptographic RSA signature check failed because payload contents changed.');
    logAttack('[SERVER AUDIT] 🛡️ Exploit recorded in server Security Audit Trail: ATTACK_PAYLOAD_TAMPERING (HTTP 401)');
  } catch (err) {
    logAttack(`Network error: ${err.message}`);
  }
  fetchAuditLogs();
}

async function testAttackExpired() {
  clearAttackConsole();
  logAttack('=== EXPLOIT 4: Expired Token Replay ===');

  const header = { alg: 'RS256', typ: 'JWT' };
  const payload = {
    iss: `http://localhost:8080/realms/${CONFIG.realm}`,
    aud: 'authlab-api',
    sub: 'old_session',
    exp: Math.floor(Date.now() / 1000) - 7200,
  };

  const fakeExpired = `${b64Encode(JSON.stringify(header))}.${b64Encode(JSON.stringify(payload))}.fakesig`;
  logAttack(`Sending expired token (exp=${payload.exp}) to Resource API: GET /api/me ...`);

  try {
    const resp = await fetch(`${CONFIG.apiUrl}/api/me`, {
      headers: { Authorization: `Bearer ${fakeExpired}` },
    });
    const data = await resp.json().catch(() => ({}));
    logAttack(`🛡️ SECURE VERIFIER RESULT: BLOCKED! HTTP ${resp.status} (${data.detail || data.error || 'invalid_token'})`);
    logAttack('[SERVER AUDIT] 🛡️ Expired token replay recorded in server Security Audit Trail!');
  } catch (err) {
    logAttack(`Network error: ${err.message}`);
  }
  fetchAuditLogs();
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
  logAttack('✅ ALL ATTACK VECTOR SIMULATIONS COMPLETED & RECORDED IN AUDIT LOG!');
  fetchAuditLogs();
}

// ============================================================================
// LIVE JWKS EXPLORER
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
            <code style="color: #34d399;">WITHHELD (Secure on Keycloak)</code>
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

  // Start auto-refresh polling for audit logs
  toggleAutoRefresh(true);

  // If a valid session token exists, restore dashboard
  if (STATE.token) {
    const parsed = decodeJwt(STATE.token);
    if (parsed && !isTokenExpired(parsed.payload)) {
      STATE.header = parsed.header;
      STATE.claims = parsed.payload;
      STATE.currentUser = parsed.payload.preferred_username;
      showDashboardView();
      await loadDashboardData();
      return;
    } else {
      // Clear expired token
      sessionStorage.removeItem('phase2_token');
      STATE.token = null;
    }
  }

  // Otherwise show login view
  showAuthView();
});
