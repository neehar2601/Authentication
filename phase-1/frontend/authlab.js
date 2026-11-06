/**
 * AuthLab — Role-Based Content Showcase Controller
 * Realm: authlab | Client: authlab-frontend | Roles: viewer (Reader), developer, admin
 */

const CONFIG = {
  keycloakBase: 'http://localhost:8080',
  realm: 'authlab',
  clientId: 'authlab-frontend',
  apiUrl: 'http://localhost:5001',
};

const STATE = {
  accessToken: sessionStorage.getItem('authlab_showcase_token') || null,
  portalData: null,
};

function escapeHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function decodeJwtPayload(token) {
  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
    return JSON.parse(atob(padded));
  } catch {
    return null;
  }
}

function showAuthAlert(msg, isError = true) {
  const box = document.getElementById('auth-alert');
  if (!box) return;
  box.className = `alert-box ${isError ? 'alert-error' : 'alert-success'}`;
  box.innerHTML = msg;
  box.classList.remove('hidden');
}

function hideAuthAlert() {
  const box = document.getElementById('auth-alert');
  if (box) box.classList.add('hidden');
}

function showToast(msg) {
  const toast = document.getElementById('portal-toast');
  if (!toast) return;
  toast.innerHTML = msg;
  toast.classList.remove('hidden');
  setTimeout(() => toast.classList.add('hidden'), 4000);
}

function switchAuthTab(tab) {
  hideAuthAlert();
  const isLogin = tab === 'login';
  document.getElementById('tab-btn-login').classList.toggle('active', isLogin);
  document.getElementById('tab-btn-register').classList.toggle('active', !isLogin);
  document.getElementById('login-form').classList.toggle('hidden', !isLogin);
  document.getElementById('register-form').classList.toggle('hidden', isLogin);
}

function setSessionToken(token) {
  STATE.accessToken = token;
  sessionStorage.setItem('authlab_showcase_token', token);
}

async function authenticateWithPassword(username, password) {
  hideAuthAlert();
  const tokenUrl = `${CONFIG.keycloakBase}/realms/${CONFIG.realm}/protocol/openid-connect/token`;
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
    throw new Error(data.error_description || data.error || 'Invalid credentials in authlab realm.');
  }

  setSessionToken(data.access_token);
  await loadPortalContent();
}

async function handleLoginSubmit(e) {
  e.preventDefault();
  const btn = document.getElementById('login-submit-btn');
  const username = document.getElementById('login-username').value;
  const password = document.getElementById('login-password').value;
  btn.disabled = true;
  btn.textContent = 'Signing in via Keycloak...';
  try {
    await authenticateWithPassword(username, password);
  } catch (err) {
    showAuthAlert(`<strong>Sign-In Failed:</strong> ${escapeHtml(err.message)}`, true);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Sign In with Keycloak (Realm: authlab)';
  }
}

async function quickLogin(username, password) {
  const uInput = document.getElementById('login-username');
  const pInput = document.getElementById('login-password');
  if (uInput) uInput.value = username;
  if (pInput) pInput.value = password;
  try {
    await authenticateWithPassword(username, password);
    showToast(`🔄 Switched active session to <strong>${escapeHtml(username)}</strong>.`);
  } catch (err) {
    showAuthAlert(`<strong>Demo Login Failed:</strong> ${escapeHtml(err.message)}`, true);
  }
}

function loginWithKeycloakRedirect() {
  const redirectUri = window.location.origin + window.location.pathname;
  const authUrl =
    `${CONFIG.keycloakBase}/realms/${CONFIG.realm}/protocol/openid-connect/auth` +
    `?client_id=${encodeURIComponent(CONFIG.clientId)}` +
    `&response_type=code` +
    `&scope=openid` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}`;
  window.location.href = authUrl;
}

async function handleOidcRedirectCallback() {
  const params = new URLSearchParams(window.location.search);
  const code = params.get('code');
  if (!code) return false;

  const redirectUri = window.location.origin + window.location.pathname;
  window.history.replaceState({}, document.title, redirectUri);

  try {
    const tokenUrl = `${CONFIG.keycloakBase}/realms/${CONFIG.realm}/protocol/openid-connect/token`;
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: CONFIG.clientId,
      code,
      redirect_uri: redirectUri,
    });
    const resp = await fetch(tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });
    const data = await resp.json();
    if (!resp.ok) {
      throw new Error(data.error_description || 'Failed to exchange code');
    }
    setSessionToken(data.access_token);
    await loadPortalContent();
    return true;
  } catch (err) {
    showAuthAlert(`<strong>Keycloak Redirect Error:</strong> ${escapeHtml(err.message)}`, true);
    return false;
  }
}

async function handleRegisterSubmit(e) {
  e.preventDefault();
  hideAuthAlert();
  const btn = document.getElementById('reg-submit-btn');
  const payload = {
    username: document.getElementById('reg-username').value.trim(),
    role: document.getElementById('reg-role').value,
    firstName: document.getElementById('reg-firstname').value.trim(),
    lastName: document.getElementById('reg-lastname').value.trim(),
    email: document.getElementById('reg-email').value.trim(),
    password: document.getElementById('reg-password').value,
  };

  btn.disabled = true;
  btn.textContent = 'Creating user in Keycloak...';
  try {
    const resp = await fetch(`${CONFIG.apiUrl}/api/authlab/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      throw new Error(data.detail || data.error || 'Registration failed');
    }

    await authenticateWithPassword(payload.username, payload.password);
    showToast(`🎉 Registered <strong>${escapeHtml(payload.username)}</strong> in <code>authlab</code> realm with role <code>${escapeHtml(payload.role)}</code>!`);
  } catch (err) {
    showAuthAlert(`<strong>Registration Failed:</strong> ${escapeHtml(err.message)}`, true);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Register in Keycloak (authlab) & Sign In';
  }
}

function logoutUser() {
  STATE.accessToken = null;
  STATE.portalData = null;
  sessionStorage.removeItem('authlab_showcase_token');

  document.getElementById('portal-view').classList.add('hidden');
  document.getElementById('nav-user-controls').classList.add('hidden');
  document.getElementById('auth-view').classList.remove('hidden');
}

// ============================================================================
// PORTAL CONTENT LOADING & ROLE-BASED RENDERING
// ============================================================================

async function apiRequest(path, method = 'GET', body = null) {
  const headers = {
    Authorization: `Bearer ${STATE.accessToken || ''}`,
  };
  if (body) headers['Content-Type'] = 'application/json';

  const resp = await fetch(`${CONFIG.apiUrl}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : null,
  });
  const data = await resp.json().catch(() => ({}));
  if (resp.status === 401) {
    logoutUser();
    showAuthAlert('Session expired. Please sign in again.', true);
    throw new Error('Unauthorized');
  }
  if (!resp.ok) {
    throw new Error(data.detail || data.error || `HTTP ${resp.status}`);
  }
  return data;
}

async function loadPortalContent() {
  const data = await apiRequest('/api/authlab/content');
  STATE.portalData = data;

  document.getElementById('auth-view').classList.add('hidden');
  document.getElementById('portal-view').classList.remove('hidden');
  document.getElementById('nav-user-controls').classList.remove('hidden');

  const u = data.user;
  const perms = data.permissions;
  const roleIcon = u.primary_role === 'admin' ? '🛡️' : u.primary_role === 'developer' ? '💻' : '📖';

  document.getElementById('nav-user-icon').textContent = roleIcon;
  document.getElementById('nav-user-name').textContent = `${u.name} (${u.username})`;
  document.getElementById('nav-user-role').textContent = u.role_label;

  // Update Banner Title & Description based on Role
  const bannerTitle = document.getElementById('banner-role-title');
  const bannerDesc = document.getElementById('banner-role-desc');
  if (u.primary_role === 'admin') {
    bannerTitle.textContent = `🛡️ Admin Access — ${u.name} (${u.username})`;
    bannerDesc.innerHTML =
      'You have <strong>Full Access</strong> to <strong>Reader Content</strong>, <strong>Developer Content</strong>, and <strong>Admin Content</strong> (Create, Edit &amp; Delete all tiers).';
  } else if (u.primary_role === 'developer') {
    bannerTitle.textContent = `💻 Developer Access — ${u.name} (${u.username})`;
    bannerDesc.innerHTML =
      'You have <strong>Read + Edit Access</strong> to both <strong>Reader Content</strong> and <strong>Developer Content</strong>. Admin Content is locked.';
  } else {
    bannerTitle.textContent = `📖 Reader Access — ${u.name} (${u.username})`;
    bannerDesc.innerHTML =
      'You have <strong>Read-Only Access</strong> to <strong>Reader Content</strong> only. Developer and Admin sections are locked.';
  }

  // Render Unlocked/Locked Pills
  document.getElementById('tier-status-pills').innerHTML = `
    <span class="tier-pill tier-unlocked">🔓 Reader Content</span>
    <span class="tier-pill ${perms.can_view_developer ? 'tier-unlocked' : 'tier-locked'}">
      ${perms.can_view_developer ? '🔓 Developer Content (Edit)' : '🔒 Developer Content'}
    </span>
    <span class="tier-pill ${perms.can_view_admin ? 'tier-unlocked' : 'tier-locked'}">
      ${perms.can_view_admin ? '🔓 Admin Content (Full)' : '🔒 Admin Content'}
    </span>
  `;

  // Show/hide Create Content form (only for developer & admin)
  const createBox = document.getElementById('create-content-box');
  createBox.classList.toggle('hidden', !perms.can_edit);
  const optAdmin = document.getElementById('opt-tier-admin');
  if (optAdmin) {
    optAdmin.disabled = !perms.can_view_admin;
    optAdmin.textContent = perms.can_view_admin
      ? '🛡️ Tier 3: Admin Content'
      : '🔒 Tier 3: Admin Content (Admin Only)';
  }

  // Filter items by tier
  const readerItems = data.items.filter(i => i.tier === 'reader');
  const devItems = data.items.filter(i => i.tier === 'developer');
  const adminItems = data.items.filter(i => i.tier === 'admin');

  // 1. Render Reader Tier (Always visible; editable if developer or admin)
  renderTierGrid('grid-reader', readerItems, perms.can_edit, perms.can_delete);

  // 2. Render Developer Tier (Visible & editable only if developer or admin)
  document.getElementById('section-developer').classList.toggle('hidden', !perms.can_view_developer);
  document.getElementById('locked-developer').classList.toggle('hidden', perms.can_view_developer);
  const lockedDevUser = document.getElementById('locked-dev-user');
  if (lockedDevUser) lockedDevUser.textContent = u.username;
  if (perms.can_view_developer) {
    renderTierGrid('grid-developer', devItems, perms.can_edit, perms.can_delete);
  }

  // 3. Render Admin Tier (Visible, editable, deletable only if admin)
  document.getElementById('section-admin').classList.toggle('hidden', !perms.can_view_admin);
  document.getElementById('locked-admin').classList.toggle('hidden', perms.can_view_admin);
  if (perms.can_view_admin) {
    renderTierGrid('grid-admin', adminItems, true, true);
  }
}

function renderTierGrid(containerId, items, canEdit, canDelete) {
  const container = document.getElementById(containerId);
  if (!container) return;

  container.innerHTML = items
    .map(item => {
      const badgeColor =
        item.tier === 'admin' ? 'badge-amber' : item.tier === 'developer' ? 'badge-blue' : 'badge-green';

      if (!canEdit) {
        // Strict Read-Only Card for Reader (viewer)
        return `
          <div class="content-card">
            <div>
              <div style="display:flex;justify-content:space-between;align-items:center;">
                <span class="badge ${badgeColor}">${escapeHtml(item.category)}</span>
                <span style="font-size:0.72rem;color:var(--text-dim);">📖 Read-Only</span>
              </div>
              <h4>${escapeHtml(item.title)}</h4>
              <p style="font-size:0.84rem;color:var(--text-dim);margin-top:0.35rem;">${escapeHtml(item.content_body)}</p>
            </div>
            <div>
              ${item.config_note ? `<div class="config-box">${escapeHtml(item.config_note)}</div>` : ''}
              <div style="font-size:0.72rem;color:var(--text-dim);margin-top:0.55rem;">
                Last updated by <code>${escapeHtml(item.updated_by)}</code> • ${escapeHtml(item.updated_at)}
              </div>
            </div>
          </div>
        `;
      }

      // Editable Card for Developer & Admin
      return `
        <div class="content-card">
          <div style="display:flex;flex-direction:column;gap:0.5rem;">
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <span class="badge ${badgeColor}">${escapeHtml(item.category)}</span>
              <span style="font-size:0.72rem;color:var(--text-muted);">✏️ Editable (${item.tier.toUpperCase()})</span>
            </div>
            <input
              type="text"
              id="edit-title-${item.id}"
              class="form-input"
              value="${escapeHtml(item.title)}"
              style="font-weight:600;padding:0.45rem 0.65rem;"
            />
            <textarea
              id="edit-body-${item.id}"
              class="form-input"
              rows="3"
              style="padding:0.45rem 0.65rem;font-size:0.82rem;resize:vertical;"
            >${escapeHtml(item.content_body)}</textarea>
            <input
              type="text"
              id="edit-cfg-${item.id}"
              class="form-input"
              value="${escapeHtml(item.config_note || '')}"
              placeholder="Config parameters"
              style="font-family:var(--font-mono);font-size:0.75rem;padding:0.4rem 0.65rem;"
            />
          </div>
          <div style="display:flex;justify-content:space-between;align-items:center;padding-top:0.5rem;border-top:1px solid var(--border-subtle);">
            <span style="font-size:0.7rem;color:var(--text-dim);">By <code>${escapeHtml(item.updated_by)}</code></span>
            <div style="display:inline-flex;gap:0.4rem;">
              <button type="button" class="btn btn-primary btn-sm" onclick="handleSaveContent(${item.id})">
                💾 Save Edit
              </button>
              ${
                canDelete
                  ? `<button type="button" class="btn btn-danger-soft btn-sm" onclick="handleDeleteContent(${item.id})">🗑️ Delete</button>`
                  : ''
              }
            </div>
          </div>
        </div>
      `;
    })
    .join('');
}

async function handleSaveContent(itemId) {
  const payload = {
    title: document.getElementById(`edit-title-${itemId}`).value,
    content_body: document.getElementById(`edit-body-${itemId}`).value,
    config_note: document.getElementById(`edit-cfg-${itemId}`).value,
  };
  const res = await apiRequest(`/api/authlab/content/${itemId}`, 'PUT', payload);
  showToast(`✅ ${escapeHtml(res.message)}`);
  await loadPortalContent();
}

async function handleCreateContent(e) {
  e.preventDefault();
  const payload = {
    tier: document.getElementById('new-tier').value,
    category: document.getElementById('new-category').value,
    title: document.getElementById('new-title').value,
    content_body: document.getElementById('new-body').value,
    config_note: document.getElementById('new-config').value,
  };
  const res = await apiRequest('/api/authlab/content', 'POST', payload);
  document.getElementById('new-category').value = '';
  document.getElementById('new-title').value = '';
  document.getElementById('new-body').value = '';
  document.getElementById('new-config').value = '';
  showToast(`✨ ${escapeHtml(res.message)}`);
  await loadPortalContent();
}

async function handleDeleteContent(itemId) {
  const res = await apiRequest(`/api/authlab/content/${itemId}`, 'DELETE');
  showToast(`🗑️ ${escapeHtml(res.message)}`);
  await loadPortalContent();
}

function toggleJwtModal() {
  const modal = document.getElementById('jwt-modal');
  modal.classList.toggle('hidden');
  if (!modal.classList.contains('hidden')) {
    const claims = decodeJwtPayload(STATE.accessToken);
    document.getElementById('jwt-decoded-pre').textContent = JSON.stringify(claims, null, 2);
  }
}

window.addEventListener('DOMContentLoaded', async () => {
  const handledRedirect = await handleOidcRedirectCallback();
  if (!handledRedirect && STATE.accessToken) {
    try {
      await loadPortalContent();
    } catch {
      logoutUser();
    }
  }
});

