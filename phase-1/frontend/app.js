/**
 * FarmSight 360 — Keycloak Integrated Sample Application
 * Realm: farm360 | Client: farm360-web | API: http://localhost:5001
 */

const CONFIG = {
  keycloakBase: 'http://localhost:8080',
  realm: 'farm360',
  clientId: 'farm360-web',
  apiUrl: 'http://localhost:5001',
};

const STATE = {
  accessToken: sessionStorage.getItem('farm360_token') || null,
  claims: null,
  dashboard: null,
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
  const toast = document.getElementById('dashboard-toast');
  if (!toast) return;
  toast.innerHTML = msg;
  toast.classList.remove('hidden');
  setTimeout(() => toast.classList.add('hidden'), 4000);
}

// ============================================================================
// AUTHENTICATION TABS & KEYCLOAK FLOWS
// ============================================================================

function switchAuthTab(tab) {
  hideAuthAlert();
  const isLogin = tab === 'login';
  document.getElementById('tab-btn-login').classList.toggle('active', isLogin);
  document.getElementById('tab-btn-register').classList.toggle('active', !isLogin);
  document.getElementById('login-form').classList.toggle('hidden', !isLogin);
  document.getElementById('register-form').classList.toggle('hidden', isLogin);
}

async function checkRealmHealth() {
  const textEl = document.getElementById('kc-status-text');
  try {
    const res = await fetch(`${CONFIG.apiUrl}/health`);
    const data = await res.json();
    if (res.ok && data.status === 'ok') {
      textEl.textContent = `Keycloak Realm: ${data.realm} (Online)`;
    } else {
      textEl.textContent = 'Keycloak: Initializing...';
    }
  } catch {
    textEl.textContent = 'Keycloak / API Offline';
  }
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
    throw new Error(data.error_description || data.error || 'Invalid credentials or account disabled in Keycloak.');
  }

  setSessionToken(data.access_token);
  await loadDashboard();
}

function setSessionToken(token) {
  STATE.accessToken = token;
  STATE.claims = decodeJwtPayload(token);
  sessionStorage.setItem('farm360_token', token);
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
    btn.textContent = 'Sign In with Keycloak (Realm: farm360)';
  }
}

async function quickLogin(username, password) {
  document.getElementById('login-username').value = username;
  document.getElementById('login-password').value = password;
  try {
    await authenticateWithPassword(username, password);
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
      throw new Error(data.error_description || 'Failed to exchange authorization code');
    }
    setSessionToken(data.access_token);
    await loadDashboard();
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
    const resp = await fetch(`${CONFIG.apiUrl}/api/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      throw new Error(data.detail || data.error || 'Registration failed');
    }

    await authenticateWithPassword(payload.username, payload.password);
    showToast(`🎉 Welcome <strong>${escapeHtml(payload.username)}</strong>! Your account is now registered in Keycloak realm <code>farm360</code>.`);
  } catch (err) {
    showAuthAlert(`<strong>Registration Failed:</strong> ${escapeHtml(err.message)}`, true);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Create Account in Keycloak & Sign In';
  }
}

function logoutUser() {
  STATE.accessToken = null;
  STATE.claims = null;
  STATE.dashboard = null;
  sessionStorage.removeItem('farm360_token');

  document.getElementById('dashboard-view').classList.add('hidden');
  document.getElementById('nav-user-controls').classList.add('hidden');
  document.getElementById('auth-view').classList.remove('hidden');
}

// ============================================================================
// DASHBOARD LOADING & RENDERING
// ============================================================================

async function apiRequest(path, method = 'GET', body = null) {
  const headers = {
    Authorization: `Bearer ${STATE.accessToken || ''}`,
  };
  if (body) {
    headers['Content-Type'] = 'application/json';
  }
  const resp = await fetch(`${CONFIG.apiUrl}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : null,
  });
  const data = await resp.json().catch(() => ({}));
  if (resp.status === 401) {
    logoutUser();
    showAuthAlert('Your Keycloak session expired or was revoked. Please sign in again.', true);
    throw new Error('Unauthorized');
  }
  if (!resp.ok) {
    throw new Error(data.detail || data.error || `HTTP ${resp.status}`);
  }
  return data;
}

async function loadDashboard() {
  const data = await apiRequest('/api/dashboard');
  STATE.dashboard = data;

  document.getElementById('auth-view').classList.add('hidden');
  document.getElementById('dashboard-view').classList.remove('hidden');
  document.getElementById('nav-user-controls').classList.remove('hidden');

  const u = data.user;
  const roleIcon = u.primary_role === 'admin' ? '🛡️' : u.primary_role === 'service_provider' ? '🚜' : '👨‍🌾';
  document.getElementById('nav-user-icon').textContent = roleIcon;
  document.getElementById('nav-user-name').textContent = `${u.name} (${u.username})`;
  document.getElementById('nav-user-role').textContent = `Keycloak Role: ${u.primary_role}`;

  // Update KPIs
  document.getElementById('kpi-plots').textContent = data.kpis.total_plots;
  document.getElementById('kpi-acres').textContent = `${data.kpis.total_acres} Acres Total`;
  document.getElementById('kpi-workers').textContent = data.kpis.active_workers;
  document.getElementById('kpi-bookings').textContent = data.kpis.open_bookings;
  document.getElementById('kpi-balance').textContent = `₹${Number(data.kpis.net_balance).toLocaleString('en-IN')}`;
  document.getElementById('kpi-inc-exp').textContent =
    `Income: ₹${Number(data.kpis.total_income).toLocaleString('en-IN')} | Expense: ₹${Number(data.kpis.total_expense).toLocaleString('en-IN')}`;

  renderCrops(data.crops);
  renderWorkers(data.workers);
  renderMarketplace(data.services, data.bookings);
  renderFinances(data.finances);
}

function switchModuleTab(tabName) {
  document.querySelectorAll('.module-tab').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.tab === tabName);
  });
  ['crops', 'workers', 'marketplace', 'finances'].forEach(mod => {
    document.getElementById(`mod-${mod}`).classList.toggle('hidden', mod !== tabName);
  });
}

function renderCrops(crops) {
  const tbody = document.getElementById('crops-tbody');
  const stages = ['Planted', 'Growing', 'Flowering', 'Ready for Harvest', 'Harvested'];

  tbody.innerHTML = crops
    .map(c => {
      const badgeClass =
        c.stage === 'Ready for Harvest'
          ? 'badge-amber'
          : c.stage === 'Harvested'
            ? 'badge-blue'
            : 'badge-green';

      return `
        <tr>
          <td><strong>${escapeHtml(c.farm_name)}</strong></td>
          <td>${escapeHtml(c.crop_name)} <span style="color:var(--text-dim);font-size:0.78rem;">(${escapeHtml(c.variety)})</span></td>
          <td>${c.area_acres} ac</td>
          <td><span class="badge ${badgeClass}">${escapeHtml(c.stage)}</span></td>
          <td><strong>${Number(c.expected_yield_kg).toLocaleString('en-IN')} kg</strong></td>
          <td><code>${escapeHtml(c.owner_username)}</code></td>
          <td style="text-align: right;">
            <div style="display:inline-flex;gap:0.4rem;align-items:center;">
              <select class="form-input" style="width:auto;padding:0.25rem 0.5rem;font-size:0.76rem;" onchange="handleUpdateCropStage(${c.id}, this.value)">
                ${stages.map(s => `<option value="${s}" ${s === c.stage ? 'selected' : ''}>${s}</option>`).join('')}
              </select>
              <button type="button" class="btn btn-danger-soft btn-sm" onclick="handleDeleteCrop(${c.id})">🗑️</button>
            </div>
          </td>
        </tr>
      `;
    })
    .join('');
}

function renderWorkers(workers) {
  const tbody = document.getElementById('workers-tbody');
  tbody.innerHTML = workers
    .map(w => {
      const badgeClass =
        w.attendance_status === 'Present'
          ? 'badge-green'
          : w.attendance_status === 'Half-Day'
            ? 'badge-amber'
            : 'badge-red';
      return `
        <tr>
          <td><strong>${escapeHtml(w.worker_name)}</strong></td>
          <td>${escapeHtml(w.role_title)}</td>
          <td>${escapeHtml(w.assigned_farm)}</td>
          <td>₹${Number(w.daily_wage).toLocaleString('en-IN')} / day</td>
          <td><span class="badge ${badgeClass}">${escapeHtml(w.attendance_status)}</span></td>
          <td style="text-align: right;">
            <div style="display:inline-flex;gap:0.35rem;">
              <button type="button" class="btn btn-ghost btn-sm" onclick="handleMarkAttendance(${w.id}, 'Present')">✅ Present</button>
              <button type="button" class="btn btn-ghost btn-sm" onclick="handleMarkAttendance(${w.id}, 'Half-Day')">⏳ Half-Day</button>
              <button type="button" class="btn btn-ghost btn-sm" onclick="handleMarkAttendance(${w.id}, 'Absent')">❌ Absent</button>
            </div>
          </td>
        </tr>
      `;
    })
    .join('');
}

function renderMarketplace(services, bookings) {
  const grid = document.getElementById('services-grid');
  grid.innerHTML = services
    .map(
      s => `
      <div class="service-card">
        <div>
          <span class="badge badge-green" style="margin-bottom:0.4rem;">${escapeHtml(s.category)}</span>
          <h4>${escapeHtml(s.service_name)}</h4>
          <p style="font-size:0.78rem;color:var(--text-dim);margin:0.35rem 0;">${escapeHtml(s.description)}</p>
          <div style="font-size:0.74rem;color:var(--text-secondary);">Provider: <strong>${escapeHtml(s.provider_name)}</strong> (<code>${escapeHtml(s.provider_username)}</code>)</div>
        </div>
        <div style="display:flex;justify-content:space-between;align-items:center;padding-top:0.65rem;border-top:1px solid var(--border-subtle);">
          <div>
            <span class="service-rate">₹${Number(s.rate_inr).toLocaleString('en-IN')}</span>
            <span style="font-size:0.74rem;color:var(--text-dim);">${escapeHtml(s.rate_unit)}</span>
          </div>
          <button type="button" class="btn btn-primary btn-sm" onclick="handleBookService(${s.id}, '${escapeHtml(s.service_name)}')">
            📅 Book Service
          </button>
        </div>
      </div>
    `
    )
    .join('');

  const bTbody = document.getElementById('bookings-tbody');
  bTbody.innerHTML = bookings
    .map(b => {
      const badgeClass =
        b.status === 'Completed'
          ? 'badge-green'
          : b.status === 'Confirmed'
            ? 'badge-blue'
            : 'badge-amber';
      return `
        <tr>
          <td>
            <strong>${escapeHtml(b.service_name)}</strong>
            <div style="font-size:0.74rem;color:var(--text-dim);">Farm: ${escapeHtml(b.farm_name)} | By: <code>${escapeHtml(b.farmer_username)}</code></div>
          </td>
          <td>${escapeHtml(b.scheduled_date)}</td>
          <td><strong>₹${Number(b.amount_inr).toLocaleString('en-IN')}</strong></td>
          <td><span class="badge ${badgeClass}">${escapeHtml(b.status)}</span></td>
          <td style="text-align: right;">
            <select class="form-input" style="width:auto;padding:0.25rem 0.45rem;font-size:0.74rem;" onchange="handleUpdateBookingStatus(${b.id}, this.value)">
              <option value="Pending" ${b.status === 'Pending' ? 'selected' : ''}>Pending</option>
              <option value="Confirmed" ${b.status === 'Confirmed' ? 'selected' : ''}>Confirmed</option>
              <option value="Completed" ${b.status === 'Completed' ? 'selected' : ''}>Completed</option>
            </select>
          </td>
        </tr>
      `;
    })
    .join('');
}

function renderFinances(finances) {
  const tbody = document.getElementById('finances-tbody');
  tbody.innerHTML = finances
    .map(f => {
      const isInc = f.tx_type === 'INCOME';
      return `
        <tr>
          <td><span class="badge ${isInc ? 'badge-green' : 'badge-red'}">${escapeHtml(f.tx_type)}</span></td>
          <td><strong>${escapeHtml(f.category)}</strong></td>
          <td>${escapeHtml(f.description)}</td>
          <td><code>${escapeHtml(f.recorded_by)}</code></td>
          <td>${escapeHtml(f.tx_date)}</td>
          <td style="text-align:right;font-weight:700;color:${isInc ? '#34d399' : '#fca5a5'};">
            ${isInc ? '+' : '-'}₹${Number(f.amount_inr).toLocaleString('en-IN')}
          </td>
        </tr>
      `;
    })
    .join('');
}

// ============================================================================
// CRUD HANDLERS
// ============================================================================

async function handleAddCrop(e) {
  e.preventDefault();
  const payload = {
    farm_name: document.getElementById('crop-farm').value,
    crop_name: document.getElementById('crop-name').value,
    variety: document.getElementById('crop-variety').value || 'Standard',
    area_acres: parseFloat(document.getElementById('crop-acres').value || '1'),
    expected_yield_kg: parseInt(document.getElementById('crop-yield').value || '1000', 10),
  };
  await apiRequest('/api/crops', 'POST', payload);
  e.target.reset();
  showToast(`🌾 Added crop plot <strong>${escapeHtml(payload.crop_name)}</strong>.`);
  await loadDashboard();
}

async function handleUpdateCropStage(cropId, stage) {
  await apiRequest(`/api/crops/${cropId}`, 'PUT', { stage });
  showToast(`🌱 Updated crop #${cropId} stage to <strong>${escapeHtml(stage)}</strong>.`);
  await loadDashboard();
}

async function handleDeleteCrop(cropId) {
  await apiRequest(`/api/crops/${cropId}`, 'DELETE');
  showToast(`🗑️ Removed crop plot #${cropId}.`);
  await loadDashboard();
}

async function handleAddWorker(e) {
  e.preventDefault();
  const payload = {
    worker_name: document.getElementById('wrk-name').value,
    role_title: document.getElementById('wrk-role').value,
    daily_wage: parseInt(document.getElementById('wrk-wage').value || '550', 10),
    assigned_farm: document.getElementById('wrk-farm').value,
  };
  await apiRequest('/api/workers', 'POST', payload);
  document.getElementById('wrk-name').value = '';
  document.getElementById('wrk-role').value = '';
  showToast(`👷 Added worker <strong>${escapeHtml(payload.worker_name)}</strong>.`);
  await loadDashboard();
}

async function handleMarkAttendance(workerId, status) {
  await apiRequest(`/api/workers/${workerId}/attendance`, 'PUT', { attendance_status: status });
  showToast(`📋 Attendance updated to <strong>${escapeHtml(status)}</strong>.`);
  await loadDashboard();
}

async function handleAddService(e) {
  e.preventDefault();
  const payload = {
    service_name: document.getElementById('svc-name').value,
    category: document.getElementById('svc-category').value,
    rate_inr: parseInt(document.getElementById('svc-rate').value || '1000', 10),
    rate_unit: document.getElementById('svc-unit').value,
  };
  await apiRequest('/api/services', 'POST', payload);
  e.target.reset();
  showToast(`🚜 Listed new marketplace service <strong>${escapeHtml(payload.service_name)}</strong>.`);
  await loadDashboard();
}

async function handleBookService(serviceId, serviceName) {
  const defaultFarm = STATE.dashboard?.crops?.[0]?.farm_name || 'Green Valley Estate';
  const res = await apiRequest('/api/bookings', 'POST', {
    service_id: serviceId,
    farm_name: defaultFarm,
    scheduled_date: new Date(Date.now() + 86400000 * 2).toISOString().slice(0, 10),
    units: 2,
  });
  showToast(`📅 ${escapeHtml(res.message)}`);
  await loadDashboard();
}

async function handleUpdateBookingStatus(bookingId, status) {
  await apiRequest(`/api/bookings/${bookingId}/status`, 'PUT', { status });
  showToast(`✅ Booking #${bookingId} marked as <strong>${escapeHtml(status)}</strong>.`);
  await loadDashboard();
}

async function handleAddFinance(e) {
  e.preventDefault();
  const payload = {
    tx_type: document.getElementById('fin-type').value,
    category: document.getElementById('fin-category').value,
    description: document.getElementById('fin-desc').value,
    amount_inr: parseInt(document.getElementById('fin-amount').value || '0', 10),
  };
  await apiRequest('/api/finances', 'POST', payload);
  document.getElementById('fin-category').value = '';
  document.getElementById('fin-desc').value = '';
  document.getElementById('fin-amount').value = '';
  showToast(`💰 Recorded ${escapeHtml(payload.tx_type)} entry.`);
  await loadDashboard();
}

function toggleJwtModal() {
  const modal = document.getElementById('jwt-modal');
  modal.classList.toggle('hidden');
  if (!modal.classList.contains('hidden')) {
    const claims = decodeJwtPayload(STATE.accessToken);
    document.getElementById('jwt-decoded-pre').textContent = JSON.stringify(claims, null, 2);
  }
}

// ============================================================================
// INITIALIZATION
// ============================================================================

window.addEventListener('DOMContentLoaded', async () => {
  await checkRealmHealth();
  const handledRedirect = await handleOidcRedirectCallback();
  if (!handledRedirect && STATE.accessToken) {
    try {
      await loadDashboard();
    } catch {
      logoutUser();
    }
  }
});
