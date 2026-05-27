// Global State
let adminKey = sessionStorage.getItem('adminKey') || '';
let currentTab = 'dashboard';
let appPaused = false;
let appSecretRevealed = false;
let originalSecret = '';

// Pagination States
let licensePage = 1;
let userPage = 1;
let logPage = 1;

let licensesData = [];
let usersData = [];

// Initialize Dashboard
document.addEventListener('DOMContentLoaded', () => {
  if (adminKey) {
    document.getElementById('loginOverlay').style.display = 'none';
    document.getElementById('app').style.display = 'flex';
    initDashboard();
  }
});

// Toast System
function showToast(message, type = 'success') {
  const container = document.getElementById('toastContainer');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `
    <span>${type === 'success' ? '✅' : '❌'}</span>
    <div>${message}</div>
  `;
  container.appendChild(toast);
  
  setTimeout(() => {
    toast.style.animation = 'slideIn 0.3s reverse forwards';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// API Fetch Wrapper
async function apiCall(endpoint, method = 'GET', body = null) {
  const headers = {
    'Content-Type': 'application/json',
    'X-Admin-Key': adminKey
  };
  
  const options = { method, headers };
  if (body) {
    options.body = JSON.stringify(body);
  }
  
  try {
    const res = await fetch(endpoint, options);
    const data = await res.json();
    if (!res.ok || data.success === false) {
      throw new Error(data.message || 'API request failed.');
    }
    return data;
  } catch (error) {
    showToast(error.message, 'error');
    if (res.status === 401) {
      handleLogout();
    }
    throw error;
  }
}

// Auth Login
async function handleLogin(e) {
  e.preventDefault();
  const inputKey = document.getElementById('adminKeyInput').value;
  
  try {
    const res = await fetch('/api/admin/auth', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: inputKey })
    });
    const data = await res.json();
    
    if (data.success) {
      adminKey = inputKey;
      sessionStorage.setItem('adminKey', adminKey);
      document.getElementById('loginOverlay').style.display = 'none';
      document.getElementById('app').style.display = 'flex';
      showToast('Authenticated successfully.');
      initDashboard();
    } else {
      showToast(data.message || 'Incorrect Admin Key.', 'error');
    }
  } catch (err) {
    showToast('Failed to connect to authentication server.', 'error');
  }
}

// Auth Logout
function handleLogout() {
  adminKey = '';
  sessionStorage.removeItem('adminKey');
  document.getElementById('app').style.display = 'none';
  document.getElementById('loginOverlay').style.display = 'flex';
  document.getElementById('adminKeyInput').value = '';
}

// Switch Page
function switchPage(pageId) {
  currentTab = pageId;
  
  // Update sidebar active class
  document.querySelectorAll('.nav-menu li').forEach(li => {
    li.classList.remove('active');
    if (li.getAttribute('data-page') === pageId) {
      li.classList.add('active');
    }
  });
  
  // Show page
  document.querySelectorAll('section').forEach(sec => {
    sec.classList.remove('active');
  });
  const activeSec = document.getElementById(`page-${pageId}`);
  if (activeSec) {
    activeSec.classList.add('active');
  }
  
  // Refresh page data
  if (pageId === 'dashboard') loadDashboardStats();
  if (pageId === 'licenses') loadLicenses(1);
  if (pageId === 'users') loadUsers(1);
  if (pageId === 'logs') loadLogs(1);
  if (pageId === 'settings') loadSettings();
}

// Init everything
function initDashboard() {
  switchPage('dashboard');
}

// Helper formatting functions
function formatDate(isoString) {
  if (!isoString) return 'Never';
  const date = new Date(isoString);
  return date.toLocaleString();
}

function truncateString(str, len = 12) {
  if (!str) return 'N/A';
  if (str.length <= len) return str;
  return str.substring(0, len) + '...';
}

function getStatusBadge(status) {
  switch (status) {
    case 'unused': return `<span class="badge badge-unused">Unused</span>`;
    case 'used': return `<span class="badge badge-active">Active</span>`;
    case 'banned': return `<span class="badge badge-banned">Banned</span>`;
    case 'expired': return `<span class="badge badge-expired">Expired</span>`;
    default: return `<span class="badge badge-expired">${status}</span>`;
  }
}

// ==========================================
// DASHBOARD
// ==========================================
async function loadDashboardStats() {
  try {
    const data = await apiCall('/api/admin/stats');
    if (data.success) {
      document.getElementById('stat-total-users').innerText = data.stats.totalUsers;
      document.getElementById('stat-total-licenses').innerText = data.stats.totalLicenses;
      document.getElementById('stat-active-licenses').innerText = data.stats.activeLicenses;
      document.getElementById('stat-unused-licenses').innerText = data.stats.unusedLicenses;
      
      // Load recent logs
      const logsBody = document.getElementById('dashboard-recent-logs');
      logsBody.innerHTML = '';
      if (data.stats.recentLogins.length === 0) {
        logsBody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-muted);">No login events yet.</td></tr>`;
      } else {
        data.stats.recentLogins.slice(0, 10).forEach(log => {
          logsBody.innerHTML += `
            <tr>
              <td><span class="badge badge-active">${log.event}</span></td>
              <td>${log.username || 'Anonymous'}</td>
              <td>${log.details}</td>
              <td>${formatDate(log.created_at)}</td>
            </tr>
          `;
        });
      }
    }
  } catch (err) {}
}

// ==========================================
// LICENSES
// ==========================================
async function loadLicenses(page = 1) {
  licensePage = page;
  try {
    const data = await apiCall(`/api/admin/licenses?page=${page}&limit=20`);
    if (data.success) {
      licensesData = data.licenses;
      renderLicensesTable(licensesData);
      document.getElementById('license-page-num').innerText = `Page ${page} of ${Math.ceil(data.total / 20) || 1}`;
      
      document.getElementById('btn-license-prev').disabled = page === 1;
      document.getElementById('btn-license-next').disabled = page >= Math.ceil(data.total / 20);
    }
  } catch (err) {}
}

function renderLicensesTable(licenses) {
  const tbody = document.getElementById('licenses-table-body');
  tbody.innerHTML = '';
  
  if (licenses.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted);">No licenses found.</td></tr>`;
    return;
  }
  
  licenses.forEach(lic => {
    const actionBtn = lic.status === 'banned' 
      ? `<button class="btn btn-secondary btn-sm" onclick="unbanLicense(${lic.id})">😇 Unban</button>`
      : `<button class="btn btn-danger btn-sm" onclick="banLicense(${lic.id})">🚫 Ban</button>`;
      
    tbody.innerHTML += `
      <tr>
        <td style="font-family: monospace; font-weight: 600; color: var(--text-primary);">${lic.key}</td>
        <td>${lic.duration_days} Days</td>
        <td>Level ${lic.level}</td>
        <td>${getStatusBadge(lic.status)}</td>
        <td>
          <div style="font-weight: 500;">${lic.used_by || 'Unused'}</div>
          <div style="font-size: 0.75rem; color: var(--text-muted);" title="${lic.hwid || 'N/A'}">${truncateString(lic.hwid, 16)}</div>
        </td>
        <td>${formatDate(lic.created_at)}</td>
        <td>${formatDate(lic.expires_at)}</td>
        <td style="text-align: right; display: flex; justify-content: flex-end; gap: 8px;">
          ${actionBtn}
          <button class="btn btn-secondary btn-sm" onclick="resetLicenseHwid(${lic.id})" title="Reset License HWID">🔄 HWID</button>
          <button class="btn btn-danger btn-sm" onclick="deleteLicense(${lic.id})" style="padding: 6px 10px;">🗑️</button>
        </td>
      </tr>
    `;
  });
}

function changeLicensePage(dir) {
  loadLicenses(licensePage + dir);
}

function filterLicenses() {
  const query = document.getElementById('license-search').value.toLowerCase();
  const filtered = licensesData.filter(lic => 
    lic.key.toLowerCase().includes(query) || 
    (lic.used_by && lic.used_by.toLowerCase().includes(query)) ||
    (lic.hwid && lic.hwid.toLowerCase().includes(query))
  );
  renderLicensesTable(filtered);
}

async function banLicense(id) {
  if (confirm('Are you sure you want to ban this license key?')) {
    await apiCall(`/api/admin/licenses/${id}/ban`, 'POST');
    showToast('License key banned.');
    loadLicenses(licensePage);
  }
}

async function unbanLicense(id) {
  await apiCall(`/api/admin/licenses/${id}/unban`, 'POST');
  showToast('License key unbanned.');
  loadLicenses(licensePage);
}

async function deleteLicense(id) {
  if (confirm('Are you sure you want to permanently delete this license?')) {
    await apiCall(`/api/admin/licenses/${id}`, 'DELETE');
    showToast('License deleted.');
    loadLicenses(licensePage);
  }
}

async function resetLicenseHwid(id) {
  if (confirm('Are you sure you want to reset the HWID lock for this license?')) {
    await apiCall(`/api/admin/licenses/${id}/reset-hwid`, 'POST');
    showToast("License's HWID lock has been reset.");
    loadLicenses(licensePage);
  }
}

// Generate License Modals
function openGenerateModal() {
  document.getElementById('generateModal').classList.add('active');
  document.getElementById('generate-results-wrapper').style.display = 'none';
  document.getElementById('generated-keys-list').innerHTML = '';
}

function closeGenerateModal() {
  document.getElementById('generateModal').classList.remove('active');
}

async function submitGenerateLicenses(e) {
  e.preventDefault();
  
  const count = document.getElementById('genCount').value;
  const duration_days = document.getElementById('genDuration').value;
  const level = document.getElementById('genLevel').value;
  const prefix = document.getElementById('genPrefix').value;
  const note = document.getElementById('genNote').value;
  
  try {
    const data = await apiCall('/api/admin/licenses/generate', 'POST', { count, duration_days, level, prefix, note });
    if (data.success) {
      showToast(`Successfully generated ${count} licenses.`);
      
      const resultsWrapper = document.getElementById('generate-results-wrapper');
      const listArea = document.getElementById('generated-keys-list');
      
      listArea.innerHTML = '';
      data.keys.forEach(k => {
        listArea.innerHTML += `<div class="generated-key-item">${k}</div>`;
      });
      
      resultsWrapper.style.display = 'block';
    }
  } catch (err) {}
}

function copyAllGeneratedKeys() {
  const items = document.querySelectorAll('.generated-key-item');
  const keys = Array.from(items).map(div => div.innerText).join('\n');
  
  navigator.clipboard.writeText(keys).then(() => {
    showToast('All keys copied to clipboard!');
  }).catch(() => {
    showToast('Failed to copy. Please manually select and copy.', 'error');
  });
}

// ==========================================
// USERS
// ==========================================
async function loadUsers(page = 1) {
  userPage = page;
  try {
    const data = await apiCall(`/api/admin/users?page=${page}&limit=20`);
    if (data.success) {
      usersData = data.users;
      renderUsersTable(usersData);
      document.getElementById('user-page-num').innerText = `Page ${page} of ${Math.ceil(data.total / 20) || 1}`;
      
      document.getElementById('btn-user-prev').disabled = page === 1;
      document.getElementById('btn-user-next').disabled = page >= Math.ceil(data.total / 20);
    }
  } catch (err) {}
}

function renderUsersTable(users) {
  const tbody = document.getElementById('users-table-body');
  tbody.innerHTML = '';
  
  if (users.length === 0) {
    tbody.innerHTML = `<tr><td colspan="10" style="text-align: center; color: var(--text-muted);">No users found.</td></tr>`;
    return;
  }
  
  users.forEach(usr => {
    const statusLabel = usr.banned === 1 
      ? `<span class="badge badge-banned">Banned</span>`
      : (new Date(usr.expires_at) < new Date() ? `<span class="badge badge-expired">Expired</span>` : `<span class="badge badge-active">Active</span>`);
      
    const actionBtn = usr.banned === 1
      ? `<button class="btn btn-secondary btn-sm" onclick="unbanUser(${usr.id})">😇 Unban</button>`
      : `<button class="btn btn-danger btn-sm" onclick="banUser(${usr.id})">🚫 Ban</button>`;

    const emailDisplay = usr.email
      ? `<span title="${usr.email}" style="color:var(--text-primary);">${usr.email}</span>`
      : `<span style="color:var(--text-muted);">—</span>`;

    const discordDisplay = usr.discord
      ? `<span title="${usr.discord}" style="color:#7289da;font-weight:500;">🎮 ${usr.discord}</span>`
      : `<span style="color:var(--text-muted);">—</span>`;
      
    tbody.innerHTML += `
      <tr>
        <td style="font-weight: 600; color: var(--text-primary);">${usr.username}</td>
        <td style="font-family: monospace; font-size: 0.8rem;" title="${usr.hwid || 'No HWID locked'}">${truncateString(usr.hwid, 16)}</td>
        <td>Level ${usr.subscription_level}</td>
        <td>${statusLabel}</td>
        <td style="font-family:monospace;font-size:0.8rem;">${usr.ip || '<span style="color:var(--text-muted);">N/A</span>'}</td>
        <td>${emailDisplay}</td>
        <td>${discordDisplay}</td>
        <td>${formatDate(usr.last_login)}</td>
        <td>${formatDate(usr.expires_at)}</td>
        <td style="text-align: right; display: flex; justify-content: flex-end; gap: 8px;">
          ${actionBtn}
          <button class="btn btn-secondary btn-sm" onclick="resetHwid(${usr.id})" title="Reset HWID Lock">🔄 HWID</button>
          <button class="btn btn-danger btn-sm" onclick="deleteUser(${usr.id})">🗑️</button>
        </td>
      </tr>
    `;
  });
}

function changeUserPage(dir) {
  loadUsers(userPage + dir);
}

function filterUsers() {
  const query = document.getElementById('user-search').value.toLowerCase();
  const filtered = usersData.filter(usr => 
    usr.username.toLowerCase().includes(query) || 
    (usr.hwid && usr.hwid.toLowerCase().includes(query)) ||
    (usr.ip && usr.ip.toLowerCase().includes(query)) ||
    (usr.email && usr.email.toLowerCase().includes(query)) ||
    (usr.discord && usr.discord.toLowerCase().includes(query))
  );
  renderUsersTable(filtered);
}

async function banUser(id) {
  if (confirm('Are you sure you want to ban this user?')) {
    await apiCall(`/api/admin/users/${id}/ban`, 'POST');
    showToast('User account banned.');
    loadUsers(userPage);
  }
}

async function unbanUser(id) {
  await apiCall(`/api/admin/users/${id}/unban`, 'POST');
  showToast('User account unbanned.');
  loadUsers(userPage);
}

async function resetHwid(id) {
  await apiCall(`/api/admin/users/${id}/reset-hwid`, 'POST');
  showToast("User's HWID lock has been reset.");
  loadUsers(userPage);
}

async function deleteUser(id) {
  if (confirm('Are you sure you want to permanently delete this user?')) {
    await apiCall(`/api/admin/users/${id}`, 'DELETE');
    showToast('User account deleted.');
    loadUsers(userPage);
  }
}

// ==========================================
// LOGS
// ==========================================
async function loadLogs(page = 1) {
  logPage = page;
  const filter = document.getElementById('log-filter-select').value;
  const filterQuery = filter ? `&event=${filter}` : '';
  
  try {
    const data = await apiCall(`/api/admin/logs?page=${page}&limit=20${filterQuery}`);
    if (data.success) {
      const tbody = document.getElementById('logs-table-body');
      tbody.innerHTML = '';
      
      if (data.logs.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No logs found.</td></tr>`;
      } else {
        data.logs.forEach(log => {
          let badgeClass = 'badge-unused';
          if (log.event === 'login' || log.event === 'init') badgeClass = 'badge-active';
          if (log.event.includes('fail')) badgeClass = 'badge-banned';
          
          tbody.innerHTML += `
            <tr>
              <td style="color: var(--text-muted);">${formatDate(log.created_at)}</td>
              <td><span class="badge ${badgeClass}">${log.event}</span></td>
              <td style="font-weight: 500; color: var(--text-primary);">${log.username || 'Anonymous'}</td>
              <td>${log.ip || 'N/A'}</td>
              <td>${log.details}</td>
            </tr>
          `;
        });
      }
      
      document.getElementById('log-page-num').innerText = `Page ${page} of ${Math.ceil(data.total / 20) || 1}`;
      document.getElementById('btn-log-prev').disabled = page === 1;
      document.getElementById('btn-log-next').disabled = page >= Math.ceil(data.total / 20);
    }
  } catch (err) {}
}

function changeLogPage(dir) {
  loadLogs(logPage + dir);
}

// ==========================================
// SETTINGS
// ==========================================
async function loadSettings() {
  try {
    const data = await apiCall('/api/admin/settings');
    if (data.success) {
      document.getElementById('setting-app-name').value = data.settings.name;
      document.getElementById('setting-owner-id').value = data.settings.ownerid;
      document.getElementById('setting-version').value = data.settings.version;
      
      originalSecret = data.settings.secret;
      updateSecretDisplay();
      
      appPaused = data.settings.paused === 1;
      updatePauseUI();
    }
  } catch (err) {}
}

function updateSecretDisplay() {
  const secretField = document.getElementById('setting-secret');
  if (appSecretRevealed) {
    secretField.value = originalSecret;
    secretField.type = 'text';
  } else {
    secretField.value = '••••••••••••••••••••••••••••••••••••••••';
    secretField.type = 'password';
  }
}

function toggleSecretVisibility() {
  appSecretRevealed = !appSecretRevealed;
  updateSecretDisplay();
  const btn = document.querySelector('.secret-container .btn');
  btn.innerText = appSecretRevealed ? 'Hide' : 'Reveal';
}

async function regenerateSecret() {
  if (confirm('Are you sure you want to rotate the application secret? Old sessions/clients using custom integration will mismatch until updated.')) {
    try {
      const data = await apiCall('/api/admin/settings/refresh-secret', 'POST');
      if (data.success) {
        showToast('Application secret rotated successfully.');
        originalSecret = data.secret;
        updateSecretDisplay();
      }
    } catch (err) {}
  }
}

function updatePauseUI() {
  const pauseBtn = document.getElementById('setting-pause-btn');
  const quickPauseBtn = document.getElementById('quick-pause-btn');
  const statusText = document.getElementById('setting-app-status-text');
  
  if (appPaused) {
    pauseBtn.innerText = 'Resume App';
    pauseBtn.className = 'btn btn-primary btn-sm';
    if (quickPauseBtn) {
      quickPauseBtn.innerText = '▶️ Resume Application';
      quickPauseBtn.className = 'btn btn-primary';
    }
    statusText.innerText = 'Paused (Clients will be blocked)';
    statusText.style.color = 'var(--status-banned)';
  } else {
    pauseBtn.innerText = 'Pause App';
    pauseBtn.className = 'btn btn-danger btn-sm';
    if (quickPauseBtn) {
      quickPauseBtn.innerText = '⏸️ Pause Application';
      quickPauseBtn.className = 'btn btn-danger';
    }
    statusText.innerText = 'Active (Receiving Requests)';
    statusText.style.color = 'var(--status-active)';
  }
}

async function togglePauseApp() {
  try {
    const data = await apiCall('/api/admin/settings/pause', 'POST');
    if (data.success) {
      appPaused = data.paused === 1;
      updatePauseUI();
      showToast(appPaused ? 'Application paused.' : 'Application resumed.');
    }
  } catch (err) {}
}

async function promptMasterKeyChange() {
  const newKeyInput = document.getElementById('setting-master-key');
  const newKey = newKeyInput.value.trim();
  
  if (!newKey) {
    showToast('Please enter a new master key.', 'error');
    return;
  }
  
  const pin = prompt('Enter the 4-digit master Security PIN to confirm this change:');
  if (pin === null) return; // user cancelled
  
  if (!pin.trim()) {
    showToast('Security PIN is required to authorize master key change.', 'error');
    return;
  }
  
  try {
    const data = await apiCall('/api/admin/settings/change-key', 'POST', {
      newKey: newKey,
      pin: pin.trim()
    });
    
    if (data.success) {
      showToast('Master Admin Key updated successfully!');
      newKeyInput.value = '';
      
      // Keep session logged in under new key
      adminKey = newKey;
      sessionStorage.setItem('adminKey', adminKey);
    }
  } catch (err) {
    // apiCall automatically handles showing toast for API errors
  }
}
