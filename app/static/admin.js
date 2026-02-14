// EasyEnclave Admin Dashboard JavaScript

let adminToken = null;
let isAdmin = true;
let currentUserLogin = null;
let currentUserOrgs = [];

async function fetchJSON(url, options) {
    const response = await fetch(url, options);
    if (!response.ok) {
        const text = await response.text();
        throw new Error(`HTTP ${response.status}: ${text.substring(0, 200)}`);
    }
    const ct = response.headers.get('content-type') || '';
    if (!ct.includes('application/json')) {
        const body = await response.text();
        throw new Error(`Expected JSON from ${url} but got ${ct}: ${body.substring(0, 100)}`);
    }
    return response.json();
}

// Check if already logged in or OAuth callback
document.addEventListener('DOMContentLoaded', () => {
    // Check for OAuth callback token in URL
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token');
    if (token) {
        adminToken = token;
        sessionStorage.setItem('adminToken', adminToken);
        // Clean URL
        window.history.replaceState({}, document.title, '/admin');

        // If returning from wizard OAuth link step, resume wizard at step 4
        if (sessionStorage.getItem('wizardResumeAfterOAuth')) {
            sessionStorage.removeItem('wizardResumeAfterOAuth');
            showDashboard({ resumeWizardStep4: true });
        } else {
            showDashboard();
        }
        return;
    }

    // Check session storage
    adminToken = sessionStorage.getItem('adminToken');
    if (adminToken) {
        showDashboard();
    } else {
        // Configure login page: show/hide methods based on server config
        configureLoginMethods();
    }
});

async function configureLoginMethods() {
    try {
        const methods = await fetchJSON('/auth/methods');
        if (!methods.password) {
            const pwSection = document.getElementById('passwordLoginSection');
            if (pwSection) pwSection.classList.add('hidden');
        }
        if (!methods.github) {
            const ghSection = document.getElementById('githubLoginSection');
            if (ghSection) ghSection.classList.add('hidden');
        }
        if (!methods.password && !methods.github) {
            const noMethods = document.getElementById('noLoginMethods');
            if (noMethods) noMethods.classList.remove('hidden');
        }
        // Auto-fill generated password (shown when ADMIN_PASSWORD_HASH not configured)
        if (methods.generated_password) {
            const pwInput = document.getElementById('password');
            if (pwInput) pwInput.value = methods.generated_password;
            const errorDiv = document.getElementById('loginError');
            if (errorDiv) {
                errorDiv.textContent = 'Auto-generated password (set ADMIN_PASSWORD_HASH to use your own)';
                errorDiv.style.display = 'block';
                errorDiv.style.color = '#2563eb';
                errorDiv.style.background = '#eff6ff';
                errorDiv.style.border = '1px solid #bfdbfe';
            }
        }
    } catch (err) {
        // If endpoint fails, show both methods as fallback
        console.error('Failed to check auth methods:', err);
    }
}

// GitHub OAuth login
document.getElementById('githubLoginBtn')?.addEventListener('click', async () => {
    const errorDiv = document.getElementById('loginError');
    try {
        const data = await fetchJSON('/auth/github');
        // Redirect to GitHub OAuth
        window.location.href = data.auth_url;
    } catch (error) {
        errorDiv.textContent = 'GitHub OAuth not configured';
        errorDiv.style.display = 'block';
    }
});

// Password login
async function login(event) {
    event.preventDefault();
    const password = document.getElementById('password').value;
    const errorDiv = document.getElementById('loginError');

    try {
        const data = await fetchJSON('/admin/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password })
        });
        adminToken = data.token;
        sessionStorage.setItem('adminToken', adminToken);
        // Clear stale wizard flag from previous sessions
        sessionStorage.removeItem('wizardResumeAfterOAuth');
        showDashboard({ freshPasswordLogin: true });
    } catch (error) {
        errorDiv.textContent = error.message.includes('401') ? 'Invalid password' : 'Connection error';
        errorDiv.style.display = 'block';
    }
}

async function loadUserInfo() {
    try {
        const user = await fetchJSON('/auth/me', {
            headers: { 'Authorization': `Bearer ${adminToken}` }
        });

        // Store role info
        isAdmin = user.is_admin !== undefined ? user.is_admin : true;
        currentUserLogin = user.github_login || null;
        currentUserOrgs = user.github_orgs || [];

        // Show user info in header
        const userInfo = document.getElementById('userInfo');
        const userName = document.getElementById('userName');
        const userMethod = document.getElementById('userMethod');
        const userAvatar = document.getElementById('userAvatar');

        if (user.github_login) {
            userName.textContent = user.github_login;
            userMethod.textContent = isAdmin ? 'GitHub (Admin)' : 'GitHub (Owner)';
            if (user.github_avatar_url) {
                userAvatar.src = user.github_avatar_url;
                userAvatar.style.display = 'block';
            }
        } else {
            userName.textContent = 'Admin';
            userMethod.textContent = 'Password';
            userAvatar.style.display = 'none';
        }

        userInfo.style.display = 'flex';
        configureUIForRole();
    } catch (err) {
        console.error('Failed to load user info:', err);
    }
}

function configureUIForRole() {
    // Admin-only tabs: settings, measurements, cloud/cloudflare, system, accounts
    const adminOnlyTabs = ['settings', 'measurements', 'cloud', 'cloudflare', 'system', 'accounts', 'stripe'];

    if (!isAdmin) {
        // Hide admin-only tab buttons
        document.querySelectorAll('.tab').forEach(tab => {
            const tabName = tab.getAttribute('onclick')?.match(/showAdminTab\('(\w+)'\)/)?.[1];
            if (tabName && adminOnlyTabs.includes(tabName)) {
                tab.style.display = 'none';
            }
        });
    } else {
        // Ensure all tabs are visible for admin
        document.querySelectorAll('.tab').forEach(tab => {
            tab.style.display = '';
        });
    }
}

function logout() {
    sessionStorage.removeItem('adminToken');
    sessionStorage.removeItem('wizardResumeAfterOAuth');
    adminToken = null;
    document.getElementById('loginPage').classList.remove('hidden');
    document.getElementById('adminPage').classList.add('hidden');
    document.getElementById('setupWizard').classList.add('hidden');
    // Hide user info
    document.getElementById('userInfo').style.display = 'none';
}

async function showDashboard(options = {}) {
    // Validate session is still valid (catches stale tokens after server restart)
    if (!options.freshPasswordLogin && !options.resumeWizardStep4) {
        try {
            await fetchJSON('/auth/me', {
                headers: { 'Authorization': `Bearer ${adminToken}` }
            });
        } catch (err) {
            logout();
            return;
        }
    }

    document.getElementById('loginPage').classList.add('hidden');
    document.getElementById('setupWizard').classList.add('hidden');
    document.getElementById('adminPage').classList.remove('hidden');
    loadUserInfo();
    loadAgents();

    if (options.resumeWizardStep4) {
        // Returning from OAuth link — show wizard completion step
        document.getElementById('adminPage').classList.add('hidden');
        document.getElementById('wizardDoneMsg').textContent =
            'GitHub account linked successfully! OAuth is configured and ready to use.';
        showWizard(4);
    } else if (options.freshPasswordLogin) {
        await checkAndShowWizard();
    }
}

// Tab navigation
function showAdminTab(tabName) {
    document.querySelectorAll('.tab-content').forEach(tab => tab.classList.add('hidden'));
    document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
    document.getElementById(`${tabName}-admin-tab`).classList.remove('hidden');
    event.target.classList.add('active');

    // Stop log auto-refresh when leaving logs tab
    if (tabName !== 'logs' && logAutoRefreshTimer) {
        clearInterval(logAutoRefreshTimer);
        logAutoRefreshTimer = null;
    }

    // Load data for tab
    if (tabName === 'agents') loadAgents();
    else if (tabName === 'accounts') loadAccounts();
    else if (tabName === 'stripe') loadStripeAdmin();
    else if (tabName === 'measurements') loadMeasurements();
    else if (tabName === 'settings') loadSettings();
    else if (tabName === 'cloud') loadCloudResources();
    else if (tabName === 'logs') {
        loadLogs();
        loadContainerLogs();
        if (document.getElementById('logAutoRefresh').checked) {
            logAutoRefreshTimer = setInterval(() => { loadLogs(); loadContainerLogs(); }, 5000);
        }
    }
    else if (tabName === 'cloudflare') loadCloudflare();
    else if (tabName === 'system') loadSystem();
}

// ── Stripe admin tab ─────────────────────────────────────────────────────────

function _renderStripeStatusCard(status) {
    const mode = status.mode ? status.mode.toUpperCase() : 'UNKNOWN';
    const available = status.stripe_available ? 'Yes' : 'No';
    const enabled = status.stripe_enabled ? 'Yes' : 'No';
    const key = status.secret_key_configured ? `Yes (${status.secret_key_source})` : `No (${status.secret_key_source})`;
    const wh = status.webhook_secret_configured ? `Yes (${status.webhook_secret_source})` : `No (${status.webhook_secret_source})`;

    const validation = status.validation || {};
    let validationHtml = '';
    if (validation.attempted) {
        if (validation.ok) {
            validationHtml = `<div style="margin-top:10px;color:var(--success);font-weight:600;">Key validation: OK</div>`;
        } else {
            validationHtml = `<div style="margin-top:10px;color:var(--danger);font-weight:600;">Key validation: FAILED</div>
                              <div style="margin-top:6px;color:var(--muted);font-family: var(--mono, ui-monospace, SFMono-Regular, Menlo, monospace); font-size:0.9rem;">
                                  ${escapeHtml(validation.error || 'Unknown error')}
                              </div>`;
        }
    }

    return `
        <div class="stats-grid" style="margin-top: 10px;">
            <div class="stat-card">
                <div class="stat-label">Mode</div>
                <div class="stat-value">${mode}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Stripe SDK Available</div>
                <div class="stat-value">${available}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Stripe Enabled</div>
                <div class="stat-value">${enabled}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Secret Key</div>
                <div class="stat-value">${key}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Webhook Secret</div>
                <div class="stat-value">${wh}</div>
            </div>
        </div>
        <div style="display:flex; gap:10px; margin-top: 14px; flex-wrap: wrap;">
            <button class="btn-small btn-secondary" onclick="validateStripeKey()">Validate Key</button>
            <button class="btn-small btn-secondary" onclick="showAdminTab('settings'); filterSettingsGroup('stripe');">Open In Settings</button>
        </div>
        ${validationHtml}
    `;
}

function _renderStripeWebhookBlock(status) {
    const webhookUrl = window.location.origin + (status.webhook_path || '/api/v1/webhooks/stripe');
    return `
        <div style="display:flex; gap: 12px; align-items: center; flex-wrap: wrap;">
            <div style="flex: 1; min-width: 260px;">
                <div style="color: var(--muted); font-size: 0.9rem; margin-bottom: 6px;">Webhook URL</div>
                <div style="font-family: var(--mono, ui-monospace, SFMono-Regular, Menlo, monospace); padding: 10px 12px; border: 1px solid var(--line); border-radius: 10px; background: var(--surface-2); overflow-x: auto;">
                    ${escapeHtml(webhookUrl)}
                </div>
                <div style="color: var(--muted); font-size: 0.9rem; margin-top: 8px;">
                    In Stripe (Test mode): Developers → Webhooks → Add endpoint → event <code>payment_intent.succeeded</code>.
                </div>
            </div>
            <div>
                <button class="btn-small btn-primary" onclick="copyStripeWebhookUrl()">Copy URL</button>
            </div>
        </div>
    `;
}

function _renderStripeSettings(settings) {
    const map = {};
    (settings || []).forEach(s => { map[s.key] = s; });
    const secretKey = map['stripe.secret_key'];
    const webhookSecret = map['stripe.webhook_secret'];

    if (!secretKey || !webhookSecret) {
        return `<div class="error">Stripe settings not found in settings registry.</div>`;
    }

    function row(s) {
        const placeholder = s.is_secret && s.source === 'db' ? '(saved in DB)' : (s.default || '');
        return `
            <tr>
                <td>
                    <strong>${s.key}</strong>
                    <div class="setting-desc">${escapeHtml(s.description || '')}</div>
                    <div class="setting-env">Env: <code>${escapeHtml(s.env_var || '')}</code></div>
                </td>
                <td>
                    <input
                        class="setting-input"
                        type="password"
                        id="setting-${s.key}"
                        value=""
                        placeholder="${escapeHtml(placeholder)}"
                        autocomplete="off"
                    >
                </td>
                <td><span class="source-badge ${s.source}">${s.source}</span></td>
                <td class="action-buttons">
                    <button class="btn-small btn-primary" onclick="saveSetting('${s.key}')">Save</button>
                    ${s.source === 'db' ? `<button class="btn-small btn-secondary" onclick="resetSetting('${s.key}')">Reset</button>` : ''}
                </td>
            </tr>
        `;
    }

    return `
        <table class="data-table">
            <thead>
                <tr>
                    <th>Setting</th>
                    <th>Value</th>
                    <th>Source</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                ${row(secretKey)}
                ${row(webhookSecret)}
            </tbody>
        </table>
        <div style="margin-top: 10px; color: var(--muted); font-size: 0.9rem;">
            Note: values are never shown after saving. If a value comes from <strong>env</strong>, edit your deployment env vars.
        </div>
    `;
}

async function loadStripeAdmin() {
    const statusEl = document.getElementById('stripeAdminStatus');
    const webhookEl = document.getElementById('stripeAdminWebhook');
    const settingsEl = document.getElementById('stripeAdminSettings');

    statusEl.innerHTML = '<div class="loading">Loading Stripe status...</div>';
    webhookEl.innerHTML = '<div class="loading">Loading webhook info...</div>';
    settingsEl.innerHTML = '<div class="loading">Loading Stripe settings...</div>';

    try {
        const [status, settings] = await Promise.all([
            adminFetchJSON('/api/v1/admin/stripe/status'),
            fetchJSON('/api/v1/admin/settings?group=stripe', {
                headers: { 'Authorization': `Bearer ${adminToken}` }
            }),
        ]);

        statusEl.innerHTML = _renderStripeStatusCard(status);
        webhookEl.innerHTML = _renderStripeWebhookBlock(status);
        settingsEl.innerHTML = _renderStripeSettings(settings.settings || []);
    } catch (err) {
        statusEl.innerHTML = `<div class="error">Error loading Stripe status: ${escapeHtml(err.message)}</div>`;
        webhookEl.innerHTML = `<div class="error">Error loading webhook info: ${escapeHtml(err.message)}</div>`;
        settingsEl.innerHTML = `<div class="error">Error loading Stripe settings: ${escapeHtml(err.message)}</div>`;
    }
}

async function validateStripeKey() {
    const statusEl = document.getElementById('stripeAdminStatus');
    statusEl.innerHTML = '<div class="loading">Validating Stripe key...</div>';
    try {
        const status = await adminFetchJSON('/api/v1/admin/stripe/status?validate=true');
        statusEl.innerHTML = _renderStripeStatusCard(status);
    } catch (err) {
        statusEl.innerHTML = `<div class="error">Validation failed: ${escapeHtml(err.message)}</div>`;
    }
}

async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
    } catch (e) {
        // Fallback for older browsers
        const ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
    }
    alert('Copied');
}

function copyStripeWebhookUrl() {
    const url = window.location.origin + '/api/v1/webhooks/stripe';
    copyToClipboard(url);
}

// API helper with auth
async function adminFetch(url, options = {}) {
    options.headers = options.headers || {};
    if (adminToken) {
        options.headers['Authorization'] = `Bearer ${adminToken}`;
    }
    const response = await fetch(url, options);
    if (response.status === 401) {
        logout();
        throw new Error('Session expired');
    }
    return response;
}

async function adminFetchJSON(url, options = {}) {
    const response = await adminFetch(url, options);
    if (!response.ok) {
        const text = await response.text();
        throw new Error(`HTTP ${response.status}: ${text.substring(0, 200)}`);
    }
    const ct = response.headers.get('content-type') || '';
    if (!ct.includes('application/json')) {
        const body = await response.text();
        throw new Error(`Expected JSON from ${url} but got ${ct}: ${body.substring(0, 100)}`);
    }
    return response.json();
}

function normalizeCloudName(value) {
    const cloud = (value || '').trim().toLowerCase();
    if (!cloud) return '';
    if (cloud === 'google') return 'gcp';
    if (cloud === 'az') return 'azure';
    if (cloud === 'bare-metal' || cloud === 'onprem' || cloud === 'on-prem' || cloud === 'self-hosted') {
        return 'baremetal';
    }
    return cloud;
}

function parseDatacenterLabel(datacenter) {
    const raw = (datacenter || '').trim();
    if (!raw) {
        return { raw: '', cloud: '', zone: '' };
    }
    const parts = raw.split(':', 2);
    if (parts.length === 2) {
        return {
            raw,
            cloud: normalizeCloudName(parts[0]),
            zone: (parts[1] || '').trim(),
        };
    }
    return { raw, cloud: normalizeCloudName(raw), zone: '' };
}

function renderAgentLocation(agent) {
    const parsed = parseDatacenterLabel(agent.datacenter);
    const cloud = normalizeCloudName(agent.cloud_provider) || parsed.cloud;
    const zone = (agent.availability_zone || parsed.zone || '').trim();
    const region = (agent.region || '').trim();
    const meta = [
        cloud ? `cloud: ${cloud}` : '',
        zone ? `az: ${zone}` : '',
        region ? `region: ${region}` : '',
    ].filter(Boolean).join(' | ');

    if (!parsed.raw && !meta) {
        return '<span style="color:#666">N/A</span>';
    }

    return `
        <div>${parsed.raw ? `<code>${parsed.raw}</code>` : '<span style="color:#666">N/A</span>'}</div>
        ${meta ? `<div style="font-size:0.75rem;color:#666">${meta}</div>` : ''}
    `;
}

async function loadCloudResources() {
    const summaryCards = document.getElementById('cloudSummaryCards');
    const summaryTable = document.getElementById('cloudSummaryTable');
    const agentTable = document.getElementById('cloudAgentTable');
    const externalStatus = document.getElementById('cloudExternalStatus');
    const externalSummary = document.getElementById('cloudExternalSummary');
    const externalTable = document.getElementById('cloudExternalTable');

    summaryCards.innerHTML = '<div class="loading">Loading cloud summary...</div>';
    summaryTable.innerHTML = '<div class="loading">Loading cloud rollups...</div>';
    agentTable.innerHTML = '<div class="loading">Loading agent inventory...</div>';
    if (externalStatus) externalStatus.textContent = 'Loading external inventory status...';
    if (externalSummary) externalSummary.innerHTML = '<div class="loading">Loading external cloud summary...</div>';
    if (externalTable) externalTable.innerHTML = '<div class="loading">Loading external cloud resources...</div>';

    const [internalResult, externalResult] = await Promise.allSettled([
        adminFetchJSON('/api/v1/admin/cloud/resources'),
        adminFetchJSON('/api/v1/admin/cloud/resources/external'),
    ]);

    if (internalResult.status === 'fulfilled') {
        const data = internalResult.value;
        const clouds = data.clouds || [];
        const agents = data.agents || [];
        const generatedAt = data.generated_at ? new Date(data.generated_at).toLocaleString() : 'N/A';

        summaryCards.innerHTML = `
            <div class="stat-card">
                <span class="stat-value">${data.total_agents || 0}</span>
                <span class="stat-label">Agents</span>
            </div>
            <div class="stat-card">
                <span class="stat-value">${clouds.length}</span>
                <span class="stat-label">Clouds</span>
            </div>
            <div class="stat-card">
                <span class="stat-value">${data.total_deployments || 0}</span>
                <span class="stat-label">Deployments</span>
            </div>
            <div class="stat-card">
                <span class="stat-value">${data.active_deployments || 0}</span>
                <span class="stat-label">Active Deployments</span>
            </div>
            <div class="stat-card">
                <span class="stat-value" style="font-size:0.95rem">${generatedAt}</span>
                <span class="stat-label">Generated</span>
            </div>
        `;

        if (clouds.length === 0) {
            summaryTable.innerHTML = '<div class="empty">No cloud resources observed</div>';
        } else {
            summaryTable.innerHTML = `
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Cloud</th>
                            <th>Agents</th>
                            <th>Healthy</th>
                            <th>Verified</th>
                            <th>Undeployed</th>
                            <th>Deployed</th>
                            <th>Deploying</th>
                            <th>Node Sizes</th>
                            <th>Datacenters</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${clouds.map(cloud => `
                            <tr>
                                <td><strong>${cloud.cloud}</strong></td>
                                <td>${cloud.total_agents}</td>
                                <td>${cloud.healthy_agents}</td>
                                <td>${cloud.verified_agents}</td>
                                <td>${cloud.undeployed_agents}</td>
                                <td>${cloud.deployed_agents}</td>
                                <td>${cloud.deploying_agents}</td>
                                <td>${Object.entries(cloud.node_size_counts || {}).map(([k, v]) => `${k}:${v}`).join(', ') || 'N/A'}</td>
                                <td>${(cloud.datacenters || []).map(dc => `<code>${dc}</code>`).join('<br>') || 'N/A'}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            `;
        }

        if (agents.length === 0) {
            agentTable.innerHTML = '<div class="empty">No agents in inventory</div>';
        } else {
            agentTable.innerHTML = `
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>VM Name</th>
                            <th>Cloud</th>
                            <th>Location</th>
                            <th>Size</th>
                            <th>Status</th>
                            <th>Health</th>
                            <th>Verified</th>
                            <th>App</th>
                            <th>Hostname</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${agents.map(agent => `
                            <tr>
                                <td><strong>${agent.vm_name}</strong><br><code style="font-size:0.7rem">${agent.agent_id.substring(0, 8)}...</code></td>
                                <td>${agent.cloud || 'unknown'}</td>
                                <td>${renderAgentLocation(agent)}</td>
                                <td>${agent.node_size ? `<span class="status-badge">${agent.node_size}</span>` : 'N/A'}</td>
                                <td><span class="status-badge ${agent.status}">${agent.status}</span></td>
                                <td><span class="health-dot ${agent.health_status || 'unknown'}"></span> ${agent.health_status || 'unknown'}</td>
                                <td>${agent.verified ? '<span class="verified-badge">Yes</span>' : '<span class="unverified-badge">No</span>'}</td>
                                <td>${agent.deployed_app ? `<code>${agent.deployed_app}</code>` : '<span style="color:#666">none</span>'}</td>
                                <td>${agent.hostname ? `<a href="https://${agent.hostname}" target="_blank">${agent.hostname}</a>` : 'No tunnel'}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            `;
        }
    } else {
        const msg = `<div class="error">Error loading cloud resources: ${internalResult.reason?.message || internalResult.reason}</div>`;
        summaryCards.innerHTML = msg;
        summaryTable.innerHTML = msg;
        agentTable.innerHTML = msg;
    }

    if (externalResult.status === 'fulfilled') {
        renderExternalCloudResources(externalResult.value);
    } else if (externalStatus && externalSummary && externalTable) {
        const errorMessage = externalResult.reason?.message || String(externalResult.reason || 'unknown error');
        externalStatus.innerHTML = `<span style="color:#dc2626;">Failed to load external inventory: ${escapeHtml(errorMessage)}</span>`;
        externalSummary.innerHTML = '<div class="error">Error loading external inventory</div>';
        externalTable.innerHTML = '<div class="error">Unable to load external cloud resources</div>';
    }
}

function renderExternalCloudResources(data) {
    const statusEl = document.getElementById('cloudExternalStatus');
    const summaryEl = document.getElementById('cloudExternalSummary');
    const tableEl = document.getElementById('cloudExternalTable');
    if (!statusEl || !summaryEl || !tableEl) return;

    if (!data.configured) {
        statusEl.innerHTML = '<span style="color:#b45309;">External inventory is not configured. Set <code>AGENT_PROVISIONER_INVENTORY_URL</code>.</span>';
        summaryEl.innerHTML = '<div class="empty">External inventory webhook is not configured.</div>';
        tableEl.innerHTML = '<div class="empty">No external resources loaded.</div>';
        return;
    }

    const resources = Array.isArray(data.resources) ? data.resources : [];
    const generatedAt = data.generated_at ? new Date(data.generated_at).toLocaleString() : 'N/A';
    const cloudCount = new Set(resources.map(r => normalizeCloudName(r.cloud || r.provider || 'unknown'))).size;
    const vmLikeCount = resources.filter(r => (r.resource_type || '').includes('vm') || (r.resource_type || '').includes('instance')).length;

    statusEl.innerHTML = `
        Last sync: <strong>${generatedAt}</strong>
        ${data.detail ? `<span style="margin-left:10px;color:#b45309;">${escapeHtml(data.detail)}</span>` : ''}
    `;
    summaryEl.innerHTML = `
        <div class="stat-card">
            <span class="stat-value">${data.total_resources || 0}</span>
            <span class="stat-label">External Resources</span>
        </div>
        <div class="stat-card">
            <span class="stat-value">${data.tracked_count || 0}</span>
            <span class="stat-label">Tracked</span>
        </div>
        <div class="stat-card">
            <span class="stat-value" style="color:${(data.orphaned_count || 0) > 0 ? '#dc2626' : 'inherit'}">${data.orphaned_count || 0}</span>
            <span class="stat-label">Orphaned</span>
        </div>
        <div class="stat-card">
            <span class="stat-value">${cloudCount}</span>
            <span class="stat-label">Clouds</span>
        </div>
        <div class="stat-card">
            <span class="stat-value">${vmLikeCount}</span>
            <span class="stat-label">VM/Instance Resources</span>
        </div>
    `;

    if (resources.length === 0) {
        tableEl.innerHTML = '<div class="empty">Inventory webhook returned no resources.</div>';
        return;
    }

    tableEl.innerHTML = `
        <table class="data-table">
            <thead>
                <tr>
                    <th>Cloud</th>
                    <th>Type</th>
                    <th>Name / ID</th>
                    <th>Location</th>
                    <th>Status</th>
                    <th>Agent Link</th>
                    <th>Tracked</th>
                </tr>
            </thead>
            <tbody>
                ${resources.map(r => {
                    const cloud = normalizeCloudName(r.cloud || r.provider || 'unknown') || 'unknown';
                    const type = (r.resource_type || '').trim() || 'unknown';
                    const name = (r.name || '').trim();
                    const locationPieces = [
                        (r.datacenter || '').trim() ? `<code>${escapeHtml(r.datacenter)}</code>` : '',
                        (r.region || '').trim() ? `region: ${escapeHtml(r.region)}` : '',
                        (r.availability_zone || '').trim() ? `az: ${escapeHtml(r.availability_zone)}` : '',
                    ].filter(Boolean);
                    const link = r.linked_agent_id
                        ? `<strong>${escapeHtml(r.linked_vm_name || 'agent')}</strong><br><code style="font-size:0.7rem">${escapeHtml(r.linked_agent_id.substring(0, 8))}...</code>`
                        : '<span class="orphan-badge">none</span>';
                    return `
                        <tr class="${r.orphaned ? 'row-orphaned' : ''}">
                            <td><strong>${escapeHtml(cloud)}</strong></td>
                            <td>${escapeHtml(type)}</td>
                            <td><strong>${escapeHtml(name || 'N/A')}</strong><br><code style="font-size:0.7rem">${escapeHtml(r.resource_id || 'N/A')}</code></td>
                            <td>${locationPieces.join('<br>') || 'N/A'}</td>
                            <td>${escapeHtml((r.status || '').trim() || 'unknown')}</td>
                            <td>${link}</td>
                            <td>${r.tracked ? '<span class="linked-badge">tracked</span>' : '<span class="orphan-badge">orphaned</span>'}</td>
                        </tr>
                    `;
                }).join('')}
            </tbody>
        </table>
    `;
}

async function externalCloudCleanup(dryRun) {
    const modeLabel = dryRun ? 'dry run' : 'deletion';
    if (!confirm(`Run external cloud cleanup (${modeLabel}) for orphaned resources?`)) return;
    if (!dryRun && !confirm('This will delete orphaned Azure/GCP resources reported by the provisioner. Continue?')) return;

    try {
        const result = await adminFetchJSON('/api/v1/admin/cloud/resources/cleanup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                dry_run: dryRun,
                only_orphaned: true,
                providers: [],
                resource_ids: [],
                reason: `admin-cloud-${dryRun ? 'dry-run' : 'cleanup'}`,
            }),
        });

        if (!result.configured) {
            alert(`External cleanup is not configured: ${result.detail || 'set AGENT_PROVISIONER_CLEANUP_URL'}`);
            return;
        }

        const statusText = result.dispatched ? 'dispatched' : 'failed';
        const details = result.detail ? `\nDetail: ${result.detail}` : '';
        alert(`External cleanup ${statusText} (${modeLabel}).\nRequested resources: ${result.requested_count || 0}${details}`);
        await loadCloudResources();
    } catch (error) {
        alert('Error dispatching external cleanup: ' + error.message);
    }
}

// Apps management
async function loadApps() {
    const container = document.getElementById('appsAdminList');
    try {
        const data = await fetchJSON('/api/v1/apps');

        if (data.apps.length === 0) {
            container.innerHTML = '<div class="empty">No apps published</div>';
            return;
        }

        container.innerHTML = `
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Description</th>
                        <th>Tags</th>
                        <th>Versions</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ${data.apps.map(app => `
                        <tr>
                            <td><strong>${app.name}</strong></td>
                            <td>${app.description || 'N/A'}</td>
                            <td>${app.tags?.join(', ') || 'N/A'}</td>
                            <td><button class="btn-small btn-info" onclick="loadAppVersions('${app.name}')">View Versions</button></td>
                            <td class="action-buttons">
                                <button class="btn-small btn-secondary" onclick="loadAppVersions('${app.name}')">Details</button>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
    } catch (error) {
        container.innerHTML = `<div class="error">Error loading apps: ${error.message}</div>`;
    }
}

async function loadAppVersions(appName) {
    const container = document.getElementById('appsAdminList');
    try {
        const data = await fetchJSON(`/api/v1/apps/${appName}/versions`);

        container.innerHTML = `
            <div style="margin-bottom: 15px;">
                <button class="btn-secondary" onclick="loadApps()">← Back to Apps</button>
                <h3 style="display: inline; margin-left: 15px;">Versions for ${appName}</h3>
            </div>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Version</th>
                        <th>Size</th>
                        <th>Status</th>
                        <th>Ingress</th>
                        <th>Published</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ${data.versions.map(version => `
                        <tr>
                            <td><strong>${version.version}</strong></td>
                            <td>${version.node_size ? `<span class="status-badge">${version.node_size}</span>` : ''}</td>
                            <td><span class="status-badge ${version.status}">${version.status}</span></td>
                            <td>${version.ingress ? `${version.ingress.length} rule(s)` : 'Default'}</td>
                            <td>${new Date(version.published_at).toLocaleString()}</td>
                            <td class="action-buttons">
                                <button class="btn-small btn-info" onclick="showAppVersionDetails('${appName}', '${version.version}')">Details</button>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
    } catch (error) {
        container.innerHTML = `<div class="error">Error loading versions: ${error.message}</div>`;
    }
}

async function showAppVersionDetails(appName, version) {
    document.getElementById('appVersionModal').classList.remove('hidden');
    document.getElementById('appVersionModalTitle').textContent = `${appName}@${version}`;
    const detailsDiv = document.getElementById('appVersionDetails');
    detailsDiv.innerHTML = '<div class="loading">Loading version details...</div>';

    try {
        const data = await fetchJSON(`/api/v1/apps/${appName}/versions/${version}`);

        let ingressHtml = '<p>Default (all traffic to port 8081)</p>';
        if (data.ingress && data.ingress.length > 0) {
            ingressHtml = `
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Path</th>
                            <th>Port</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${data.ingress.map(rule => `
                            <tr>
                                <td><code>${rule.path || '/*'}</code></td>
                                <td><code>${rule.port}</code></td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            `;
        }

        let attestationHtml = '<p>Not yet measured</p>';
        if (data.attestation) {
            const att = data.attestation;
            let rows = [];
            if (att.compose_hash) rows.push(`<tr><td>Compose Hash</td><td><code>${att.compose_hash}</code></td></tr>`);
            if (att.resolved_images) {
                for (const [svc, img] of Object.entries(att.resolved_images)) {
                    rows.push(`<tr><td>Image: ${svc}</td><td><code style="font-size:0.75rem">${img.digest || img.original || JSON.stringify(img)}</code></td></tr>`);
                }
            }
            attestationHtml = rows.length > 0 ? `<table class="data-table">${rows.join('')}</table>` : '<p>Attested (no details)</p>';
        }

        detailsDiv.innerHTML = `
            <div class="section-card">
                <h3>Version Info</h3>
                <p><strong>Status:</strong> <span class="status-badge ${data.status}">${data.status}</span></p>
                <p><strong>Version ID:</strong> <code>${data.version_id}</code></p>
                ${data.node_size ? `<p><strong>Node Size:</strong> <span class="status-badge">${data.node_size}</span></p>` : ''}
                <p><strong>Published:</strong> ${new Date(data.published_at).toLocaleString()}</p>
                ${data.source_commit ? `<p><strong>Source Commit:</strong> <code>${data.source_commit}</code></p>` : ''}
                ${data.source_tag ? `<p><strong>Source Tag:</strong> <code>${data.source_tag}</code></p>` : ''}
                ${data.rejection_reason ? `<p><strong>Rejection Reason:</strong> ${data.rejection_reason}</p>` : ''}
            </div>
            <div class="section-card">
                <h3>Ingress Configuration</h3>
                ${ingressHtml}
            </div>
            <div class="section-card">
                <h3>Attestation</h3>
                ${attestationHtml}
            </div>
        `;
    } catch (error) {
        detailsDiv.innerHTML = `<div class="error">Error: ${error.message}</div>`;
    }
}

function closeAppVersionModal() {
    document.getElementById('appVersionModal').classList.add('hidden');
}

// Agents management
async function loadAgents() {
    const container = document.getElementById('agentsAdminList');
    try {
        const url = isAdmin ? '/api/v1/agents' : '/api/v1/me/agents';
        const data = await fetchJSON(url);

        if (data.agents.length === 0) {
            container.innerHTML = '<div class="empty">No agents registered</div>';
            return;
        }

        // For non-admin, use owner-scoped endpoint
        const agentList = isAdmin ? data.agents : data.agents;

        container.innerHTML = `
            <table class="data-table">
                <thead>
                    <tr>
                        <th>VM Name</th>
                        <th>Status</th>
                        <th>App</th>
                        <th>Size</th>
                        <th>Datacenter</th>
                        <th>Health</th>
                        <th>Verified</th>
                        ${isAdmin ? '<th>Owner</th>' : ''}
                        <th>Hostname</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ${agentList.map(agent => `
                        <tr>
                            <td><strong>${agent.vm_name}</strong><br><code style="font-size: 0.7rem">${agent.agent_id.substring(0, 8)}...</code></td>
                            <td><span class="status-badge ${agent.status}">${agent.status}</span></td>
                            <td>
                                ${agent.deployed_app
                                    ? `<div><code>${agent.deployed_app}</code></div>${agent.service_url ? `<div style="font-size:0.75rem"><a href="${agent.service_url}" target="_blank">service</a></div>` : ''}`
                                    : '<span style="color:#666">none</span>'
                                }
                            </td>
                            <td>${agent.node_size ? `<span class="status-badge">${agent.node_size}</span>` : ''}</td>
                            <td>${renderAgentLocation(agent)}</td>
                            <td><span class="health-dot ${agent.health_status || 'unknown'}"></span> ${agent.health_status || 'unknown'}</td>
                            <td>${agent.verified ? '<span class="verified-badge">Verified</span>' : '<span class="unverified-badge">Unverified</span>'}</td>
                            ${isAdmin ? `<td>${agent.github_owner ? `<code>${agent.github_owner}</code>` : '<span style="color:#666">none</span>'} <button class="btn-small btn-secondary" onclick="setAgentOwner('${agent.agent_id}', '${agent.github_owner || ''}')">Set</button></td>` : ''}
                            <td>${agent.hostname ? `<a href="https://${agent.hostname}" target="_blank">${agent.hostname}</a>` : 'No tunnel'}</td>
                            <td class="action-buttons">
                                ${agent.hostname ? `<button class="btn-small btn-info" onclick="showAgentDetails('${agent.agent_id}', '${agent.vm_name}')">Details</button>` : ''}
                                <button class="btn-small btn-secondary" onclick="resetAgent('${agent.agent_id}')">Reset</button>
                                ${isAdmin ? `<button class="btn-small btn-danger" onclick="deleteAgent('${agent.agent_id}')">Delete</button>` : ''}
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
    } catch (error) {
        container.innerHTML = `<div class="error">Error loading agents: ${error.message}</div>`;
    }
}

async function deleteAgent(agentId) {
    if (!confirm('Delete this agent? This will remove the tunnel and all agent data.')) return;

    try {
        const response = await adminFetch(`/api/v1/agents/${agentId}`, { method: 'DELETE' });
        if (response.ok) {
            loadAgents();
        } else {
            alert('Failed to delete agent');
        }
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

async function resetAgent(agentId) {
    if (!confirm('Reset this agent to undeployed state?')) return;

    try {
        const url = isAdmin ? `/api/v1/agents/${agentId}/reset` : `/api/v1/me/agents/${agentId}/reset`;
        const response = await adminFetch(url, { method: 'POST' });
        if (response.ok) {
            loadAgents();
        } else {
            alert('Failed to reset agent');
        }
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

async function setAgentOwner(agentId, currentOwner) {
    const owner = prompt('Set GitHub owner (login or org). Leave empty to clear:', currentOwner);
    if (owner === null) return; // Cancelled

    try {
        const response = await adminFetch(`/api/v1/agents/${agentId}/owner`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ github_owner: owner || null })
        });
        if (response.ok) {
            loadAgents();
        } else {
            const text = await response.text();
            alert('Failed to set owner: ' + text);
        }
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

// Measurements overview — tree view showing shared vs. divergent measurements
const RTMR_LABELS = {
    rtmr0: 'Firmware measurement',
    rtmr1: 'OS kernel + initrd',
    rtmr2: 'Runtime configuration (cmdline, roothash)',
    rtmr3: 'Application layer',
};

async function loadMeasurements() {
    const container = document.getElementById('measurementsAdminList');
    try {
        const agentData = await fetchJSON('/api/v1/agents');

        // Group verified agents by node_size, pick a representative per size
        const bySize = {};
        for (const agent of agentData.agents) {
            const size = agent.node_size || '(default)';
            if (!bySize[size]) bySize[size] = { verified: 0, total: 0, agents: [], sample: null };
            bySize[size].total++;
            if (agent.verified) {
                bySize[size].verified++;
                if (!bySize[size].sample && agent.mrtd) bySize[size].sample = agent;
            }
        }

        const sizes = Object.keys(bySize).sort();
        if (sizes.length === 0) {
            container.innerHTML = '<div class="empty">No agents registered</div>';
            return;
        }

        // Collect per-measurement values across sizes to find shared vs. divergent
        const measurementKeys = ['mrtd', 'rtmr0', 'rtmr1', 'rtmr2', 'rtmr3'];
        const measurementLabels = {
            mrtd:  'TD identity (firmware + kernel + initrd + cmdline)',
            rtmr0: 'Firmware measurement',
            rtmr1: 'OS kernel + initrd',
            rtmr2: 'Runtime config (cmdline, roothash)',
            rtmr3: 'Application layer',
        };

        // Build map: key -> { size -> value }
        const valuesByKey = {};
        for (const key of measurementKeys) {
            valuesByKey[key] = {};
            for (const size of sizes) {
                const agent = bySize[size].sample;
                if (!agent) continue;
                if (key === 'mrtd') {
                    valuesByKey[key][size] = agent.mrtd || null;
                } else {
                    valuesByKey[key][size] = agent.rtmrs?.[key] || null;
                }
            }
        }

        // Render measurement tree
        let treeHtml = '<div class="section-card"><h3>Measurement Tree</h3>';
        treeHtml += '<div style="font-family:monospace;font-size:0.85rem;line-height:1.8">';

        for (const key of measurementKeys) {
            const vals = valuesByKey[key];
            const uniqueVals = new Set(Object.values(vals).filter(v => v));
            const allSame = uniqueVals.size <= 1;
            const label = key === 'mrtd' ? 'MRTD' : key.toUpperCase();
            const desc = measurementLabels[key];

            if (allSame && uniqueVals.size === 1) {
                const val = [...uniqueVals][0];
                treeHtml += `<div style="margin-bottom:8px">`;
                treeHtml += `<span style="color:green">&#9679;</span> `;
                treeHtml += `<strong>${label}</strong> <span style="color:var(--gray-500)">${desc}</span><br>`;
                treeHtml += `&nbsp;&nbsp;&nbsp;&nbsp;<code style="font-size:0.75rem;color:var(--gray-600)">${val.substring(0, 24)}...</code> `;
                treeHtml += `<span style="color:green;font-size:0.8rem">shared across all sizes</span>`;
                treeHtml += `</div>`;
            } else if (uniqueVals.size > 1) {
                treeHtml += `<div style="margin-bottom:8px">`;
                treeHtml += `<span style="color:orange">&#9679;</span> `;
                treeHtml += `<strong>${label}</strong> <span style="color:var(--gray-500)">${desc}</span><br>`;
                const sizeList = Object.entries(vals).filter(([, v]) => v);
                sizeList.forEach(([size, val], i) => {
                    const connector = i < sizeList.length - 1 ? '&#x251C;&#x2500;' : '&#x2514;&#x2500;';
                    treeHtml += `&nbsp;&nbsp;&nbsp;&nbsp;${connector} <span class="status-badge" style="font-size:0.7rem">${size}</span> <code style="font-size:0.75rem">${val.substring(0, 24)}...</code><br>`;
                });
                treeHtml += `</div>`;
            } else {
                treeHtml += `<div style="margin-bottom:8px;color:var(--gray-400)">`;
                treeHtml += `<span>&#9675;</span> <strong>${label}</strong> <span>${desc}</span> &mdash; no data`;
                treeHtml += `</div>`;
            }
        }

        treeHtml += '</div></div>';

        // Node size overview table
        let tableHtml = `
            <div class="section-card"><h3>Node Sizes</h3>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Size</th>
                        <th>Agents</th>
                        <th>MRTD</th>
                        <th>Measurer</th>
                        <th></th>
                    </tr>
                </thead>
                <tbody>
                    ${sizes.map(size => {
                        const info = bySize[size];
                        const mrtdPreview = info.sample ? info.sample.mrtd.substring(0, 16) + '...' : 'N/A';
                        return `
                            <tr>
                                <td><span class="status-badge">${size}</span></td>
                                <td>${info.verified}/${info.total} verified</td>
                                <td><code>${mrtdPreview}</code></td>
                                <td><span id="measurer-${size.replace(/[^a-z0-9]/gi, '')}">checking...</span></td>
                                <td><button class="btn-small btn-info" onclick="showMeasurementDetails('${size}')">Details</button></td>
                            </tr>
                        `;
                    }).join('')}
                </tbody>
            </table></div>
        `;

        container.innerHTML = treeHtml + tableHtml;

        // Async: check measurer health
        for (const size of sizes) {
            const cleanSize = size.replace(/[^a-z0-9]/gi, '');
            const el = document.getElementById(`measurer-${cleanSize}`);
            if (!el) continue;
            const measurerName = size === '(default)' ? 'measuring-enclave' : `measuring-enclave-${size}`;
            try {
                const services = await fetchJSON(`/api/v1/services?name=${measurerName}`);
                const svc = services.services?.find(s => s.name === measurerName);
                if (svc && svc.health_status === 'healthy') {
                    el.innerHTML = '<span class="verified-badge">healthy</span>';
                } else if (svc) {
                    el.innerHTML = `<span class="unverified-badge">${svc.health_status}</span>`;
                } else {
                    el.innerHTML = '<span style="color:#999">not deployed</span>';
                }
            } catch {
                el.innerHTML = '<span style="color:#999">unknown</span>';
            }
        }
    } catch (error) {
        container.innerHTML = `<div class="error">Error loading measurements: ${error.message}</div>`;
    }
}

async function showMeasurementDetails(nodeSize) {
    document.getElementById('measurementModal').classList.remove('hidden');
    document.getElementById('measurementModalTitle').textContent = `Node: ${nodeSize}`;
    const container = document.getElementById('measurementDetails');
    container.innerHTML = '<div class="loading">Loading...</div>';

    try {
        const agentData = await fetchJSON('/api/v1/agents');
        const agents = agentData.agents.filter(a => (a.node_size || '(default)') === nodeSize);
        const verifiedAgents = agents.filter(a => a.verified);
        const sampleAgent = verifiedAgents[0] || agents[0];

        let html = '<div class="section-card"><h3>Platform Measurements</h3>';
        if (sampleAgent) {
            html += `<table class="data-table">`;
            html += `<tr><td><strong>MRTD</strong></td><td><code style="font-size:0.75rem;word-break:break-all">${sampleAgent.mrtd || 'N/A'}</code></td><td style="color:var(--gray-600)">TD identity</td></tr>`;
            if (sampleAgent.rtmrs) {
                for (const [key, value] of Object.entries(sampleAgent.rtmrs)) {
                    html += `<tr><td><strong>${key.toUpperCase()}</strong></td><td><code style="font-size:0.75rem;word-break:break-all">${value}</code></td><td style="color:var(--gray-600)">${RTMR_LABELS[key] || ''}</td></tr>`;
                }
            }
            html += `</table>`;
        } else {
            html += '<p>No agents for this node size</p>';
        }
        html += '</div>';

        // Live agents
        html += '<div class="section-card"><h3>Agents</h3>';
        html += `<table class="data-table"><thead><tr><th>VM Name</th><th>Status</th><th>Verified</th><th>MRTD Match</th></tr></thead><tbody>`;
        for (const agent of agents) {
            const mrtdMatch = sampleAgent && agent.mrtd === sampleAgent.mrtd;
            html += `<tr>
                <td>${agent.vm_name}</td>
                <td><span class="status-badge ${agent.status}">${agent.status}</span></td>
                <td>${agent.verified ? '<span class="verified-badge">Yes</span>' : '<span class="unverified-badge">No</span>'}</td>
                <td>${agent.mrtd ? (mrtdMatch ? '<span style="color:green">Match</span>' : '<span style="color:red">Mismatch</span>') : 'N/A'}</td>
            </tr>`;
        }
        html += `</tbody></table></div>`;

        container.innerHTML = html;
    } catch (error) {
        container.innerHTML = `<div class="error">Error: ${error.message}</div>`;
    }
}

function closeMeasurementModal() {
    document.getElementById('measurementModal').classList.add('hidden');
}

// Logs viewer
let logAutoRefreshTimer = null;

async function loadLogs() {
    const container = document.getElementById('logsViewer');
    const minLevel = document.getElementById('logLevelFilter').value;
    const lines = document.getElementById('logLinesFilter').value;

    try {
        const data = await fetchJSON(`/api/v1/logs/control-plane?lines=${lines}&min_level=${minLevel}`);

        if (data.logs.length === 0) {
            container.innerHTML = 'No logs found';
            return;
        }

        const wasAtBottom = container.scrollTop + container.clientHeight >= container.scrollHeight - 20;

        container.innerHTML = data.logs.map(log => {
            const levelClass = log.level.toLowerCase();
            const time = new Date(log.timestamp).toLocaleTimeString();
            const source = `[${log.logger.split('.').pop()}]`;
            return `<div class="log-entry ${levelClass}">${time} ${log.level.padEnd(7)} ${source} ${log.message}</div>`;
        }).join('');

        if (wasAtBottom) {
            container.scrollTop = container.scrollHeight;
        }
    } catch (error) {
        container.innerHTML = `Error loading logs: ${error.message}`;
    }
}

async function loadContainerLogs() {
    const container = document.getElementById('containerLogsViewer');
    const since = document.getElementById('containerLogSince').value;

    try {
        const data = await fetchJSON(`/api/v1/logs/containers?since=${since}`);

        if (data.error) {
            container.innerHTML = `<span style="color: #fbbf24;">${data.error}</span>`;
            return;
        }

        if (!data.logs || data.logs.length === 0) {
            container.innerHTML = 'No container logs found';
            return;
        }

        const wasAtBottom = container.scrollTop + container.clientHeight >= container.scrollHeight - 20;

        container.innerHTML = data.logs.map(log => {
            return `<div class="log-entry">[${log.container}] ${log.line}</div>`;
        }).join('');

        if (wasAtBottom) {
            container.scrollTop = container.scrollHeight;
        }
    } catch (error) {
        container.innerHTML = `Error loading container logs: ${error.message}`;
    }
}

function toggleLogAutoRefresh() {
    if (document.getElementById('logAutoRefresh').checked) {
        logAutoRefreshTimer = setInterval(() => { loadLogs(); loadContainerLogs(); }, 5000);
    } else {
        clearInterval(logAutoRefreshTimer);
        logAutoRefreshTimer = null;
    }
}

function exportLogs() {
    const minLevel = document.getElementById('logLevelFilter').value;
    const since = document.getElementById('containerLogSince').value;
    window.open(`/api/v1/logs/export?since=${encodeURIComponent(since)}&min_level=${encodeURIComponent(minLevel)}`, '_blank');
}

// System status
async function loadSystem() {
    // Health check
    try {
        const data = await fetchJSON('/health');
        document.getElementById('healthStatus').innerHTML = `
            <table class="data-table">
                <tr><td>Status</td><td><span class="verified-badge">${data.status}</span></td></tr>
                <tr><td>Timestamp</td><td>${new Date(data.timestamp).toLocaleString()}</td></tr>
            </table>
        `;
    } catch (error) {
        document.getElementById('healthStatus').innerHTML = `<span class="error-text">Error: ${error.message}</span>`;
    }

    // System info
    try {
        const [agents, apps, deployments] = await Promise.all([
            fetchJSON('/api/v1/agents'),
            fetchJSON('/api/v1/apps'),
            fetchJSON('/api/v1/deployments')
        ]);

        const healthyAgents = agents.agents.filter(a => a.health_status === 'healthy').length;
        const verifiedAgents = agents.agents.filter(a => a.verified).length;

        document.getElementById('systemInfo').innerHTML = `
            <table class="data-table">
                <tr><td>Total Agents</td><td>${agents.total}</td></tr>
                <tr><td>Healthy Agents</td><td>${healthyAgents}</td></tr>
                <tr><td>Verified Agents</td><td>${verifiedAgents}</td></tr>
                <tr><td>Total Apps</td><td>${apps.total}</td></tr>
                <tr><td>Total Deployments</td><td>${deployments.total}</td></tr>
            </table>
        `;
    } catch (error) {
        document.getElementById('systemInfo').innerHTML = `<span class="error-text">Error: ${error.message}</span>`;
    }
}

// Danger zone actions
async function deleteAllAgents() {
    if (!confirm('DELETE ALL AGENTS? This cannot be undone!')) return;
    if (!confirm('Are you REALLY sure? All tunnels and agent data will be lost.')) return;

    try {
        const data = await fetchJSON('/api/v1/agents');

        for (const agent of data.agents) {
            await adminFetch(`/api/v1/agents/${agent.agent_id}`, { method: 'DELETE' });
        }

        alert(`Deleted ${data.agents.length} agents`);
        loadAgents();
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

async function resetFailedAgents() {
    if (!confirm('Reset all agents in attestation_failed state?')) return;

    try {
        const data = await fetchJSON('/api/v1/agents');

        let count = 0;
        for (const agent of data.agents) {
            if (agent.status === 'attestation_failed') {
                await adminFetch(`/api/v1/agents/${agent.agent_id}/reset`, { method: 'POST' });
                count++;
            }
        }

        alert(`Reset ${count} agents`);
        loadAgents();
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

// Agent details modal - pull logs and stats from agent
let currentAgentId = null;

async function showAgentDetails(agentId, vmName) {
    currentAgentId = agentId;
    document.getElementById('agentModalTitle').textContent = `Agent: ${vmName}`;
    document.getElementById('agentModal').classList.remove('hidden');

    // Load stats, attestation, and logs
    await Promise.all([loadAgentStats(agentId), loadAgentAttestation(agentId), loadAgentLogs(agentId)]);
}

function closeAgentModal() {
    document.getElementById('agentModal').classList.add('hidden');
    currentAgentId = null;
}

async function loadAgentStats(agentId) {
    const container = document.getElementById('agentStats');
    container.innerHTML = '<div class="loading">Loading stats...</div>';

    try {
        const stats = await fetchJSON(`/api/v1/agents/${agentId}/stats`);

        container.innerHTML = `
            <div class="stat-card">
                <div class="stat-label">CPU Usage</div>
                <div class="stat-value">${stats.cpu_percent || 0}%</div>
                <div class="stat-detail">Load: ${(stats.load_avg || [0, 0, 0]).map(l => l.toFixed(2)).join(', ')}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Memory</div>
                <div class="stat-value">${stats.memory_percent || 0}%</div>
                <div class="stat-detail">${(stats.memory_used_gb || 0).toFixed(1)} / ${(stats.memory_total_gb || 0).toFixed(1)} GB</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Disk</div>
                <div class="stat-value">${stats.disk_percent || 0}%</div>
                <div class="stat-detail">${(stats.disk_used_gb || 0).toFixed(1)} / ${(stats.disk_total_gb || 0).toFixed(1)} GB</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Network</div>
                <div class="stat-value">↑ ${formatBytes(stats.net_bytes_sent || 0)}</div>
                <div class="stat-detail">↓ ${formatBytes(stats.net_bytes_recv || 0)}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Uptime</div>
                <div class="stat-value">${formatUptime(stats.uptime_seconds || 0)}</div>
            </div>
        `;
    } catch (error) {
        container.innerHTML = `<div class="error">Error loading stats: ${error.message}</div>`;
    }
}

async function loadAgentAttestation(agentId) {
    const container = document.getElementById('agentAttestation');
    container.innerHTML = '<div class="loading">Loading attestation...</div>';

    try {
        const [data, agent] = await Promise.all([
            fetchJSON(`/api/v1/agents/${agentId}/attestation`),
            fetchJSON(`/api/v1/agents/${agentId}`),
        ]);

        const rows = [];
        const parsed = parseDatacenterLabel(agent?.datacenter);
        const cloud = normalizeCloudName(agent?.cloud_provider) || parsed.cloud;
        const zone = (agent?.availability_zone || parsed.zone || '').trim();
        const region = (agent?.region || '').trim();

        rows.push(`<tr><td>Verified</td><td>${data.verified ? '<span class="verified-badge">Yes</span>' : '<span class="unverified-badge">No</span>'}</td></tr>`);
        rows.push(`<tr><td>Node Size</td><td>${agent?.node_size ? `<span class="status-badge">${agent.node_size}</span>` : 'N/A'}</td></tr>`);
        rows.push(`<tr><td>Datacenter</td><td>${parsed.raw ? `<code>${parsed.raw}</code>` : 'N/A'}</td></tr>`);
        rows.push(`<tr><td>Cloud</td><td>${cloud || 'N/A'}</td></tr>`);
        rows.push(`<tr><td>Availability Zone</td><td>${zone || 'N/A'}</td></tr>`);
        rows.push(`<tr><td>Region</td><td>${region || 'N/A'}</td></tr>`);
        rows.push(`<tr><td>MRTD</td><td><code style="font-size: 0.75rem; word-break: break-all;">${data.mrtd || 'N/A'}</code></td></tr>`);
        if (data.mrtd_type) {
            rows.push(`<tr><td>MRTD Type</td><td>${data.mrtd_type}</td></tr>`);
        }
        if (data.rtmrs) {
            for (const [key, value] of Object.entries(data.rtmrs)) {
                rows.push(`<tr><td>${key.toUpperCase()}</td><td><code style="font-size: 0.75rem; word-break: break-all;">${value}</code></td></tr>`);
            }
        }

        const itaStatus = data.intel_ta_verified ? '<span class="verified-badge">Valid</span>' : '<span class="unverified-badge">Expired/Invalid</span>';
        rows.push(`<tr><td>Intel TA Token</td><td>${itaStatus}</td></tr>`);

        if (data.intel_ta_claims) {
            const claims = data.intel_ta_claims;
            if (claims.attester_type) rows.push(`<tr><td>Attester Type</td><td>${claims.attester_type}</td></tr>`);
            if (claims.attester_tcb_status) rows.push(`<tr><td>TCB Status</td><td>${claims.attester_tcb_status}</td></tr>`);
            if (claims.token_issued) rows.push(`<tr><td>Token Issued</td><td>${new Date(claims.token_issued).toLocaleString()}</td></tr>`);
            if (claims.token_expiry) rows.push(`<tr><td>Token Expiry</td><td>${new Date(claims.token_expiry).toLocaleString()}</td></tr>`);
        }

        if (data.verification_error) {
            rows.push(`<tr><td>Error</td><td style="color: var(--danger);">${data.verification_error}</td></tr>`);
        }

        rows.push(`<tr><td>Hostname</td><td>${data.hostname ? `<a href="https://${data.hostname}" target="_blank">${data.hostname}</a>` : 'No tunnel'}</td></tr>`);
        rows.push(`<tr><td>Registered</td><td>${new Date(data.registered_at).toLocaleString()}</td></tr>`);

        container.innerHTML = `<table class="data-table">${rows.join('')}</table>`;
    } catch (error) {
        container.innerHTML = `<div class="error">Error loading attestation: ${error.message}</div>`;
    }
}

async function loadAgentLogs(agentId) {
    const container = document.getElementById('agentLogs');
    const since = document.getElementById('modalLogSince').value;
    container.innerHTML = 'Loading logs...';

    try {
        const data = await fetchJSON(`/api/v1/agents/${agentId}/logs?since=${since}`);

        if (!data.logs || data.logs.length === 0) {
            container.innerHTML = 'No logs found';
            return;
        }

        container.innerHTML = data.logs.map(log => {
            const line = log.line || log.message || JSON.stringify(log);
            const containerName = log.container || 'unknown';
            return `<div class="log-entry">[${containerName}] ${line}</div>`;
        }).join('');

        container.scrollTop = container.scrollHeight;
    } catch (error) {
        container.innerHTML = `Error loading logs: ${error.message}`;
    }
}

function refreshAgentLogs() {
    if (currentAgentId) {
        loadAgentLogs(currentAgentId);
    }
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function formatUptime(seconds) {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    if (days > 0) return `${days}d ${hours}h`;
    if (hours > 0) return `${hours}h ${mins}m`;
    return `${mins}m`;
}

// Accounts management
async function loadAccounts() {
    const container = document.getElementById('accountsAdminList');
    try {
        const resp = await adminFetch('/api/v1/accounts');
        const data = await resp.json();

        if (data.accounts.length === 0) {
            container.innerHTML = '<div class="empty">No accounts created</div>';
            return;
        }

        container.innerHTML = `
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Type</th>
                        <th>Balance</th>
                        <th>Created</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ${data.accounts.map(acct => `
                        <tr>
                            <td><strong>${acct.name}</strong><br><code style="font-size: 0.7rem">${acct.account_id.substring(0, 8)}...</code></td>
                            <td><span class="status-badge">${acct.account_type}</span></td>
                            <td>$${acct.balance.toFixed(2)}</td>
                            <td>${new Date(acct.created_at).toLocaleDateString()}</td>
                            <td class="action-buttons">
                                <button class="btn-small btn-info" onclick="promptDeposit('${acct.account_id}', '${acct.name}')">Deposit</button>
                                <button class="btn-small btn-danger" onclick="deleteAccount('${acct.account_id}', '${acct.name}')">Delete</button>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
    } catch (error) {
        container.innerHTML = `<div class="error">Error loading accounts: ${error.message}</div>`;
    }
}

async function createAccount() {
    const name = document.getElementById('accountName').value.trim();
    const accountType = document.getElementById('accountType').value;

    if (!name) {
        alert('Please enter an account name');
        return;
    }

    try {
        const resp = await adminFetch('/api/v1/accounts', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, account_type: accountType })
        });
        if (!resp.ok) throw new Error(await resp.text());
        document.getElementById('accountName').value = '';
        loadAccounts();
    } catch (error) {
        alert('Error creating account: ' + error.message);
    }
}

async function promptDeposit(accountId, accountName) {
    const amount = prompt(`Deposit amount (USD) for "${accountName}":`);
    if (!amount) return;

    const parsed = parseFloat(amount);
    if (isNaN(parsed) || parsed <= 0) {
        alert('Please enter a positive number');
        return;
    }

    try {
        const resp = await adminFetch(`/api/v1/accounts/${accountId}/deposit`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ amount: parsed, description: 'Manual deposit via admin UI' })
        });
        if (!resp.ok) throw new Error(await resp.text());
        loadAccounts();
    } catch (error) {
        alert('Error depositing: ' + error.message);
    }
}

async function deleteAccount(accountId, accountName) {
    if (!confirm(`Delete account "${accountName}"? Account must have zero balance.`)) return;

    try {
        const response = await adminFetch(`/api/v1/accounts/${accountId}`, { method: 'DELETE' });
        if (response.ok) {
            loadAccounts();
        } else {
            const text = await response.text();
            alert('Failed to delete account: ' + text);
        }
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

// Cloudflare management
async function loadCloudflare() {
    const notConfigured = document.getElementById('cfNotConfigured');
    const content = document.getElementById('cfContent');

    try {
        const status = await fetchJSON('/api/v1/admin/cloudflare/status', {
            headers: { 'Authorization': `Bearer ${adminToken}` }
        });

        if (!status.configured) {
            notConfigured.classList.remove('hidden');
            content.classList.add('hidden');
            return;
        }

        notConfigured.classList.add('hidden');
        content.classList.remove('hidden');

        const [tunnelsData, dnsData] = await Promise.all([
            fetchJSON('/api/v1/admin/cloudflare/tunnels', {
                headers: { 'Authorization': `Bearer ${adminToken}` }
            }),
            fetchJSON('/api/v1/admin/cloudflare/dns', {
                headers: { 'Authorization': `Bearer ${adminToken}` }
            })
        ]);

        // Summary stats
        document.getElementById('cfSummary').innerHTML = `
            <div class="stat-card">
                <div class="stat-label">Total Tunnels</div>
                <div class="stat-value">${tunnelsData.total}</div>
                <div class="stat-detail">${tunnelsData.connected_count} connected</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Orphaned Tunnels</div>
                <div class="stat-value" style="color: ${tunnelsData.orphaned_count > 0 ? '#ef4444' : 'inherit'}">${tunnelsData.orphaned_count}</div>
                <div class="stat-detail">No matching agent</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">DNS Records</div>
                <div class="stat-value">${dnsData.total}</div>
                <div class="stat-detail">${dnsData.tunnel_record_count} tunnel CNAMEs</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Orphaned DNS</div>
                <div class="stat-value" style="color: ${dnsData.orphaned_count > 0 ? '#ef4444' : 'inherit'}">${dnsData.orphaned_count}</div>
                <div class="stat-detail">Tunnel deleted</div>
            </div>
        `;

        // Show cleanup button if orphans exist
        const cleanupBar = document.getElementById('cfCleanupBar');
        if (tunnelsData.orphaned_count > 0 || dnsData.orphaned_count > 0) {
            cleanupBar.classList.remove('hidden');
        } else {
            cleanupBar.classList.add('hidden');
        }

        renderTunnelsTable(tunnelsData.tunnels);
        renderDnsTable(dnsData.records);
    } catch (error) {
        document.getElementById('cfTunnelsTable').innerHTML = `<div class="error">Error: ${error.message}</div>`;
    }
}

function renderTunnelsTable(tunnels) {
    const container = document.getElementById('cfTunnelsTable');
    if (tunnels.length === 0) {
        container.innerHTML = '<div class="empty">No tunnels found</div>';
        return;
    }

    container.innerHTML = `
        <table class="data-table">
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Status</th>
                    <th>Connections</th>
                    <th>Agent</th>
                    <th>Created</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                ${tunnels.map(t => `
                    <tr class="${t.orphaned ? 'row-orphaned' : ''}">
                        <td><strong>${t.name}</strong><br><code style="font-size: 0.7rem">${t.tunnel_id.substring(0, 8)}...</code></td>
                        <td><span class="status-dot ${t.has_connections ? 'active' : 'inactive'}"></span>${t.has_connections ? 'Active' : 'Inactive'}</td>
                        <td>${t.connection_count}</td>
                        <td>${t.agent_vm_name
                            ? `<strong>${t.agent_vm_name}</strong><br><span class="status-badge ${t.agent_status}">${t.agent_status}</span>`
                            : '<span class="orphan-badge">Orphaned</span>'
                        }</td>
                        <td>${t.created_at ? new Date(t.created_at).toLocaleDateString() : 'N/A'}</td>
                        <td><button class="btn-small btn-danger" onclick="deleteTunnel('${t.tunnel_id}', '${t.name}')">Delete</button></td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;
}

function renderDnsTable(records) {
    const container = document.getElementById('cfDnsTable');
    if (records.length === 0) {
        container.innerHTML = '<div class="empty">No DNS records found</div>';
        return;
    }

    container.innerHTML = `
        <table class="data-table">
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Content</th>
                    <th>Proxied</th>
                    <th>Tunnel Link</th>
                    <th>Created</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                ${records.map(r => `
                    <tr class="${r.orphaned ? 'row-orphaned' : ''}">
                        <td><strong>${r.name}</strong></td>
                        <td><code style="font-size: 0.75rem">${r.content}</code></td>
                        <td>${r.proxied ? 'Yes' : 'No'}</td>
                        <td>${r.orphaned
                            ? '<span class="orphan-badge">Orphaned</span>'
                            : r.is_tunnel_record
                                ? `<span class="linked-badge">Linked</span><br><code style="font-size: 0.7rem">${r.linked_tunnel_id.substring(0, 8)}...</code>`
                                : 'N/A'
                        }</td>
                        <td>${r.created_on ? new Date(r.created_on).toLocaleDateString() : 'N/A'}</td>
                        <td><button class="btn-small btn-danger" onclick="deleteDnsRecord('${r.record_id}', '${r.name}')">Delete</button></td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;
}

async function deleteTunnel(tunnelId, name) {
    if (!confirm(`Delete tunnel "${name}"? This will also clear the agent's tunnel info.`)) return;

    try {
        await fetchJSON(`/api/v1/admin/cloudflare/tunnels/${tunnelId}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${adminToken}` }
        });
        loadCloudflare();
    } catch (error) {
        alert('Error deleting tunnel: ' + error.message);
    }
}

async function deleteDnsRecord(recordId, name) {
    if (!confirm(`Delete DNS record "${name}"?`)) return;

    try {
        await fetchJSON(`/api/v1/admin/cloudflare/dns/${recordId}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${adminToken}` }
        });
        loadCloudflare();
    } catch (error) {
        alert('Error deleting DNS record: ' + error.message);
    }
}

async function cloudflareCleanup(buttonEl) {
    if (!confirm('Delete ALL orphaned tunnels and DNS records?')) return;
    if (!confirm('Are you REALLY sure? This will permanently delete all orphaned Cloudflare resources.')) return;

    const button = buttonEl instanceof HTMLElement ? buttonEl : null;
    const originalLabel = button ? button.textContent : null;
    if (button) {
        button.disabled = true;
        button.textContent = 'Cleaning...';
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 180000);

    try {
        const result = await fetchJSON('/api/v1/admin/cloudflare/cleanup', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${adminToken}` },
            signal: controller.signal,
        });
        const failedParts = [];
        if (result.tunnels_failed > 0) failedParts.push(`${result.tunnels_failed} tunnel delete(s) failed`);
        if (result.dns_failed > 0) failedParts.push(`${result.dns_failed} DNS delete(s) failed`);
        const failedSummary = failedParts.length > 0 ? `\nWarnings: ${failedParts.join('; ')}` : '';
        alert(
            `Cleanup complete: ${result.tunnels_deleted}/${result.tunnels_candidates} tunnels and ` +
            `${result.dns_deleted}/${result.dns_candidates} DNS records deleted.${failedSummary}`
        );
        loadCloudflare();
    } catch (error) {
        if (error.name === 'AbortError') {
            alert('Cleanup is taking longer than 3 minutes. Check logs and refresh Cloudflare resources in a moment.');
        } else {
            alert('Error during cleanup: ' + error.message);
        }
    } finally {
        clearTimeout(timeoutId);
        if (button) {
            button.disabled = false;
            button.textContent = originalLabel || 'Cleanup All Orphaned Resources';
        }
    }
}

// ── Settings management ─────────────────────────────────────────────────────

let _settingsData = [];
let _settingsGroup = '';

function filterSettingsGroup(group) {
    _settingsGroup = group;
    document.querySelectorAll('.settings-group-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.group === group);
    });
    renderSettingsTable();
}

async function loadSettings() {
    const container = document.getElementById('settingsAdminList');
    try {
        const data = await fetchJSON('/api/v1/admin/settings', {
            headers: { 'Authorization': `Bearer ${adminToken}` }
        });
        _settingsData = data.settings;
        renderSettingsTable();
    } catch (error) {
        container.innerHTML = `<div class="error">Error loading settings: ${error.message}</div>`;
    }
}

function renderSettingsTable() {
    const container = document.getElementById('settingsAdminList');
    const settings = _settingsGroup
        ? _settingsData.filter(s => s.group === _settingsGroup)
        : _settingsData;

    if (settings.length === 0) {
        container.innerHTML = '<div class="empty">No settings in this group</div>';
        return;
    }

    container.innerHTML = `
        <table class="data-table">
            <thead>
                <tr>
                    <th>Setting</th>
                    <th>Value</th>
                    <th>Source</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                ${settings.map(s => {
                    const inputType = s.is_secret ? 'password' : 'text';
                    // For secret fields that have a db value, show placeholder
                    const placeholder = s.is_secret && s.source === 'db' ? '(saved in DB)' : s.default || '';
                    // Don't pre-fill secret fields; for non-secret, show current value
                    const inputValue = s.is_secret ? '' : (s.source !== 'default' ? s.value : '');
                    return `
                        <tr>
                            <td>
                                <strong>${s.key}</strong>
                                <div class="setting-desc">${s.description}</div>
                                <div class="setting-env">Env: <code>${s.env_var}</code></div>
                            </td>
                            <td>
                                <input
                                    class="setting-input"
                                    type="${inputType}"
                                    id="setting-${s.key}"
                                    value="${escapeHtml(inputValue)}"
                                    placeholder="${escapeHtml(placeholder)}"
                                    autocomplete="off"
                                >
                            </td>
                            <td><span class="source-badge ${s.source}">${s.source}</span></td>
                            <td class="action-buttons">
                                <button class="btn-small btn-primary" onclick="saveSetting('${s.key}')">Save</button>
                                ${s.source === 'db' ? `<button class="btn-small btn-secondary" onclick="resetSetting('${s.key}')">Reset</button>` : ''}
                            </td>
                        </tr>
                    `;
                }).join('')}
            </tbody>
        </table>
    `;
}

function escapeHtml(str) {
    if (!str) return '';
    const value = String(str);
    return value
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

async function saveSetting(key) {
    const input = document.getElementById(`setting-${key}`);
    const value = input.value;
    if (!value) {
        alert('Please enter a value');
        return;
    }

    try {
        await fetchJSON(`/api/v1/admin/settings/${key}`, {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${adminToken}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ value }),
        });
        loadSettings();
    } catch (error) {
        alert('Error saving setting: ' + error.message);
    }
}

async function resetSetting(key) {
    if (!confirm(`Reset "${key}" to its env var or default value?`)) return;

    try {
        await fetchJSON(`/api/v1/admin/settings/${key}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${adminToken}` },
        });
        loadSettings();
    } catch (error) {
        alert('Error resetting setting: ' + error.message);
    }
}

// ── Setup Wizard ─────────────────────────────────────────────────────────────

async function checkAndShowWizard() {
    try {
        const data = await fetchJSON('/api/v1/admin/settings?group=github_oauth', {
            headers: { 'Authorization': `Bearer ${adminToken}` }
        });
        const clientId = data.settings.find(s => s.key === 'github_oauth.client_id');
        // Show wizard only if client_id is not configured (source is "default" with empty value)
        if (clientId && clientId.source === 'default' && !clientId.value) {
            showWizard(1);
        }
    } catch (err) {
        // Settings fetch failed — skip wizard silently
        console.error('Wizard check failed:', err);
    }
}

function showWizard(step) {
    document.getElementById('adminPage').classList.add('hidden');
    document.getElementById('setupWizard').classList.remove('hidden');

    // Compute callback URL for step 2
    const callbackInput = document.getElementById('wizardCallbackUrl');
    if (callbackInput) {
        callbackInput.value = window.location.origin + '/auth/github/callback';
    }

    wizardNext(step);
}

function wizardNext(step) {
    // Hide all panels
    for (let i = 1; i <= 4; i++) {
        document.getElementById(`wizardStep${i}`).classList.add('hidden');
    }
    // Show target panel
    document.getElementById(`wizardStep${step}`).classList.remove('hidden');

    // Update step indicators
    document.querySelectorAll('.wizard-step-indicator').forEach(dot => {
        const dotStep = parseInt(dot.dataset.step);
        dot.classList.remove('active', 'completed');
        if (dotStep < step) {
            dot.classList.add('completed');
        } else if (dotStep === step) {
            dot.classList.add('active');
        }
    });

    // Show disable-password option on step 4 (OAuth was just configured)
    if (step === 4) {
        const option = document.getElementById('wizardDisablePasswordOption');
        if (option) option.classList.remove('hidden');
    }
}

async function wizardSaveOAuth() {
    const clientId = document.getElementById('wizardClientId').value.trim();
    const clientSecret = document.getElementById('wizardClientSecret').value.trim();
    const errorDiv = document.getElementById('wizardOAuthError');
    errorDiv.style.display = 'none';

    if (!clientId || !clientSecret) {
        errorDiv.textContent = 'Both Client ID and Client Secret are required.';
        errorDiv.style.display = 'block';
        return;
    }

    const redirectUri = window.location.origin + '/auth/github/callback';
    const headers = {
        'Authorization': `Bearer ${adminToken}`,
        'Content-Type': 'application/json',
    };

    try {
        await Promise.all([
            fetchJSON('/api/v1/admin/settings/github_oauth.client_id', {
                method: 'PUT', headers,
                body: JSON.stringify({ value: clientId }),
            }),
            fetchJSON('/api/v1/admin/settings/github_oauth.client_secret', {
                method: 'PUT', headers,
                body: JSON.stringify({ value: clientSecret }),
            }),
            fetchJSON('/api/v1/admin/settings/github_oauth.redirect_uri', {
                method: 'PUT', headers,
                body: JSON.stringify({ value: redirectUri }),
            }),
        ]);
        wizardNext(3);
    } catch (err) {
        errorDiv.textContent = 'Failed to save settings: ' + err.message;
        errorDiv.style.display = 'block';
    }
}

function wizardLinkGitHub() {
    sessionStorage.setItem('wizardResumeAfterOAuth', 'true');
    // Start the OAuth flow — this will redirect away
    window.location.href = '/auth/github';
}

function skipWizard() {
    document.getElementById('setupWizard').classList.add('hidden');
    document.getElementById('adminPage').classList.remove('hidden');
}

async function finishWizard() {
    const checkbox = document.getElementById('wizardDisablePassword');
    if (checkbox && checkbox.checked) {
        try {
            await fetchJSON('/api/v1/admin/settings/auth.password_login_enabled', {
                method: 'PUT',
                headers: {
                    'Authorization': `Bearer ${adminToken}`,
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ value: 'false' }),
            });
        } catch (err) {
            console.error('Failed to disable password login:', err);
        }
    }
    document.getElementById('setupWizard').classList.add('hidden');
    document.getElementById('adminPage').classList.remove('hidden');
}

function copyCallbackUrl() {
    const input = document.getElementById('wizardCallbackUrl');
    navigator.clipboard.writeText(input.value).then(() => {
        const btn = input.nextElementSibling;
        const orig = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.textContent = orig; }, 1500);
    }).catch(() => {
        input.select();
    });
}
