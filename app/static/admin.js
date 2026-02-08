// EasyEnclave Admin Dashboard JavaScript

let adminToken = null;

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
        showDashboard();
        return;
    }

    // Check session storage
    adminToken = sessionStorage.getItem('adminToken');
    if (adminToken) {
        showDashboard();
    }
});

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
        showDashboard();
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

        // Show user info in header
        const userInfo = document.getElementById('userInfo');
        const userName = document.getElementById('userName');
        const userMethod = document.getElementById('userMethod');
        const userAvatar = document.getElementById('userAvatar');

        if (user.github_login) {
            userName.textContent = user.github_login;
            userMethod.textContent = 'GitHub';
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
    } catch (err) {
        console.error('Failed to load user info:', err);
    }
}

function logout() {
    sessionStorage.removeItem('adminToken');
    adminToken = null;
    document.getElementById('loginPage').classList.remove('hidden');
    document.getElementById('adminPage').classList.add('hidden');
    // Hide user info
    document.getElementById('userInfo').style.display = 'none';
}

function showDashboard() {
    document.getElementById('loginPage').classList.add('hidden');
    document.getElementById('adminPage').classList.remove('hidden');
    loadUserInfo();
    loadAgents();
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
    else if (tabName === 'mrtds') loadMrtds();
    else if (tabName === 'logs') {
        loadLogs();
        loadContainerLogs();
        if (document.getElementById('logAutoRefresh').checked) {
            logAutoRefreshTimer = setInterval(() => { loadLogs(); loadContainerLogs(); }, 5000);
        }
    }
    else if (tabName === 'system') loadSystem();
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
                        <th>Status</th>
                        <th>MRTD</th>
                        <th>Ingress</th>
                        <th>Published</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ${data.versions.map(version => `
                        <tr>
                            <td><strong>${version.version}</strong></td>
                            <td><span class="status-badge ${version.status}">${version.status}</span></td>
                            <td><code>${version.mrtd ? version.mrtd.substring(0, 16) + '...' : 'N/A'}</code></td>
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

        detailsDiv.innerHTML = `
            <div class="section-card">
                <h3>Version Info</h3>
                <p><strong>Status:</strong> <span class="status-badge ${data.status}">${data.status}</span></p>
                <p><strong>Version ID:</strong> <code>${data.version_id}</code></p>
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
                <h3>Measurement (MRTD)</h3>
                ${data.mrtd ? `<p><code>${data.mrtd}</code></p>` : '<p>Not yet measured</p>'}
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
        const data = await fetchJSON('/api/v1/agents');

        if (data.agents.length === 0) {
            container.innerHTML = '<div class="empty">No agents registered</div>';
            return;
        }

        container.innerHTML = `
            <table class="data-table">
                <thead>
                    <tr>
                        <th>VM Name</th>
                        <th>Status</th>
                        <th>Health</th>
                        <th>Verified</th>
                        <th>MRTD</th>
                        <th>Hostname</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ${data.agents.map(agent => `
                        <tr>
                            <td><strong>${agent.vm_name}</strong><br><code style="font-size: 0.7rem">${agent.agent_id.substring(0, 8)}...</code></td>
                            <td><span class="status-badge ${agent.status}">${agent.status}</span></td>
                            <td><span class="health-dot ${agent.health_status || 'unknown'}"></span> ${agent.health_status || 'unknown'}</td>
                            <td>${agent.verified ? '<span class="verified-badge">Verified</span>' : '<span class="unverified-badge">Unverified</span>'}</td>
                            <td><code>${agent.mrtd ? agent.mrtd.substring(0, 16) + '...' : 'N/A'}</code></td>
                            <td>${agent.hostname ? `<a href="https://${agent.hostname}" target="_blank">${agent.hostname}</a>` : 'No tunnel'}</td>
                            <td class="action-buttons">
                                ${agent.hostname ? `<button class="btn-small btn-info" onclick="showAgentDetails('${agent.agent_id}', '${agent.vm_name}')">Details</button>` : ''}
                                <button class="btn-small btn-secondary" onclick="resetAgent('${agent.agent_id}')">Reset</button>
                                <button class="btn-small btn-danger" onclick="deleteAgent('${agent.agent_id}')">Delete</button>
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
        const response = await adminFetch(`/api/v1/agents/${agentId}/reset`, { method: 'POST' });
        if (response.ok) {
            loadAgents();
        } else {
            alert('Failed to reset agent');
        }
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

// MRTDs (read-only, loaded from env vars)
async function loadMrtds() {
    const container = document.getElementById('mrtdsAdminList');
    try {
        const data = await fetchJSON('/api/v1/trusted-mrtds');

        if (data.trusted_mrtds.length === 0) {
            container.innerHTML = '<div class="empty">No trusted MRTDs configured</div>';
            return;
        }

        container.innerHTML = `
            <table class="data-table">
                <thead>
                    <tr>
                        <th>MRTD</th>
                        <th>Type</th>
                    </tr>
                </thead>
                <tbody>
                    ${data.trusted_mrtds.map(mrtd => `
                        <tr>
                            <td><code>${mrtd.mrtd.substring(0, 24)}...</code></td>
                            <td><span class="status-badge">${mrtd.type}</span></td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
    } catch (error) {
        container.innerHTML = `<div class="error">Error loading MRTDs: ${error.message}</div>`;
    }
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
        const data = await fetchJSON(`/api/v1/agents/${agentId}/attestation`);

        const rows = [];
        rows.push(`<tr><td>Verified</td><td>${data.verified ? '<span class="verified-badge">Yes</span>' : '<span class="unverified-badge">No</span>'}</td></tr>`);
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
        const data = await fetchJSON('/api/v1/accounts');

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
        await fetchJSON('/api/v1/accounts', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, account_type: accountType })
        });
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
        await fetchJSON(`/api/v1/accounts/${accountId}/deposit`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ amount: parsed, description: 'Manual deposit via admin UI' })
        });
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
