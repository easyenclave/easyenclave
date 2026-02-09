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
    sessionStorage.removeItem('wizardResumeAfterOAuth');
    adminToken = null;
    document.getElementById('loginPage').classList.remove('hidden');
    document.getElementById('adminPage').classList.add('hidden');
    document.getElementById('setupWizard').classList.add('hidden');
    // Hide user info
    document.getElementById('userInfo').style.display = 'none';
}

async function showDashboard(options = {}) {
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
    else if (tabName === 'mrtds') loadMrtds();
    else if (tabName === 'settings') loadSettings();
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

async function cloudflareCleanup() {
    if (!confirm('Delete ALL orphaned tunnels and DNS records?')) return;
    if (!confirm('Are you REALLY sure? This will permanently delete all orphaned Cloudflare resources.')) return;

    try {
        const result = await fetchJSON('/api/v1/admin/cloudflare/cleanup', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${adminToken}` }
        });
        alert(`Cleanup complete: ${result.tunnels_deleted} tunnels and ${result.dns_deleted} DNS records deleted.`);
        loadCloudflare();
    } catch (error) {
        alert('Error during cleanup: ' + error.message);
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
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
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

function finishWizard() {
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
