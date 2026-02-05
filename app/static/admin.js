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

// Check if already logged in
document.addEventListener('DOMContentLoaded', () => {
    adminToken = sessionStorage.getItem('adminToken');
    if (adminToken) {
        showDashboard();
    }
});

// Login
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

function logout() {
    sessionStorage.removeItem('adminToken');
    adminToken = null;
    document.getElementById('loginPage').classList.remove('hidden');
    document.getElementById('adminPage').classList.add('hidden');
}

function showDashboard() {
    document.getElementById('loginPage').classList.add('hidden');
    document.getElementById('adminPage').classList.remove('hidden');
    loadAgents();
    populateAgentFilter();
}

// Tab navigation
function showAdminTab(tabName) {
    document.querySelectorAll('.tab-content').forEach(tab => tab.classList.add('hidden'));
    document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
    document.getElementById(`${tabName}-admin-tab`).classList.remove('hidden');
    event.target.classList.add('active');

    // Load data for tab
    if (tabName === 'agents') loadAgents();
    else if (tabName === 'mrtds') loadMrtds();
    else if (tabName === 'logs') loadLogs();
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
async function populateAgentFilter() {
    try {
        const data = await fetchJSON('/api/v1/agents');
        const select = document.getElementById('logAgentFilter');
        select.innerHTML = '<option value="">All Agents</option>' +
            data.agents.map(a => `<option value="${a.agent_id}">${a.vm_name}</option>`).join('');
    } catch (error) {
        console.error('Failed to load agents for filter:', error);
    }
}

async function loadLogs() {
    const container = document.getElementById('logsViewer');
    const agentId = document.getElementById('logAgentFilter').value;
    const minLevel = document.getElementById('logLevelFilter').value;

    try {
        let url = `/api/v1/logs/control-plane?lines=200`;
        const data = await fetchJSON(url);

        if (data.logs.length === 0) {
            container.innerHTML = 'No logs found';
            return;
        }

        container.innerHTML = data.logs.map(log => {
            const levelClass = log.level.toLowerCase();
            const time = new Date(log.timestamp).toLocaleTimeString();
            const source = log.container_name ? `[${log.container_name}]` : '[agent]';
            return `<div class="log-entry ${levelClass}">${time} ${log.level.toUpperCase().padEnd(7)} ${source} ${log.message}</div>`;
        }).join('');

        container.scrollTop = container.scrollHeight;
    } catch (error) {
        container.innerHTML = `Error loading logs: ${error.message}`;
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

    // Load stats and logs
    await Promise.all([loadAgentStats(agentId), loadAgentLogs(agentId)]);
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
