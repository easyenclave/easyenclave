// EasyEnclave Admin Dashboard JavaScript

let adminToken = null;

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
        const response = await fetch('/admin/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password })
        });

        if (response.ok) {
            const data = await response.json();
            adminToken = data.token;
            sessionStorage.setItem('adminToken', adminToken);
            showDashboard();
        } else {
            errorDiv.textContent = 'Invalid password';
            errorDiv.style.display = 'block';
        }
    } catch (error) {
        errorDiv.textContent = 'Connection error';
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
        const response = await fetch('/api/v1/agents');
        const data = await response.json();

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
                        <th>Registered</th>
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
                            <td>${new Date(agent.registered_at).toLocaleString()}</td>
                            <td class="action-buttons">
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

// MRTDs management
async function loadMrtds() {
    const container = document.getElementById('mrtdsAdminList');
    try {
        const response = await fetch('/api/v1/trusted-mrtds?include_inactive=true');
        const data = await response.json();

        if (data.trusted_mrtds.length === 0) {
            container.innerHTML = '<div class="empty">No trusted MRTDs</div>';
            return;
        }

        container.innerHTML = `
            <table class="data-table">
                <thead>
                    <tr>
                        <th>MRTD</th>
                        <th>Type</th>
                        <th>Description</th>
                        <th>Source</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ${data.trusted_mrtds.map(mrtd => `
                        <tr style="${!mrtd.active ? 'opacity: 0.5' : ''}">
                            <td><code>${mrtd.mrtd.substring(0, 24)}...</code></td>
                            <td><span class="status-badge">${mrtd.type || 'agent'}</span></td>
                            <td>${mrtd.description || '-'}</td>
                            <td>${mrtd.source_repo ? `<a href="https://github.com/${mrtd.source_repo}" target="_blank">${mrtd.source_repo}</a>` : '-'}</td>
                            <td>${mrtd.active ? '<span class="verified-badge">Active</span>' : '<span class="unverified-badge">Inactive</span>'}</td>
                            <td class="action-buttons">
                                ${mrtd.locked ? '<span style="color: var(--gray-400)">Locked</span>' : `
                                    ${mrtd.active ?
                                        `<button class="btn-small btn-warning" onclick="deactivateMrtd('${mrtd.mrtd}')">Deactivate</button>` :
                                        `<button class="btn-small btn-secondary" onclick="activateMrtd('${mrtd.mrtd}')">Activate</button>`
                                    }
                                    <button class="btn-small btn-danger" onclick="deleteMrtd('${mrtd.mrtd}')">Delete</button>
                                `}
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
    } catch (error) {
        container.innerHTML = `<div class="error">Error loading MRTDs: ${error.message}</div>`;
    }
}

async function addMrtd(event) {
    event.preventDefault();
    const mrtd = document.getElementById('newMrtd').value;
    const type = document.getElementById('newMrtdType').value;
    const description = document.getElementById('newMrtdDesc').value;

    try {
        const response = await adminFetch('/api/v1/trusted-mrtds', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ mrtd, type, description })
        });

        if (response.ok) {
            document.getElementById('newMrtd').value = '';
            document.getElementById('newMrtdDesc').value = '';
            loadMrtds();
        } else {
            const err = await response.json();
            alert('Failed: ' + (err.detail || 'Unknown error'));
        }
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

async function deactivateMrtd(mrtd) {
    if (!confirm('Deactivate this MRTD? Agents with this MRTD will no longer be verified.')) return;

    try {
        const response = await adminFetch(`/api/v1/trusted-mrtds/${encodeURIComponent(mrtd)}/deactivate`, { method: 'POST' });
        if (response.ok) {
            loadMrtds();
        } else {
            const err = await response.json();
            alert('Failed: ' + (err.detail || 'Unknown error'));
        }
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

async function activateMrtd(mrtd) {
    try {
        const response = await adminFetch(`/api/v1/trusted-mrtds/${encodeURIComponent(mrtd)}/activate`, { method: 'POST' });
        if (response.ok) {
            loadMrtds();
        } else {
            alert('Failed to activate MRTD');
        }
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

async function deleteMrtd(mrtd) {
    if (!confirm('Delete this MRTD from the trusted list?')) return;

    try {
        const response = await adminFetch(`/api/v1/trusted-mrtds/${encodeURIComponent(mrtd)}`, { method: 'DELETE' });
        if (response.ok) {
            loadMrtds();
        } else {
            const err = await response.json();
            alert('Failed: ' + (err.detail || 'Unknown error'));
        }
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

// Logs viewer
async function populateAgentFilter() {
    try {
        const response = await fetch('/api/v1/agents');
        const data = await response.json();
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
        let url = `/api/v1/logs?min_level=${minLevel}&limit=200`;
        if (agentId) url += `&agent_id=${agentId}`;

        const response = await fetch(url);
        const data = await response.json();

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
        const response = await fetch('/health');
        const data = await response.json();
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
            fetch('/api/v1/agents').then(r => r.json()),
            fetch('/api/v1/apps').then(r => r.json()),
            fetch('/api/v1/deployments').then(r => r.json())
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
        const response = await fetch('/api/v1/agents');
        const data = await response.json();

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
        const response = await fetch('/api/v1/agents');
        const data = await response.json();

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
