// EasyEnclave App Store Dashboard

const API_BASE = '/api/v1';
let allApps = [];
let allAgents = [];
let allDeployments = [];

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    loadAll();
    // Refresh every 30 seconds
    setInterval(loadAll, 30000);
});

async function loadAll() {
    await Promise.all([loadApps(), loadAgents(), loadDeployments()]);
    updateStats();
}

// Load apps from API
async function loadApps() {
    try {
        const response = await fetch(`${API_BASE}/apps`);
        const data = await response.json();
        allApps = data.apps;
        renderApps(allApps);
    } catch (error) {
        console.error('Failed to load apps:', error);
        document.getElementById('appsList').innerHTML =
            '<div class="error">Failed to load apps</div>';
    }
}

// Load agents from API
async function loadAgents() {
    try {
        const response = await fetch(`${API_BASE}/agents`);
        const data = await response.json();
        allAgents = data.agents;
        renderAgents(allAgents);
    } catch (error) {
        console.error('Failed to load agents:', error);
        document.getElementById('agentsList').innerHTML =
            '<div class="error">Failed to load agents</div>';
    }
}

// Load deployments from API
async function loadDeployments() {
    try {
        const response = await fetch(`${API_BASE}/deployments`);
        const data = await response.json();
        allDeployments = data.deployments.slice(0, 20); // Show last 20
        renderDeployments(allDeployments);
    } catch (error) {
        console.error('Failed to load deployments:', error);
        document.getElementById('deploymentsList').innerHTML =
            '<div class="error">Failed to load deployments</div>';
    }
}

// Update statistics
function updateStats() {
    document.getElementById('totalApps').textContent = allApps.length;
    document.getElementById('totalAgents').textContent = allAgents.length;
    document.getElementById('healthyAgents').textContent =
        allAgents.filter(a => a.health_status === 'healthy').length;

    // Count total versions across all apps
    let totalVersions = 0;
    // We'd need to fetch versions for each app, so just show apps for now
    document.getElementById('totalVersions').textContent = '-';
}

// Render apps grid
function renderApps(apps) {
    const container = document.getElementById('appsList');

    if (apps.length === 0) {
        container.innerHTML = `
            <div class="empty">
                <p>No apps registered yet.</p>
                <p>Register your first app to get started!</p>
            </div>
        `;
        return;
    }

    container.innerHTML = apps.map(app => `
        <div class="app-card" onclick="showAppDetails('${escapeHtml(app.name)}')">
            <div class="app-header">
                <h3>${escapeHtml(app.name)}</h3>
            </div>
            <p class="app-description">${escapeHtml(app.description || 'No description')}</p>
            ${app.source_repo ? `
                <div class="app-repo">
                    <svg viewBox="0 0 16 16" width="14" height="14">
                        <path fill="currentColor" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
                    </svg>
                    <span>${escapeHtml(app.source_repo)}</span>
                </div>
            ` : ''}
            <div class="app-meta">
                <span>Created ${formatDate(app.created_at)}</span>
            </div>
        </div>
    `).join('');
}

// Render agents grid
function renderAgents(agents) {
    const container = document.getElementById('agentsList');

    if (agents.length === 0) {
        container.innerHTML = '<div class="empty">No agents registered</div>';
        return;
    }

    container.innerHTML = agents.map(agent => `
        <div class="agent-card" onclick="showAgentDetails('${agent.agent_id}')">
            <div class="agent-header">
                <h3>${escapeHtml(agent.vm_name)}</h3>
                <span class="status-badge ${agent.status}">${agent.status}</span>
            </div>
            <div class="agent-status">
                <span class="health-dot ${agent.health_status}"></span>
                <span>${agent.health_status}</span>
                ${agent.verified ? '<span class="verified-badge">Verified</span>' : '<span class="unverified-badge">Unverified</span>'}
            </div>
            ${agent.hostname ? `<div class="agent-hostname">${escapeHtml(agent.hostname)}</div>` : ''}
            <div class="agent-meta">
                <span>Registered ${formatDate(agent.registered_at)}</span>
            </div>
        </div>
    `).join('');
}

// Render deployments list
function renderDeployments(deployments) {
    const container = document.getElementById('deploymentsList');

    if (deployments.length === 0) {
        container.innerHTML = '<div class="empty">No deployments yet</div>';
        return;
    }

    container.innerHTML = `
        <table class="deployments-table">
            <thead>
                <tr>
                    <th>Deployment ID</th>
                    <th>Agent</th>
                    <th>Status</th>
                    <th>Created</th>
                </tr>
            </thead>
            <tbody>
                ${deployments.map(d => `
                    <tr>
                        <td><code>${d.deployment_id.substring(0, 8)}...</code></td>
                        <td>${d.agent_id.substring(0, 8)}...</td>
                        <td><span class="status-badge ${d.status}">${d.status}</span></td>
                        <td>${formatDate(d.created_at)}</td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;
}

// Show app details modal
async function showAppDetails(appName) {
    try {
        const [appResponse, versionsResponse] = await Promise.all([
            fetch(`${API_BASE}/apps/${encodeURIComponent(appName)}`),
            fetch(`${API_BASE}/apps/${encodeURIComponent(appName)}/versions`)
        ]);

        const app = await appResponse.json();
        const versionsData = await versionsResponse.json();
        const versions = versionsData.versions || [];

        const details = document.getElementById('appDetails');
        details.innerHTML = `
            <h2>${escapeHtml(app.name)}</h2>
            <p class="description">${escapeHtml(app.description || 'No description')}</p>

            <div class="detail-section">
                <h3>App Info</h3>
                <table>
                    <tr><td>App ID</td><td><code>${escapeHtml(app.app_id)}</code></td></tr>
                    ${app.source_repo ? `<tr><td>Source Repo</td><td><a href="https://github.com/${escapeHtml(app.source_repo)}" target="_blank">${escapeHtml(app.source_repo)}</a></td></tr>` : ''}
                    <tr><td>Created</td><td>${formatDate(app.created_at)}</td></tr>
                </table>
            </div>

            <div class="detail-section">
                <h3>Versions (${versions.length})</h3>
                ${versions.length > 0 ? `
                    <table class="versions-table">
                        <thead>
                            <tr>
                                <th>Version</th>
                                <th>Status</th>
                                <th>Published</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${versions.map(v => `
                                <tr>
                                    <td><code>${escapeHtml(v.version)}</code></td>
                                    <td><span class="status-badge ${v.status}">${v.status}</span></td>
                                    <td>${formatDate(v.published_at)}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                ` : '<p>No versions published yet</p>'}
            </div>

            <div class="detail-section">
                <h3>Deploy via GitHub Action</h3>
                <pre><code>- uses: easyenclave/easyenclave/.github/actions/deploy@main
  with:
    app_name: ${escapeHtml(app.name)}
    compose_file: docker-compose.yml
    service_name: ${escapeHtml(app.name)}</code></pre>
            </div>

            <div class="detail-actions">
                <button onclick="deleteApp('${escapeHtml(app.name)}')" class="delete-btn">Delete App</button>
            </div>
        `;

        document.getElementById('appModal').classList.remove('hidden');
    } catch (error) {
        console.error('Failed to load app details:', error);
        alert('Failed to load app details');
    }
}

// Show agent details modal
async function showAgentDetails(agentId) {
    try {
        const [agentResponse, attestationResponse] = await Promise.all([
            fetch(`${API_BASE}/agents/${agentId}`),
            fetch(`${API_BASE}/agents/${agentId}/attestation`)
        ]);

        const agent = await agentResponse.json();
        const attestation = await attestationResponse.json();

        const details = document.getElementById('agentDetails');
        details.innerHTML = `
            <h2>${escapeHtml(agent.vm_name)}</h2>

            <div class="detail-section">
                <h3>Status</h3>
                <table>
                    <tr><td>Agent ID</td><td><code>${escapeHtml(agent.agent_id)}</code></td></tr>
                    <tr><td>Status</td><td><span class="status-badge ${agent.status}">${agent.status}</span></td></tr>
                    <tr><td>Health</td><td><span class="health-dot ${agent.health_status}"></span> ${agent.health_status}</td></tr>
                    <tr><td>Verified</td><td>${agent.verified ? '<span class="verified-badge">Yes</span>' : '<span class="unverified-badge">No</span>'}</td></tr>
                    ${agent.hostname ? `<tr><td>Hostname</td><td><a href="https://${escapeHtml(agent.hostname)}" target="_blank">${escapeHtml(agent.hostname)}</a></td></tr>` : ''}
                </table>
            </div>

            <div class="detail-section">
                <h3>Attestation</h3>
                <table>
                    ${agent.mrtd ? `<tr><td>MRTD</td><td><code class="mrtd-code">${escapeHtml(agent.mrtd.substring(0, 16))}...</code></td></tr>` : ''}
                    <tr>
                        <td>Intel TDX</td>
                        <td>
                            ${attestation.intel_ta_verified
                                ? '<span class="verified-badge">Verified</span>'
                                : '<span class="unverified-badge">Not Verified</span>'}
                            <a href="https://portal.trustauthority.intel.com" target="_blank" class="attestation-link">Intel Trust Authority</a>
                        </td>
                    </tr>
                    ${attestation.intel_ta_claims ? `
                    <tr>
                        <td>TCB Status</td>
                        <td>
                            <span class="${attestation.intel_ta_claims.attester_tcb_status === 'UpToDate' ? 'verified-badge' : 'status-badge'}">${escapeHtml(attestation.intel_ta_claims.attester_tcb_status || 'Unknown')}</span>
                        </td>
                    </tr>
                    ${attestation.intel_ta_claims.attester_type ? `
                    <tr>
                        <td>Attester Type</td>
                        <td>${escapeHtml(attestation.intel_ta_claims.attester_type)}</td>
                    </tr>
                    ` : ''}
                    ${attestation.intel_ta_claims.token_expiry ? `
                    <tr>
                        <td>Token Expiry</td>
                        <td>${formatDate(attestation.intel_ta_claims.token_expiry)}</td>
                    </tr>
                    ` : ''}
                    ` : ''}
                    ${attestation.github_attestation ? `
                    <tr>
                        <td>GitHub Source</td>
                        <td>
                            <span class="verified-badge">Attested</span>
                            ${attestation.github_attestation.source_repo ? `
                                <a href="https://github.com/${escapeHtml(attestation.github_attestation.source_repo)}/commit/${escapeHtml(attestation.github_attestation.source_commit || '')}" target="_blank" class="attestation-link">
                                    ${escapeHtml(attestation.github_attestation.source_repo)}@${escapeHtml((attestation.github_attestation.source_commit || '').substring(0, 7))}
                                </a>
                            ` : ''}
                        </td>
                    </tr>
                    ${attestation.github_attestation.build_workflow ? `
                    <tr>
                        <td>Build Workflow</td>
                        <td>
                            <a href="${escapeHtml(attestation.github_attestation.build_workflow)}" target="_blank" class="attestation-link">
                                View GitHub Actions Run
                            </a>
                        </td>
                    </tr>
                    ` : ''}
                    ${attestation.github_attestation.attestation_url ? `
                    <tr>
                        <td>SLSA Provenance</td>
                        <td>
                            <a href="${escapeHtml(attestation.github_attestation.attestation_url)}" target="_blank" class="attestation-link">
                                View GitHub Attestations
                            </a>
                        </td>
                    </tr>
                    ` : ''}
                    ` : `
                    <tr>
                        <td>GitHub Source</td>
                        <td><span class="unverified-badge">No attestation</span></td>
                    </tr>
                    `}
                </table>
                ${agent.verification_error ? `<p class="error-text">Error: ${escapeHtml(agent.verification_error)}</p>` : ''}
            </div>

            <div class="detail-section">
                <h3>Deployment</h3>
                ${agent.current_deployment_id ? `
                    <p>Current: <code>${escapeHtml(agent.current_deployment_id)}</code></p>
                ` : '<p>No active deployment</p>'}
            </div>

            <div class="detail-section">
                <h3>Timestamps</h3>
                <table>
                    <tr><td>Registered</td><td>${formatDate(agent.registered_at)}</td></tr>
                    <tr><td>Last Heartbeat</td><td>${formatDate(agent.last_heartbeat)}</td></tr>
                    ${agent.last_health_check ? `<tr><td>Last Health Check</td><td>${formatDate(agent.last_health_check)}</td></tr>` : ''}
                </table>
            </div>
        `;

        document.getElementById('agentModal').classList.remove('hidden');
    } catch (error) {
        console.error('Failed to load agent details:', error);
        alert('Failed to load agent details');
    }
}

// Tab navigation
function showTab(tabName) {
    // Hide all tabs
    document.querySelectorAll('.tab-content').forEach(tab => tab.classList.add('hidden'));
    document.querySelectorAll('.tab').forEach(btn => btn.classList.remove('active'));

    // Show selected tab
    document.getElementById(`${tabName}-tab`).classList.remove('hidden');
    event.target.classList.add('active');
}

// Modal functions
function closeModal(modalId) {
    document.getElementById(modalId).classList.add('hidden');
}

function showRegisterAppModal() {
    document.getElementById('registerModal').classList.remove('hidden');
}

// Close modal on click outside
document.addEventListener('click', (e) => {
    if (e.target.classList.contains('modal')) {
        e.target.classList.add('hidden');
    }
});

// Register new app
async function registerApp(event) {
    event.preventDefault();

    const name = document.getElementById('appName').value.trim();
    const description = document.getElementById('appDescription').value.trim();
    const sourceRepo = document.getElementById('sourceRepo').value.trim();

    try {
        const response = await fetch(`${API_BASE}/apps`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                name,
                description,
                source_repo: sourceRepo || null
            })
        });

        if (!response.ok) {
            const error = await response.json();
            alert(`Failed to register app: ${error.detail || 'Unknown error'}`);
            return;
        }

        closeModal('registerModal');
        document.getElementById('registerAppForm').reset();
        loadApps();
    } catch (error) {
        console.error('Failed to register app:', error);
        alert('Failed to register app');
    }
}

// Delete app
async function deleteApp(appName) {
    if (!confirm(`Are you sure you want to delete "${appName}"? This will also delete all versions.`)) {
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/apps/${encodeURIComponent(appName)}`, {
            method: 'DELETE'
        });

        if (response.ok) {
            closeModal('appModal');
            loadApps();
        } else {
            alert('Failed to delete app');
        }
    } catch (error) {
        console.error('Delete failed:', error);
        alert('Failed to delete app');
    }
}

// Utility functions
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatDate(dateStr) {
    if (!dateStr) return 'N/A';
    const date = new Date(dateStr);
    return date.toLocaleString();
}
