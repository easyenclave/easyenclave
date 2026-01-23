// EasyEnclave Web GUI JavaScript

// Use CONFIG.API_BASE from config.js, fallback to relative URL for local dev
const API_BASE = (typeof CONFIG !== 'undefined' && CONFIG.API_BASE) ? CONFIG.API_BASE : '/api/v1';
const REFRESH_INTERVAL = (typeof CONFIG !== 'undefined' && CONFIG.REFRESH_INTERVAL) ? CONFIG.REFRESH_INTERVAL : 30000;

let allServices = [];

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    loadServices();
    // Refresh periodically
    setInterval(loadServices, REFRESH_INTERVAL);

    // Search on Enter key
    document.getElementById('searchInput').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') searchServices();
    });
});

// Load all services from API
async function loadServices() {
    try {
        const response = await fetch(`${API_BASE}/services`);
        const data = await response.json();
        allServices = data.services;
        updateStats(allServices);
        renderServices(allServices);
    } catch (error) {
        console.error('Failed to load services:', error);
        document.getElementById('servicesList').innerHTML =
            '<div class="error">Failed to load services. Please try again.</div>';
    }
}

// Update statistics display
function updateStats(services) {
    document.getElementById('totalServices').textContent = services.length;
    document.getElementById('healthyServices').textContent =
        services.filter(s => s.health_status === 'healthy').length;
    document.getElementById('attestedServices').textContent =
        services.filter(s => s.intel_ta_token || s.mrtd).length;
}

// Render services grid
function renderServices(services) {
    const container = document.getElementById('servicesList');

    if (services.length === 0) {
        container.innerHTML = '<div class="empty">No services registered yet.</div>';
        return;
    }

    container.innerHTML = services.map(service => `
        <div class="service-card" onclick="showServiceDetails('${service.service_id}')">
            <div class="service-header">
                <h3>${escapeHtml(service.name)}</h3>
                <span class="health-badge ${service.health_status}">${service.health_status}</span>
            </div>
            <p class="service-description">${escapeHtml(service.description || 'No description')}</p>
            <div class="service-meta">
                ${service.source_repo ? `<a href="${escapeHtml(service.source_repo)}" target="_blank" onclick="event.stopPropagation()">Source</a>` : ''}
                ${Object.keys(service.endpoints).length > 0 ? `<span>${Object.keys(service.endpoints).length} endpoint(s)</span>` : ''}
            </div>
            <div class="service-tags">
                ${service.tags.map(tag => `<span class="tag">${escapeHtml(tag)}</span>`).join('')}
            </div>
            <div class="service-attestation">
                ${service.intel_ta_token ? '<span class="attested">ITA Verified</span>' : ''}
                ${service.mrtd ? `<span class="mrtd" title="${escapeHtml(service.mrtd)}">MRTD</span>` : ''}
            </div>
        </div>
    `).join('');
}

// Search services
async function searchServices() {
    const query = document.getElementById('searchInput').value.trim();
    if (!query) {
        renderServices(allServices);
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/services?q=${encodeURIComponent(query)}`);
        const data = await response.json();
        renderServices(data.services);
    } catch (error) {
        console.error('Search failed:', error);
    }
}

// Clear search and filters
function clearSearch() {
    document.getElementById('searchInput').value = '';
    document.getElementById('envFilter').value = '';
    document.getElementById('healthFilter').value = '';
    renderServices(allServices);
}

// Filter services by environment and health
function filterServices() {
    const envFilter = document.getElementById('envFilter').value;
    const healthFilter = document.getElementById('healthFilter').value;

    let filtered = allServices;

    if (envFilter) {
        filtered = filtered.filter(s => s.endpoints && s.endpoints[envFilter]);
    }

    if (healthFilter) {
        filtered = filtered.filter(s => s.health_status === healthFilter);
    }

    renderServices(filtered);
}

// Show service details modal
async function showServiceDetails(serviceId) {
    try {
        const response = await fetch(`${API_BASE}/services/${serviceId}`);
        const service = await response.json();

        const details = document.getElementById('serviceDetails');
        details.innerHTML = `
            <h2>${escapeHtml(service.name)}</h2>
            <p class="description">${escapeHtml(service.description || 'No description')}</p>

            <div class="detail-section">
                <h3>Service Info</h3>
                <table>
                    <tr><td>Service ID</td><td><code>${escapeHtml(service.service_id)}</code></td></tr>
                    <tr><td>Health Status</td><td><span class="health-badge ${service.health_status}">${service.health_status}</span></td></tr>
                    <tr><td>Registered</td><td>${formatDate(service.registered_at)}</td></tr>
                    ${service.last_health_check ? `<tr><td>Last Health Check</td><td>${formatDate(service.last_health_check)}</td></tr>` : ''}
                </table>
            </div>

            ${service.source_repo ? `
            <div class="detail-section">
                <h3>Source Info</h3>
                <table>
                    <tr><td>Repository</td><td><a href="${escapeHtml(service.source_repo)}" target="_blank">${escapeHtml(service.source_repo)}</a></td></tr>
                    ${service.source_commit ? `<tr><td>Commit</td><td><code>${escapeHtml(service.source_commit)}</code></td></tr>` : ''}
                    ${service.compose_hash ? `<tr><td>Compose Hash</td><td><code>${escapeHtml(service.compose_hash.substring(0, 16))}...</code></td></tr>` : ''}
                </table>
            </div>
            ` : ''}

            ${Object.keys(service.endpoints).length > 0 ? `
            <div class="detail-section">
                <h3>Endpoints</h3>
                <table>
                    ${Object.entries(service.endpoints).map(([env, url]) =>
                        `<tr><td>${escapeHtml(env)}</td><td><a href="${escapeHtml(url)}" target="_blank">${escapeHtml(url)}</a></td></tr>`
                    ).join('')}
                </table>
            </div>
            ` : ''}

            <div class="detail-section">
                <h3>Attestation</h3>
                ${service.mrtd ? `<p><strong>MRTD:</strong> <code>${escapeHtml(service.mrtd)}</code></p>` : '<p>No MRTD recorded</p>'}
                ${service.intel_ta_token ? `
                    <p><strong>Intel Trust Authority Token:</strong> Present</p>
                    <button onclick="verifyAttestation('${serviceId}')" class="verify-btn">Verify Attestation</button>
                    <div id="verificationResult"></div>
                ` : '<p>No ITA token</p>'}
                ${service.attestation_json ? `
                    <details>
                        <summary>Full Attestation JSON</summary>
                        <pre>${escapeHtml(JSON.stringify(service.attestation_json, null, 2))}</pre>
                    </details>
                ` : ''}
            </div>

            ${service.tags.length > 0 ? `
            <div class="detail-section">
                <h3>Tags</h3>
                <div class="tags-list">
                    ${service.tags.map(tag => `<span class="tag">${escapeHtml(tag)}</span>`).join('')}
                </div>
            </div>
            ` : ''}

            <div class="detail-actions">
                <button onclick="deleteService('${serviceId}')" class="delete-btn">Delete Service</button>
            </div>
        `;

        document.getElementById('serviceModal').classList.remove('hidden');
    } catch (error) {
        console.error('Failed to load service details:', error);
        alert('Failed to load service details');
    }
}

// Close modal
function closeModal() {
    document.getElementById('serviceModal').classList.add('hidden');
}

// Close modal on click outside
document.addEventListener('click', (e) => {
    const modal = document.getElementById('serviceModal');
    if (e.target === modal) {
        closeModal();
    }
});

// Verify attestation
async function verifyAttestation(serviceId) {
    const resultDiv = document.getElementById('verificationResult');
    resultDiv.innerHTML = '<p>Verifying...</p>';

    try {
        const response = await fetch(`${API_BASE}/services/${serviceId}/verify`);
        const result = await response.json();

        if (result.verified) {
            resultDiv.innerHTML = `
                <div class="verification-success">
                    <p>Attestation Verified</p>
                    <p>Verified at: ${formatDate(result.verification_time)}</p>
                    ${result.details ? `<pre>${escapeHtml(JSON.stringify(result.details, null, 2))}</pre>` : ''}
                </div>
            `;
        } else {
            resultDiv.innerHTML = `
                <div class="verification-failed">
                    <p>Verification Failed</p>
                    <p>${escapeHtml(result.error || 'Unknown error')}</p>
                </div>
            `;
        }
    } catch (error) {
        resultDiv.innerHTML = `<div class="verification-failed"><p>Verification request failed</p></div>`;
    }
}

// Delete service
async function deleteService(serviceId) {
    if (!confirm('Are you sure you want to delete this service?')) {
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/services/${serviceId}`, {
            method: 'DELETE'
        });

        if (response.ok) {
            closeModal();
            loadServices();
        } else {
            alert('Failed to delete service');
        }
    } catch (error) {
        console.error('Delete failed:', error);
        alert('Failed to delete service');
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
