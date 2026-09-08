/**
 * Live Monitoring and Event Inspector Interactions
 */

document.addEventListener('DOMContentLoaded', function () {
    const inspectButtons = document.querySelectorAll('.btn-inspect-event');
    const modalElement = document.getElementById('eventModal');
    let modalInstance = null;

    if (modalElement && typeof bootstrap !== 'undefined') {
        modalInstance = new bootstrap.Modal(modalElement);
    }

    inspectButtons.forEach(btn => {
        btn.addEventListener('click', function () {
            const eventId = this.getAttribute('data-event-id');
            if (eventId) {
                openEventInspector(eventId, modalInstance);
            }
        });
    });
});

function openEventInspector(eventId, modalInstance) {
    const detailsContainer = document.getElementById('eventModalBody');
    if (!detailsContainer) return;

    detailsContainer.innerHTML = `
        <div class="text-center py-4">
            <div class="spinner-border text-info" role="status">
                <span class="visually-hidden">Loading telemetry...</span>
            </div>
            <p class="text-muted mt-2 small">Fetching sanitized honeypot payload...</p>
        </div>
    `;

    if (modalInstance) {
        modalInstance.show();
    }

    fetch(`/monitoring/api/event/${eventId}`)
        .then(response => {
            if (!response.ok) {
                throw new Error('Event not found or access denied');
            }
            return response.json();
        })
        .then(event => {
            renderEventDetails(event, detailsContainer);
        })
        .catch(err => {
            detailsContainer.innerHTML = `
                <div class="alert alert-danger">
                    <i class="bi bi-exclamation-triangle-fill me-2"></i>Error loading event details: ${err.message}
                </div>
            `;
        });
}

function renderEventDetails(event, container) {
    let severityBadgeClass = 'bg-secondary';
    if (event.severity === 'CRITICAL') severityBadgeClass = 'bg-danger text-light';
    else if (event.severity === 'HIGH') severityBadgeClass = 'bg-warning text-dark';
    else if (event.severity === 'MEDIUM') severityBadgeClass = 'bg-primary text-light';
    else if (event.severity === 'LOW') severityBadgeClass = 'bg-success text-light';

    let formattedRaw = event.raw_log;
    try {
        const parsed = JSON.parse(event.raw_log);
        formattedRaw = JSON.stringify(parsed, null, 2);
    } catch (e) {
        // Keep as string
    }

    container.innerHTML = `
        <div class="row g-3 mb-3">
            <div class="col-md-6">
                <small class="text-muted text-uppercase fw-bold">Event ID</small>
                <div class="text-light fw-bold">#${event.id}</div>
            </div>
            <div class="col-md-6">
                <small class="text-muted text-uppercase fw-bold">Severity Score</small>
                <div><span class="badge ${severityBadgeClass} px-3 py-1">${event.severity}</span></div>
            </div>
            <div class="col-md-6">
                <small class="text-muted text-uppercase fw-bold">Attacker Source IP</small>
                <div class="text-info fw-bold font-monospace">${event.source_ip}:${event.source_port || 'N/A'}</div>
            </div>
            <div class="col-md-6">
                <small class="text-muted text-uppercase fw-bold">Targeted Port / Protocol</small>
                <div class="text-light font-monospace">${event.destination_port} (${event.protocol.toUpperCase()})</div>
            </div>
            <div class="col-md-6">
                <small class="text-muted text-uppercase fw-bold">Timestamp (UTC)</small>
                <div class="text-light">${event.timestamp}</div>
            </div>
            <div class="col-md-6">
                <small class="text-muted text-uppercase fw-bold">Event Type</small>
                <div class="text-info">${event.event_type}</div>
            </div>
        </div>

        ${event.username ? `
        <div class="mb-3 p-2 rounded bg-dark border border-secondary">
            <small class="text-muted text-uppercase fw-bold d-block">Attempted Credential (Username)</small>
            <span class="text-warning font-monospace fs-6">${escapeHtml(event.username)}</span>
        </div>` : ''}

        ${event.command ? `
        <div class="mb-3 p-2 rounded bg-dark border border-danger border-opacity-50">
            <small class="text-danger text-uppercase fw-bold d-block">Injected Shell Command</small>
            <code class="text-light fs-6 font-monospace d-block p-1">${escapeHtml(event.command)}</code>
        </div>` : ''}

        <div class="mt-3">
            <small class="text-muted text-uppercase fw-bold d-block mb-1">Raw Honeypot JSON Payload</small>
            <pre class="bg-dark p-3 rounded border border-secondary text-info font-monospace small mb-0" style="max-height: 220px; overflow-y: auto;"><code>${escapeHtml(formattedRaw)}</code></pre>
        </div>
    `;
}

function escapeHtml(text) {
    if (!text) return '';
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
