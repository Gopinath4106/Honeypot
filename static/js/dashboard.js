/**
 * SOC Dashboard Chart.js Integration
 * Fetches real-time telemetry aggregations and renders responsive dark-themed charts.
 */

document.addEventListener('DOMContentLoaded', function () {
    fetchDashboardCharts();
});

function fetchDashboardCharts() {
    fetch('/api/dashboard/charts')
        .then(response => {
            if (!response.ok) {
                throw new Error('Failed to load chart metrics: ' + response.statusText);
            }
            return response.json();
        })
        .then(data => {
            renderSeverityChart(data.severity);
            renderTopIpsChart(data.top_ips);
            renderEventTypesChart(data.event_types);
        })
        .catch(err => {
            console.error('Error rendering SOC charts:', err);
        });
}

function renderSeverityChart(severityData) {
    const ctx = document.getElementById('severityChart');
    if (!ctx) return;

    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: severityData.labels,
            datasets: [{
                data: severityData.counts,
                backgroundColor: [
                    '#10b981', // LOW (Emerald)
                    '#f59e0b', // MEDIUM (Amber)
                    '#f97316', // HIGH (Orange)
                    '#ef4444'  // CRITICAL (Crimson)
                ],
                borderColor: '#111827',
                borderWidth: 2,
                hoverOffset: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#9ca3af',
                        font: { size: 12, family: 'Segoe UI' },
                        padding: 15
                    }
                },
                tooltip: {
                    backgroundColor: '#162032',
                    titleColor: '#00e5ff',
                    bodyColor: '#f3f4f6',
                    borderColor: '#243048',
                    borderWidth: 1
                }
            },
            cutout: '70%'
        }
    });
}

function renderTopIpsChart(topIpsData) {
    const ctx = document.getElementById('topIpsChart');
    if (!ctx) return;

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: topIpsData.labels,
            datasets: [{
                label: 'Interactions',
                data: topIpsData.counts,
                backgroundColor: 'rgba(0, 229, 255, 0.65)',
                borderColor: '#00e5ff',
                borderWidth: 1,
                borderRadius: 6
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: '#162032',
                    titleColor: '#00e5ff',
                    bodyColor: '#f3f4f6',
                    borderColor: '#243048',
                    borderWidth: 1
                }
            },
            scales: {
                x: {
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: { color: '#9ca3af', stepSize: 1 }
                },
                y: {
                    grid: { display: false },
                    ticks: { color: '#f3f4f6', font: { family: 'Consolas', size: 12 } }
                }
            }
        }
    });
}

function renderEventTypesChart(eventTypesData) {
    const ctx = document.getElementById('eventTypesChart');
    if (!ctx) return;

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: eventTypesData.labels,
            datasets: [{
                label: 'Event Count',
                data: eventTypesData.counts,
                backgroundColor: 'rgba(59, 130, 246, 0.6)',
                borderColor: '#3b82f6',
                borderWidth: 1,
                borderRadius: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: '#162032',
                    titleColor: '#00e5ff',
                    bodyColor: '#f3f4f6',
                    borderColor: '#243048',
                    borderWidth: 1
                }
            },
            scales: {
                x: {
                    grid: { display: false },
                    ticks: { color: '#9ca3af', font: { size: 11 } }
                },
                y: {
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: { color: '#9ca3af', stepSize: 1 }
                }
            }
        }
    });
}
