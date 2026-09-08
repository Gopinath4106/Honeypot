"""SOC Dashboard Route Blueprint

Provides dashboard summary metrics, Chart.js telemetry visualization APIs,
and real-time activity stream feeds.
"""

from flask import Blueprint, render_template, jsonify, current_app
from routes.auth import login_required
from services.statistics_service import StatisticsService

dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/')
@login_required
def index():
    """Main SOC Dashboard view displaying quick metric cards, charts, and recent activity."""
    metrics = StatisticsService.get_summary_metrics()
    top_ips = StatisticsService.get_top_source_ips(limit=5)
    recent_events = StatisticsService.get_recent_events(limit=8)
    common_creds = StatisticsService.get_common_credentials(limit=5)
    common_cmds = StatisticsService.get_common_commands(limit=5)

    system_stats = {
        'total_events': metrics['total_events'],
        'unique_ips': metrics['unique_ips'],
        'critical_events': metrics['critical_events'],
        'high_events': metrics['high_events'],
        'honeypot_status': 'Active',
        'mode': current_app.config.get('HONEYPOT_MODE', 'sample')
    }

    return render_template(
        'dashboard.html',
        stats=system_stats,
        top_ips=top_ips,
        recent_events=recent_events,
        common_creds=common_creds,
        common_cmds=common_cmds
    )


@dashboard_bp.route('/api/dashboard/charts')
@login_required
def charts_api():
    """JSON API returning statistical aggregations for Chart.js rendering."""
    severity_dist = StatisticsService.get_severity_distribution()
    top_ips = StatisticsService.get_top_source_ips(limit=6)
    event_types = StatisticsService.get_event_type_distribution(limit=6)

    return jsonify({
        'status': 'success',
        'severity': {
            'labels': ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
            'counts': [
                severity_dist.get('LOW', 0),
                severity_dist.get('MEDIUM', 0),
                severity_dist.get('HIGH', 0),
                severity_dist.get('CRITICAL', 0)
            ],
            'colors': ['#10b981', '#f59e0b', '#f97316', '#ef4444']
        },
        'top_ips': {
            'labels': [row['source_ip'] for row in top_ips],
            'counts': [row['count'] for row in top_ips]
        },
        'event_types': {
            'labels': [row['event_type'].replace('cowrie.', '') for row in event_types],
            'counts': [row['count'] for row in event_types]
        }
    })
