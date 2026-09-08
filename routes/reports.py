"""Security Reports and Export Route Blueprint

Provides downloadable executive PDF reports, CSV dataset streaming,
and system audit log review.
"""

from datetime import datetime, timezone
from flask import Blueprint, render_template, Response, make_response, current_app
from routes.auth import login_required
from database.db import query_db
from services.statistics_service import StatisticsService
from services.report_service import ReportService

reports_bp = Blueprint('reports', __name__, url_prefix='/reports')


@reports_bp.route('/')
@login_required
def index():
    """Reports overview and system audit trail view."""
    metrics = StatisticsService.get_summary_metrics()
    audit_logs = query_db(
        "SELECT * FROM system_logs ORDER BY id DESC LIMIT 15"
    )
    return render_template(
        'reports.html',
        metrics=metrics,
        audit_logs=audit_logs
    )


@reports_bp.route('/generate/pdf')
@login_required
def download_pdf():
    """Generate and stream executive security PDF report."""
    pdf_bytes = ReportService.generate_pdf_report()
    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"sentinel_security_report_{timestamp_str}.pdf"

    response = make_response(pdf_bytes)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response


@reports_bp.route('/export/csv')
@login_required
def export_csv():
    """Generate and stream all normalized telemetry records as CSV."""
    csv_content = ReportService.generate_csv_export()
    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"honeypot_telemetry_{timestamp_str}.csv"

    response = make_response(csv_content)
    response.headers['Content-Type'] = 'text/csv; charset=utf-8'
    response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response
