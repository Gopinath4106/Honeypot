"""Live Monitoring and Event Inspection Route Blueprint

Provides paginated event explorer, multi-field search, severity and protocol filtering,
interactive event inspection modals, and attacker threat profiling.
"""

import math
from flask import Blueprint, render_template, request, jsonify, abort
from routes.auth import login_required
from database.db import query_db
from services.analysis_service import AnalysisService

monitoring_bp = Blueprint('monitoring', __name__, url_prefix='/monitoring')

PER_PAGE = 12


@monitoring_bp.route('/')
@login_required
def events_view():
    """Paginated, filterable event explorer view."""
    page = request.args.get('page', 1, type=int)
    if page < 1:
        page = 1

    search_query = request.args.get('q', '').strip()
    severity_filter = request.args.get('severity', 'ALL').strip().upper()
    protocol_filter = request.args.get('protocol', 'ALL').strip().upper()
    sort_option = request.args.get('sort', 'timestamp_desc').strip()

    # Build parameterized SQL WHERE clause
    where_clauses = ["1=1"]
    params = []

    if search_query:
        where_clauses.append(
            "(source_ip LIKE ? OR username LIKE ? OR command LIKE ? OR event_type LIKE ?)"
        )
        wildcard_term = f"%{search_query}%"
        params.extend([wildcard_term, wildcard_term, wildcard_term, wildcard_term])

    if severity_filter and severity_filter != 'ALL':
        where_clauses.append("severity = ?")
        params.append(severity_filter)

    if protocol_filter and protocol_filter != 'ALL':
        where_clauses.append("protocol = ?")
        params.append(protocol_filter.lower())

    where_sql = " AND ".join(where_clauses)

    # Safe Whitelist for Sorting
    sort_mapping = {
        'timestamp_desc': 'ORDER BY timestamp DESC, id DESC',
        'timestamp_asc': 'ORDER BY timestamp ASC, id ASC',
        'severity_desc': """ORDER BY CASE severity 
                            WHEN 'CRITICAL' THEN 1 
                            WHEN 'HIGH' THEN 2 
                            WHEN 'MEDIUM' THEN 3 
                            ELSE 4 END ASC, timestamp DESC""",
        'ip_asc': 'ORDER BY source_ip ASC, timestamp DESC'
    }
    order_by_sql = sort_mapping.get(sort_option, 'ORDER BY timestamp DESC, id DESC')

    # Query total matching records for pagination calculation
    count_query = f"SELECT COUNT(*) as count FROM events WHERE {where_sql}"
    total_row = query_db(count_query, params, one=True)
    total_records = total_row['count'] if total_row else 0

    total_pages = math.ceil(total_records / PER_PAGE) if total_records > 0 else 1
    if page > total_pages:
        page = total_pages

    offset = (page - 1) * PER_PAGE

    # Query paginated rows
    data_query = f"SELECT * FROM events WHERE {where_sql} {order_by_sql} LIMIT ? OFFSET ?"
    query_params = list(params) + [PER_PAGE, offset]
    events = query_db(data_query, query_params)

    return render_template(
        'monitoring.html',
        events=events,
        current_page=page,
        total_pages=total_pages,
        total_records=total_records,
        search_query=search_query,
        severity_filter=severity_filter,
        protocol_filter=protocol_filter,
        sort_option=sort_option
    )


@monitoring_bp.route('/api/event/<int:event_id>')
@login_required
def event_json(event_id):
    """JSON endpoint for retrieving full event details for modal inspection."""
    event = AnalysisService.get_event_by_id(event_id)
    if not event:
        return jsonify({'error': 'Event not found'}), 404

    return jsonify({
        'id': event['id'],
        'timestamp': event['timestamp'],
        'source_ip': event['source_ip'],
        'source_port': event['source_port'],
        'destination_port': event['destination_port'],
        'protocol': event['protocol'],
        'event_type': event['event_type'],
        'severity': event['severity'],
        'username': event['username'],
        'command': event['command'],
        'raw_log': event['raw_log'],
        'created_at': str(event['created_at'])
    })


@monitoring_bp.route('/api/attacker/<source_ip>')
@login_required
def attacker_profile_api(source_ip):
    """JSON API returning full attacker threat profile."""
    profile = AnalysisService.get_attacker_profile(source_ip)
    return jsonify({
        'status': 'success',
        'source_ip': profile['source_ip'],
        'summary': dict(profile['summary']) if profile['summary'] else {},
        'credentials_tried': [dict(c) for c in profile['credentials_tried']],
        'commands_executed': [dict(cmd) for cmd in profile['commands_executed']],
        'total_events': len(profile['recent_events'])
    })
