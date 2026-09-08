"""Security Reports and Data Export Unit Tests

Verifies PDF report generation, CSV telemetry streaming,
system audit trail logging, and HTTP security response headers.
"""

from honeypot.collector import HoneypotCollector
from routes.auth import create_user_account
from database.db import query_db


def test_reports_view_authenticated(app, client):
    """Verify that the reports center view loads successfully."""
    with app.app_context():
        create_user_account("rep_admin", "ReportPass123!")
        HoneypotCollector.ingest_logs()

    client.post('/auth/login', data={'username': 'rep_admin', 'password': 'ReportPass123!'})

    response = client.get('/reports/')
    assert response.status_code == 200
    assert b'Security Reports &amp; Compliance Center' in response.data or b'Security Reports' in response.data
    assert b'Executive Security Audit Report' in response.data
    assert b'Full Telemetry Dataset Export' in response.data


def test_generate_pdf_report_route(app, client):
    """Verify that downloading the PDF report returns valid PDF binary stream."""
    with app.app_context():
        create_user_account("pdf_admin", "PdfPass123!")
        HoneypotCollector.ingest_logs()

    client.post('/auth/login', data={'username': 'pdf_admin', 'password': 'PdfPass123!'})

    response = client.get('/reports/generate/pdf')
    assert response.status_code == 200
    assert response.headers['Content-Type'] == 'application/pdf'
    assert 'attachment;' in response.headers['Content-Disposition']
    assert '.pdf' in response.headers['Content-Disposition']
    # Standard PDF magic bytes check (%PDF-)
    assert response.data.startswith(b'%PDF-')

    # Verify audit log was recorded
    with app.app_context():
        audit = query_db("SELECT * FROM system_logs WHERE message LIKE '%executive security PDF report%'")
        assert len(audit) > 0


def test_export_csv_route(app, client):
    """Verify that exporting the CSV dataset returns valid CSV data rows."""
    with app.app_context():
        create_user_account("csv_admin", "CsvPass123!")
        HoneypotCollector.ingest_logs()

    client.post('/auth/login', data={'username': 'csv_admin', 'password': 'CsvPass123!'})

    response = client.get('/reports/export/csv')
    assert response.status_code == 200
    assert 'text/csv' in response.headers['Content-Type']
    assert 'attachment;' in response.headers['Content-Disposition']
    assert '.csv' in response.headers['Content-Disposition']

    # Verify CSV headers and data content
    csv_text = response.data.decode('utf-8')
    assert 'timestamp_utc' in csv_text
    assert 'source_ip' in csv_text
    assert '198.51.100.24' in csv_text

    # Verify audit log was recorded
    with app.app_context():
        audit = query_db("SELECT * FROM system_logs WHERE message LIKE '%Exported%telemetry records to CSV%'")
        assert len(audit) > 0


def test_http_security_headers(client):
    """Verify that defensive security headers are applied to HTTP responses."""
    response = client.get('/health')
    assert response.status_code == 200
    assert response.headers.get('X-Content-Type-Options') == 'nosniff'
    assert response.headers.get('X-Frame-Options') == 'SAMEORIGIN'
    assert response.headers.get('X-XSS-Protection') == '1; mode=block'
    assert response.headers.get('Referrer-Policy') == 'strict-origin-when-cross-origin'


def test_unauthenticated_reports_access_denied(client):
    """Verify that unauthenticated users cannot access reports or trigger downloads."""
    res1 = client.get('/reports/', follow_redirects=False)
    assert res1.status_code == 302
    assert '/auth/login' in res1.headers['Location']

    res2 = client.get('/reports/generate/pdf', follow_redirects=False)
    assert res2.status_code == 302
    assert '/auth/login' in res2.headers['Location']
