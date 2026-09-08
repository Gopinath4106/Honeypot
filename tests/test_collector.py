"""Honeypot Collector and Statistics Service Unit Tests

Verifies log ingestion from sample files, duplicate prevention,
statistical aggregation, and CLI commands.
"""

from honeypot.collector import HoneypotCollector
from services.statistics_service import StatisticsService
from database.db import query_db


def test_ingest_sample_logs(app):
    """Verify that HoneypotCollector successfully ingests sample Cowrie log entries."""
    with app.app_context():
        result = HoneypotCollector.ingest_logs()
        assert result['ingested'] > 0
        assert result['error'] is None if 'error' in result else True

        # Verify records in database
        events = query_db("SELECT COUNT(*) as count FROM events", one=True)
        assert events['count'] == result['ingested']


def test_ingest_duplicate_prevention(app):
    """Verify that re-ingesting the same log file does not create duplicates."""
    with app.app_context():
        # First ingestion
        res1 = HoneypotCollector.ingest_logs()
        initial_ingested = res1['ingested']
        assert initial_ingested > 0

        # Second ingestion of same file
        res2 = HoneypotCollector.ingest_logs()
        assert res2['ingested'] == 0
        assert res2['skipped'] == initial_ingested


def test_statistics_service_after_ingestion(app):
    """Verify that StatisticsService computes accurate summaries from ingested data."""
    with app.app_context():
        HoneypotCollector.ingest_logs()

        # Check summary metrics
        metrics = StatisticsService.get_summary_metrics()
        assert metrics['total_events'] > 0
        assert metrics['unique_ips'] > 0
        assert metrics['critical_events'] > 0

        # Check severity distribution
        sev_dist = StatisticsService.get_severity_distribution()
        assert sev_dist['CRITICAL'] > 0
        assert sev_dist['MEDIUM'] > 0

        # Check top source IPs
        top_ips = StatisticsService.get_top_source_ips(limit=3)
        assert len(top_ips) > 0
        assert top_ips[0]['source_ip'] is not None

        # Check common commands
        common_cmds = StatisticsService.get_common_commands(limit=5)
        assert len(common_cmds) > 0
        assert common_cmds[0]['command'] is not None


def test_ingest_logs_cli(runner):
    """Verify that the flask ingest-logs CLI command executes properly."""
    result = runner.invoke(args=['ingest-logs'])
    assert result.exit_code == 0
    assert 'Ingestion Finished' in result.output
