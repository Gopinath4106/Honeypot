"""Honeypot Log Collector Service

Reads raw honeypot telemetry from sample logs or live Cowrie logs,
invokes the parser and analyzer, and stores normalized event records in SQLite.
"""

from pathlib import Path
import click
from flask import current_app
from flask.cli import with_appcontext

from database.db import get_db, query_db, modify_db, log_system_event
from honeypot.log_parser import CowrieLogParser


class HoneypotCollector:
    """Service to collect and ingest honeypot telemetry logs into SQLite."""

    @classmethod
    def ingest_logs(cls, log_path=None, app=None):
        """Ingest log records from file into SQLite database.

        Args:
            log_path (str | Path, optional): Custom path to log file. If None, uses app config.
            app (Flask, optional): Flask application instance.

        Returns:
            dict: Summary metrics {'ingested': count, 'skipped': count, 'total': count}
        """
        if not log_path:
            log_path = current_app.config.get('HONEYPOT_LOG_PATH')

        path_obj = Path(log_path)
        if not path_obj.exists():
            log_system_event("WARNING", f"Honeypot log file not found at: {log_path}")
            return {'ingested': 0, 'skipped': 0, 'total': 0, 'error': 'File not found'}

        parsed_events = CowrieLogParser.parse_file(path_obj)
        ingested_count = 0
        skipped_count = 0

        db = get_db()
        for event in parsed_events:
            # Check for existing duplicate event by unique combination of timestamp, IP, and event_type
            existing = query_db(
                "SELECT id FROM events WHERE timestamp = ? AND source_ip = ? AND event_type = ? AND (command = ? OR (command IS NULL AND ? IS NULL))",
                (event['timestamp'], event['source_ip'], event['event_type'], event['command'], event['command']),
                one=True
            )

            if existing:
                skipped_count += 1
                continue

            # Insert normalized event into events table
            modify_db(
                """INSERT INTO events (
                    timestamp, source_ip, source_port, destination_port,
                    protocol, event_type, severity, username, command, raw_log
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event['timestamp'],
                    event['source_ip'],
                    event['source_port'],
                    event['destination_port'],
                    event['protocol'],
                    event['event_type'],
                    event['severity'],
                    event['username'],
                    event['command'],
                    event['raw_log']
                )
            )
            ingested_count += 1

        summary_msg = f"Honeypot Ingestion Complete: {ingested_count} new events inserted, {skipped_count} duplicates skipped."
        log_system_event("INFO", summary_msg)

        return {
            'ingested': ingested_count,
            'skipped': skipped_count,
            'total': len(parsed_events)
        }


@click.command('ingest-logs')
@click.option('--path', default=None, help='Custom log file path to ingest.')
@with_appcontext
def ingest_logs_command(path):
    """Flask CLI command to ingest honeypot logs into SQLite: `flask ingest-logs`."""
    click.echo("Starting honeypot log collection & ingestion...")
    result = HoneypotCollector.ingest_logs(path)
    if 'error' in result:
        click.echo(f"Error: {result['error']}", err=True)
    else:
        click.echo(
            f"Ingestion Finished: Ingested={result['ingested']}, Skipped={result['skipped']}, Total Parsed={result['total']}"
        )
