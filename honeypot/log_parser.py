"""Honeypot Log Parser Module

Parses Cowrie JSON and text log entries, normalizes telemetry fields,
handles malformed or incomplete entries gracefully, and integrates with the
ThreatAnalyzer for deterministic threat categorization.
"""

import json
import re
from datetime import datetime, timezone
from honeypot.analyzer import ThreatAnalyzer


class CowrieLogParser:
    """Resilient parser for Cowrie SSH/Telnet honeypot telemetry logs."""

    @staticmethod
    def normalize_timestamp(timestamp_str):
        """Normalize various timestamp formats to standardized ISO-8601 UTC string.

        Args:
            timestamp_str (str): Raw timestamp string from log entry.

        Returns:
            str: Normalized ISO-8601 UTC formatted timestamp string.
        """
        if not timestamp_str:
            return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Strip extra trailing characters and microseconds if variable
        try:
            # Handle standard ISO format: 2026-08-23T10:15:00.123456Z or 2026-08-23T10:15:00Z
            clean_ts = timestamp_str.replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean_ts)
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            pass

        # Fallback to current UTC time if parsing fails
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    @classmethod
    def parse_entry(cls, raw_line):
        """Parse a single raw log entry string or dictionary into a normalized event dict.

        Args:
            raw_line (str | dict): Raw JSON line or dictionary from Cowrie log file.

        Returns:
            dict | None: Normalized event dictionary or None if completely unparseable.
        """
        if not raw_line:
            return None

        data = {}
        raw_str = ""

        if isinstance(raw_line, dict):
            data = raw_line
            raw_str = json.dumps(data)
        elif isinstance(raw_line, str):
            raw_str = raw_line.strip()
            if not raw_str:
                return None
            try:
                data = json.loads(raw_str)
            except json.JSONDecodeError:
                # Handle legacy/non-JSON text format lines via fallback regex extraction
                data = cls._parse_text_fallback(raw_str)

        # Extract normalized attributes with safe defaults
        event_type = data.get('eventid') or data.get('event_type') or 'cowrie.generic.event'
        timestamp = cls.normalize_timestamp(data.get('timestamp'))
        source_ip = data.get('src_ip') or data.get('source_ip') or '127.0.0.1'

        # Sanitize port numbers
        try:
            source_port = int(data.get('src_port') or data.get('source_port')) if data.get('src_port') or data.get('source_port') else None
        except (ValueError, TypeError):
            source_port = None

        try:
            destination_port = int(data.get('dst_port') or data.get('destination_port')) if data.get('dst_port') or data.get('destination_port') else 2222
        except (ValueError, TypeError):
            destination_port = 2222

        protocol = (data.get('protocol') or 'ssh').lower()
        username = data.get('username') or None
        command = data.get('input') or data.get('command') or None

        # Apply deterministic rule evaluation
        category, severity, explanation = ThreatAnalyzer.evaluate_event(
            event_type=event_type,
            command=command,
            username=username,
            duration=data.get('duration')
        )

        return {
            'timestamp': timestamp,
            'source_ip': str(source_ip),
            'source_port': source_port,
            'destination_port': destination_port,
            'protocol': protocol,
            'event_type': event_type,
            'severity': severity,
            'category': category,
            'username': username,
            'command': command,
            'explanation': explanation,
            'raw_log': raw_str
        }

    @classmethod
    def _parse_text_fallback(cls, text_line):
        """Fallback parser for non-JSON formatted textual honeypot logs."""
        extracted = {
            'eventid': 'cowrie.legacy.text',
            'timestamp': None,
            'src_ip': 'UNKNOWN',
            'protocol': 'ssh'
        }

        # Attempt to extract IPv4 address
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text_line)
        if ip_match:
            extracted['src_ip'] = ip_match.group(0)

        # Attempt to extract command input
        cmd_match = re.search(r'CMD:\s*(.*)', text_line)
        if cmd_match:
            extracted['input'] = cmd_match.group(1).strip()
            extracted['eventid'] = 'cowrie.command.input'

        # Attempt to extract login attempts
        login_match = re.search(r'login attempt\s*\[(.*?)/(.*?)\]', text_line)
        if login_match:
            extracted['username'] = login_match.group(1)
            extracted['eventid'] = 'cowrie.login.failed'

        return extracted

    @classmethod
    def parse_file(cls, file_path):
        """Parse an entire Cowrie log file line-by-line.

        Args:
            file_path (str | Path): Path to the log file.

        Returns:
            list[dict]: List of successfully normalized event dictionaries.
        """
        events = []
        try:
            with open(file_path, mode='r', encoding='utf-8', errors='replace') as log_file:
                for line in log_file:
                    parsed = cls.parse_entry(line)
                    if parsed:
                        events.append(parsed)
        except Exception as e:
            print(f"[LOG_PARSER_ERROR] Failed to read log file {file_path}: {e}")

        return events
