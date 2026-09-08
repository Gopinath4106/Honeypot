"""Honeypot Log Parser Unit Tests

Verifies JSON parsing, field extraction, timestamp normalization,
and resilient error handling for malformed logs.
"""

from honeypot.log_parser import CowrieLogParser


def test_parse_valid_login_json():
    """Verify parsing a valid Cowrie login failed JSON record."""
    raw_json = '{"eventid": "cowrie.login.failed", "timestamp": "2026-08-23T10:15:02.345678Z", "src_ip": "198.51.100.24", "src_port": 51234, "dst_port": 2222, "protocol": "ssh", "username": "root", "password": "123"}'
    event = CowrieLogParser.parse_entry(raw_json)

    assert event is not None
    assert event['event_type'] == 'cowrie.login.failed'
    assert event['source_ip'] == '198.51.100.24'
    assert event['source_port'] == 51234
    assert event['destination_port'] == 2222
    assert event['protocol'] == 'ssh'
    assert event['username'] == 'root'
    assert event['severity'] == 'MEDIUM'
    assert event['timestamp'].startswith('2026-08-23T10:15:02')


def test_parse_valid_command_json():
    """Verify parsing a dangerous command input JSON record."""
    raw_json = '{"eventid": "cowrie.command.input", "timestamp": "2026-08-23T11:00:20Z", "src_ip": "203.0.113.88", "input": "cat /etc/shadow"}'
    event = CowrieLogParser.parse_entry(raw_json)

    assert event is not None
    assert event['event_type'] == 'cowrie.command.input'
    assert event['command'] == 'cat /etc/shadow'
    assert event['severity'] == 'CRITICAL'


def test_parse_malformed_json_resilience():
    """Verify that corrupt or malformed JSON strings do not crash the parser."""
    corrupt_line = 'MALFORMED NON JSON LINE WITH IP 192.168.1.100 and login attempt [guest/guest123]'
    event = CowrieLogParser.parse_entry(corrupt_line)

    assert event is not None
    assert event['source_ip'] == '192.168.1.100'
    assert event['username'] == 'guest'
    assert event['severity'] == 'MEDIUM'


def test_parse_empty_or_whitespace():
    """Verify that empty or whitespace strings return None without error."""
    assert CowrieLogParser.parse_entry("") is None
    assert CowrieLogParser.parse_entry("   \n") is None
    assert CowrieLogParser.parse_entry(None) is None


def test_timestamp_normalization():
    """Verify normalization of various timestamp formats."""
    iso_z = "2026-08-23T14:30:00.000Z"
    normalized = CowrieLogParser.normalize_timestamp(iso_z)
    assert normalized == "2026-08-23T14:30:00Z"

    # Invalid timestamp falls back gracefully
    fallback = CowrieLogParser.normalize_timestamp("invalid-date-string")
    assert "T" in fallback
    assert fallback.endswith("Z")
