"""Deterministic Rule-Based Threat Analyzer Module

Categorizes honeypot events and assigns severity levels using transparent,
deterministic pattern matching and heuristic security rules without AI/ML.
"""

import re

# Threat Severity Constants
SEVERITY_LOW = 'LOW'
SEVERITY_MEDIUM = 'MEDIUM'
SEVERITY_HIGH = 'HIGH'
SEVERITY_CRITICAL = 'CRITICAL'

# Event Category Constants
CATEGORY_CONNECTION_ATTEMPT = 'Connection Attempt'
CATEGORY_FAILED_AUTH = 'Failed Authentication'
CATEGORY_SUCCESSFUL_AUTH = 'Successful Honeypot Authentication'
CATEGORY_COMMAND_EXECUTION = 'Command Execution'
CATEGORY_RECONNAISSANCE = 'Reconnaissance / Probe'
CATEGORY_SUSPICIOUS_INTERACTION = 'Suspicious Interaction'
CATEGORY_MALICIOUS_PAYLOAD = 'Malicious Payload / Exploit Attempt'
CATEGORY_SESSION_LIFECYCLE = 'Session Lifecycle'
CATEGORY_OTHER = 'Other'

# Deterministic Command Pattern Signatures
CRITICAL_COMMAND_PATTERNS = [
    r'/etc/shadow',
    r'curl\s+.*\|\s*(ba)?sh',
    r'wget\s+.*\|\s*(ba)?sh',
    r'wget\s+.*miner',
    r'rm\s+-rf\s+/',
    r'history\s+-c',
    r'nc(\.traditional)?\s+.*-[e|c]',
    r'/dev/tcp/',
    r'chmod\s+(\+x|777)\s+/tmp',
    r'insmod|modprobe',
    r':\(\)\{\s*:\|:&\s*\};:',  # Fork bomb
    r'mkfifo\s+/tmp',
    r'python.*import\s+(socket|pty|subprocess)',
    r'bash\s+-i\s+>&',
]

RECONNAISSANCE_COMMAND_PATTERNS = [
    r'^uname(\s+-[a-zA-Z]+)?',
    r'^whoami$',
    r'^id$',
    r'^hostname$',
    r'^cat\s+/etc/passwd',
    r'^cat\s+/etc/issue',
    r'^ps\s+[a-zA-Z\-]+',
    r'^netstat(\s+-[a-zA-Z]+)?',
    r'^ifconfig',
    r'^ip\s+a(ddr)?',
    r'^w$',
    r'^last$',
    r'^uptime$',
    r'^ls(\s+-[a-zA-Z]+)?',
]


class ThreatAnalyzer:
    """Deterministic, rule-based threat evaluation engine for honeypot telemetry."""

    @staticmethod
    def analyze_command(command_str):
        """Analyze shell command string and determine category, severity, and rationale.

        Args:
            command_str (str): Input command executed in honeypot shell.

        Returns:
            tuple[str, str, str]: (category, severity, explanation)
        """
        if not command_str or not command_str.strip():
            return CATEGORY_SUSPICIOUS_INTERACTION, SEVERITY_LOW, "Empty interaction received."

        cleaned_cmd = command_str.strip()

        # Check for Critical Malicious Patterns (Downloader, Reverse Shell, Privilege Escalation)
        for pattern in CRITICAL_COMMAND_PATTERNS:
            if re.search(pattern, cleaned_cmd, re.IGNORECASE):
                return (
                    CATEGORY_MALICIOUS_PAYLOAD,
                    SEVERITY_CRITICAL,
                    f"Dangerous payload execution or system tampering detected matching signature: '{pattern}'"
                )

        # Check for Common Reconnaissance Commands
        for pattern in RECONNAISSANCE_COMMAND_PATTERNS:
            if re.search(pattern, cleaned_cmd, re.IGNORECASE):
                return (
                    CATEGORY_RECONNAISSANCE,
                    SEVERITY_MEDIUM,
                    f"System reconnaissance command observed: '{cleaned_cmd}'"
                )

        # Default for unrecognized or arbitrary executed command
        return (
            CATEGORY_COMMAND_EXECUTION,
            SEVERITY_HIGH,
            f"Arbitrary shell command executed in honeypot environment: '{cleaned_cmd}'"
        )

    @classmethod
    def evaluate_event(cls, event_type, command=None, username=None, duration=None):
        """Evaluate honeypot event telemetry using deterministic rules.

        Args:
            event_type (str): Event identifier (e.g. 'cowrie.login.failed', 'cowrie.command.input').
            command (str, optional): Executed command string.
            username (str, optional): Attempted username.
            duration (float, optional): Connection session duration.

        Returns:
            tuple[str, str, str]: (category, severity, rule_description)
        """
        event_type = (event_type or '').lower()

        # 1. Command Execution Events
        if 'command.input' in event_type or 'command.failed' in event_type or command:
            if command:
                return cls.analyze_command(command)
            return CATEGORY_COMMAND_EXECUTION, SEVERITY_HIGH, "Attacker shell command interaction."

        # 2. Successful Honeypot Authentication (High Priority Alert)
        if 'login.success' in event_type:
            user_info = f" as '{username}'" if username else ""
            return (
                CATEGORY_SUCCESSFUL_AUTH,
                SEVERITY_HIGH,
                f"Attacker successfully gained shell access into honeypot{user_info}."
            )

        # 3. Failed Authentication Attempt
        if 'login.failed' in event_type:
            user_info = f" for user '{username}'" if username else ""
            return (
                CATEGORY_FAILED_AUTH,
                SEVERITY_MEDIUM,
                f"Unauthorized credential brute-force probe attempt{user_info}."
            )

        # 4. Connection Initiation
        if 'session.connect' in event_type:
            return (
                CATEGORY_CONNECTION_ATTEMPT,
                SEVERITY_LOW,
                "Inbound TCP handshake / session established to honeypot listener."
            )

        # 5. Session Termination / Client Version
        if 'session.closed' in event_type or 'client.version' in event_type:
            return (
                CATEGORY_SESSION_LIFECYCLE,
                SEVERITY_LOW,
                "Honeypot session lifecycle event."
            )

        # 6. Direct TCP/IP Tunneling Probe
        if 'direct-tcpip' in event_type:
            return (
                CATEGORY_SUSPICIOUS_INTERACTION,
                SEVERITY_HIGH,
                "Attacker attempted TCP port forwarding / proxy tunneling via honeypot."
            )

        # Default fallback category
        return CATEGORY_OTHER, SEVERITY_LOW, f"Observed honeypot event: {event_type}"
