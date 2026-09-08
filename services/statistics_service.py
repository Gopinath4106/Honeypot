"""Statistics and Aggregation Service

Provides clean, parameterized data access for dashboard metric cards,
Chart.js visualizations, top attacker rankings, and telemetry breakdowns.
"""

from database.db import query_db


class StatisticsService:
    """Service to compute statistical summaries and charts telemetry from SQLite."""

    @staticmethod
    def get_summary_metrics():
        """Retrieve high-level overview metrics for the dashboard cards.

        Returns:
            dict: Summary metrics (total_events, unique_ips, critical_count, high_count).
        """
        total_row = query_db("SELECT COUNT(*) as c FROM events", one=True)
        unique_ips_row = query_db("SELECT COUNT(DISTINCT source_ip) as c FROM events", one=True)
        critical_row = query_db("SELECT COUNT(*) as c FROM events WHERE severity = 'CRITICAL'", one=True)
        high_row = query_db("SELECT COUNT(*) as c FROM events WHERE severity = 'HIGH'", one=True)
        recent_row = query_db("SELECT COUNT(*) as c FROM events WHERE timestamp >= date('now', '-1 day')", one=True)

        return {
            'total_events': total_row['c'] if total_row else 0,
            'unique_ips': unique_ips_row['c'] if unique_ips_row else 0,
            'critical_events': critical_row['c'] if critical_row else 0,
            'high_events': high_row['c'] if high_row else 0,
            'recent_events_24h': recent_row['c'] if recent_row else 0
        }

    @staticmethod
    def get_severity_distribution():
        """Retrieve count of events grouped by severity level.

        Returns:
            dict: Mapping of severity ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') to event count.
        """
        rows = query_db(
            "SELECT severity, COUNT(*) as count FROM events GROUP BY severity"
        )
        distribution = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
        for row in rows:
            if row['severity'] in distribution:
                distribution[row['severity']] = row['count']
        return distribution

    @staticmethod
    def get_top_source_ips(limit=5):
        """Retrieve the top attacking source IP addresses by event frequency.

        Args:
            limit (int): Number of top IPs to return.

        Returns:
            list[dict]: List of {'source_ip': ip, 'count': total, 'critical_count': crit}.
        """
        return query_db(
            """SELECT source_ip, COUNT(*) as count,
                      SUM(CASE WHEN severity IN ('HIGH', 'CRITICAL') THEN 1 ELSE 0 END) as threat_count
               FROM events
               GROUP BY source_ip
               ORDER BY count DESC
               LIMIT ?""",
            (limit,)
        )

    @staticmethod
    def get_event_type_distribution(limit=6):
        """Retrieve the most frequent honeypot event types.

        Args:
            limit (int): Number of categories to return.

        Returns:
            list[dict]: List of {'event_type': name, 'count': total}.
        """
        return query_db(
            """SELECT event_type, COUNT(*) as count
               FROM events
               GROUP BY event_type
               ORDER BY count DESC
               LIMIT ?""",
            (limit,)
        )

    @staticmethod
    def get_recent_events(limit=10):
        """Retrieve the latest observed honeypot events.

        Args:
            limit (int): Number of recent records to retrieve.

        Returns:
            list[dict]: List of event records.
        """
        return query_db(
            """SELECT id, timestamp, source_ip, protocol, event_type, severity, username, command
               FROM events
               ORDER BY id DESC
               LIMIT ?""",
            (limit,)
        )

    @staticmethod
    def get_common_credentials(limit=5):
        """Retrieve the most frequently attempted usernames during brute-force probes.

        Args:
            limit (int): Max usernames to return.

        Returns:
            list[dict]: List of {'username': name, 'count': total}.
        """
        return query_db(
            """SELECT username, COUNT(*) as count
               FROM events
               WHERE username IS NOT NULL AND TRIM(username) != ''
               GROUP BY username
               ORDER BY count DESC
               LIMIT ?""",
            (limit,)
        )

    @staticmethod
    def get_common_commands(limit=5):
        """Retrieve the most frequently executed shell commands in honeypot.

        Args:
            limit (int): Max commands to return.

        Returns:
            list[dict]: List of {'command': cmd, 'severity': sev, 'count': total}.
        """
        return query_db(
            """SELECT command, severity, COUNT(*) as count
               FROM events
               WHERE command IS NOT NULL AND TRIM(command) != ''
               GROUP BY command
               ORDER BY count DESC
               LIMIT ?""",
            (limit,)
        )
