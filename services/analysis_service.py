"""Analysis Service Module

Provides incident investigation, IP profile aggregation, and detailed event querying.
"""

from database.db import query_db


class AnalysisService:
    """Service to handle deep event analysis and attacker profiling."""

    @staticmethod
    def get_event_by_id(event_id):
        """Retrieve full details of a specific event including raw payload.

        Args:
            event_id (int): Primary key ID of the event.

        Returns:
            sqlite3.Row | None: Event details or None if not found.
        """
        return query_db(
            "SELECT * FROM events WHERE id = ?",
            (event_id,),
            one=True
        )

    @staticmethod
    def get_attacker_profile(source_ip):
        """Aggregate all observed activity for a specific attacker source IP.

        Args:
            source_ip (str): Attacker IPv4/IPv6 address.

        Returns:
            dict: Attacker summary profile and event history.
        """
        summary_row = query_db(
            """SELECT COUNT(*) as total_events,
                      MIN(timestamp) as first_seen,
                      MAX(timestamp) as last_seen,
                      SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count,
                      SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high_count
               FROM events
               WHERE source_ip = ?""",
            (source_ip,),
            one=True
        )

        credentials = query_db(
            """SELECT username, COUNT(*) as count
               FROM events
               WHERE source_ip = ? AND username IS NOT NULL
               GROUP BY username
               ORDER BY count DESC""",
            (source_ip,)
        )

        commands = query_db(
            """SELECT command, severity, timestamp
               FROM events
               WHERE source_ip = ? AND command IS NOT NULL
               ORDER BY id DESC""",
            (source_ip,)
        )

        events_timeline = query_db(
            """SELECT id, timestamp, event_type, severity, protocol, username, command
               FROM events
               WHERE source_ip = ?
               ORDER BY id DESC
               LIMIT 50""",
            (source_ip,)
        )

        return {
            'source_ip': source_ip,
            'summary': summary_row,
            'credentials_tried': credentials,
            'commands_executed': commands,
            'recent_events': events_timeline
        }
