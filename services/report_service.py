"""Security Report Generation Service

Generates professional executive PDF security reports using ReportLab
and formatted CSV telemetry datasets for compliance and incident analysis.
"""

import io
import csv
from datetime import datetime, timezone
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

from database.db import query_db, log_system_event
from services.statistics_service import StatisticsService


class ReportService:
    """Service for generating cybersecurity audit reports and telemetry data exports."""

    @classmethod
    def generate_pdf_report(cls, min_severity='LOW'):
        """Generate an executive security analysis PDF report in memory.

        Args:
            min_severity (str): Minimum severity threshold for included incidents.

        Returns:
            bytes: Generated PDF binary data.
        """
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()
        
        # Custom ReportLab Typography Styles
        title_style = ParagraphStyle(
            'ReportTitle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=22,
            leading=26,
            textColor=colors.HexColor('#0f172a'),
            spaceAfter=4
        )
        subtitle_style = ParagraphStyle(
            'ReportSubtitle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=10,
            textColor=colors.HexColor('#64748b'),
            spaceAfter=15
        )
        section_heading = ParagraphStyle(
            'SectionHeading',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=13,
            leading=16,
            textColor=colors.HexColor('#1e293b'),
            spaceBefore=12,
            spaceAfter=6
        )
        body_style = ParagraphStyle(
            'ReportBody',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            leading=13,
            textColor=colors.HexColor('#334155'),
            spaceAfter=8
        )
        disclaimer_style = ParagraphStyle(
            'ReportDisclaimer',
            parent=styles['Italic'],
            fontName='Helvetica-Oblique',
            fontSize=8,
            leading=11,
            textColor=colors.HexColor('#64748b')
        )
        table_header_style = ParagraphStyle(
            'TableHeader',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=8.5,
            textColor=colors.white,
            alignment=1
        )
        table_cell_style = ParagraphStyle(
            'TableCell',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=8,
            leading=10,
            textColor=colors.HexColor('#1e293b')
        )
        code_cell_style = ParagraphStyle(
            'CodeCell',
            parent=styles['Normal'],
            fontName='Courier',
            fontSize=7.5,
            leading=9,
            textColor=colors.HexColor('#b91c1c')
        )

        elements = []

        # 1. Header Banner & Title
        elements.append(Paragraph("SENTINEL HONEYPOT SECURITY AUDIT REPORT", title_style))
        gen_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        elements.append(Paragraph(f"Autonomous Incident Analysis & Telemetry Assessment | Generated: {gen_time}", subtitle_style))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0284c7'), spaceAfter=15))

        # 2. Executive Summary Metrics
        metrics = StatisticsService.get_summary_metrics()
        sev_dist = StatisticsService.get_severity_distribution()
        top_ips = StatisticsService.get_top_source_ips(limit=5)

        elements.append(Paragraph("1. Executive Summary & Telemetry Overview", section_heading))
        summary_text = (
            f"During the active monitoring period, the honeypot detection engine captured a total of "
            f"<b>{metrics['total_events']}</b> suspicious interactions originating from <b>{metrics['unique_ips']}</b> "
            f"unique attacker IP addresses. A total of <b>{metrics['critical_events']}</b> critical threat payloads "
            f"and <b>{metrics['high_events']}</b> high-severity unauthorized access attempts were identified and classified "
            f"using transparent, deterministic security heuristics without AI/ML non-determinism."
        )
        elements.append(Paragraph(summary_text, body_style))

        # Key Metrics Table
        summary_data = [
            [
                Paragraph("<b>Total Logged Events</b>", table_cell_style),
                Paragraph(str(metrics['total_events']), table_cell_style),
                Paragraph("<b>Unique Source IPs</b>", table_cell_style),
                Paragraph(str(metrics['unique_ips']), table_cell_style)
            ],
            [
                Paragraph("<b>Critical Threat Alerts</b>", table_cell_style),
                Paragraph(str(metrics['critical_events']), table_cell_style),
                Paragraph("<b>High-Severity Incidents</b>", table_cell_style),
                Paragraph(str(metrics['high_events']), table_cell_style)
            ]
        ]
        sum_table = Table(summary_data, colWidths=[1.8 * inch, 1.0 * inch, 1.8 * inch, 1.0 * inch])
        sum_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('PADDING', (0, 0), (-1, -1), 5),
        ]))
        elements.append(sum_table)
        elements.append(Spacer(1, 12))

        # 3. Severity Distribution Breakdown
        elements.append(Paragraph("2. Threat Severity Classification Breakdown", section_heading))
        total_ev = max(metrics['total_events'], 1)
        sev_table_data = [
            [
                Paragraph("Severity Level", table_header_style),
                Paragraph("Observed Events", table_header_style),
                Paragraph("Percentage", table_header_style),
                Paragraph("Heuristic Classification Rationale", table_header_style)
            ],
            [
                Paragraph("<b>CRITICAL</b>", table_cell_style),
                Paragraph(str(sev_dist.get('CRITICAL', 0)), table_cell_style),
                Paragraph(f"{(sev_dist.get('CRITICAL', 0) / total_ev) * 100:.1f}%", table_cell_style),
                Paragraph("Malicious payload injection, reverse shells, shadow/passwd dumping, miner droppers", table_cell_style)
            ],
            [
                Paragraph("<b>HIGH</b>", table_cell_style),
                Paragraph(str(sev_dist.get('HIGH', 0)), table_cell_style),
                Paragraph(f"{(sev_dist.get('HIGH', 0) / total_ev) * 100:.1f}%", table_cell_style),
                Paragraph("Successful honeypot authentication, arbitrary shell command execution", table_cell_style)
            ],
            [
                Paragraph("<b>MEDIUM</b>", table_cell_style),
                Paragraph(str(sev_dist.get('MEDIUM', 0)), table_cell_style),
                Paragraph(f"{(sev_dist.get('MEDIUM', 0) / total_ev) * 100:.1f}%", table_cell_style),
                Paragraph("Single failed credential attempts, host reconnaissance (uname, whoami, id)", table_cell_style)
            ],
            [
                Paragraph("<b>LOW</b>", table_cell_style),
                Paragraph(str(sev_dist.get('LOW', 0)), table_cell_style),
                Paragraph(f"{(sev_dist.get('LOW', 0) / total_ev) * 100:.1f}%", table_cell_style),
                Paragraph("TCP handshakes, client protocol banners, session termination events", table_cell_style)
            ]
        ]
        sev_table = Table(sev_table_data, colWidths=[1.1 * inch, 0.9 * inch, 0.8 * inch, 4.0 * inch])
        sev_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f172a')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('PADDING', (0, 0), (-1, -1), 4),
            ('TEXTCOLOR', (0, 1), (0, 1), colors.HexColor('#dc2626')),
            ('TEXTCOLOR', (0, 2), (0, 2), colors.HexColor('#ea580c')),
            ('TEXTCOLOR', (0, 3), (0, 3), colors.HexColor('#0284c7')),
            ('TEXTCOLOR', (0, 4), (0, 4), colors.HexColor('#16a34a')),
        ]))
        elements.append(sev_table)
        elements.append(Spacer(1, 12))

        # 4. Top Attacker Entities
        elements.append(Paragraph("3. Top Threat Entities (Attacker Source IPs)", section_heading))
        top_ip_rows = [
            [
                Paragraph("Source IP Address", table_header_style),
                Paragraph("Total Probes", table_header_style),
                Paragraph("High/Critical Probes", table_header_style),
                Paragraph("Threat Level", table_header_style)
            ]
        ]
        for ip_data in top_ips:
            crit_count = ip_data['threat_count'] or 0
            threat_badge = "CRITICAL / HIGH" if crit_count > 0 else "SCANNER / PROBE"
            top_ip_rows.append([
                Paragraph(f"<b>{ip_data['source_ip']}</b>", table_cell_style),
                Paragraph(str(ip_data['count']), table_cell_style),
                Paragraph(str(crit_count), table_cell_style),
                Paragraph(threat_badge, table_cell_style)
            ])

        if len(top_ip_rows) == 1:
            top_ip_rows.append([Paragraph("No IP telemetry available", table_cell_style), "-", "-", "-"])

        ip_table = Table(top_ip_rows, colWidths=[2.2 * inch, 1.2 * inch, 1.6 * inch, 1.8 * inch])
        ip_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(ip_table)
        elements.append(Spacer(1, 12))

        # 5. Recent High-Severity Incidents Table
        elements.append(Paragraph("4. Critical & High Threat Telemetry Samples", section_heading))
        incidents = query_db(
            """SELECT timestamp, source_ip, protocol, event_type, severity, username, command
               FROM events
               WHERE severity IN ('HIGH', 'CRITICAL')
               ORDER BY id DESC
               LIMIT 8"""
        )
        incident_rows = [
            [
                Paragraph("Timestamp", table_header_style),
                Paragraph("Source IP", table_header_style),
                Paragraph("Severity", table_header_style),
                Paragraph("Extracted Credential / Shell Command", table_header_style)
            ]
        ]
        for inc in incidents:
            payload = inc['command'] if inc['command'] else (f"User: {inc['username']}" if inc['username'] else inc['event_type'])
            incident_rows.append([
                Paragraph(str(inc['timestamp']), table_cell_style),
                Paragraph(str(inc['source_ip']), table_cell_style),
                Paragraph(f"<b>{inc['severity']}</b>", table_cell_style),
                Paragraph(payload, code_cell_style if inc['command'] else table_cell_style)
            ])

        if len(incident_rows) == 1:
            incident_rows.append([Paragraph("No critical incidents recorded", table_cell_style), "-", "-", "-"])

        inc_table = Table(incident_rows, colWidths=[1.8 * inch, 1.3 * inch, 0.9 * inch, 2.8 * inch])
        inc_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#334155')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(inc_table)
        elements.append(Spacer(1, 15))

        # 6. Academic & Research Disclaimer
        elements.append(Paragraph("5. Research Notice & Academic Disclaimer", section_heading))
        disclaimer_text = (
            "<b>Evaluation Notice:</b> This security report was generated by the <i>Honeypot-Based Attack Monitoring "
            "and Security Analysis System</i> (3rd-Year BCA Cyber Security Major Project). All telemetry data was captured "
            "inside an isolated, controlled laboratory honeypot trap. No offensive or retaliatory actions were performed. "
            "The classifications shown reflect observed trap telemetry analyzed via deterministic heuristic signatures."
        )
        elements.append(Paragraph(disclaimer_text, disclaimer_style))

        # Build Document
        doc.build(elements)
        pdf_bytes = buffer.getvalue()
        buffer.close()

        log_system_event("INFO", f"Generated executive security PDF report ({len(pdf_bytes)} bytes).")
        return pdf_bytes

    @classmethod
    def generate_csv_export(cls):
        """Export all normalized honeypot telemetry events as a CSV stream.

        Returns:
            str: CSV text content.
        """
        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

        # Write CSV Header
        writer.writerow([
            'id',
            'timestamp_utc',
            'source_ip',
            'source_port',
            'destination_port',
            'protocol',
            'event_type',
            'severity',
            'username_attempted',
            'command_injected',
            'ingested_at'
        ])

        events = query_db("SELECT * FROM events ORDER BY id ASC")
        for ev in events:
            writer.writerow([
                ev['id'],
                ev['timestamp'],
                ev['source_ip'],
                ev['source_port'] or '',
                ev['destination_port'] or '',
                ev['protocol'],
                ev['event_type'],
                ev['severity'],
                ev['username'] or '',
                ev['command'] or '',
                ev['created_at']
            ])

        csv_content = output.getvalue()
        output.close()

        log_system_event("INFO", f"Exported {len(events)} telemetry records to CSV.")
        return csv_content
