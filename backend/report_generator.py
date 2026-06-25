# =============================================================
# THREAT REPORT GENERATOR
# Generates a professional PDF report of the analysis
# =============================================================

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime
import os

# Color scheme
DARK_BLUE = colors.HexColor('#0f1629')
BLUE = colors.HexColor('#38bdf8')
RED = colors.HexColor('#ef4444')
ORANGE = colors.HexColor('#fb923c')
YELLOW = colors.HexColor('#fbbf24')
GREEN = colors.HexColor('#22c55e')
GRAY = colors.HexColor('#94a3b8')
WHITE = colors.white
LIGHT_GRAY = colors.HexColor('#f1f5f9')

def severity_color(severity):
    return {
        'Critical': RED,
        'High': ORANGE,
        'Medium': YELLOW,
        'Low': GREEN,
        'Clean': GREEN
    }.get(severity, GRAY)

def generate_report(report_data, output_path):
    """
    Generates a PDF threat intelligence report.
    
    report_data should contain:
    - title: report title
    - analyst: analyst name
    - summary: executive summary text
    - threat_intel: list of IOC results from VirusTotal
    - log_findings: list of findings from log analyzer
    - recommendations: list of recommendation strings
    - overall_severity: Critical/High/Medium/Low/Clean
    """

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=0.75*inch,
        leftMargin=0.75*inch,
        topMargin=0.75*inch,
        bottomMargin=0.75*inch
    )

    styles = getSampleStyleSheet()
    story = []

    # ---- Custom styles ----
    title_style = ParagraphStyle('Title',
        parent=styles['Normal'],
        fontSize=22, fontName='Helvetica-Bold',
        textColor=DARK_BLUE, alignment=TA_CENTER, spaceAfter=6)

    subtitle_style = ParagraphStyle('Subtitle',
        parent=styles['Normal'],
        fontSize=11, textColor=GRAY,
        alignment=TA_CENTER, spaceAfter=4)

    section_style = ParagraphStyle('Section',
        parent=styles['Normal'],
        fontSize=13, fontName='Helvetica-Bold',
        textColor=DARK_BLUE, spaceBefore=14, spaceAfter=6)

    body_style = ParagraphStyle('Body',
        parent=styles['Normal'],
        fontSize=10, textColor=colors.HexColor('#334155'),
        spaceAfter=4, leading=14)

    # ---- HEADER ----
    story.append(Spacer(1, 0.2*inch))
    story.append(Paragraph("🛡️ SOC ASSISTANT", title_style))
    story.append(Paragraph("Threat Intelligence Report", subtitle_style))
    story.append(Paragraph(
        f"Generated: {datetime.now().strftime('%B %d, %Y at %H:%M')} | Analyst: {report_data.get('analyst','SOC Analyst')}",
        subtitle_style))
    story.append(HRFlowable(width="100%", thickness=2, color=BLUE, spaceAfter=14))

    # ---- SEVERITY BANNER ----
    severity = report_data.get('overall_severity', 'Low')
    sev_color = severity_color(severity)
    sev_table = Table([[f"OVERALL SEVERITY: {severity.upper()}"]], colWidths=[6.5*inch])
    sev_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), sev_color),
        ('TEXTCOLOR', (0,0), (-1,-1), WHITE),
        ('FONTNAME', (0,0), (-1,-1), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 14),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('TOPPADDING', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ('ROWBACKGROUNDS', (0,0), (-1,-1), [sev_color]),
    ]))
    story.append(sev_table)
    story.append(Spacer(1, 0.15*inch))

    # ---- EXECUTIVE SUMMARY ----
    story.append(Paragraph("Executive Summary", section_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BLUE, spaceAfter=8))
    summary = report_data.get('summary', 'No summary provided.')
    story.append(Paragraph(summary, body_style))

    # ---- THREAT INTELLIGENCE ----
    threat_intel = report_data.get('threat_intel', [])
    if threat_intel:
        story.append(Paragraph("Threat Intelligence Results", section_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=BLUE, spaceAfter=8))

        ioc_data = [['Indicator', 'Type', 'Verdict', 'Malicious', 'Country']]
        for t in threat_intel:
            if 'error' not in t:
                ioc_data.append([
                    t.get('value', 'N/A'),
                    t.get('type', 'N/A').upper(),
                    t.get('verdict', 'N/A'),
                    str(t.get('malicious', 0)),
                    t.get('country', 'N/A')
                ])

        ioc_table = Table(ioc_data, colWidths=[2.2*inch, 0.8*inch, 1.0*inch, 0.9*inch, 0.9*inch])
        ioc_style = [
            ('BACKGROUND', (0,0), (-1,0), DARK_BLUE),
            ('TEXTCOLOR', (0,0), (-1,0), WHITE),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [LIGHT_GRAY, WHITE]),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ]
        # Color verdict cells
        for i, row in enumerate(ioc_data[1:], 1):
            verdict = row[2]
            if verdict == 'Malicious':
                ioc_style.append(('TEXTCOLOR', (2,i), (2,i), RED))
                ioc_style.append(('FONTNAME', (2,i), (2,i), 'Helvetica-Bold'))
            elif verdict == 'Suspicious':
                ioc_style.append(('TEXTCOLOR', (2,i), (2,i), ORANGE))
            else:
                ioc_style.append(('TEXTCOLOR', (2,i), (2,i), GREEN))

        ioc_table.setStyle(TableStyle(ioc_style))
        story.append(ioc_table)
        story.append(Spacer(1, 0.1*inch))

    # ---- LOG ANALYSIS FINDINGS ----
    log_findings = report_data.get('log_findings', [])
    if log_findings:
        story.append(Paragraph("Log Analysis Findings", section_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=BLUE, spaceAfter=8))

        log_data = [['Attack Type', 'Severity', 'Occurrences', 'Description']]
        for f in log_findings:
            log_data.append([
                f.get('attack_type', 'N/A'),
                f.get('severity', 'N/A'),
                str(f.get('occurrences', 0)),
                f.get('description', 'N/A')[:60] + '...' if len(f.get('description','')) > 60 else f.get('description','')
            ])

        log_table = Table(log_data, colWidths=[1.6*inch, 0.9*inch, 0.9*inch, 3.3*inch])
        log_style = [
            ('BACKGROUND', (0,0), (-1,0), DARK_BLUE),
            ('TEXTCOLOR', (0,0), (-1,0), WHITE),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('ALIGN', (0,0), (2,-1), 'CENTER'),
            ('ALIGN', (3,0), (3,-1), 'LEFT'),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [LIGHT_GRAY, WHITE]),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('WORDWRAP', (3,0), (3,-1), True),
        ]
        for i, row in enumerate(log_data[1:], 1):
            sev = row[1]
            sev_c = severity_color(sev)
            log_style.append(('TEXTCOLOR', (1,i), (1,i), sev_c))
            log_style.append(('FONTNAME', (1,i), (1,i), 'Helvetica-Bold'))

        log_table.setStyle(TableStyle(log_style))
        story.append(log_table)
        story.append(Spacer(1, 0.1*inch))

    # ---- RECOMMENDATIONS ----
    recommendations = report_data.get('recommendations', [])
    if recommendations:
        story.append(Paragraph("Recommendations", section_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=BLUE, spaceAfter=8))
        for i, rec in enumerate(recommendations, 1):
            story.append(Paragraph(f"{i}. {rec}", body_style))

    # ---- FOOTER ----
    story.append(Spacer(1, 0.3*inch))
    story.append(HRFlowable(width="100%", thickness=0.5, color=GRAY))
    story.append(Spacer(1, 0.1*inch))
    story.append(Paragraph(
        "This report was generated by SOC Assistant — AI-powered Security Operations Center",
        ParagraphStyle('Footer', parent=styles['Normal'],
            fontSize=8, textColor=GRAY, alignment=TA_CENTER)))

    doc.build(story)
    return output_path

# Test it
if __name__ == '__main__':
    test_data = {
        "title": "Incident Report",
        "analyst": "Azin",
        "overall_severity": "Critical",
        "summary": "Analysis detected multiple critical threats including SQL injection and brute force attacks from IP 192.168.1.105. Immediate action required.",
        "threat_intel": [
            {"value": "185.220.101.45", "type": "ip", "verdict": "Malicious", "malicious": 16, "suspicious": 2, "country": "DE"},
            {"value": "8.8.8.8", "type": "ip", "verdict": "Clean", "malicious": 0, "suspicious": 0, "country": "US"}
        ],
        "log_findings": [
            {"attack_type": "Brute Force", "severity": "High", "occurrences": 45, "description": "Multiple failed SSH login attempts"},
            {"attack_type": "SQL Injection", "severity": "Critical", "occurrences": 3, "description": "UNION SELECT detected in web requests"}
        ],
        "recommendations": [
            "Immediately isolate affected systems from the network",
            "Block malicious IP 185.220.101.45 at the firewall",
            "Reset all passwords and enable MFA",
            "Review database for unauthorized access",
            "Escalate to senior SOC analyst"
        ]
    }

    path = '/Users/aziniftikhar/soc_assistant/threat_report.pdf'
    generate_report(test_data, path)
    print(f"Report generated: {path}")
    import subprocess
    subprocess.run(['open', path])
