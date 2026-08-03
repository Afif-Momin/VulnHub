import io
from pathlib import Path
from typing import List, Dict, Any
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

from backend.models.finding import Finding

class ReportBuilder:
    """
    Generates PDF and JSON vulnerability assessment reports.
    Supports executive summary layout and technical findings details layout.
    """

    def __init__(self, findings: List[Finding]):
        self.findings = findings

    def generate_json_report(self) -> Dict[str, Any]:
        """Generate structured JSON report representation."""
        # Calculate summary statistics
        total = len(self.findings)
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        tool_counts = {}
        host_vulns = {}

        for f in self.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
            tool_counts[f.source_tool] = tool_counts.get(f.source_tool, 0) + 1
            host_vulns[f.host] = host_vulns.get(f.host, 0) + 1

        return {
            "summary": {
                "total_findings": total,
                "severities": severity_counts,
                "scanners": tool_counts,
                "top_affected_hosts": dict(sorted(host_vulns.items(), key=lambda item: item[1], reverse=True)[:5])
            },
            "findings": [f.model_dump() for f in self.findings]
        }

    def generate_pdf_report(self, mode: str = "technical") -> bytes:
        """
        Generate a PDF report in-memory and return raw bytes.
        Modes: 'technical' or 'executive'.
        """
        buffer = io.BytesIO()
        
        # Build Page Template
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=54,
            leftMargin=54,
            topMargin=54,
            bottomMargin=54
        )

        styles = getSampleStyleSheet()
        
        # Custom styles for look & feel
        style_title = ParagraphStyle(
            name="ReportTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=24,
            leading=28,
            textColor=colors.HexColor("#1A365D"),
            alignment=0, # Left-aligned
            spaceAfter=20
        )
        
        style_h1 = ParagraphStyle(
            name="ReportH1",
            parent=styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=16,
            leading=20,
            textColor=colors.HexColor("#2B6CB0"),
            spaceBefore=15,
            spaceAfter=10,
            keepWithNext=True
        )

        style_h2 = ParagraphStyle(
            name="ReportH2",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=16,
            textColor=colors.HexColor("#2D3748"),
            spaceBefore=10,
            spaceAfter=6,
            keepWithNext=True
        )

        style_body = ParagraphStyle(
            name="ReportBody",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#2D3748"),
            spaceAfter=8
        )

        style_bold = ParagraphStyle(
            name="ReportBold",
            parent=style_body,
            fontName="Helvetica-Bold"
        )

        style_code = ParagraphStyle(
            name="ReportCode",
            parent=styles["Code"],
            fontName="Courier",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#1A202C"),
            backColor=colors.HexColor("#EDF2F7"),
            borderPadding=6,
            spaceAfter=8
        )

        story = []

        # Header Title
        title_text = "Vulnerability Assessment Report"
        if mode == "executive":
            title_text += " - Executive Summary"
        else:
            title_text += " - Technical Analysis"
            
        story.append(Paragraph(title_text, style_title))
        story.append(Spacer(1, 10))

        # Generate summary counts
        total = len(self.findings)
        sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in self.findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

        # Summary KPIs block (Table)
        summary_data = [
            ["Total Findings", "Critical", "High", "Medium", "Low", "Info"],
            [
                str(total),
                str(sev_counts["Critical"]),
                str(sev_counts["High"]),
                str(sev_counts["Medium"]),
                str(sev_counts["Low"]),
                str(sev_counts["Info"])
            ]
        ]
        
        t = Table(summary_data, colWidths=[1.2*inch]*6)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1A365D")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 10),
            ('BOTTOMPADDING', (0,0), (-1,0), 6),
            ('BACKGROUND', (0,1), (-1,1), colors.HexColor("#F7FAFC")),
            ('TEXTCOLOR', (0,1), (-1,1), colors.HexColor("#2D3748")),
            ('FONTNAME', (0,1), (-1,1), 'Helvetica'),
            ('FONTSIZE', (0,1), (-1,1), 12),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ]))
        
        story.append(t)
        story.append(Spacer(1, 20))

        if mode == "executive":
            # Executive Summary Section
            story.append(Paragraph("Executive Summary", style_h1))
            story.append(Paragraph(
                "This report summarizes the security posture details found during recent automated vulnerability assessments. "
                "The scanning processes included Nmap infrastructure scans, active web checks, and network vulnerability tasks.",
                style_body
            ))
            
            # Action Priorities table
            story.append(Paragraph("Remediation Priorities & Strategy", style_h2))
            story.append(Paragraph(
                "Critical and High severity issues present immediate risks and should be remediated within 24 to 72 hours. "
                "Medium findings should be planned during standard maintenance windows, while Low and Info items can be addressed "
                "according to long-term engineering capacity cycles.",
                style_body
            ))

            # Unique affected hosts count
            affected_hosts = set(f.host for f in self.findings)
            story.append(Paragraph(f"Total Unique Targets Scanned: {len(affected_hosts)}", style_bold))
            for host in sorted(affected_hosts):
                host_vulns = [f for f in self.findings if f.host == host]
                criticals = len([f for f in host_vulns if f.severity == "Critical"])
                highs = len([f for f in host_vulns if f.severity == "High"])
                mediums = len([f for f in host_vulns if f.severity == "Medium"])
                
                story.append(Paragraph(
                    f"• <b>{host}</b>: {len(host_vulns)} findings ({criticals} Critical, {highs} High, {mediums} Medium)",
                    style_body
                ))

        else:
            # Technical Details Section
            story.append(Paragraph("Detailed Findings", style_h1))
            
            if not self.findings:
                story.append(Paragraph("No findings recorded in this report.", style_body))
            else:
                for idx, f in enumerate(self.findings, 1):
                    # Severity color helper
                    sev_colors = {
                        "Critical": "#E53E3E",
                        "High": "#ED8936",
                        "Medium": "#ECC94B",
                        "Low": "#4299E1",
                        "Info": "#A0AEC0"
                    }
                    sev_color = sev_colors.get(f.severity, "#718096")
                    
                    # Finding title line with severity badge
                    title_text = f"<b>{idx}. [{f.severity}] {f.title}</b>"
                    
                    finding_elements = []
                    finding_elements.append(Paragraph(title_text, ParagraphStyle(
                        name=f"FTitle_{idx}", parent=style_h2, textColor=colors.HexColor(sev_color)
                    )))
                    
                    # Finding metadata table
                    meta_data = [
                        [
                            Paragraph(f"<b>Host:</b> {f.host}", style_body),
                            Paragraph(f"<b>Port:</b> {f.port or 'N/A'}/{f.protocol or 'N/A'}", style_body)
                        ],
                        [
                            Paragraph(f"<b>Tool:</b> {f.source_tool}", style_body),
                            Paragraph(f"<b>Service:</b> {f.service or 'N/A'}", style_body)
                        ]
                    ]
                    
                    if f.cve or f.cvss:
                        meta_data.append([
                            Paragraph(f"<b>CVE:</b> {f.cve or 'N/A'}", style_body),
                            Paragraph(f"<b>CVSS:</b> {f.cvss or 'N/A'}", style_body)
                        ])

                    meta_table = Table(meta_data, colWidths=[3.2*inch, 3.2*inch])
                    meta_table.setStyle(TableStyle([
                        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                        ('BOTTOMPADDING', (0,0), (-1,-1), 2),
                        ('TOPPADDING', (0,0), (-1,-1), 2),
                    ]))
                    finding_elements.append(meta_table)
                    finding_elements.append(Spacer(1, 4))
                    
                    # Description
                    finding_elements.append(Paragraph("<b>Description:</b>", style_bold))
                    finding_elements.append(Paragraph(f.description, style_body))
                    
                    # Remediation Text
                    if f.remediation_text:
                        finding_elements.append(Paragraph("<b>Remediation Guidance:</b>", style_bold))
                        finding_elements.append(Paragraph(f.remediation_text, style_body))
                        
                    # Raw evidence (if available)
                    if f.raw_evidence:
                        finding_elements.append(Paragraph("<b>Evidence:</b>", style_bold))
                        # Limit evidence length to prevent giant tables breaking ReportLab flow
                        ev_text = f.raw_evidence[:600] + ("..." if len(f.raw_evidence) > 600 else "")
                        finding_elements.append(Paragraph(ev_text.replace("<", "&lt;").replace(">", "&gt;"), style_code))
                        
                    finding_elements.append(Spacer(1, 15))
                    
                    # Use KeepTogether to ensure a single finding doesn't split awkwardly across pages
                    story.append(KeepTogether(finding_elements))

        # Build Document
        doc.build(story)
        pdf_data = buffer.getvalue()
        buffer.close()
        return pdf_data
