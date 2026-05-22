# generate_report.py
import os
import json
import sqlite3
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.pdfgen import canvas
from core.remediation import get_remediations_for_headers

DB_FILE = "archon_data.db"
PDF_FILE = "security_posture_summary.pdf"

class NumberedCanvas(canvas.Canvas):
    """
    A canvas that enables two-pass rendering to dynamically compute total pages 
    and output a standardized header and footer on all pages.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_decorations(self, page_count):
        self.saveState()
        
        # Primary Color: Deep Navy, Accent Color: Teal
        navy = HexColor('#0B0F19')
        slate = HexColor('#64748B')
        border_color = HexColor('#E2E8F0')
        
        # 1. Header (Only on pages > 1)
        if self._pageNumber > 1:
            self.setFont("Helvetica-Bold", 8)
            self.setFillColor(navy)
            self.drawString(54, 792 - 36, "SECURITY POSTURE EXECUTIVE SUMMARY")
            
            self.setFont("Helvetica", 8)
            self.setFillColor(slate)
            self.drawRightString(612 - 54, 792 - 36, datetime.now().strftime("%B %d, %Y | %H:%M"))
            
            self.setStrokeColor(border_color)
            self.setLineWidth(0.5)
            self.line(54, 792 - 42, 612 - 54, 792 - 42)
            
        # 2. Footer (On all pages)
        self.setFont("Helvetica", 8)
        self.setFillColor(slate)
        self.drawString(54, 30, "CONFIDENTIAL - ARCHON SECURITY AUDIT & SCANNING SYSTEM")
        
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(612 - 54, 30, page_text)
        
        self.setStrokeColor(border_color)
        self.setLineWidth(0.5)
        self.line(54, 42, 612 - 54, 42)
        
        self.restoreState()

def fetch_data():
    """Queries target findings and background alerts from archon_data.db."""
    if not os.path.exists(DB_FILE):
        raise FileNotFoundError(f"Database file '{DB_FILE}' not found.")
        
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Get scan findings
    c.execute("SELECT target, connector, data, timestamp FROM scan_findings")
    findings_raw = c.fetchall()
    
    # Get alerts
    c.execute("SELECT type, target, message, timestamp FROM alerts ORDER BY timestamp DESC")
    alerts_raw = c.fetchall()
    
    conn.close()
    return findings_raw, alerts_raw

def build_pdf():
    findings_raw, alerts_raw = fetch_data()
    
    # Parse findings by target
    findings_by_target = {}
    for target, connector, data_str, timestamp in findings_raw:
        try:
            data = json.loads(data_str)
        except Exception:
            data = data_str
            
        if target not in findings_by_target:
            findings_by_target[target] = {
                "status": "Offline",
                "ports": [],
                "vulns": [],
                "shodan": None,
                "censys": None,
                "scout": None
            }
            
        if connector == "ArchonEyes":
            findings_by_target[target]["status"] = data.get("status", "Offline")
            exposed = data.get("exposed_ports", {})
            findings_by_target[target]["ports"] = list(exposed.keys())
            findings_by_target[target]["vulns"] = data.get("vulnerabilities_detected", [])
        elif connector == "Shodan":
            findings_by_target[target]["shodan"] = data
        elif connector == "Censys":
            findings_by_target[target]["censys"] = data
        elif connector == "ArchonScout":
            findings_by_target[target]["scout"] = data

    # Count parameters
    total_assets = len(findings_by_target)
    total_ports = sum(len(info["ports"]) for info in findings_by_target.values())
    
    all_vulns = []
    missing_headers = set()
    for target, info in findings_by_target.items():
        for v in info["vulns"]:
            all_vulns.append((target, v))
            vuln_name = v.get("vulnerability", "")
            hdr = vuln_name.replace("Missing ", "").strip()
            if hdr:
                missing_headers.add(hdr)
                
    total_gaps = len(all_vulns)
    total_alerts = len(alerts_raw)

    # Setup styles
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'CoverTitle',
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=30,
        textColor=HexColor('#0B0F19'),
        spaceAfter=6
    )
    
    subtitle_style = ParagraphStyle(
        'CoverSubtitle',
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=HexColor('#0EA5E9'),
        spaceAfter=25
    )
    
    h1_style = ParagraphStyle(
        'Heading1',
        fontName='Helvetica-Bold',
        fontSize=16,
        leading=20,
        textColor=HexColor('#0B0F19'),
        spaceBefore=18,
        spaceAfter=10,
        keepWithNext=True
    )

    h2_style = ParagraphStyle(
        'Heading2',
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=15,
        textColor=HexColor('#0D9488'),
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True
    )
    
    body_style = ParagraphStyle(
        'Body',
        fontName='Helvetica',
        fontSize=9.5,
        leading=13.5,
        textColor=HexColor('#334155'),
        spaceAfter=8
    )
    
    body_bold = ParagraphStyle(
        'BodyBold',
        parent=body_style,
        fontName='Helvetica-Bold'
    )
    
    code_style = ParagraphStyle(
        'Code',
        fontName='Courier',
        fontSize=8,
        leading=10,
        textColor=HexColor('#0F172A'),
        backColor=HexColor('#F8FAFC'),
        borderColor=HexColor('#E2E8F0'),
        borderWidth=0.5,
        borderPadding=6,
        spaceBefore=5,
        spaceAfter=8
    )
    
    kpi_style = ParagraphStyle(
        'KPI',
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        alignment=TA_CENTER,
        textColor=HexColor('#00FFD0')
    )
    
    kpi_lbl_style = ParagraphStyle(
        'KPILbl',
        fontName='Helvetica',
        fontSize=8,
        leading=10,
        alignment=TA_CENTER,
        textColor=HexColor('#94A3B8')
    )
    
    table_hdr_style = ParagraphStyle(
        'TableHdr',
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=11,
        textColor=HexColor('#FFFFFF')
    )
    
    table_body_style = ParagraphStyle(
        'TableBody',
        fontName='Helvetica',
        fontSize=8,
        leading=10.5,
        textColor=HexColor('#1E293B')
    )
    
    table_body_bold = ParagraphStyle(
        'TableBodyBold',
        parent=table_body_style,
        fontName='Helvetica-Bold'
    )

    doc = SimpleDocTemplate(
        PDF_FILE,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )
    
    story = []
    
    # ------------------ COVER PAGE / HEADER BLOCK ------------------
    story.append(Spacer(1, 15))
    story.append(Paragraph("ARCHON INTELLIGENCE ENGINE", subtitle_style))
    story.append(Paragraph("SECURITY POSTURE EXECUTIVE SUMMARY", title_style))
    story.append(Paragraph("Automated Vulnerability Scan, Threat Intelligence & Perimeter Audit Report", ParagraphStyle('Sub2', parent=body_style, fontSize=11, leading=15, textColor=HexColor('#64748B'))))
    story.append(Spacer(1, 15))
    
    # Metagrid table
    meta_data = [
        [
            Paragraph("<b>Target Domain / Scope:</b> Selected Assets (External Perimeter)", table_body_style),
            Paragraph("<b>Classification:</b> STAGE 1 - HIGHLY CONFIDENTIAL", table_body_style)
        ],
        [
            Paragraph(f"<b>Generated On:</b> {datetime.now().strftime('%B %d, %Y %H:%M')}", table_body_style),
            Paragraph("<b>Auditor Profile:</b> Archon Autonomous Agent Suite v2.0", table_body_style)
        ]
    ]
    meta_table = Table(meta_data, colWidths=[252, 252])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), HexColor('#F8FAFC')),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('BOX', (0,0), (-1,-1), 0.5, HexColor('#E2E8F0'))
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 20))
    
    # ------------------ KPI METRIC CARDS ------------------
    # 4 metrics cards
    kpi_data = [
        [
            Paragraph("Total Assets", kpi_lbl_style),
            Paragraph("Exposed Ports", kpi_lbl_style),
            Paragraph("Security Gaps", kpi_lbl_style),
            Paragraph("Watcher Alerts", kpi_lbl_style)
        ],
        [
            Paragraph(str(total_assets), kpi_style),
            Paragraph(str(total_ports), kpi_style),
            Paragraph(str(total_gaps), kpi_style),
            Paragraph(str(total_alerts), kpi_style)
        ]
    ]
    kpi_table = Table(kpi_data, colWidths=[126, 126, 126, 126])
    kpi_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), HexColor('#0B0F19')),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (0,-1), 8),
        ('BOTTOMPADDING', (0,0), (0,-1), 2),
        ('TOPPADDING', (0,1), (1,-1), 2),
        ('BOTTOMPADDING', (0,1), (1,-1), 8),
        ('INNERGRID', (0,0), (-1,-1), 0.5, HexColor('#1E293B')),
        ('BOX', (0,0), (-1,-1), 1, HexColor('#0EA5E9'))
    ]))
    story.append(kpi_table)
    story.append(Spacer(1, 20))
    
    # ------------------ EXECUTIVE SUMMARY SECTION ------------------
    story.append(Paragraph("1. Executive Summary", h1_style))
    intro_txt = (
        "This Executive Security Summary provides a consolidated view of findings compiled by the Archon Autonomous Security Suite. "
        "The system scanned the active target inventory to enumerate exposed network ports, test secure HTTP configuration, and retrieve "
        "passive intelligence from Shodan and Censys indexers. Simultaneously, the background Watcher daemon continuously monitored certificate "
        "transparency logs and subdomain updates to capture immediate threat variations. "
        "<br/><br/>"
        "<b>Key Takeaways:</b> Multiple assets are exposing legacy clear-text web interfaces (Port 80) and missing standard HTTP Security Headers. "
        "These deficiencies leave endpoints susceptible to Man-in-the-Middle (MITM) hijacking and Cross-Site Scripting (XSS). Immediate remediation "
        "is recommended for the critical gaps identified below."
    )
    story.append(Paragraph(intro_txt, body_style))
    story.append(Spacer(1, 10))
    
    # ------------------ ASSET OVERVIEW TABLE ------------------
    story.append(Paragraph("2. Asset Perimeter Summary", h1_style))
    
    asset_headers = ["Asset Target", "Ports Exposed", "Security Gaps", "Audit Status"]
    asset_data = [[Paragraph(h, table_hdr_style) for h in asset_headers]]
    
    for target, info in sorted(findings_by_target.items()):
        ports_str = ", ".join(info["ports"]) if info["ports"] else "None Detected"
        gaps_cnt = len(info["vulns"])
        
        status_color = "#EF4444" if gaps_cnt > 0 else "#10B981"
        status_str = f"<font color='{status_color}'><b>{gaps_cnt} Gaps</b></font>" if gaps_cnt > 0 else "<font color='#10B981'><b>Secure</b></font>"
        
        asset_data.append([
            Paragraph(target, table_body_bold),
            Paragraph(ports_str, table_body_style),
            Paragraph(str(gaps_cnt), table_body_style),
            Paragraph(status_str, table_body_style)
        ])
        
    asset_table = Table(asset_data, colWidths=[160, 120, 100, 124])
    asset_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), HexColor('#0B0F19')),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [HexColor('#FFFFFF'), HexColor('#F8FAFC')]),
        ('GRID', (0,0), (-1,-1), 0.5, HexColor('#E2E8F0'))
    ]))
    story.append(asset_table)
    story.append(PageBreak()) # Clean break to the next page
    
    # ------------------ DETECTED VULNERABILITIES TABLE ------------------
    story.append(Paragraph("3. Detailed Vulnerability Breakdown", h1_style))
    story.append(Paragraph("The following security gaps were detected by the ArchonEyes active connection auditing module. Each requires active configuration updates.", body_style))
    story.append(Spacer(1, 8))
    
    vuln_headers = ["Target Endpoint", "Severity", "Security Header Gap", "Threat Impact / Description"]
    vuln_data = [[Paragraph(h, table_hdr_style) for h in vuln_headers]]
    
    for target, v in all_vulns:
        severity = v.get("severity", "Medium")
        name = v.get("vulnerability", "Unknown")
        impact = v.get("threat_impact", "")
        
        sev_color = "#EF4444" if severity.lower() == "high" else "#F59E0B"
        sev_p = Paragraph(f"<font color='{sev_color}'><b>{severity}</b></font>", table_body_bold)
        
        vuln_data.append([
            Paragraph(target, table_body_bold),
            sev_p,
            Paragraph(name, table_body_style),
            Paragraph(impact, table_body_style)
        ])
        
    vuln_table = Table(vuln_data, colWidths=[110, 60, 150, 184])
    vuln_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), HexColor('#0B0F19')),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [HexColor('#FFFFFF'), HexColor('#F8FAFC')]),
        ('GRID', (0,0), (-1,-1), 0.5, HexColor('#E2E8F0'))
    ]))
    story.append(vuln_table)
    story.append(Spacer(1, 15))
    
    # ------------------ REMEDIATION CONFIG GENERATOR ------------------
    story.append(Paragraph("4. Recommended Hardening Actions", h1_style))
    story.append(Paragraph("To address the missing headers, apply the following standard configurations to your web server configurations.", body_style))
    
    # Call remediation module config generator
    remediations = get_remediations_for_headers(list(missing_headers))
    
    story.append(Paragraph("<b>Nginx Configuration Hardening:</b>", h2_style))
    clean_nginx = remediations["nginx"].replace("\n", "<br/>").replace(" ", "&nbsp;")
    story.append(Paragraph(clean_nginx, code_style))
    
    story.append(Paragraph("<b>Apache Hardening Header Block:</b>", h2_style))
    clean_apache = remediations["apache"].replace("\n", "<br/>").replace(" ", "&nbsp;")
    story.append(Paragraph(clean_apache, code_style))
    
    story.append(Spacer(1, 10))
    story.append(PageBreak())
    
    # ------------------ BACKGROUND MONITOR ALERTS TABLE ------------------
    story.append(Paragraph("5. Live Watcher Alerts Log", h1_style))
    story.append(Paragraph("Below is a log of critical background alerts registered by the daemon watcher checking subdomains and SSL certificates.", body_style))
    story.append(Spacer(1, 8))
    
    alert_headers = ["Timestamp", "Target Domain", "Alert Type", "Notification Message"]
    alert_data = [[Paragraph(h, table_hdr_style) for h in alert_headers]]
    
    for row in alerts_raw[:15]:  # show top 15 alerts
        atype, target, msg, ts = row
        alert_data.append([
            Paragraph(ts, table_body_style),
            Paragraph(target, table_body_bold),
            Paragraph(atype, table_body_style),
            Paragraph(msg, table_body_style)
        ])
        
    alert_table = Table(alert_data, colWidths=[110, 100, 94, 200])
    alert_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), HexColor('#0B0F19')),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [HexColor('#FFFFFF'), HexColor('#F8FAFC')]),
        ('GRID', (0,0), (-1,-1), 0.5, HexColor('#E2E8F0'))
    ]))
    story.append(alert_table)
    
    # Build Document using our NumberedCanvas
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"[Report] Successfully created PDF report: {PDF_FILE}")
    
    # Generate Markdown Report
    build_markdown(findings_by_target, all_vulns, alerts_raw, missing_headers, total_assets, total_ports, total_gaps, total_alerts)

def build_markdown(findings_by_target, all_vulns, alerts_raw, missing_headers, total_assets, total_ports, total_gaps, total_alerts):
    md_file = "security_posture_summary.md"
    timestamp = datetime.now().strftime("%B %d, %Y %H:%M")
    
    md_content = []
    md_content.append("# SECURITY POSTURE EXECUTIVE SUMMARY")
    md_content.append("**Automated Vulnerability Scan, Threat Intelligence & Perimeter Audit Report**\n")
    md_content.append(f"- **Scope:** Selected Assets (External Perimeter)")
    md_content.append(f"- **Classification:** STAGE 1 - HIGHLY CONFIDENTIAL")
    md_content.append(f"- **Generated On:** {timestamp}")
    md_content.append(f"- **Auditor Profile:** Archon Autonomous Agent Suite v2.0\n")
    md_content.append("---")
    
    md_content.append("\n## 1. Key Metrics\n")
    md_content.append("| Metric | Count |")
    md_content.append("| :--- | :--- |")
    md_content.append(f"| **Total Assets** | {total_assets} |")
    md_content.append(f"| **Exposed Ports** | {total_ports} |")
    md_content.append(f"| **Security Gaps** | {total_gaps} |")
    md_content.append(f"| **Watcher Alerts** | {total_alerts} |")
    md_content.append("\n---")
    
    md_content.append("\n## 2. Executive Summary\n")
    intro_txt = (
        "This Executive Security Summary provides a consolidated view of findings compiled by the Archon Autonomous Security Suite. "
        "The system scanned the active target inventory to enumerate exposed network ports, test secure HTTP configuration, and retrieve "
        "passive intelligence from Shodan and Censys indexers. Simultaneously, the background Watcher daemon continuously monitored certificate "
        "transparency logs and subdomain updates to capture immediate threat variations.\n\n"
        "**Key Takeaways:** Multiple assets are exposing legacy clear-text web interfaces (Port 80) and missing standard HTTP Security Headers. "
        "These deficiencies leave endpoints susceptible to Man-in-the-Middle (MITM) hijacking and Cross-Site Scripting (XSS). Immediate remediation "
        "is recommended for the critical gaps identified below."
    )
    md_content.append(intro_txt)
    md_content.append("\n---")
    
    md_content.append("\n## 3. Asset Perimeter Summary\n")
    md_content.append("| Asset Target | Ports Exposed | Security Gaps | Audit Status |")
    md_content.append("| :--- | :--- | :--- | :--- |")
    for target, info in sorted(findings_by_target.items()):
        ports_str = ", ".join(info["ports"]) if info["ports"] else "None Detected"
        gaps_cnt = len(info["vulns"])
        status_str = f"**{gaps_cnt} Gaps**" if gaps_cnt > 0 else "Secure"
        md_content.append(f"| `{target}` | {ports_str} | {gaps_cnt} | {status_str} |")
    md_content.append("\n---")
    
    md_content.append("\n## 4. Detailed Vulnerability Breakdown\n")
    md_content.append("| Target Endpoint | Severity | Security Header Gap | Threat Impact / Description |")
    md_content.append("| :--- | :--- | :--- | :--- |")
    for target, v in all_vulns:
        severity = v.get("severity", "Medium")
        name = v.get("vulnerability", "Unknown")
        impact = v.get("threat_impact", "")
        md_content.append(f"| `{target}` | **{severity}** | {name} | {impact} |")
    md_content.append("\n---")
    
    md_content.append("\n## 5. Recommended Hardening Actions\n")
    md_content.append("To address the missing headers, apply the following standard configurations to your web server configurations.\n")
    
    remediations = get_remediations_for_headers(list(missing_headers))
    md_content.append("### Nginx Configuration Hardening")
    md_content.append(f"```nginx\n{remediations['nginx']}\n```\n")
    md_content.append("### Apache Hardening Header Block")
    md_content.append(f"```apache\n{remediations['apache']}\n```\n")
    md_content.append("### Caddy Hardening Config")
    md_content.append(f"```caddy\n{remediations['caddy']}\n```")
    md_content.append("\n---")
    
    md_content.append("\n## 6. Live Watcher Alerts Log\n")
    md_content.append("| Timestamp | Target Domain | Alert Type | Notification Message |")
    md_content.append("| :--- | :--- | :--- | :--- |")
    for row in alerts_raw[:15]:
        atype, target, msg, ts = row
        md_content.append(f"| {ts} | `{target}` | {atype} | {msg} |")
        
    with open(md_file, "w", encoding="utf-8") as f:
        f.write("\n".join(md_content))
        
    print(f"[Report] Successfully created Markdown report: {md_file}")

if __name__ == "__main__":
    build_pdf()
