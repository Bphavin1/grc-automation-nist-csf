"""
GRC Automation Script — NIST CSF Compliance Report Generator
Author: Brian Pascal | github.com/Bphavin1
Description: Generates a professional PDF compliance report based on NIST CSF controls.
             Accepts control status input and produces CISO-ready output with scoring.
"""

import json
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

# ─── COLOR PALETTE ────────────────────────────────────────────────────────────
DARK_NAVY    = colors.HexColor("#0D1B2A")
ACCENT_BLUE  = colors.HexColor("#1B6CA8")
LIGHT_BLUE   = colors.HexColor("#4A9FD4")
SUCCESS      = colors.HexColor("#2ECC71")
WARNING      = colors.HexColor("#F39C12")
DANGER       = colors.HexColor("#E74C3C")
PARTIAL      = colors.HexColor("#F39C12")
LIGHT_GRAY   = colors.HexColor("#F4F6F8")
MID_GRAY     = colors.HexColor("#BDC3C7")
TEXT_DARK    = colors.HexColor("#2C3E50")
WHITE        = colors.white

# ─── NIST CSF CONTROL DEFINITIONS ────────────────────────────────────────────
CONTROLS = [
    # IDENTIFY
    {"id": "ID.AM-1", "function": "Identify", "category": "Asset Management",
     "description": "Physical devices and systems within the organization are inventoried.",
     "status": "Implemented"},
    {"id": "ID.AM-2", "function": "Identify", "category": "Asset Management",
     "description": "Software platforms and applications within the organization are inventoried.",
     "status": "Implemented"},
    {"id": "ID.AM-3", "function": "Identify", "category": "Asset Management",
     "description": "Organizational communication and data flows are mapped.",
     "status": "Partial"},
    {"id": "ID.AM-5", "function": "Identify", "category": "Asset Management",
     "description": "Resources (e.g., hardware, devices, data, time, personnel) are prioritized based on their classification, criticality, and business value.",
     "status": "Partial"},
    {"id": "ID.BE-1", "function": "Identify", "category": "Business Environment",
     "description": "The organization's role in the supply chain is identified and communicated.",
     "status": "Implemented"},
    {"id": "ID.BE-3", "function": "Identify", "category": "Business Environment",
     "description": "Priorities for organizational mission, objectives, and activities are established and communicated.",
     "status": "Implemented"},
    {"id": "ID.GV-1", "function": "Identify", "category": "Governance",
     "description": "Organizational cybersecurity policy is established and communicated.",
     "status": "Implemented"},
    {"id": "ID.GV-3", "function": "Identify", "category": "Governance",
     "description": "Legal and regulatory requirements regarding cybersecurity are understood and managed.",
     "status": "Partial"},
    {"id": "ID.RA-1", "function": "Identify", "category": "Risk Assessment",
     "description": "Asset vulnerabilities are identified and documented.",
     "status": "Implemented"},
    {"id": "ID.RA-3", "function": "Identify", "category": "Risk Assessment",
     "description": "Threats, both internal and external, are identified and documented.",
     "status": "Partial"},
    {"id": "ID.RA-5", "function": "Identify", "category": "Risk Assessment",
     "description": "Threats, vulnerabilities, likelihoods, and impacts are used to determine risk.",
     "status": "Implemented"},
    {"id": "ID.RM-1", "function": "Identify", "category": "Risk Management",
     "description": "Risk management processes are established, managed, and agreed to by stakeholders.",
     "status": "Not Implemented"},

    # PROTECT
    {"id": "PR.AC-1", "function": "Protect", "category": "Access Control",
     "description": "Identities and credentials are issued, managed, verified, revoked, and audited for authorized devices, users, and processes.",
     "status": "Implemented"},
    {"id": "PR.AC-3", "function": "Protect", "category": "Access Control",
     "description": "Remote access is managed.",
     "status": "Implemented"},
    {"id": "PR.AC-4", "function": "Protect", "category": "Access Control",
     "description": "Access permissions and authorizations are managed, incorporating the principles of least privilege and separation of duties.",
     "status": "Partial"},
    {"id": "PR.AC-5", "function": "Protect", "category": "Access Control",
     "description": "Network integrity is protected (e.g., network segregation, network segmentation).",
     "status": "Partial"},
    {"id": "PR.AT-1", "function": "Protect", "category": "Awareness & Training",
     "description": "All users are informed and trained.",
     "status": "Implemented"},
    {"id": "PR.AT-2", "function": "Protect", "category": "Awareness & Training",
     "description": "Privileged users understand their roles and responsibilities.",
     "status": "Implemented"},
    {"id": "PR.DS-1", "function": "Protect", "category": "Data Security",
     "description": "Data-at-rest is protected.",
     "status": "Implemented"},
    {"id": "PR.DS-2", "function": "Protect", "category": "Data Security",
     "description": "Data-in-transit is protected.",
     "status": "Implemented"},
    {"id": "PR.DS-5", "function": "Protect", "category": "Data Security",
     "description": "Protections against data leaks are implemented.",
     "status": "Partial"},
    {"id": "PR.IP-1", "function": "Protect", "category": "Info Protection",
     "description": "A baseline configuration of information technology/industrial control systems is created and maintained.",
     "status": "Not Implemented"},
    {"id": "PR.IP-3", "function": "Protect", "category": "Info Protection",
     "description": "Configuration change control processes are in place.",
     "status": "Partial"},
    {"id": "PR.MA-1", "function": "Protect", "category": "Maintenance",
     "description": "Maintenance and repair of organizational assets are performed and logged.",
     "status": "Implemented"},
    {"id": "PR.PT-1", "function": "Protect", "category": "Protective Technology",
     "description": "Audit/log records are determined, documented, implemented, and reviewed.",
     "status": "Implemented"},
    {"id": "PR.PT-3", "function": "Protect", "category": "Protective Technology",
     "description": "The principle of least functionality is incorporated by configuring systems to provide only essential capabilities.",
     "status": "Partial"},

    # DETECT
    {"id": "DE.AE-1", "function": "Detect", "category": "Anomaly & Events",
     "description": "A baseline of network operations and expected data flows is established and managed.",
     "status": "Partial"},
    {"id": "DE.AE-2", "function": "Detect", "category": "Anomaly & Events",
     "description": "Detected events are analyzed to understand attack targets and methods.",
     "status": "Implemented"},
    {"id": "DE.AE-3", "function": "Detect", "category": "Anomaly & Events",
     "description": "Event data are collected and correlated from multiple sources and sensors.",
     "status": "Implemented"},
    {"id": "DE.CM-1", "function": "Detect", "category": "Continuous Monitoring",
     "description": "The network is monitored to detect potential cybersecurity events.",
     "status": "Implemented"},
    {"id": "DE.CM-3", "function": "Detect", "category": "Continuous Monitoring",
     "description": "Personnel activity is monitored to detect potential cybersecurity events.",
     "status": "Partial"},
    {"id": "DE.CM-7", "function": "Detect", "category": "Continuous Monitoring",
     "description": "Monitoring for unauthorized personnel, connections, devices, and software is performed.",
     "status": "Partial"},
    {"id": "DE.DP-1", "function": "Detect", "category": "Detection Processes",
     "description": "Roles and responsibilities for detection are well defined to ensure accountability.",
     "status": "Implemented"},
    {"id": "DE.DP-4", "function": "Detect", "category": "Detection Processes",
     "description": "Event detection information is communicated.",
     "status": "Implemented"},

    # RESPOND
    {"id": "RS.RP-1", "function": "Respond", "category": "Response Planning",
     "description": "Response plan is executed during or after an incident.",
     "status": "Partial"},
    {"id": "RS.CO-1", "function": "Respond", "category": "Communications",
     "description": "Personnel know their roles and order of operations when a response is needed.",
     "status": "Implemented"},
    {"id": "RS.CO-3", "function": "Respond", "category": "Communications",
     "description": "Information is shared consistent with response plans.",
     "status": "Partial"},
    {"id": "RS.AN-1", "function": "Respond", "category": "Analysis",
     "description": "Notifications from detection systems are investigated.",
     "status": "Implemented"},
    {"id": "RS.AN-4", "function": "Respond", "category": "Analysis",
     "description": "Incidents are categorized consistent with response plans.",
     "status": "Implemented"},
    {"id": "RS.MI-1", "function": "Respond", "category": "Mitigation",
     "description": "Incidents are contained.",
     "status": "Partial"},
    {"id": "RS.MI-2", "function": "Respond", "category": "Mitigation",
     "description": "Incidents are mitigated.",
     "status": "Partial"},
    {"id": "RS.IM-1", "function": "Respond", "category": "Improvements",
     "description": "Response plans incorporate lessons learned.",
     "status": "Not Implemented"},

    # RECOVER
    {"id": "RC.RP-1", "function": "Recover", "category": "Recovery Planning",
     "description": "Recovery plan is executed during or after a cybersecurity incident.",
     "status": "Partial"},
    {"id": "RC.IM-1", "function": "Recover", "category": "Improvements",
     "description": "Recovery plans incorporate lessons learned.",
     "status": "Not Implemented"},
    {"id": "RC.IM-2", "function": "Recover", "category": "Improvements",
     "description": "Recovery strategies are updated.",
     "status": "Partial"},
    {"id": "RC.CO-1", "function": "Recover", "category": "Communications",
     "description": "Public relations are managed.",
     "status": "Not Implemented"},
    {"id": "RC.CO-3", "function": "Recover", "category": "Communications",
     "description": "Recovery activities are communicated to internal and external stakeholders.",
     "status": "Partial"},
]

# ─── SCORING LOGIC ────────────────────────────────────────────────────────────
STATUS_SCORE = {
    "Implemented":     1.0,
    "Partial":         0.5,
    "Not Implemented": 0.0,
}

def calculate_scores(controls):
    functions = ["Identify", "Protect", "Detect", "Respond", "Recover"]
    results = {}
    for func in functions:
        func_controls = [c for c in controls if c["function"] == func]
        if not func_controls:
            results[func] = {"score": 0, "pct": 0, "total": 0,
                             "implemented": 0, "partial": 0, "not_implemented": 0}
            continue
        total_possible = len(func_controls)
        earned = sum(STATUS_SCORE[c["status"]] for c in func_controls)
        implemented = sum(1 for c in func_controls if c["status"] == "Implemented")
        partial = sum(1 for c in func_controls if c["status"] == "Partial")
        not_impl = sum(1 for c in func_controls if c["status"] == "Not Implemented")
        results[func] = {
            "score": earned,
            "pct": round((earned / total_possible) * 100, 1),
            "total": total_possible,
            "implemented": implemented,
            "partial": partial,
            "not_implemented": not_impl,
        }
    all_earned = sum(STATUS_SCORE[c["status"]] for c in controls)
    overall_pct = round((all_earned / len(controls)) * 100, 1)
    return results, overall_pct

def score_color(pct):
    if pct >= 75:
        return SUCCESS
    elif pct >= 50:
        return WARNING
    else:
        return DANGER

def score_label(pct):
    if pct >= 75:
        return "COMPLIANT"
    elif pct >= 50:
        return "NEEDS IMPROVEMENT"
    else:
        return "NON-COMPLIANT"

# ─── REPORT BUILDER ───────────────────────────────────────────────────────────
def build_report(controls, output_path="NIST_CSF_Compliance_Report.pdf",
                 org_name="Acme Corporation", assessor="Brian Pascal",
                 assessment_date=None):

    if assessment_date is None:
        assessment_date = datetime.now().strftime("%B %d, %Y")

    scores, overall_pct = calculate_scores(controls)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    cover_title = ParagraphStyle("CoverTitle", fontSize=28, textColor=WHITE,
                                  alignment=TA_CENTER, fontName="Helvetica-Bold",
                                  spaceAfter=6)
    cover_sub = ParagraphStyle("CoverSub", fontSize=13, textColor=LIGHT_BLUE,
                                alignment=TA_CENTER, fontName="Helvetica",
                                spaceAfter=4)
    cover_meta = ParagraphStyle("CoverMeta", fontSize=10, textColor=MID_GRAY,
                                 alignment=TA_CENTER, fontName="Helvetica")
    section_header = ParagraphStyle("SectionHeader", fontSize=14, textColor=WHITE,
                                     fontName="Helvetica-Bold", alignment=TA_LEFT,
                                     spaceAfter=8, spaceBefore=12)
    body_style = ParagraphStyle("Body", fontSize=9, textColor=TEXT_DARK,
                                 fontName="Helvetica", spaceAfter=4, leading=14)
    small_label = ParagraphStyle("SmallLabel", fontSize=8, textColor=MID_GRAY,
                                  fontName="Helvetica")
    control_id_style = ParagraphStyle("CtrlID", fontSize=8, textColor=ACCENT_BLUE,
                                       fontName="Helvetica-Bold")
    control_desc_style = ParagraphStyle("CtrlDesc", fontSize=8, textColor=TEXT_DARK,
                                         fontName="Helvetica", leading=12)

    story = []

    # ── COVER PAGE ──────────────────────────────────────────────────────────
    # Dark background header block via table
    cover_data = [[Paragraph("NIST CSF COMPLIANCE ASSESSMENT", cover_title)]]
    cover_table = Table(cover_data, colWidths=[7.0 * inch])
    cover_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), DARK_NAVY),
        ("TOPPADDING", (0, 0), (-1, -1), 30),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 30),
        ("LEFTPADDING", (0, 0), (-1, -1), 20),
        ("RIGHTPADDING", (0, 0), (-1, -1), 20),
        ("ROUNDEDCORNERS", [8, 8, 8, 8]),
    ]))
    story.append(cover_table)
    story.append(Spacer(1, 20))

    story.append(Paragraph(f"Organization: {org_name}", cover_sub))
    story.append(Paragraph(f"Framework: NIST Cybersecurity Framework (CSF) v1.1", cover_sub))
    story.append(Spacer(1, 10))
    story.append(Paragraph(f"Assessment Date: {assessment_date}", cover_meta))
    story.append(Paragraph(f"Assessed By: {assessor}", cover_meta))
    story.append(Paragraph(f"Classification: CONFIDENTIAL", cover_meta))
    story.append(Spacer(1, 30))

    # Overall score badge
    badge_color = score_color(overall_pct)
    badge_label = score_label(overall_pct)
    badge_data = [[
        Paragraph(f"<b>OVERALL COMPLIANCE SCORE</b>", ParagraphStyle(
            "badge_label", fontSize=11, textColor=WHITE, fontName="Helvetica-Bold",
            alignment=TA_CENTER)),
        Paragraph(f"<b>{overall_pct}%</b>", ParagraphStyle(
            "badge_pct", fontSize=28, textColor=WHITE, fontName="Helvetica-Bold",
            alignment=TA_CENTER)),
        Paragraph(f"<b>{badge_label}</b>", ParagraphStyle(
            "badge_status", fontSize=11, textColor=WHITE, fontName="Helvetica-Bold",
            alignment=TA_CENTER)),
    ]]
    badge_table = Table(badge_data, colWidths=[2.5*inch, 1.5*inch, 3.0*inch])
    badge_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), badge_color),
        ("TOPPADDING", (0, 0), (-1, -1), 18),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 18),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(badge_table)
    story.append(Spacer(1, 30))

    # Controls summary on cover
    total_impl = sum(1 for c in controls if c["status"] == "Implemented")
    total_part = sum(1 for c in controls if c["status"] == "Partial")
    total_not  = sum(1 for c in controls if c["status"] == "Not Implemented")
    summary_data = [
        ["Total Controls", "Implemented", "Partial", "Not Implemented"],
        [str(len(controls)), str(total_impl), str(total_part), str(total_not)],
    ]
    summary_table = Table(summary_data, colWidths=[1.75*inch]*4)
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), DARK_NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("BACKGROUND", (0, 1), (-1, 1), LIGHT_GRAY),
        ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 1), (-1, 1), 16),
        ("TEXTCOLOR", (0, 1), (0, 1), TEXT_DARK),
        ("TEXTCOLOR", (1, 1), (1, 1), SUCCESS),
        ("TEXTCOLOR", (2, 1), (2, 1), WARNING),
        ("TEXTCOLOR", (3, 1), (3, 1), DANGER),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.5, MID_GRAY),
    ]))
    story.append(summary_table)
    story.append(PageBreak())

    # ── EXECUTIVE SUMMARY ───────────────────────────────────────────────────
    hdr = [[Paragraph("  EXECUTIVE SUMMARY", section_header)]]
    hdr_t = Table(hdr, colWidths=[7.0*inch])
    hdr_t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), DARK_NAVY),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(hdr_t)
    story.append(Spacer(1, 12))

    exec_text = (
        f"This report presents the results of a NIST Cybersecurity Framework (CSF) v1.1 "
        f"compliance assessment conducted for <b>{org_name}</b> on {assessment_date}. "
        f"The assessment evaluated {len(controls)} controls across the five NIST CSF functions: "
        f"Identify, Protect, Detect, Respond, and Recover."
    )
    story.append(Paragraph(exec_text, body_style))
    story.append(Spacer(1, 8))

    finding_text = (
        f"The organization achieved an overall compliance score of <b>{overall_pct}%</b>, "
        f"rated as <b>{score_label(overall_pct)}</b>. Of {len(controls)} total controls assessed, "
        f"{total_impl} are fully implemented, {total_part} are partially implemented, "
        f"and {total_not} have not been implemented. "
        f"Immediate remediation priority should be placed on the Not Implemented controls "
        f"within the Respond and Recover functions, as these represent the greatest risk exposure "
        f"during an active security incident."
    )
    story.append(Paragraph(finding_text, body_style))
    story.append(Spacer(1, 20))

    # Per-function score table
    func_header = ["CSF Function", "Controls", "Implemented", "Partial", "Not Impl.", "Score", "Status"]
    func_rows = [func_header]
    func_colors = {
        "Identify": colors.HexColor("#1B4F72"),
        "Protect":  colors.HexColor("#1A5276"),
        "Detect":   colors.HexColor("#154360"),
        "Respond":  colors.HexColor("#1B2631"),
        "Recover":  colors.HexColor("#0E2A3D"),
    }
    for func, data in scores.items():
        func_rows.append([
            func,
            str(data["total"]),
            str(data["implemented"]),
            str(data["partial"]),
            str(data["not_implemented"]),
            f"{data['pct']}%",
            score_label(data["pct"]),
        ])

    func_table = Table(func_rows, colWidths=[1.2*inch, 0.7*inch, 0.9*inch, 0.7*inch, 0.7*inch, 0.65*inch, 1.45*inch])
    ts = TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), DARK_NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [LIGHT_GRAY, WHITE]),
        ("GRID", (0, 0), (-1, -1), 0.5, MID_GRAY),
    ])
    # Color the Status column cells
    for i, (func, data) in enumerate(scores.items(), start=1):
        ts.add("TEXTCOLOR", (6, i), (6, i), score_color(data["pct"]))
        ts.add("FONTNAME", (6, i), (6, i), "Helvetica-Bold")
        ts.add("TEXTCOLOR", (5, i), (5, i), score_color(data["pct"]))
        ts.add("FONTNAME", (5, i), (5, i), "Helvetica-Bold")

    func_table.setStyle(ts)
    story.append(func_table)
    story.append(PageBreak())

    # ── FUNCTION BREAKDOWN PAGES ─────────────────────────────────────────────
    func_emojis = {
        "Identify": "ID",
        "Protect":  "PR",
        "Detect":   "DE",
        "Respond":  "RS",
        "Recover":  "RC",
    }

    for func in ["Identify", "Protect", "Detect", "Respond", "Recover"]:
        data = scores[func]
        prefix = func_emojis[func]

        # Function header bar
        hdr = [[Paragraph(f"  {func.upper()} ({prefix})", section_header)]]
        hdr_t = Table(hdr, colWidths=[7.0*inch])
        hdr_t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), DARK_NAVY),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(hdr_t)
        story.append(Spacer(1, 8))

        # Score badge row
        badge_data = [[
            Paragraph(f"<b>{data['pct']}%</b>", ParagraphStyle(
                "fn_pct", fontSize=22, textColor=score_color(data["pct"]),
                fontName="Helvetica-Bold", alignment=TA_CENTER)),
            Paragraph(f"<b>{score_label(data['pct'])}</b>", ParagraphStyle(
                "fn_status", fontSize=10, textColor=score_color(data["pct"]),
                fontName="Helvetica-Bold", alignment=TA_LEFT, spaceAfter=4)),
            Paragraph(
                f"Implemented: <b>{data['implemented']}</b>     "
                f"Partial: <b>{data['partial']}</b>     "
                f"Not Implemented: <b>{data['not_implemented']}</b>",
                ParagraphStyle("fn_counts", fontSize=8, textColor=TEXT_DARK,
                               fontName="Helvetica", alignment=TA_LEFT)),
        ]]
        badge_t = Table(badge_data, colWidths=[1.0*inch, 1.5*inch, 4.5*inch])
        badge_t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), LIGHT_GRAY),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LEFTPADDING", (0, 0), (-1, -1), 12),
            ("BOX", (0, 0), (-1, -1), 1, MID_GRAY),
        ]))
        story.append(badge_t)
        story.append(Spacer(1, 12))

        # Control detail table
        ctrl_header = ["Control ID", "Category", "Description", "Status"]
        ctrl_rows = [ctrl_header]
        func_controls = [c for c in controls if c["function"] == func]
        for c in func_controls:
            ctrl_rows.append([
                Paragraph(c["id"], control_id_style),
                Paragraph(c["category"], ParagraphStyle("cat", fontSize=8,
                           textColor=TEXT_DARK, fontName="Helvetica-Bold")),
                Paragraph(c["description"], control_desc_style),
                c["status"],
            ])

        ctrl_table = Table(ctrl_rows, colWidths=[0.75*inch, 1.1*inch, 4.0*inch, 1.15*inch])
        cts = TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), ACCENT_BLUE),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("ALIGN", (0, 0), (-1, 0), "CENTER"),
            ("ALIGN", (3, 1), (3, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [LIGHT_GRAY, WHITE]),
            ("GRID", (0, 0), (-1, -1), 0.5, MID_GRAY),
        ])
        # Color status cells
        for i, c in enumerate(func_controls, start=1):
            if c["status"] == "Implemented":
                cts.add("TEXTCOLOR", (3, i), (3, i), SUCCESS)
                cts.add("FONTNAME",  (3, i), (3, i), "Helvetica-Bold")
            elif c["status"] == "Partial":
                cts.add("TEXTCOLOR", (3, i), (3, i), PARTIAL)
                cts.add("FONTNAME",  (3, i), (3, i), "Helvetica-Bold")
            else:
                cts.add("TEXTCOLOR", (3, i), (3, i), DANGER)
                cts.add("FONTNAME",  (3, i), (3, i), "Helvetica-Bold")

        ctrl_table.setStyle(cts)
        story.append(ctrl_table)
        story.append(PageBreak())

    # ── RECOMMENDATIONS PAGE ─────────────────────────────────────────────────
    hdr = [[Paragraph("  RECOMMENDATIONS", section_header)]]
    hdr_t = Table(hdr, colWidths=[7.0*inch])
    hdr_t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), DARK_NAVY),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(hdr_t)
    story.append(Spacer(1, 12))

    story.append(Paragraph("Priority 1 — Immediate Action (Not Implemented Controls)", ParagraphStyle(
        "P1", fontSize=10, textColor=DANGER, fontName="Helvetica-Bold", spaceAfter=6)))

    not_impl = [c for c in controls if c["status"] == "Not Implemented"]
    rec_header = ["Control ID", "Function", "Description", "Recommended Action"]
    rec_rows = [rec_header]
    rec_actions = {
        "ID.RM-1": "Establish a formal risk management committee. Document risk appetite and tolerance thresholds. Obtain executive sign-off.",
        "PR.IP-1": "Develop and publish a hardening baseline using CIS Benchmarks. Enforce via configuration management tooling.",
        "RS.IM-1": "Schedule quarterly IR retrospectives. Create a lessons-learned register. Update playbooks after each incident.",
        "RC.IM-1": "Integrate lessons learned into BCP/DRP. Conduct annual tabletop exercises.",
        "RC.CO-1": "Develop a communications plan for external stakeholders. Designate a PR lead for security incidents.",
    }
    for c in not_impl:
        rec_rows.append([
            Paragraph(c["id"], control_id_style),
            c["function"],
            Paragraph(c["description"][:80] + "...", control_desc_style),
            Paragraph(rec_actions.get(c["id"], "Develop and implement a formal policy and procedure."), control_desc_style),
        ])

    rec_table = Table(rec_rows, colWidths=[0.75*inch, 0.75*inch, 2.5*inch, 3.0*inch])
    rec_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), DANGER),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#FFF5F5"), WHITE]),
        ("GRID", (0, 0), (-1, -1), 0.5, MID_GRAY),
    ]))
    story.append(rec_table)
    story.append(Spacer(1, 20))

    story.append(Paragraph("Priority 2 — Short-Term (Partial Controls)", ParagraphStyle(
        "P2", fontSize=10, textColor=WARNING, fontName="Helvetica-Bold", spaceAfter=6)))
    story.append(Paragraph(
        f"There are {total_part} partially implemented controls requiring completion. "
        f"Focus first on PR.AC-4 (least privilege enforcement), PR.IP-3 (change control), "
        f"RS.MI-1 and RS.MI-2 (incident containment and mitigation), and RC.RP-1 (recovery plan execution). "
        f"These partial controls in the Respond and Recover functions represent the highest risk during an active incident.",
        body_style))
    story.append(Spacer(1, 20))

    # Footer
    story.append(HRFlowable(width="100%", thickness=1, color=MID_GRAY))
    story.append(Spacer(1, 8))
    footer_text = (
        f"Generated by GRC Automation Script | Author: {assessor} | "
        f"github.com/Bphavin1/grc-automation-nist-csf | {assessment_date}"
    )
    story.append(Paragraph(footer_text, ParagraphStyle(
        "footer", fontSize=7, textColor=MID_GRAY, alignment=TA_CENTER, fontName="Helvetica")))

    doc.build(story)
    print(f"[+] Report generated: {output_path}")
    return output_path


# ─── ENTRY POINT ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    build_report(
        controls=CONTROLS,
        output_path="NIST_CSF_Compliance_Report.pdf",
        org_name="Acme Corporation",
        assessor="Brian Pascal",
    )
