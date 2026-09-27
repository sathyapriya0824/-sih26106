"""Generates a downloadable PDF forensic report from an analysis result dict."""

from io import BytesIO
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle(name="H1c", parent=ss["Heading1"], textColor=colors.HexColor("#123B52")))
    ss.add(ParagraphStyle(name="H2c", parent=ss["Heading2"], textColor=colors.HexColor("#1D5D7A")))
    ss.add(ParagraphStyle(name="Mono", parent=ss["Normal"], fontName="Courier", fontSize=8, leading=10))
    return ss


def build_pdf_report(case_id, analysis):
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=18 * mm, bottomMargin=18 * mm)
    ss = _styles()
    story = []

    threat = analysis["threat"]
    summary = analysis["summary"]

    story.append(Paragraph("Email Forensic Intelligence Report", ss["H1c"]))
    story.append(Paragraph(f"Case ID: {case_id}", ss["Normal"]))
    story.append(Paragraph(f"Generated: {datetime.utcnow().isoformat()}Z", ss["Normal"]))
    story.append(Spacer(1, 10))

    risk_color = {
        "Low": colors.HexColor("#2E8B57"), "Medium": colors.HexColor("#D9A441"),
        "High": colors.HexColor("#D9622B"), "Critical": colors.HexColor("#B23A2E"),
    }.get(threat["risk_level"], colors.grey)
    story.append(Paragraph(
        f'<font color="{risk_color.hexval() if hasattr(risk_color,"hexval") else "#000000"}">'
        f'Threat Score: {threat["score"]}/100 &nbsp;&nbsp; Risk Level: {threat["risk_level"]}</font>',
        ss["Heading2"],
    ))
    story.append(Spacer(1, 10))

    story.append(Paragraph("1. Message Summary", ss["H2c"]))
    meta_rows = [["Field", "Value"]] + [
        [k.replace("_", " ").title(), str(v) if v else "-"] for k, v in summary.items()
    ]
    t = Table(meta_rows, colWidths=[110, 380])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#123B52")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(t)
    story.append(Spacer(1, 12))

    story.append(Paragraph("2. Authentication Results", ss["H2c"]))
    auth = analysis["authentication"]
    at = Table([["Mechanism", "Result"]] + [[k.upper(), v] for k, v in auth.items()], colWidths=[110, 380])
    at.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#123B52")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ]))
    story.append(at)
    story.append(Spacer(1, 12))

    story.append(Paragraph("3. Risk Findings", ss["H2c"]))
    if threat["findings"]:
        rows = [["Pts", "Severity", "Finding"]]
        for f in threat["findings"]:
            rows.append([str(f["points"]), f["severity"].title(), f["label"]])
        ft = Table(rows, colWidths=[35, 65, 390])
        ft.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#123B52")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(ft)
    else:
        story.append(Paragraph("No risk indicators were triggered.", ss["Normal"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("4. Delivery Path (Received Hops, oldest to newest)", ss["H2c"]))
    hop_rows = [["#", "From Host", "IP(s)", "Location"]]
    for hop in analysis["hops"]:
        locs = []
        for g in hop.get("geolocation", []):
            if g.get("status") == "success":
                locs.append(f'{g.get("city","?")}, {g.get("country","?")}')
            elif g.get("status") == "private":
                locs.append("Internal/Private")
            else:
                locs.append("Unresolved")
        hop_rows.append([
            str(hop["hop_index"]), hop.get("from_host") or "-",
            ", ".join(hop["public_ips"]) or "(private)", "; ".join(locs) or "-",
        ])
    ht = Table(hop_rows, colWidths=[20, 150, 110, 210])
    ht.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#123B52")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(ht)
    story.append(Spacer(1, 12))

    story.append(Paragraph("5. Suspicious Links", ss["H2c"]))
    if analysis["links"]:
        for lf in analysis["links"]:
            story.append(Paragraph(f'<font face="Courier" size=8>{lf["url"]}</font>', ss["Normal"]))
            for issue in lf["issues"]:
                story.append(Paragraph(f"&nbsp;&nbsp;- {issue}", ss["Normal"]))
    else:
        story.append(Paragraph("No suspicious links detected.", ss["Normal"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("6. Attachments", ss["H2c"]))
    if analysis["attachments"]:
        rows = [["Filename", "Type", "Size", "SHA-256", "Suspicious"]]
        for a in analysis["attachments"]:
            rows.append([
                a["filename"], a["content_type"], f'{a["size_bytes"]} B',
                (a["sha256"] or "")[:16] + "...", "YES" if a["suspicious_extension"] else "no",
            ])
        att_t = Table(rows, colWidths=[100, 90, 55, 130, 60])
        att_t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#123B52")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ]))
        story.append(att_t)
    else:
        story.append(Paragraph("No attachments found.", ss["Normal"]))

    story.append(Spacer(1, 16))
    story.append(Paragraph(
        "This report was generated automatically by the SIH26106 Email Threat Detection, "
        "GeoLocation & Forensic Intelligence platform (Team 404 FOUNDERSS). "
        "Findings are heuristic/AI-assisted and should be corroborated during a formal investigation.",
        ss["Normal"],
    ))

    doc.build(story)
    buf.seek(0)
    return buf
