import io
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

class ReportService:
    @classmethod
    def generate_pdf_report(cls, forensic_data: any, email_message: any, analysis_result: any) -> io.BytesIO:
        """
        Generates a highly styled, professional PDF forensic report using reportlab.
        """
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=40,
            leftMargin=40,
            topMargin=40,
            bottomMargin=40
        )
        
        styles = getSampleStyleSheet()
        
        # Define clean, premium style guides
        primary_color = colors.HexColor("#1e293b")  # Slate 800
        secondary_color = colors.HexColor("#3b82f6") # Blue 500
        text_color = colors.HexColor("#334155")      # Slate 700
        light_bg = colors.HexColor("#f8fafc")        # Slate 50
        border_color = colors.HexColor("#e2e8f0")    # Slate 200
        
        title_style = ParagraphStyle(
            'ReportTitle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#0f172a") # Slate 900
        )
        
        subtitle_style = ParagraphStyle(
            'ReportSubtitle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#64748b") # Slate 500
        )
        
        section_style = ParagraphStyle(
            'SectionHeader',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=14,
            leading=18,
            textColor=secondary_color,
            spaceBefore=14,
            spaceAfter=8
        )
        
        body_style = ParagraphStyle(
            'ReportBody',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            leading=13,
            textColor=text_color
        )
        
        body_bold = ParagraphStyle(
            'ReportBodyBold',
            parent=body_style,
            fontName='Helvetica-Bold'
        )
        
        code_style = ParagraphStyle(
            'ReportCode',
            parent=styles['Normal'],
            fontName='Courier',
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#1e293b")
        )

        story = []

        # --- 1. Header Banner ---
        header_data = [
            [
                Paragraph("<b>MAILSHIELD FORENSICS</b>", ParagraphStyle('H1', fontName='Helvetica-Bold', fontSize=14, leading=16, textColor=colors.white)),
                Paragraph(f"REPORT GENERATED: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", ParagraphStyle('H2', fontName='Helvetica-Bold', fontSize=8, leading=10, textColor=colors.white, alignment=2))
            ]
        ]
        header_table = Table(header_data, colWidths=[270, 260])
        header_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), primary_color),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('PADDING', (0,0), (-1,-1), 10),
            ('BOTTOMPADDING', (0,0), (-1,-1), 12),
            ('TOPPADDING', (0,0), (-1,-1), 12),
        ]))
        story.append(header_table)
        story.append(Spacer(1, 15))

        # --- Title ---
        story.append(Paragraph("Incident Investigation Report", title_style))
        story.append(Paragraph(f"Forensic Audit for Email ID: {forensic_data.email_id}", subtitle_style))
        story.append(Spacer(1, 15))

        # --- 2. Executive Summary Block ---
        story.append(Paragraph("Executive Summary", section_style))
        
        verdict = "N/A"
        risk_score = 0
        confidence = 0.0
        reasons = []
        recommendations = []
        
        if analysis_result:
            verdict = analysis_result.threat_type
            risk_score = analysis_result.risk_score
            confidence = analysis_result.confidence
            reasons = analysis_result.reasons
            recommendations = analysis_result.recommendations

        verdict_color = "#10b981" # Green
        if risk_score >= 70:
            verdict_color = "#f43f5e" # Rose
        elif risk_score >= 40:
            verdict_color = "#f59e0b" # Amber

        summary_data = [
            [Paragraph("<b>Verdict:</b>", body_style), Paragraph(f"<font color='{verdict_color}'><b>{verdict.upper()}</b></font>", body_bold)],
            [Paragraph("<b>Risk Score:</b>", body_style), Paragraph(f"<b>{risk_score} / 100</b>", body_bold)],
            [Paragraph("<b>Confidence level:</b>", body_style), Paragraph(f"{int(confidence * 100)}%", body_style)],
            [Paragraph("<b>Email Sender:</b>", body_style), Paragraph(email_message.sender if email_message else "Unknown", body_style)],
            [Paragraph("<b>Email Subject:</b>", body_style), Paragraph(email_message.subject if email_message else "No Subject", body_style)],
        ]
        
        summary_table = Table(summary_data, colWidths=[120, 410])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), light_bg),
            ('BOX', (0,0), (-1,-1), 0.5, border_color),
            ('INNERGRID', (0,0), (-1,-1), 0.5, border_color),
            ('PADDING', (0,0), (-1,-1), 6),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 15))

        # --- 3. Authentication Status Matrix ---
        story.append(Paragraph("Authentication Status Matrix", section_style))
        auth = forensic_data.authentication
        
        def get_auth_label(val: str) -> str:
            norm = val.lower()
            if norm == "pass":
                return "<font color='#10b981'><b>PASS</b></font>"
            elif norm == "fail":
                return "<font color='#f43f5e'><b>FAIL</b></font>"
            elif norm == "neutral":
                return "<font color='#f59e0b'><b>NEUTRAL</b></font>"
            return "<font color='#64748b'><b>UNKNOWN</b></font>"

        auth_data = [
            [
                Paragraph("<b>SPF Status</b>", body_bold),
                Paragraph("<b>DKIM Status</b>", body_bold),
                Paragraph("<b>DMARC Status</b>", body_bold)
            ],
            [
                Paragraph(get_auth_label(auth.spf), body_style),
                Paragraph(get_auth_label(auth.dkim), body_style),
                Paragraph(get_auth_label(auth.dmarc), body_style)
            ]
        ]
        auth_table = Table(auth_data, colWidths=[176, 177, 177])
        auth_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), primary_color),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('BOX', (0,0), (-1,-1), 0.5, border_color),
            ('INNERGRID', (0,0), (-1,-1), 0.5, border_color),
            ('PADDING', (0,0), (-1,-1), 6),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        # Fix header text color in table style
        for i in range(3):
            auth_data[0][i].style.textColor = colors.white
        story.append(auth_table)
        story.append(Spacer(1, 15))

        # --- 4. Observed Threat Signals & Recommendations ---
        if reasons or recommendations:
            story.append(Paragraph("Observed Threat Signals & Recommendations", section_style))
            threat_details = []
            
            if reasons:
                threat_details.append(Paragraph("<b>Observed Alert Indicators:</b>", body_bold))
                for r in reasons:
                    threat_details.append(Paragraph(f"• {r}", body_style))
                threat_details.append(Spacer(1, 5))
                
            if recommendations:
                threat_details.append(Paragraph("<b>Security Recommendations:</b>", body_bold))
                for rec in recommendations:
                    threat_details.append(Paragraph(f"• {rec}", body_style))
            
            threat_table = Table([[threat_details]], colWidths=[530])
            threat_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), light_bg),
                ('BOX', (0,0), (-1,-1), 0.5, border_color),
                ('PADDING', (0,0), (-1,-1), 8),
            ]))
            story.append(threat_table)
            story.append(Spacer(1, 15))

        # --- 5. Hop Routing trace table ---
        story.append(Paragraph("Geographic Mail Routing Trace", section_style))
        
        hop_rows = [
            [
                Paragraph("<b>Hop</b>", body_bold),
                Paragraph("<b>IP Address</b>", body_bold),
                Paragraph("<b>Location</b>", body_bold),
                Paragraph("<b>ISP / ASN</b>", body_bold)
            ]
        ]
        
        # Override header text color for hops table
        for cell in hop_rows[0]:
            cell.style.textColor = colors.white

        route_hops = forensic_data.route_hops
        if route_hops:
            # Sort chronological (highest hop seq first / origin)
            sorted_hops = sorted(route_hops, key=lambda x: x.hop, reverse=True)
            for hop in sorted_hops:
                loc = f"{hop.city}, {hop.country}" if hop.city != "Unknown" else hop.country
                if hop.latitude is None:
                    loc = "Local Range / Private"
                hop_rows.append([
                    Paragraph(f"Hop {hop.hop}", body_style),
                    Paragraph(hop.ip or "—", code_style),
                    Paragraph(loc, body_style),
                    Paragraph(f"{hop.isp} ({hop.asn})", body_style)
                ])
        else:
            hop_rows.append([Paragraph("No hops recorded in mail headers.", body_style), "", "", ""])

        hop_table = Table(hop_rows, colWidths=[55, 100, 160, 215])
        hop_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), primary_color),
            ('BOX', (0,0), (-1,-1), 0.5, border_color),
            ('INNERGRID', (0,0), (-1,-1), 0.5, border_color),
            ('PADDING', (0,0), (-1,-1), 5),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(hop_table)
        story.append(Spacer(1, 20))

        # --- 6. Chain of Custody Certificate ---
        story.append(Paragraph("Chain of Custody Certificate", section_style))
        integrity = forensic_data.evidence_integrity
        
        evidence_id = "—"
        evidence_sha = "—"
        captured_at = "—"
        custody_status = "—"
        audit_event = "—"
        
        if integrity:
            evidence_id = integrity.evidence_id
            evidence_sha = integrity.evidence_sha256
            captured_at = integrity.captured_at
            custody_status = integrity.chain_of_custody_status
            audit_event = integrity.last_audit_event

        custody_data = [
            [Paragraph("<b>Evidence Reference ID:</b>", body_style), Paragraph(evidence_id, body_bold)],
            [Paragraph("<b>Evidence SHA-256 Hash:</b>", body_style), Paragraph(evidence_sha, code_style)],
            [Paragraph("<b>Block Custody Status:</b>", body_style), Paragraph(custody_status, body_bold)],
            [Paragraph("<b>Database Block Event:</b>", body_style), Paragraph(audit_event, body_style)],
            [Paragraph("<b>Sealing Timestamp:</b>", body_style), Paragraph(captured_at, body_style)],
        ]
        custody_table = Table(custody_data, colWidths=[150, 380])
        custody_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f1f5f9")), # Slate 100
            ('BOX', (0,0), (-1,-1), 0.8, colors.HexColor("#cbd5e1")),   # Slate 300
            ('PADDING', (0,0), (-1,-1), 6),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(custody_table)
        
        story.append(Spacer(1, 25))
        story.append(Paragraph("<font color='#64748b'>This document represents a cryptographically linked, tamper-proof record generated automatically by the MailShield Forensics platform. The integrity of this evidence is verified through a local SQLite Hash Chain of Custody database.</font>", ParagraphStyle('Disclaimer', parent=body_style, fontSize=7, leading=10, textColor=colors.HexColor("#94a3b8"))))

        doc.build(story)
        buffer.seek(0)
        return buffer
