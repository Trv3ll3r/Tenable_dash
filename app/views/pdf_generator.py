"""
PDF Generation Module for Executive Dashboard
Handles all ReportLab PDF creation logic
"""
from flask import current_app, make_response
from datetime import datetime, timedelta, timezone
from sqlalchemy import func
import io
import os
import traceback

from ..database import db
from ..models import VulnerabilityFinding


def generate_executive_pdf():
    """Generate executive dashboard PDF"""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image
        from reportlab.platypus.flowables import HRFlowable
        from reportlab.lib.enums import TA_CENTER
        
        COMPANY_NAME = current_app.config.get('COMPANY_NAME', 'Your Company Name')
        COMPANY_LOGO_PATH = current_app.config.get('COMPANY_LOGO_PATH', None)
        
        now = datetime.now(timezone.utc)
        thirty_days_ago = now - timedelta(days=30)
        sixty_days_ago = now - timedelta(days=60)
        
        current_findings = db.session.query(VulnerabilityFinding).filter(
            VulnerabilityFinding.state.in_(['OPEN', 'REOPENED']),
            VulnerabilityFinding.severity.notin_(['info']),
            VulnerabilityFinding.last_found >= thirty_days_ago
        ).all()
        
        previous_findings = db.session.query(VulnerabilityFinding).filter(
            VulnerabilityFinding.state.in_(['OPEN', 'REOPENED']),
            VulnerabilityFinding.severity.notin_(['info']),
            VulnerabilityFinding.last_found >= sixty_days_ago,
            VulnerabilityFinding.last_found < thirty_days_ago
        ).all()
        
        total_current = len(current_findings)
        total_previous = len(previous_findings)
        
        severity_current = {
            'critical': len([f for f in current_findings if f.severity == 'critical']),
            'high': len([f for f in current_findings if f.severity == 'high']),
            'medium': len([f for f in current_findings if f.severity == 'medium']),
            'low': len([f for f in current_findings if f.severity == 'low'])
        }
        
        def calculate_trend(current, previous):
            if previous == 0:
                return 100 if current > 0 else 0
            return round(((current - previous) / previous) * 100, 1)
        
        trends = {'total': calculate_trend(total_current, total_previous)}
        
        total_assets = db.session.query(
            func.count(func.distinct(VulnerabilityFinding.asset_uuid))
        ).filter(VulnerabilityFinding.last_found >= thirty_days_ago).scalar()
        
        attack_path_findings = len([f for f in current_findings if f.is_in_attack_path])
        
        risk_points = (
            severity_current['critical'] * 10 +
            severity_current['high'] * 5 +
            severity_current['medium'] * 2 +
            severity_current['low'] * 1
        )
        risk_score = min(100, risk_points)
        
        plugin_stats = {}
        for finding in current_findings:
            plugin_key = finding.plugin_id
            if plugin_key not in plugin_stats:
                plugin_stats[plugin_key] = {
                    'plugin_name': finding.plugin_name,
                    'severity': finding.severity,
                    'asset_count': 0
                }
            plugin_stats[plugin_key]['asset_count'] += 1
        
        top_vulns = sorted(plugin_stats.values(), key=lambda x: x['asset_count'], reverse=True)[:10]
        
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
        elements = []
        styles = getSampleStyleSheet()
        
        title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=24,
                                     textColor=colors.HexColor('#2c3e50'), spaceAfter=10, alignment=TA_CENTER)
        company_style = ParagraphStyle('CompanyName', parent=styles['Heading2'], fontSize=18,
                                      textColor=colors.HexColor('#34495e'), spaceAfter=20, alignment=TA_CENTER, fontName='Helvetica-Bold')
        heading_style = ParagraphStyle('CustomHeading', parent=styles['Heading2'], fontSize=16,
                                      textColor=colors.HexColor('#2c3e50'), spaceAfter=12, spaceBefore=12)
        normal_style = styles['Normal']
        
        if COMPANY_LOGO_PATH and os.path.exists(COMPANY_LOGO_PATH):
            try:
                logo = Image(COMPANY_LOGO_PATH, width=2*inch, height=1*inch, kind='proportional')
                logo.hAlign = 'CENTER'
                elements.append(logo)
                elements.append(Spacer(1, 0.2*inch))
            except Exception as e:
                current_app.logger.warning(f"Could not load logo: {e}")
        
        elements.append(Paragraph(COMPANY_NAME, company_style))
        elements.append(Paragraph("Executive Security Dashboard", title_style))
        elements.append(Paragraph(
            f"Generated: {now.strftime('%B %d, %Y at %H:%M UTC')}<br/>Reporting Period: Last 30 Days",
            ParagraphStyle('subtitle', parent=normal_style, alignment=TA_CENTER, textColor=colors.grey)
        ))
        elements.append(Spacer(1, 0.3*inch))
        elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#2c3e50')))
        elements.append(Spacer(1, 0.3*inch))
        
        trend_text = f"{trends['total']:+.0f}% vs Previous Period"
        risk_status = 'High Risk' if risk_score > 70 else 'Moderate Risk' if risk_score > 40 else 'Low Risk'
        
        metrics_data = [
            ['Metric', 'Value', 'Status'],
            ['Critical Findings', str(severity_current['critical']), 'Immediate Action Required'],
            ['High Findings', str(severity_current['high']), 'High Priority'],
            ['Total Findings', str(total_current), trend_text],
            ['Total Assets', str(total_assets), 'Under Management'],
            ['Risk Score', f"{round(risk_score, 0)}/100", risk_status],
        ]
        
        if attack_path_findings > 0:
            metrics_data.append(['Attack Paths', str(attack_path_findings), 'Chained Vulnerabilities'])
        
        metrics_table = Table(metrics_data, colWidths=[2.5*inch, 1.5*inch, 2.5*inch])
        metrics_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('FONTNAME', (0, 1), (1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
        ]))
        
        elements.append(metrics_table)
        elements.append(Spacer(1, 0.4*inch))
        
        elements.append(Paragraph("Severity Distribution", heading_style))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#3498db')))
        elements.append(Spacer(1, 0.2*inch))
        
        severity_data = [
            ['Severity', 'Count', 'Percentage'],
            ['CRITICAL', str(severity_current['critical']), f"{round(severity_current['critical']/max(total_current,1)*100, 1)}%"],
            ['HIGH', str(severity_current['high']), f"{round(severity_current['high']/max(total_current,1)*100, 1)}%"],
            ['MEDIUM', str(severity_current['medium']), f"{round(severity_current['medium']/max(total_current,1)*100, 1)}%"],
            ['LOW', str(severity_current['low']), f"{round(severity_current['low']/max(total_current,1)*100, 1)}%"],
        ]
        
        severity_table = Table(severity_data, colWidths=[2*inch, 2*inch, 2*inch])
        severity_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
            ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#e74c3c')),
            ('BACKGROUND', (0, 2), (-1, 2), colors.HexColor('#fd7e14')),
            ('BACKGROUND', (0, 3), (-1, 3), colors.HexColor('#f39c12')),
            ('BACKGROUND', (0, 4), (-1, 4), colors.HexColor('#3498db')),
            ('TEXTCOLOR', (0, 1), (-1, 4), colors.whitesmoke),
        ]))
        
        elements.append(severity_table)
        elements.append(Spacer(1, 0.4*inch))
        
        if top_vulns:
            elements.append(Paragraph("Top 10 Vulnerabilities by Asset Count", heading_style))
            elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#3498db')))
            elements.append(Spacer(1, 0.2*inch))
            
            vuln_data = [['Rank', 'Vulnerability', 'Severity', 'Assets']]
            for idx, vuln in enumerate(top_vulns[:10], 1):
                vuln_name = vuln['plugin_name']
                if vuln_name and len(vuln_name) > 50:
                    vuln_name = vuln_name[:47] + "..."
                vuln_data.append([str(idx), vuln_name or 'Unknown', (vuln['severity'] or 'unknown').upper(), str(vuln['asset_count'])])
            
            vuln_table = Table(vuln_data, colWidths=[0.5*inch, 3.5*inch, 1*inch, 1*inch])
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (0, -1), 'CENTER'),
                ('ALIGN', (2, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
            ]))
            
            elements.append(vuln_table)
            elements.append(Spacer(1, 0.4*inch))
        
        elements.append(PageBreak())
        elements.append(Paragraph("Executive Summary", heading_style))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#3498db')))
        elements.append(Spacer(1, 0.2*inch))
        
        trend_direction = 'increased' if trends['total'] > 0 else 'decreased'
        risk_level = 'high' if risk_score > 70 else 'moderate' if risk_score > 40 else 'low'
        attention_level = 'immediate' if risk_score > 70 else 'prompt' if risk_score > 40 else 'continued'
        
        summary_text = f"""
        <b>Security Posture:</b> The organization currently has <b>{total_current}</b> active security findings 
        across <b>{total_assets}</b> managed assets.<br/><br/>
        <b>Critical Issues:</b> There are <b>{severity_current['critical']}</b> critical vulnerabilities requiring 
        immediate attention and <b>{severity_current['high']}</b> high-priority issues.<br/><br/>
        <b>Trend Analysis:</b> Findings have {trend_direction} by <b>{abs(trends['total']):.1f}%</b> compared to 
        the previous 30-day period.<br/><br/>
        <b>Risk Assessment:</b> The current risk score is <b>{round(risk_score, 0)}/100</b>, indicating {risk_level} 
        risk exposure that requires {attention_level} attention from leadership.
        """
        
        if attack_path_findings > 0:
            summary_text += f"<br/><br/><b>Attack Surface:</b> <b>{attack_path_findings}</b> vulnerabilities are part of identified attack paths."
        
        elements.append(Paragraph(summary_text, normal_style))
        elements.append(Spacer(1, 0.5*inch))
        
        elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#ecf0f1')))
        elements.append(Spacer(1, 0.2*inch))
        elements.append(Paragraph(
            f"<b>Confidential - Executive Leadership</b><br/>{COMPANY_NAME} | Vulnerability Management Dashboard | Generated by Security Operations",
            ParagraphStyle('footer', parent=normal_style, alignment=TA_CENTER, textColor=colors.grey, fontSize=8)
        ))
        
        doc.build(elements)
        pdf_data = buffer.getvalue()
        buffer.close()
        
        response = make_response(pdf_data)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename=executive_security_report_{now.strftime("%Y%m%d")}.pdf'
        
        current_app.logger.info("Executive dashboard PDF generated successfully")
        return response
        
    except ImportError as e:
        current_app.logger.error(f"ReportLab not installed: {e}")
        from flask import jsonify
        return jsonify({'error': 'PDF generation requires ReportLab library', 'install': 'pip install reportlab', 'details': str(e)}), 500
    except Exception as e:
        current_app.logger.error(f"Error generating PDF: {e}")
        traceback.print_exc()
        from flask import jsonify
        return jsonify({'error': str(e)}), 500