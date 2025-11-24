"""
PDF Generation Module for Executive Dashboard - ENHANCED WITH CHARTS
Handles all ReportLab PDF creation logic with complete feature set and visualizations
"""
from flask import Blueprint, current_app, make_response
from datetime import datetime, timedelta, timezone
from sqlalchemy import func
from sqlalchemy.orm import subqueryload
from collections import defaultdict
import io
import os
import traceback

from ..database import db
from ..models import VulnerabilityFinding, CloudFinding, PluginComplianceMapping, ComplianceRequirement

# Create PDF Blueprint
pdf_bp = Blueprint('pdf', __name__)


def get_grc_summary_for_findings(findings):
    """Calculate GRC compliance summary from findings"""
    grc_summary = defaultdict(lambda: {'total_findings': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'requirements': set()})
    for finding in findings:
        if hasattr(finding, 'plugin_compliance_mappings') and finding.plugin_compliance_mappings:
            for mapping in finding.plugin_compliance_mappings:
                if mapping.compliance_requirement:
                    framework = mapping.compliance_requirement.framework
                    grc_summary[framework]['total_findings'] += 1
                    grc_summary[framework]['requirements'].add(mapping.compliance_requirement.requirement_id)
                    severity = (finding.severity or 'unknown').lower()
                    if severity in ['critical', 'high', 'medium', 'low']:
                        grc_summary[framework][severity] += 1
    
    result = {}
    for framework, data in grc_summary.items():
        result[framework] = {
            'total_findings': data['total_findings'],
            'critical': data['critical'],
            'high': data['high'],
            'medium': data['medium'],
            'low': data['low'],
            'requirements_count': len(data['requirements'])
        }
    return result


def get_nist_controls_list(findings):
    """Get NIST 800-53 controls affected by findings"""
    nist_controls = {}
    for finding in findings:
        if hasattr(finding, 'plugin_compliance_mappings') and finding.plugin_compliance_mappings:
            for mapping in finding.plugin_compliance_mappings:
                if mapping.compliance_requirement and mapping.compliance_requirement.framework == 'NIST 800-53':
                    control_id = mapping.compliance_requirement.requirement_id
                    control_desc = mapping.compliance_requirement.description
                    if control_id not in nist_controls:
                        nist_controls[control_id] = {
                            'control_id': control_id,
                            'description': control_desc,
                            'total_findings': 0,
                            'critical': 0,
                            'high': 0,
                            'medium': 0,
                            'low': 0,
                            'affected_assets': set()
                        }
                    nist_controls[control_id]['total_findings'] += 1
                    nist_controls[control_id]['affected_assets'].add(finding.asset_uuid)
                    severity = (finding.severity or 'unknown').lower()
                    if severity in ['critical', 'high', 'medium', 'low']:
                        nist_controls[control_id][severity] += 1
    
    for control_data in nist_controls.values():
        control_data['affected_assets'] = len(control_data['affected_assets'])
    
    sorted_controls = sorted(
        nist_controls.values(),
        key=lambda x: (x['critical'], x['high'], x['total_findings']),
        reverse=True
    )
    return sorted_controls


def create_gauge_chart(value, max_value, title, width=250, height=150):
    """Create a gauge/speedometer chart"""
    from reportlab.graphics.shapes import Drawing, Wedge, String, Circle, Line
    from reportlab.lib import colors as rl_colors
    
    drawing = Drawing(width, height)
    
    # Center point
    cx = width / 2
    cy = height - 30
    radius = min(width, height) / 2 - 20
    
    # Background arc (gray)
    drawing.add(Wedge(cx, cy, radius, 0, 180, fillColor=rl_colors.HexColor('#e0e0e0'), strokeColor=None))
    
    # Determine color based on value
    if value > 70:
        gauge_color = rl_colors.HexColor('#e74c3c')  # Red
    elif value > 40:
        gauge_color = rl_colors.HexColor('#f39c12')  # Orange
    else:
        gauge_color = rl_colors.HexColor('#27ae60')  # Green
    
    # Value arc
    angle = (value / max_value) * 180
    drawing.add(Wedge(cx, cy, radius, 0, angle, fillColor=gauge_color, strokeColor=None))
    
    # Inner circle (white)
    drawing.add(Circle(cx, cy, radius * 0.7, fillColor=rl_colors.white, strokeColor=None))
    
    # Needle
    needle_angle = angle * (3.14159 / 180)
    needle_length = radius * 0.65
    needle_x = cx + needle_length * (-1) * (-1 if needle_angle < 3.14159 else 1) * abs(needle_angle - 3.14159) / 3.14159 * needle_length
    needle_y = cy + needle_length * (needle_angle / 3.14159)
    
    # Simplified needle as line
    import math
    needle_x = cx - needle_length * math.cos(math.radians(180 - angle))
    needle_y = cy + needle_length * math.sin(math.radians(180 - angle))
    drawing.add(Line(cx, cy, needle_x, needle_y, strokeColor=rl_colors.black, strokeWidth=2))
    
    # Center dot
    drawing.add(Circle(cx, cy, 5, fillColor=rl_colors.black, strokeColor=None))
    
    # Value text
    value_str = String(cx, cy - 40, f"{value:.1f}", textAnchor='middle', fontSize=24, fillColor=rl_colors.black)
    drawing.add(value_str)
    
    # Title
    title_str = String(cx, height - 15, title, textAnchor='middle', fontSize=12, fillColor=rl_colors.black)
    drawing.add(title_str)
    
    # Min/Max labels
    drawing.add(String(cx - radius, cy - 10, "0", textAnchor='middle', fontSize=8, fillColor=rl_colors.grey))
    drawing.add(String(cx + radius, cy - 10, str(max_value), textAnchor='middle', fontSize=8, fillColor=rl_colors.grey))
    
    return drawing


def create_pie_chart(data_dict, title, width=300, height=250):
    """Create a pie chart"""
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics.shapes import Drawing, String
    from reportlab.lib import colors as rl_colors
    
    drawing = Drawing(width, height)
    
    pie = Pie()
    pie.x = 50
    pie.y = 50
    pie.width = 150
    pie.height = 150
    
    # Data
    labels = list(data_dict.keys())
    values = list(data_dict.values())
    
    pie.data = values
    pie.labels = [f"{label}\n{val}" for label, val in zip(labels, values)]
    
    # Colors
    color_map = {
        'Critical': rl_colors.HexColor('#e74c3c'),
        'High': rl_colors.HexColor('#fd7e14'),
        'Medium': rl_colors.HexColor('#f39c12'),
        'Low': rl_colors.HexColor('#3498db')
    }
    
    pie.slices.strokeColor = rl_colors.white
    pie.slices.strokeWidth = 2
    
    for i, label in enumerate(labels):
        pie.slices[i].fillColor = color_map.get(label, rl_colors.grey)
    
    drawing.add(pie)
    
    # Title
    title_str = String(width / 2, height - 20, title, textAnchor='middle', fontSize=14, fillColor=rl_colors.black)
    drawing.add(title_str)
    
    return drawing


def create_line_chart(weekly_data, title, width=450, height=250):
    """Create a line chart for weekly trends"""
    from reportlab.graphics.charts.linecharts import HorizontalLineChart
    from reportlab.graphics.shapes import Drawing, String
    from reportlab.lib import colors as rl_colors
    
    drawing = Drawing(width, height)
    
    chart = HorizontalLineChart()
    chart.x = 50
    chart.y = 50
    chart.width = width - 100
    chart.height = height - 100
    
    # Data: [total, critical, high]
    chart.data = [
        [w['total'] for w in weekly_data],
        [w['critical'] for w in weekly_data],
        [w['high'] for w in weekly_data]
    ]
    
    chart.categoryAxis.labels.boxAnchor = 'n'
    chart.categoryAxis.labels.angle = 45
    chart.categoryAxis.labels.fontSize = 7
    chart.categoryAxis.categoryNames = [w['week'] for w in weekly_data]
    
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueMax = max([w['total'] for w in weekly_data] + [1]) * 1.1
    chart.valueAxis.valueStep = max(10, int(chart.valueAxis.valueMax / 5))
    
    # Line colors
    chart.lines[0].strokeColor = rl_colors.HexColor('#3498db')  # Total - Blue
    chart.lines[0].strokeWidth = 2
    chart.lines[1].strokeColor = rl_colors.HexColor('#e74c3c')  # Critical - Red
    chart.lines[1].strokeWidth = 2
    chart.lines[2].strokeColor = rl_colors.HexColor('#fd7e14')  # High - Orange
    chart.lines[2].strokeWidth = 2
    
    drawing.add(chart)
    
    # Title
    title_str = String(width / 2, height - 20, title, textAnchor='middle', fontSize=14, fillColor=rl_colors.black)
    drawing.add(title_str)
    
    # Legend
    legend_y = 30
    drawing.add(String(width - 120, legend_y, "— Total", fontSize=8, fillColor=rl_colors.HexColor('#3498db')))
    drawing.add(String(width - 120, legend_y - 12, "— Critical", fontSize=8, fillColor=rl_colors.HexColor('#e74c3c')))
    drawing.add(String(width - 120, legend_y - 24, "— High", fontSize=8, fillColor=rl_colors.HexColor('#fd7e14')))
    
    return drawing


def create_horizontal_bar_chart(data_list, title, width=450, height=300):
    """Create a horizontal bar chart for top vulnerabilities"""
    from reportlab.graphics.charts.barcharts import HorizontalBarChart
    from reportlab.graphics.shapes import Drawing, String
    from reportlab.lib import colors as rl_colors
    
    drawing = Drawing(width, height)
    
    chart = HorizontalBarChart()
    chart.x = 150
    chart.y = 50
    chart.width = width - 200
    chart.height = height - 100
    
    # Data
    values = [item['asset_count'] for item in data_list[:10]]
    labels = [item['plugin_name'][:30] + "..." if len(item['plugin_name']) > 30 else item['plugin_name'] for item in data_list[:10]]
    
    chart.data = [values]
    
    chart.categoryAxis.categoryNames = labels
    chart.categoryAxis.labels.fontSize = 7
    chart.categoryAxis.labels.boxAnchor = 'e'
    
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueMax = max(values) * 1.1 if values else 10
    chart.valueAxis.valueStep = max(1, int(chart.valueAxis.valueMax / 5))
    
    # Set bar colors (simplified - all bars same color to avoid subscripting issues)
    chart.bars.strokeColor = None
    chart.bars.fillColor = rl_colors.HexColor('#3498db')  # Blue for all bars
    
    drawing.add(chart)
    
    # Title
    title_str = String(width / 2, height - 20, title, textAnchor='middle', fontSize=14, fillColor=rl_colors.black)
    drawing.add(title_str)
    
    return drawing


def create_grc_bar_chart(grc_summary, title, width=450, height=300):
    """Create a bar chart for GRC framework impact"""
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    from reportlab.graphics.shapes import Drawing, String
    from reportlab.lib import colors as rl_colors
    
    drawing = Drawing(width, height)
    
    # Sort and get top 8 frameworks
    sorted_grc = sorted(grc_summary.items(), 
                       key=lambda x: (x[1]['critical'], x[1]['high'], x[1]['total_findings']), 
                       reverse=True)[:8]
    
    chart = VerticalBarChart()
    chart.x = 50
    chart.y = 50
    chart.width = width - 100
    chart.height = height - 120
    
    # Data: [critical, high, medium]
    critical_data = [data['critical'] for fw, data in sorted_grc]
    high_data = [data['high'] for fw, data in sorted_grc]
    medium_data = [data['medium'] for fw, data in sorted_grc]
    
    chart.data = [critical_data, high_data, medium_data]
    
    # Labels - shorten if needed
    labels = [fw[:15] + "..." if len(fw) > 15 else fw for fw, _ in sorted_grc]
    chart.categoryAxis.categoryNames = labels
    chart.categoryAxis.labels.fontSize = 7
    chart.categoryAxis.labels.boxAnchor = 'n'
    chart.categoryAxis.labels.angle = 45
    
    chart.valueAxis.valueMin = 0
    max_val = max([data['total_findings'] for _, data in sorted_grc] + [1])
    chart.valueAxis.valueMax = max_val * 1.1
    chart.valueAxis.valueStep = max(1, int(chart.valueAxis.valueMax / 5))
    
    # Colors: Critical (red), High (orange), Medium (yellow)
    chart.bars[0].fillColor = rl_colors.HexColor('#e74c3c')
    chart.bars[1].fillColor = rl_colors.HexColor('#fd7e14')
    chart.bars[2].fillColor = rl_colors.HexColor('#f39c12')
    
    # Remove stroke for cleaner appearance
    chart.bars.strokeColor = None
    chart.barSpacing = 3
    
    drawing.add(chart)
    
    # Title
    title_str = String(width / 2, height - 20, title, textAnchor='middle', fontSize=14, fillColor=rl_colors.black)
    drawing.add(title_str)
    
    # Legend
    legend_x = 60
    legend_y = height - 50
    drawing.add(String(legend_x, legend_y, "■ Critical", fontSize=8, fillColor=rl_colors.HexColor('#e74c3c')))
    drawing.add(String(legend_x + 60, legend_y, "■ High", fontSize=8, fillColor=rl_colors.HexColor('#fd7e14')))
    drawing.add(String(legend_x + 110, legend_y, "■ Medium", fontSize=8, fillColor=rl_colors.HexColor('#f39c12')))
    
    return drawing


@pdf_bp.route('/executive_dashboard/pdf')
def executive_dashboard_pdf():
    """Generate comprehensive executive dashboard PDF with all metrics and charts"""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image
        from reportlab.platypus.flowables import HRFlowable
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        
        COMPANY_NAME = current_app.config.get('COMPANY_NAME', 'Your Company Name')
        COMPANY_LOGO_PATH = current_app.config.get('COMPANY_LOGO_PATH', None)
        
        now = datetime.now(timezone.utc)
        thirty_days_ago = now - timedelta(days=30)
        sixty_days_ago = now - timedelta(days=60)
        
        # ========== DATA COLLECTION ==========
        
        # Load findings with GRC mappings
        current_findings = db.session.query(VulnerabilityFinding).filter(
            VulnerabilityFinding.state.in_(['OPEN', 'REOPENED']),
            VulnerabilityFinding.severity.notin_(['info']),
            VulnerabilityFinding.last_found >= thirty_days_ago
        ).options(
            subqueryload(VulnerabilityFinding.plugin_compliance_mappings).subqueryload(PluginComplianceMapping.compliance_requirement)
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
        
        severity_previous = {
            'critical': len([f for f in previous_findings if f.severity == 'critical']),
            'high': len([f for f in previous_findings if f.severity == 'high']),
            'medium': len([f for f in previous_findings if f.severity == 'medium']),
            'low': len([f for f in previous_findings if f.severity == 'low'])
        }
        
        def calculate_trend(current, previous):
            if previous == 0:
                return 100 if current > 0 else 0
            return round(((current - previous) / previous) * 100, 1)
        
        trends = {
            'total': calculate_trend(total_current, total_previous),
            'critical': calculate_trend(severity_current['critical'], severity_previous['critical']),
            'high': calculate_trend(severity_current['high'], severity_previous['high'])
        }
        
        # Asset counts
        total_assets = db.session.query(
            func.count(func.distinct(VulnerabilityFinding.asset_uuid))
        ).filter(VulnerabilityFinding.last_found >= thirty_days_ago).scalar()
        
        critical_assets = db.session.query(
            func.count(func.distinct(VulnerabilityFinding.asset_uuid))
        ).filter(
            VulnerabilityFinding.severity == 'critical',
            VulnerabilityFinding.state.in_(['OPEN', 'REOPENED']),
            VulnerabilityFinding.last_found >= thirty_days_ago
        ).scalar()
        
        # Attack path findings
        attack_path_findings = len([f for f in current_findings if f.is_in_attack_path])
        
        # Cloud asset breakdown
        cloud_assets = {
            'aws': len(set([f.asset_uuid for f in current_findings if f.asset_aws_ec2_instance_id])),
            'azure': len(set([f.asset_uuid for f in current_findings if f.asset_azure_vm_id])),
            'gcp': len(set([f.asset_uuid for f in current_findings if f.asset_gcp_instance_id]))
        }
        total_cloud_assets = cloud_assets['aws'] + cloud_assets['azure'] + cloud_assets['gcp']
        
        # ========== MTTR CALCULATION ==========
        fixed_findings = db.session.query(VulnerabilityFinding).filter(
            VulnerabilityFinding.state == 'FIXED',
            VulnerabilityFinding.fixed_at >= thirty_days_ago,
            VulnerabilityFinding.first_found.isnot(None),
            VulnerabilityFinding.fixed_at.isnot(None)
        ).all()
        
        if fixed_findings:
            remediation_times = []
            for finding in fixed_findings:
                if finding.first_found and finding.fixed_at:
                    days = (finding.fixed_at - finding.first_found).days
                    remediation_times.append(days)
            
            if remediation_times:
                mttr_days = round(sum(remediation_times) / len(remediation_times), 1)
                critical_times = [
                    (f.fixed_at - f.first_found).days
                    for f in fixed_findings
                    if f.severity == 'critical' and f.first_found and f.fixed_at
                ]
                mttr_critical = round(sum(critical_times) / len(critical_times), 1) if critical_times else 0
            else:
                mttr_days = 0
                mttr_critical = 0
        else:
            mttr_days = 0
            mttr_critical = 0
        
        # ========== GRC & COMPLIANCE ==========
        grc_summary = get_grc_summary_for_findings(current_findings)
        nist_controls = get_nist_controls_list(current_findings)
        
        # Calculate compliance score
        if grc_summary and len(grc_summary) > 0:
            total_grc_findings = sum(fw['total_findings'] for fw in grc_summary.values())
            total_requirements = sum(fw['requirements_count'] for fw in grc_summary.values())
            
            if total_requirements > 0 and total_current > 0:
                compliance_coverage = (total_grc_findings / total_current) * 100
                critical_compliance = sum(fw['critical'] for fw in grc_summary.values())
                high_compliance = sum(fw['high'] for fw in grc_summary.values())
                
                compliance_impact = (
                    (critical_compliance * 3) + 
                    (high_compliance * 2) + 
                    (total_grc_findings - critical_compliance - high_compliance)
                ) / total_current
                
                compliance_score = max(0, min(100, 100 - (compliance_impact * 15)))
            else:
                compliance_score = 100
        else:
            compliance_score = 75
            total_grc_findings = 0
            total_requirements = 0
        
        # ========== RISK SCORE CALCULATION (IMPROVED) ==========
        if total_assets > 0:
            critical_per_asset = severity_current['critical'] / total_assets
            high_per_asset = severity_current['high'] / total_assets
            medium_per_asset = severity_current['medium'] / total_assets
            
            critical_risk = min(50, critical_per_asset * 15)
            high_risk = min(30, high_per_asset * 5)
            medium_risk = min(15, medium_per_asset * 2)
            base_risk = critical_risk + high_risk + medium_risk
            attack_path_bonus = 5 if attack_path_findings > 0 else 0
            
            risk_score = min(100, base_risk + attack_path_bonus)
        else:
            risk_score = 0
        
        # ========== SLA TRACKING ==========
        sla_thresholds = {
            'critical': 30,
            'high': 30,
            'medium': 180,
            'low': 180,
            'info': 180
        }

        sla_compliance = {
            'total_findings': len(current_findings),
            'within_sla': 0,
            'exceeding_sla': 0,
            'critical_exceeding': 0,
            'high_exceeding': 0,
            'medium_exceeding': 0,
            'low_exceeding': 0,
            'exceeding_findings': []
        }

        for finding in current_findings:
            if finding.first_found:
                # Handle timezone-aware and timezone-naive datetimes
                first_found = finding.first_found
                if first_found.tzinfo is None:
                    # If first_found is naive, make it UTC aware
                    first_found = first_found.replace(tzinfo=timezone.utc)
                
                age_days = (now - first_found).days
                severity = (finding.severity or 'low').lower()
                sla_days = sla_thresholds.get(severity, 180)
                
                if age_days > sla_days:
                    sla_compliance['exceeding_sla'] += 1
                    sla_compliance[f'{severity}_exceeding'] += 1
                    
                    sla_compliance['exceeding_findings'].append({
                        'plugin_name': finding.plugin_name,
                        'severity': finding.severity,
                        'asset_hostname': finding.asset_hostname or finding.asset_ipv4,
                        'age_days': age_days,
                        'sla_days': sla_days,
                        'days_overdue': age_days - sla_days
                    })
                else:
                    sla_compliance['within_sla'] += 1

        sla_compliance['exceeding_findings'].sort(key=lambda x: x['days_overdue'], reverse=True)

        if sla_compliance['total_findings'] > 0:
            sla_compliance['compliance_percentage'] = round(
                (sla_compliance['within_sla'] / sla_compliance['total_findings']) * 100, 1
            )
        else:
            sla_compliance['compliance_percentage'] = 100.0
        # ========== END SLA TRACKING ==========
        
        # ========== CLOUD SECURITY DATA ==========
        try:
            cloud_findings_query = db.session.query(CloudFinding).filter(CloudFinding.status == 'Open')
            all_cloud_findings = cloud_findings_query.all()
            
            cloud_summary = {
                'total_findings': len(all_cloud_findings),
                'total_resources': len(set([f.resource_name for f in all_cloud_findings if f.resource_name])),
                'critical': len([f for f in all_cloud_findings if f.severity and f.severity.lower() == 'critical']),
                'high': len([f for f in all_cloud_findings if f.severity and f.severity.lower() == 'high']),
                'medium': len([f for f in all_cloud_findings if f.severity and f.severity.lower() == 'medium']),
                'low': len([f for f in all_cloud_findings if f.severity and f.severity.lower() == 'low']),
                'aws_findings': len([f for f in all_cloud_findings if f.cloud_provider and f.cloud_provider.upper() == 'AWS']),
                'azure_findings': len([f for f in all_cloud_findings if f.cloud_provider and f.cloud_provider.upper() == 'AZURE']),
                'gcp_findings': len([f for f in all_cloud_findings if f.cloud_provider and f.cloud_provider.upper() == 'GCP'])
            }
        except Exception as cloud_error:
            current_app.logger.warning(f"Error loading cloud findings for PDF: {cloud_error}")
            cloud_summary = {
                'total_findings': 0,
                'total_resources': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'aws_findings': 0,
                'azure_findings': 0,
                'gcp_findings': 0
            }
        
        # ========== TOP VULNERABILITIES ==========
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
        
        # ========== WEEKLY TRENDS ==========
        weekly_trends = []
        for week in range(12, 0, -1):
            week_start = now - timedelta(weeks=week)
            week_end = now - timedelta(weeks=week-1)
            week_findings = db.session.query(VulnerabilityFinding).filter(
                VulnerabilityFinding.last_found >= week_start,
                VulnerabilityFinding.last_found < week_end,
                VulnerabilityFinding.state.in_(['OPEN', 'REOPENED']),
                VulnerabilityFinding.severity.notin_(['info'])
            ).all()
            
            weekly_trends.append({
                'week': f"W{13-week}",
                'total': len(week_findings),
                'critical': len([f for f in week_findings if f.severity == 'critical']),
                'high': len([f for f in week_findings if f.severity == 'high'])
            })
        
        # ========== PDF GENERATION ==========
        
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )
        
        elements = []
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=10,
            alignment=TA_CENTER
        )
        
        company_style = ParagraphStyle(
            'CompanyName',
            parent=styles['Heading2'],
            fontSize=18,
            textColor=colors.HexColor('#34495e'),
            spaceAfter=20,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=12,
            spaceBefore=12
        )
        
        subheading_style = ParagraphStyle(
            'CustomSubHeading',
            parent=styles['Heading3'],
            fontSize=14,
            textColor=colors.HexColor('#34495e'),
            spaceAfter=10,
            spaceBefore=10
        )
        
        body_style = ParagraphStyle(
            'CustomBody',
            parent=styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=6,
            spaceBefore=6
        )
        
        normal_style = styles['Normal']
        
        # ========== PAGE 1: HEADER & KEY METRICS ==========
        
        # Logo
        if COMPANY_LOGO_PATH and os.path.exists(COMPANY_LOGO_PATH):
            try:
                logo = Image(COMPANY_LOGO_PATH, width=2*inch, height=1*inch, kind='proportional')
                logo.hAlign = 'CENTER'
                elements.append(logo)
                elements.append(Spacer(1, 0.2*inch))
            except Exception as e:
                current_app.logger.warning(f"Could not load logo: {e}")
        
        # Title
        elements.append(Paragraph(COMPANY_NAME, company_style))
        elements.append(Paragraph("Executive Security Dashboard", title_style))
        elements.append(
            Paragraph(
                f"Generated: {now.strftime('%B %d, %Y at %H:%M UTC')}<br/>Reporting Period: Last 30 Days",
                ParagraphStyle('subtitle', parent=normal_style, alignment=TA_CENTER, textColor=colors.grey)
            )
        )
        elements.append(Spacer(1, 0.3*inch))
        elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#2c3e50')))
        elements.append(Spacer(1, 0.3*inch))
        
        # ========== GAUGE CHARTS: RISK & COMPLIANCE ==========
        
        elements.append(Paragraph("Security Posture Overview", heading_style))
        elements.append(Spacer(1, 0.2*inch))
        
        # Create table with two gauges side by side
        risk_gauge = create_gauge_chart(risk_score, 100, "Risk Score")
        compliance_gauge = create_gauge_chart(compliance_score, 100, "Compliance Score")
        
        gauge_table = Table([[risk_gauge, compliance_gauge]], colWidths=[3*inch, 3*inch])
        gauge_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
        ]))
        
        elements.append(gauge_table)
        elements.append(Spacer(1, 0.3*inch))
        
        # Key Metrics Table
        trend_text = f"{trends['total']:+.0f}% vs Previous Period"
        risk_status = 'High Risk' if risk_score > 70 else 'Moderate Risk' if risk_score > 40 else 'Low Risk'
        compliance_status = 'Excellent' if compliance_score > 80 else 'Good' if compliance_score > 60 else 'Needs Improvement'
        
        metrics_data = [
            ['Metric', 'Value', 'Status'],
            ['Critical Findings', str(severity_current['critical']), 'Immediate Action Required'],
            ['High Findings', str(severity_current['high']), 'High Priority'],
            ['Total Findings', str(total_current), trend_text],
            ['Total Assets', str(total_assets), 'Under Management'],
            ['Critical Assets', str(critical_assets), 'Require Attention']
        ]
        
        if attack_path_findings > 0:
            metrics_data.append(['Attack Paths', str(attack_path_findings), 'Chained Vulnerabilities'])
        
        if mttr_days > 0:
            metrics_data.append(['MTTR (Overall)', f"{mttr_days} days", f"Based on {len(fixed_findings)} fixed items"])
        
        metrics_table = Table(metrics_data, colWidths=[2.2*inch, 1.8*inch, 2.5*inch])
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
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')])
        ]))
        
        elements.append(metrics_table)
        elements.append(Spacer(1, 0.4*inch))
        
        # ========== PAGE BREAK ==========
        elements.append(PageBreak())
        
        # ========== PAGE 2: SEVERITY & TRENDS CHARTS ==========
        
        # Severity Distribution Pie Chart
        elements.append(Paragraph("Severity Distribution", heading_style))
        elements.append(Spacer(1, 0.2*inch))
        
        severity_pie_data = {
            'Critical': severity_current['critical'],
            'High': severity_current['high'],
            'Medium': severity_current['medium'],
            'Low': severity_current['low']
        }
        
        severity_pie = create_pie_chart(severity_pie_data, "Finding Severity Breakdown")
        elements.append(severity_pie)
        elements.append(Spacer(1, 0.3*inch))
        
        # ========== MTTR METRICS ==========
        
        if mttr_days > 0:
            elements.append(Paragraph("Mean Time To Remediate (MTTR)", heading_style))
            elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#3498db')))
            elements.append(Spacer(1, 0.2*inch))
            
            mttr_data = [
                ['Metric', 'Value', 'Note'],
                ['Overall MTTR', f"{mttr_days} days", f"{len(fixed_findings)} findings resolved"],
                ['Critical MTTR', f"{mttr_critical} days" if mttr_critical > 0 else 'N/A', 'Average for critical severity']
            ]
            
            mttr_table = Table(mttr_data, colWidths=[2*inch, 2*inch, 2.5*inch])
            mttr_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 11),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
                ('FONTSIZE', (0, 1), (-1, -1), 9)
            ]))
            
            elements.append(mttr_table)
            elements.append(Spacer(1, 0.3*inch))
        
        # 12-Week Trend Line Chart
        elements.append(Paragraph("12-Week Vulnerability Trends", heading_style))
        elements.append(Spacer(1, 0.2*inch))
        
        trend_chart = create_line_chart(weekly_trends, "Vulnerability Trends (12 Weeks)")
        elements.append(trend_chart)
        elements.append(Spacer(1, 0.3*inch))
        
        # ========== PAGE BREAK ==========
        elements.append(PageBreak())
        
        # ========== PAGE 3: TOP VULNERABILITIES CHART ==========
        
        if top_vulns:
            elements.append(Paragraph("Top 10 Vulnerabilities by Asset Count", heading_style))
            elements.append(Spacer(1, 0.2*inch))
            
            vuln_chart = create_horizontal_bar_chart(top_vulns, "Most Widespread Vulnerabilities")
            elements.append(vuln_chart)
            elements.append(Spacer(1, 0.4*inch))
        
        # ========== GRC COMPLIANCE FRAMEWORKS CHART ==========
        
        if grc_summary:
            elements.append(Paragraph("GRC Compliance Frameworks Impacted", heading_style))
            elements.append(Spacer(1, 0.2*inch))
            
            grc_chart = create_grc_bar_chart(grc_summary, "Compliance Framework Impact")
            elements.append(grc_chart)
            elements.append(Spacer(1, 0.4*inch))
        
        # ========== SLA COMPLIANCE SECTION ==========
        elements.append(PageBreak())
        
        # SLA Header
        elements.append(Paragraph(
            '<font size="16" color="#2c3e50"><b>SLA Compliance Status</b></font>',
            heading_style
        ))
        elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#3498db')))
        elements.append(Spacer(1, 0.2*inch))
        
        # SLA Policy Description
        elements.append(Paragraph(
            '<font size="10" color="#34495e"><b>Service Level Agreement:</b> 30 days for Critical/High severity, 180 days for Medium/Low severity</font>',
            body_style
        ))
        elements.append(Spacer(1, 0.2*inch))
        
        # SLA Metrics Table
        sla_metrics_data = [
            ['Metric', 'Value', 'Status'],
            ['Total Findings', str(sla_compliance['total_findings']), ''],
            ['Within SLA', str(sla_compliance['within_sla']), 'Compliant'],
            ['Exceeding SLA', str(sla_compliance['exceeding_sla']), 'Overdue'],
            ['Compliance Rate', f"{sla_compliance['compliance_percentage']}%", 
             'Excellent' if sla_compliance['compliance_percentage'] >= 90 else 
             'Good' if sla_compliance['compliance_percentage'] >= 70 else 'Needs Attention']
        ]
        
        sla_metrics_table = Table(sla_metrics_data, colWidths=[2.5*inch, 1.5*inch, 2*inch])
        sla_metrics_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#bdc3c7')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#ecf0f1')]),
        ]))
        elements.append(sla_metrics_table)
        elements.append(Spacer(1, 0.3*inch))
        
        # SLA Breakdown by Severity
        elements.append(Paragraph(
            '<font size="12" color="#2c3e50"><b>SLA Violations by Severity</b></font>',
            heading_style
        ))
        elements.append(Spacer(1, 0.1*inch))
        
        sla_severity_data = [
            ['Severity', 'SLA Period', 'Exceeding SLA', 'Status'],
            ['Critical', '30 days', str(sla_compliance['critical_exceeding']), 
             'Compliant' if sla_compliance['critical_exceeding'] == 0 else f"{sla_compliance['critical_exceeding']} Violation(s)"],
            ['High', '30 days', str(sla_compliance['high_exceeding']),
             'Compliant' if sla_compliance['high_exceeding'] == 0 else f"{sla_compliance['high_exceeding']} Violation(s)"],
            ['Medium', '180 days', str(sla_compliance['medium_exceeding']),
             'Compliant' if sla_compliance['medium_exceeding'] == 0 else f"{sla_compliance['medium_exceeding']} Violation(s)"],
            ['Low', '180 days', str(sla_compliance['low_exceeding']),
             'Compliant' if sla_compliance['low_exceeding'] == 0 else f"{sla_compliance['low_exceeding']} Violation(s)"]
        ]
        
        sla_severity_table = Table(sla_severity_data, colWidths=[1.5*inch, 1.5*inch, 1.5*inch, 2*inch])
        sla_severity_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#bdc3c7')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#ecf0f1')]),
        ]))
        elements.append(sla_severity_table)
        elements.append(Spacer(1, 0.3*inch))
        
        # Top SLA Violations Table
        if sla_compliance['exceeding_findings']:
            elements.append(Paragraph(
                '<font size="12" color="#2c3e50"><b>Top 15 SLA Violations (Most Overdue)</b></font>',
                heading_style
            ))
            elements.append(Spacer(1, 0.1*inch))
            
            sla_violations_data = [
                ['Rank', 'Vulnerability', 'Asset', 'Severity', 'Age', 'SLA', 'Overdue']
            ]
            
            for idx, finding in enumerate(sla_compliance['exceeding_findings'][:15], 1):
                vuln_name = finding['plugin_name'][:40] + '...' if len(finding['plugin_name']) > 40 else finding['plugin_name']
                asset_name = finding['asset_hostname'][:20] + '...' if len(finding['asset_hostname']) > 20 else finding['asset_hostname']
                
                sla_violations_data.append([
                    str(idx),
                    vuln_name,
                    asset_name,
                    finding['severity'].upper(),
                    str(finding['age_days']),
                    str(finding['sla_days']),
                    f"+{finding['days_overdue']}"
                ])
            
            sla_violations_table = Table(sla_violations_data, 
                                        colWidths=[0.4*inch, 2.2*inch, 1.3*inch, 0.7*inch, 0.5*inch, 0.5*inch, 0.6*inch])
            sla_violations_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 1), (-1, -1), 7),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#bdc3c7')),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#ecf0f1')]),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            elements.append(sla_violations_table)
            
            if len(sla_compliance['exceeding_findings']) > 15:
                elements.append(Spacer(1, 0.1*inch))
                elements.append(Paragraph(
                    f'<font size="9" color="#7f8c8d"><i>Showing top 15 violations. {len(sla_compliance["exceeding_findings"]) - 15} additional findings are exceeding SLA.</i></font>',
                    body_style
                ))
        else:
            elements.append(Paragraph(
                '<font size="10" color="#229954"><b>✓ Excellent! All findings are currently within SLA compliance periods.</b></font>',
                body_style
            ))
        
        elements.append(Spacer(1, 0.3*inch))
        # ========== END SLA COMPLIANCE SECTION ==========
        
        # ========== PAGE BREAK ==========
        elements.append(PageBreak())
        
        # ========== PAGE 4: DETAILED TABLES ==========
        
        # GRC Table
        if grc_summary:
            elements.append(Paragraph("GRC Compliance Frameworks - Detailed View", heading_style))
            elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#3498db')))
            elements.append(Spacer(1, 0.2*inch))
            
            grc_data = [['Framework', 'Total', 'Critical', 'High', 'Requirements']]
            
            sorted_grc = sorted(grc_summary.items(), 
                              key=lambda x: (x[1]['critical'], x[1]['high'], x[1]['total_findings']), 
                              reverse=True)
            
            for framework, data in sorted_grc[:10]:
                fw_name = framework if len(framework) <= 20 else framework[:17] + "..."
                grc_data.append([
                    fw_name,
                    str(data['total_findings']),
                    str(data['critical']),
                    str(data['high']),
                    str(data['requirements_count'])
                ])
            
            grc_table = Table(grc_data, colWidths=[2*inch, 1*inch, 1*inch, 1*inch, 1.5*inch])
            grc_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
                ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
                ('FONTSIZE', (0, 1), (-1, -1), 8)
            ]))
            
            elements.append(grc_table)
            elements.append(Spacer(1, 0.4*inch))
        
        # NIST Controls
        if nist_controls:
            elements.append(Paragraph("NIST 800-53 Controls - Most Affected", heading_style))
            elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#3498db')))
            elements.append(Spacer(1, 0.2*inch))
            
            nist_data = [['Control ID', 'Critical', 'High', 'Total', 'Assets']]
            
            for control in nist_controls[:12]:
                control_id = control['control_id'] if len(control['control_id']) <= 15 else control['control_id'][:12] + "..."
                nist_data.append([
                    control_id,
                    str(control['critical']),
                    str(control['high']),
                    str(control['total_findings']),
                    str(control['affected_assets'])
                ])
            
            nist_table = Table(nist_data, colWidths=[2*inch, 1*inch, 1*inch, 1*inch, 1.5*inch])
            nist_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
                ('FONTSIZE', (0, 1), (-1, -1), 8)
            ]))
            
            elements.append(nist_table)
            elements.append(Spacer(1, 0.3*inch))
        
        # ========== PAGE BREAK ==========
        elements.append(PageBreak())
        
        # ========== PAGE 5: CLOUD SECURITY & EXECUTIVE SUMMARY ==========
        
        # Cloud Security Section
        if cloud_summary['total_findings'] > 0:
            elements.append(Paragraph("Cloud Security Findings", heading_style))
            elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#3498db')))
            elements.append(Spacer(1, 0.2*inch))
            
            cloud_data = [
                ['Metric', 'Value', 'Details'],
                ['Total Cloud Findings', str(cloud_summary['total_findings']), f"{cloud_summary['total_resources']} resources affected"],
                ['Critical Issues', str(cloud_summary['critical']), 'Immediate action required'],
                ['High Issues', str(cloud_summary['high']), 'High priority'],
                ['AWS Findings', str(cloud_summary['aws_findings']), f"{cloud_assets['aws']} VM assets"],
                ['Azure Findings', str(cloud_summary['azure_findings']), f"{cloud_assets['azure']} VM assets"],
                ['GCP Findings', str(cloud_summary['gcp_findings']), f"{cloud_assets['gcp']} VM assets"]
            ]
            
            cloud_table = Table(cloud_data, colWidths=[2.2*inch, 1.8*inch, 2.5*inch])
            cloud_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 11),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
                ('FONTSIZE', (0, 1), (-1, -1), 9)
            ]))
            
            elements.append(cloud_table)
            elements.append(Spacer(1, 0.4*inch))
        
        # ========== EXECUTIVE SUMMARY ==========
        
        elements.append(Paragraph("Executive Summary", heading_style))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#3498db')))
        elements.append(Spacer(1, 0.2*inch))
        
        trend_direction = 'increased' if trends['total'] > 0 else 'decreased'
        risk_level = 'high' if risk_score > 70 else 'moderate' if risk_score > 40 else 'low'
        attention_level = 'immediate' if risk_score > 70 else 'prompt' if risk_score > 40 else 'continued'
        
        summary_text = f"""<b>Security Posture:</b> The organization currently has <b>{total_current}</b> active security findings across <b>{total_assets}</b> managed assets, with <b>{critical_assets}</b> assets containing critical vulnerabilities.<br/><br/>
<b>Critical Issues:</b> There are <b>{severity_current['critical']}</b> critical vulnerabilities requiring immediate attention and <b>{severity_current['high']}</b> high-priority issues.<br/><br/>
<b>Trend Analysis:</b> Findings have {trend_direction} by <b>{abs(trends['total']):.1f}%</b> compared to the previous 30-day period. Critical findings are {('up' if trends['critical'] > 0 else 'down')} <b>{abs(trends['critical']):.1f}%</b>.<br/><br/>
<b>Risk Assessment:</b> The current risk score is <b>{round(risk_score, 1)}/100</b>, indicating {risk_level} risk exposure that requires {attention_level} attention from leadership."""
        
        if attack_path_findings > 0:
            summary_text += f"<br/><br/><b>Attack Surface:</b> <b>{attack_path_findings}</b> vulnerabilities are part of identified attack paths, representing elevated risk."
        
        if mttr_days > 0:
            summary_text += f"<br/><br/><b>Remediation Performance:</b> The mean time to remediate vulnerabilities is <b>{mttr_days} days</b> overall, with critical issues resolved in an average of <b>{mttr_critical} days</b>."
        
        if grc_summary:
            summary_text += f"<br/><br/><b>Compliance Impact:</b> <b>{len(grc_summary)}</b> regulatory frameworks are impacted by current findings, affecting <b>{total_requirements}</b> compliance requirements. The compliance score is <b>{round(compliance_score, 1)}/100</b>."
        
        if cloud_summary['total_findings'] > 0:
            summary_text += f"<br/><br/><b>Cloud Security:</b> <b>{cloud_summary['total_findings']}</b> cloud-specific findings have been identified across <b>{total_cloud_assets}</b> cloud assets (AWS: {cloud_assets['aws']}, Azure: {cloud_assets['azure']}, GCP: {cloud_assets['gcp']})."
        
        summary_text += f"<br/><br/><b>Recommendations:</b><br/>"
        
        if severity_current['critical'] > 0:
            summary_text += f"• Prioritize remediation of {severity_current['critical']} critical findings<br/>"
        if attack_path_findings > 0:
            summary_text += f"• Address {attack_path_findings} attack path vulnerabilities to reduce exploit risk<br/>"
        if compliance_score < 75:
            summary_text += f"• Improve compliance posture (current score: {round(compliance_score, 1)}/100)<br/>"
        if mttr_critical > 30:
            summary_text += f"• Reduce MTTR for critical issues (currently {mttr_critical} days)<br/>"
        if cloud_summary['critical'] > 0:
            summary_text += f"• Remediate {cloud_summary['critical']} critical cloud security findings<br/>"
        
        elements.append(Paragraph(summary_text, normal_style))
        elements.append(Spacer(1, 0.5*inch))
        
        # ========== FOOTER ==========
        
        elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#ecf0f1')))
        elements.append(Spacer(1, 0.2*inch))
        elements.append(
            Paragraph(
                f"<b>Confidential - Executive Leadership</b><br/>{COMPANY_NAME} | Vulnerability Management Dashboard | Generated by Security Operations",
                ParagraphStyle('footer', parent=normal_style, alignment=TA_CENTER, textColor=colors.grey, fontSize=8)
            )
        )
        
        # ========== BUILD PDF ==========
        
        doc.build(elements)
        pdf_data = buffer.getvalue()
        buffer.close()
        
        response = make_response(pdf_data)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename=executive_security_report_{now.strftime("%Y%m%d")}.pdf'
        
        current_app.logger.info(f"Enhanced executive dashboard PDF with charts generated successfully - Risk: {risk_score:.1f}, Compliance: {compliance_score:.1f}")
        return response
        
    except ImportError as e:
        current_app.logger.error(f"ReportLab not installed: {e}")
        from flask import jsonify
        return jsonify({
            'error': 'PDF generation requires ReportLab library',
            'install': 'pip install reportlab',
            'details': str(e)
        }), 500
    except Exception as e:
        current_app.logger.error(f"Error generating PDF: {e}")
        traceback.print_exc()
        from flask import jsonify
        return jsonify({'error': str(e)}), 500