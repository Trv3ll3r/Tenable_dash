from flask import Blueprint, render_template, request, jsonify, current_app, make_response
from sqlalchemy.orm import subqueryload
from sqlalchemy import desc, func, case, or_
from datetime import datetime, timedelta, timezone
from collections import defaultdict
import json
import traceback
import io
import os

from ..database import db
from ..models import VulnerabilityFinding, AttackPathFinding, WASFinding, CloudFinding, PluginComplianceMapping, ComplianceRequirement

main_bp = Blueprint('main', __name__)


def get_grc_summary_for_findings(findings):
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


def get_dashboard_metrics():
    try:
        thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
        base_query = db.session.query(VulnerabilityFinding).filter(
            VulnerabilityFinding.state.in_(['OPEN', 'REOPENED']),
            VulnerabilityFinding.severity.notin_(['info']),
            VulnerabilityFinding.last_found >= thirty_days_ago
        )
        
        total_active = base_query.count()
        
        severity_counts = {}
        for sev in ['critical', 'high', 'medium', 'low']:
            count = base_query.filter(VulnerabilityFinding.severity == sev).count()
            severity_counts[sev] = count
        
        attack_path_count = base_query.filter(VulnerabilityFinding.is_in_attack_path == True).count()
        
        cloud_counts = {
            'aws': base_query.filter(VulnerabilityFinding.asset_aws_ec2_instance_id.isnot(None)).count(),
            'azure': base_query.filter(VulnerabilityFinding.asset_azure_vm_id.isnot(None)).count(),
            'gcp': base_query.filter(VulnerabilityFinding.asset_gcp_instance_id.isnot(None)).count()
        }
        
        try:
            cloud_findings_count = db.session.query(CloudFinding).filter(
                CloudFinding.status == 'Open'
            ).count()
            cloud_counts['tcs'] = cloud_findings_count
        except Exception as e:
            current_app.logger.debug(f"CloudFinding table query failed: {e}")
            cloud_counts['tcs'] = 0
        
        top_assets_query = base_query.with_entities(
            func.coalesce(VulnerabilityFinding.asset_hostname, VulnerabilityFinding.asset_ipv4, 'Unknown').label('asset'),
            func.count().label('count')
        ).group_by(
            func.coalesce(VulnerabilityFinding.asset_hostname, VulnerabilityFinding.asset_ipv4, 'Unknown')
        ).order_by(func.count().desc()).limit(5)
        
        top_assets = [{'asset': row.asset, 'count': row.count} for row in top_assets_query.all()]
        
        top_plugins_query = base_query.with_entities(
            VulnerabilityFinding.plugin_name.label('plugin'),
            func.count().label('count')
        ).group_by(
            VulnerabilityFinding.plugin_id,
            VulnerabilityFinding.plugin_name
        ).order_by(func.count().desc()).limit(5)
        
        top_plugins = []
        for row in top_plugins_query.all():
            plugin_name = row.plugin or "Unknown"
            if len(plugin_name) > 35:
                plugin_name = plugin_name[:32] + "..."
            top_plugins.append({'plugin': plugin_name, 'count': row.count})
        
        return {
            'total_active_findings': total_active,
            'severity_counts': severity_counts,
            'attack_path_findings': attack_path_count,
            'cloud_counts': cloud_counts,
            'top_assets': top_assets,
            'top_plugins': top_plugins
        }
    except Exception as e:
        current_app.logger.error(f"Error calculating dashboard metrics: {e}")
        return {
            'total_active_findings': 0,
            'severity_counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'attack_path_findings': 0,
            'cloud_counts': {'aws': 0, 'azure': 0, 'gcp': 0, 'tcs': 0},
            'top_assets': [],
            'top_plugins': []
        }


@main_bp.route('/debug_grc')
def debug_grc():
    try:
        debug_info = {
            'timestamp': datetime.now().isoformat(),
            'grc_statistics': {},
            'sample_mappings': [],
            'sample_findings': [],
            'matching_analysis': {}
        }
        
        total_requirements = db.session.query(ComplianceRequirement).count()
        total_mappings = db.session.query(PluginComplianceMapping).count()
        debug_info['grc_statistics'] = {
            'total_requirements': total_requirements,
            'total_plugin_mappings': total_mappings
        }
        
        sample_mappings = db.session.query(PluginComplianceMapping).join(ComplianceRequirement).limit(20).all()
        for mapping in sample_mappings:
            debug_info['sample_mappings'].append({
                'plugin_id': mapping.plugin_id,
                'framework': mapping.compliance_requirement.framework if mapping.compliance_requirement else None,
                'requirement_id': mapping.compliance_requirement.requirement_id if mapping.compliance_requirement else None
            })
        
        mapped_plugin_ids = db.session.query(PluginComplianceMapping.plugin_id).distinct().all()
        mapped_plugin_ids = [pid[0] for pid in mapped_plugin_ids]
        debug_info['grc_statistics']['unique_plugins_mapped'] = len(mapped_plugin_ids)
        debug_info['grc_statistics']['sample_mapped_plugin_ids'] = mapped_plugin_ids[:20]
        
        thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
        sample_findings = db.session.query(VulnerabilityFinding).filter(
            VulnerabilityFinding.state.in_(['OPEN', 'REOPENED']),
            VulnerabilityFinding.last_found >= thirty_days_ago
        ).limit(20).all()
        
        for finding in sample_findings:
            debug_info['sample_findings'].append({
                'id': finding.id,
                'plugin_id': finding.plugin_id,
                'plugin_name': finding.plugin_name,
                'severity': finding.severity,
                'has_mappings': len(finding.plugin_compliance_mappings) > 0,
                'mapping_count': len(finding.plugin_compliance_mappings)
            })
        
        finding_plugin_ids = db.session.query(VulnerabilityFinding.plugin_id).filter(
            VulnerabilityFinding.state.in_(['OPEN', 'REOPENED']),
            VulnerabilityFinding.last_found >= thirty_days_ago
        ).distinct().all()
        finding_plugin_ids = [pid[0] for pid in finding_plugin_ids]
        debug_info['grc_statistics']['unique_plugins_in_findings'] = len(finding_plugin_ids)
        debug_info['grc_statistics']['sample_finding_plugin_ids'] = finding_plugin_ids[:20]
        
        mapped_set = set(mapped_plugin_ids)
        finding_set = set(finding_plugin_ids)
        overlap = mapped_set.intersection(finding_set)
        
        debug_info['matching_analysis'] = {
            'total_mapped_plugins': len(mapped_set),
            'total_finding_plugins': len(finding_set),
            'overlapping_plugins': len(overlap),
            'overlap_percentage': round(len(overlap) / len(finding_set) * 100, 2) if finding_set else 0,
            'sample_overlapping_plugin_ids': list(overlap)[:20]
        }
        
        findings_with_grc = db.session.query(VulnerabilityFinding).join(
            PluginComplianceMapping,
            VulnerabilityFinding.plugin_id == PluginComplianceMapping.plugin_id
        ).filter(
            VulnerabilityFinding.state.in_(['OPEN', 'REOPENED']),
            VulnerabilityFinding.last_found >= thirty_days_ago
        ).count()
        debug_info['matching_analysis']['findings_with_grc_mappings'] = findings_with_grc
        
        findings_with_mappings = db.session.query(VulnerabilityFinding).options(
            subqueryload(VulnerabilityFinding.plugin_compliance_mappings).subqueryload(PluginComplianceMapping.compliance_requirement)
        ).filter(
            VulnerabilityFinding.state.in_(['OPEN', 'REOPENED']),
            VulnerabilityFinding.last_found >= thirty_days_ago
        ).limit(100).all()
        
        examples_with_mappings = []
        for finding in findings_with_mappings:
            if finding.plugin_compliance_mappings:
                examples_with_mappings.append({
                    'plugin_id': finding.plugin_id,
                    'plugin_name': finding.plugin_name,
                    'mappings': [
                        {
                            'framework': m.compliance_requirement.framework,
                            'requirement_id': m.compliance_requirement.requirement_id
                        }
                        for m in finding.plugin_compliance_mappings
                        if m.compliance_requirement
                    ]
                })
                if len(examples_with_mappings) >= 10:
                    break
        
        debug_info['examples_with_grc'] = examples_with_mappings
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>GRC Mapping Debug</title>
    <style>
        body {{
            font-family: monospace;
            padding: 20px;
            background: #1a1a1a;
            color: #00ff00;
        }}
        .section {{
            margin: 20px 0;
            padding: 15px;
            background: #2a2a2a;
            border-left: 4px solid #00ff00;
        }}
        .good {{ color: #00ff00; }}
        .warning {{ color: #ffaa00; }}
        .bad {{ color: #ff0000; }}
        h2 {{ color: #00aaff; }}
        pre {{
            background: #000;
            padding: 10px;
            overflow-x: auto;
            color: #00ff00;
        }}
        .stat {{
            display: inline-block;
            margin: 10px 20px 10px 0;
            padding: 10px 15px;
            background: #333;
            border-radius: 5px;
        }}
    </style>
</head>
<body>
    <h1>GRC MAPPING DEBUG REPORT</h1>
    <p>Generated: {debug_info['timestamp']}</p>
    
    <div class="section">
        <h2>GRC Statistics</h2>
        <div class="stat">
            <strong>Total Requirements:</strong>
            <span class="{'good' if total_requirements > 0 else 'bad'}">{total_requirements}</span>
        </div>
        <div class="stat">
            <strong>Total Plugin Mappings:</strong>
            <span class="{'good' if total_mappings > 0 else 'bad'}">{total_mappings}</span>
        </div>
    </div>
    
    <div class="section">
        <h2>Full JSON Data</h2>
        <pre>{json.dumps(debug_info, indent=2, default=str)}</pre>
    </div>
</body>
</html>"""
        return html
    except Exception as e:
        return f"""<html>
<body style="font-family: monospace; background: #1a1a1a; color: #ff0000; padding: 20px;">
    <h1>Error in GRC Debug</h1>
    <pre>{str(e)}</pre>
    <pre>{traceback.format_exc()}</pre>
</body>
</html>""", 500


@main_bp.route('/')
def dashboard():
    try:
        current_app.logger.info(f"Dashboard request - Severity: {request.args.get('severity')}")
        
        query = db.session.query(VulnerabilityFinding)
        selected_severity = request.args.get('severity', 'actionable')
        selected_state = request.args.get('state', 'active')
        selected_time_period = request.args.get('time_period', '30_days')
        sort_by = request.args.get('sort_by', 'last_found')
        sort_direction = request.args.get('sort_direction', 'desc')
        
        if selected_state == 'active':
            query = query.filter(VulnerabilityFinding.state.in_(['OPEN', 'REOPENED']))
        elif selected_state == 'fixed':
            query = query.filter(VulnerabilityFinding.state == 'FIXED')
        
        if selected_severity == 'actionable' or not selected_severity:
            query = query.filter(VulnerabilityFinding.severity.notin_(['info']))
        elif selected_severity in ['critical', 'high', 'medium', 'low']:
            query = query.filter(VulnerabilityFinding.severity == selected_severity)
        elif selected_severity == 'include_info':
            pass
        
        if selected_time_period == '30_days':
            thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
            query = query.filter(VulnerabilityFinding.last_found >= thirty_days_ago)
        elif selected_time_period == '7_days':
            seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
            query = query.filter(VulnerabilityFinding.last_found >= seven_days_ago)
        
        if sort_by == 'severity':
            severity_order = case(
                (VulnerabilityFinding.severity == 'critical', 4),
                (VulnerabilityFinding.severity == 'high', 3),
                (VulnerabilityFinding.severity == 'medium', 2),
                (VulnerabilityFinding.severity == 'low', 1),
                else_=0
            )
            if sort_direction == 'asc':
                query = query.order_by(severity_order.asc())
            else:
                query = query.order_by(severity_order.desc())
        else:
            sort_column = getattr(VulnerabilityFinding, sort_by, VulnerabilityFinding.last_found)
            if sort_direction == 'asc':
                query = query.order_by(sort_column.asc().nullslast())
            else:
                query = query.order_by(sort_column.desc().nullsfirst())
        
        query = query.options(
            subqueryload(VulnerabilityFinding.plugin_compliance_mappings).subqueryload(PluginComplianceMapping.compliance_requirement)
        )
        
        findings = query.all()
        current_app.logger.info(f"Retrieved {len(findings)} filtered VM findings")
        
        vm_grc_summary = get_grc_summary_for_findings(findings)
        
        was_query = db.session.query(WASFinding).filter(WASFinding.status == 'Active').options(
            subqueryload(WASFinding.plugin_compliance_mappings).subqueryload(PluginComplianceMapping.compliance_requirement)
        )
        was_findings = was_query.all()
        was_grc_summary = get_grc_summary_for_findings(was_findings)
        
        attack_path_findings = db.session.query(AttackPathFinding).order_by(
            AttackPathFinding.path_risk_score.desc()
        ).limit(10).all()
        
        dashboard_data = get_dashboard_metrics()
        
        return render_template(
            'index.html',
            findings=findings,
            was_findings=was_findings,
            attack_path_findings=attack_path_findings,
            dashboard_data=dashboard_data,
            vm_grc_summary=vm_grc_summary,
            was_grc_summary=was_grc_summary,
            selected_severity=selected_severity,
            selected_state=selected_state,
            selected_time_period=selected_time_period,
            sort_by=sort_by,
            sort_direction=sort_direction
        )
    except Exception as e:
        current_app.logger.error(f"Dashboard error: {e}")
        traceback.print_exc()
        return f"Error loading dashboard: {str(e)}", 500


@main_bp.route('/cloud_findings')
def cloud_findings():
    """Display cloud security findings from Tenable Cloud Security"""
    try:
        selected_severity = request.args.get('severity', 'all')
        selected_status = request.args.get('status', 'all')
        selected_cloud_provider = request.args.get('cloud_provider', 'all')
        selected_time_period = request.args.get('time_period', 'all')
        sort_by = request.args.get('sort_by', 'created_at')
        sort_direction = request.args.get('sort_direction', 'desc')
        
        query = db.session.query(CloudFinding)
        
        total_in_db = db.session.query(CloudFinding).count()
        current_app.logger.info(f"Total CloudFindings in database: {total_in_db}")
        
        if selected_status == 'open':
            query = query.filter(
                or_(
                    CloudFinding.status == 'Open',
                    CloudFinding.status == 'OPEN',
                    CloudFinding.status == 'open'
                )
            )
        elif selected_status == 'closed':
            query = query.filter(
                or_(
                    CloudFinding.status.in_(['Closed', 'Resolved', 'Fixed']),
                    CloudFinding.status.in_(['CLOSED', 'RESOLVED', 'FIXED']),
                    CloudFinding.status.in_(['closed', 'resolved', 'fixed'])
                )
            )
        
        if selected_severity != 'all':
            sev = selected_severity.lower()
            query = query.filter(
                or_(
                    CloudFinding.severity == selected_severity.capitalize(),
                    CloudFinding.severity == selected_severity.upper(),
                    CloudFinding.severity == sev
                )
            )
        
        if selected_cloud_provider != 'all':
            query = query.filter(
                or_(
                    CloudFinding.cloud_provider == selected_cloud_provider.upper(),
                    CloudFinding.cloud_provider == selected_cloud_provider.capitalize(),
                    CloudFinding.cloud_provider == selected_cloud_provider.lower()
                )
            )
        
        if selected_time_period == '30_days':
            thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
            query = query.filter(CloudFinding.created_at >= thirty_days_ago)
        elif selected_time_period == '7_days':
            seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
            query = query.filter(CloudFinding.created_at >= seven_days_ago)
        
        if sort_by == 'severity':
            severity_order = case(
                (CloudFinding.severity.in_(['Critical', 'CRITICAL', 'critical']), 4),
                (CloudFinding.severity.in_(['High', 'HIGH', 'high']), 3),
                (CloudFinding.severity.in_(['Medium', 'MEDIUM', 'medium']), 2),
                (CloudFinding.severity.in_(['Low', 'LOW', 'low']), 1),
                else_=0
            )
            if sort_direction == 'asc':
                query = query.order_by(severity_order.asc())
            else:
                query = query.order_by(severity_order.desc())
        else:
            sort_column = getattr(CloudFinding, sort_by, CloudFinding.created_at)
            if sort_direction == 'asc':
                query = query.order_by(sort_column.asc().nullslast())
            else:
                query = query.order_by(sort_column.desc().nullsfirst())
        
        cloud_findings_list = query.all()
        
        current_app.logger.info(f"Retrieved {len(cloud_findings_list)} cloud findings after filters")
        
        cloud_stats = {
            'total': len(cloud_findings_list),
            'aws': len([f for f in cloud_findings_list if f.cloud_provider and f.cloud_provider.upper() == 'AWS']),
            'azure': len([f for f in cloud_findings_list if f.cloud_provider and f.cloud_provider.upper() == 'AZURE']),
            'gcp': len([f for f in cloud_findings_list if f.cloud_provider and f.cloud_provider.upper() == 'GCP']),
            'critical': len([f for f in cloud_findings_list if f.severity and f.severity.lower() == 'critical']),
            'high': len([f for f in cloud_findings_list if f.severity and f.severity.lower() == 'high']),
            'medium': len([f for f in cloud_findings_list if f.severity and f.severity.lower() == 'medium']),
            'low': len([f for f in cloud_findings_list if f.severity and f.severity.lower() == 'low'])
        }
        
        available_providers_raw = db.session.query(CloudFinding.cloud_provider).distinct().all()
        available_providers = list(set([p[0].upper() for p in available_providers_raw if p[0]]))
        
        return render_template(
            'cloud_findings.html',
            cloud_findings=cloud_findings_list,
            cloud_stats=cloud_stats,
            available_providers=available_providers,
            selected_cloud_provider=selected_cloud_provider,
            selected_severity=selected_severity,
            selected_status=selected_status,
            selected_time_period=selected_time_period,
            sort_by=sort_by,
            sort_direction=sort_direction
        )
        
    except Exception as e:
        current_app.logger.error(f"Error in cloud_findings: {e}")
        traceback.print_exc()
        return render_template('error.html', error=str(e)), 500


@main_bp.route('/grouped_findings')
def grouped_findings():
    try:
        selected_severity = request.args.get('severity', 'actionable')
        selected_state = request.args.get('state', 'active')
        selected_time_period = request.args.get('time_period', '30_days')
        selected_ticket_status = request.args.get('ticket_status', 'all')
        
        query = db.session.query(VulnerabilityFinding)
        
        if selected_state == 'active':
            query = query.filter(VulnerabilityFinding.state.in_(['OPEN', 'REOPENED']))
        elif selected_state == 'fixed':
            query = query.filter(VulnerabilityFinding.state == 'FIXED')
        
        if selected_severity == 'actionable' or not selected_severity:
            query = query.filter(VulnerabilityFinding.severity.notin_(['info']))
        elif selected_severity in ['critical', 'high', 'medium', 'low']:
            query = query.filter(VulnerabilityFinding.severity == selected_severity)
        
        if selected_time_period == '30_days':
            thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
            query = query.filter(VulnerabilityFinding.last_found >= thirty_days_ago)
        elif selected_time_period == '7_days':
            seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
            query = query.filter(VulnerabilityFinding.last_found >= seven_days_ago)
        
        if selected_ticket_status == 'without_ticket':
            query = query.filter(
                or_(
                    VulnerabilityFinding.ticket_created == False,
                    VulnerabilityFinding.ticket_created.is_(None)
                )
            )
        elif selected_ticket_status == 'with_ticket':
            query = query.filter(VulnerabilityFinding.ticket_created == True)
        
        query = query.options(
            subqueryload(VulnerabilityFinding.plugin_compliance_mappings).subqueryload(PluginComplianceMapping.compliance_requirement)
        )
        
        all_findings = query.all()
        
        ticket_stats = {
            'with_ticket': sum(1 for f in all_findings if getattr(f, 'ticket_created', False)),
            'without_ticket': sum(1 for f in all_findings if not getattr(f, 'ticket_created', False)),
            'total': len(all_findings)
        }
        
        grouped_grc_summary = get_grc_summary_for_findings(all_findings)
        
        grouped_findings_dict = {}
        for finding in all_findings:
            plugin_key = f"{finding.plugin_id}_{finding.plugin_name or 'Unknown'}"
            
            if plugin_key not in grouped_findings_dict:
                grc_mappings = []
                grc_frameworks = set()
                
                if hasattr(finding, 'plugin_compliance_mappings') and finding.plugin_compliance_mappings:
                    for mapping in finding.plugin_compliance_mappings:
                        if mapping.compliance_requirement:
                            framework = mapping.compliance_requirement.framework
                            grc_frameworks.add(framework)
                            grc_mappings.append({
                                'framework': framework,
                                'requirement_id': mapping.compliance_requirement.requirement_id,
                                'description': mapping.compliance_requirement.description
                            })
                
                has_ticket = finding.ticket_created if hasattr(finding, 'ticket_created') else False
                
                grouped_findings_dict[plugin_key] = {
                    'plugin_id': finding.plugin_id,
                    'plugin_name': finding.plugin_name or 'Unknown Plugin',
                    'severity': finding.severity,
                    'vpr_score': finding.vpr_score,
                    'cvss_score': finding.cvss_v3_base_score,
                    'description': finding.description,
                    'solution': finding.solution,
                    'grc_mappings': grc_mappings,
                    'grc_frameworks': list(grc_frameworks),
                    'affected_assets': [],
                    'asset_count': 0,
                    'first_found': finding.first_found,
                    'last_found': finding.last_found,
                    'has_ticket': has_ticket
                }
            else:
                if hasattr(finding, 'ticket_created') and finding.ticket_created:
                    grouped_findings_dict[plugin_key]['has_ticket'] = True
            
            asset_info = {
                'hostname': finding.asset_hostname,
                'ipv4': finding.asset_ipv4,
                'os': finding.asset_os,
                'state': finding.state,
                'last_found': finding.last_found,
                'aws_instance': finding.asset_aws_ec2_instance_id,
                'azure_vm': finding.asset_azure_vm_id,
                'gcp_instance': finding.asset_gcp_instance_id,
                'finding_id': finding.id
            }
            grouped_findings_dict[plugin_key]['affected_assets'].append(asset_info)
            grouped_findings_dict[plugin_key]['asset_count'] += 1
            
            if finding.first_found and (
                not grouped_findings_dict[plugin_key]['first_found'] or 
                finding.first_found < grouped_findings_dict[plugin_key]['first_found']
            ):
                grouped_findings_dict[plugin_key]['first_found'] = finding.first_found
            
            if finding.last_found and (
                not grouped_findings_dict[plugin_key]['last_found'] or 
                finding.last_found > grouped_findings_dict[plugin_key]['last_found']
            ):
                grouped_findings_dict[plugin_key]['last_found'] = finding.last_found
        
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
        grouped_list = list(grouped_findings_dict.values())
        grouped_list.sort(
            key=lambda x: (severity_order.get(x['severity'], 0), x['asset_count']),
            reverse=True
        )
        
        return render_template(
            'grouped_findings.html',
            grouped_findings=grouped_list,
            grouped_grc_summary=grouped_grc_summary,
            ticket_stats=ticket_stats,
            selected_severity=selected_severity,
            selected_state=selected_state,
            selected_time_period=selected_time_period,
            selected_ticket_status=selected_ticket_status,
            total_groups=len(grouped_list),
            total_assets=sum(g['asset_count'] for g in grouped_list)
        )
    except Exception as e:
        current_app.logger.error(f"Error in grouped_findings: {e}")
        traceback.print_exc()
        return render_template('error.html', error=str(e)), 500


@main_bp.route('/toggle_ticket/<int:plugin_id>', methods=['POST'])
def toggle_ticket(plugin_id):
    try:
        data = request.get_json()
        ticket_created = data.get('ticket_created', False)
        
        findings = db.session.query(VulnerabilityFinding).filter(
            VulnerabilityFinding.plugin_id == plugin_id
        ).all()
        
        for finding in findings:
            finding.ticket_created = ticket_created
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'plugin_id': plugin_id,
            'ticket_created': ticket_created,
            'updated_count': len(findings)
        })
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error toggling ticket status: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@main_bp.route('/auto_clear_fixed_tickets', methods=['POST'])
def auto_clear_fixed_tickets():
    try:
        fixed_with_tickets = db.session.query(VulnerabilityFinding).filter(
            VulnerabilityFinding.state == 'FIXED',
            VulnerabilityFinding.ticket_created == True
        ).all()
        
        cleared_count = 0
        for finding in fixed_with_tickets:
            finding.ticket_created = False
            cleared_count += 1
        
        db.session.commit()
        
        return jsonify({'success': True, 'cleared_count': cleared_count})
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error clearing fixed tickets: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@main_bp.route('/was_findings')
def was_findings():
    try:
        selected_severity = request.args.get('severity', 'all')
        selected_status = request.args.get('status', 'active')
        selected_url_filter = request.args.get('subdomain', 'all')
        sort_by = request.args.get('sort_by', 'last_detected')
        sort_direction = request.args.get('sort_direction', 'desc')
        
        query = db.session.query(WASFinding)
        
        if selected_status == 'active':
            query = query.filter(WASFinding.status == 'Active')
        elif selected_status == 'fixed':
            query = query.filter(WASFinding.status == 'Fixed')
        
        if selected_severity != 'all':
            query = query.filter(WASFinding.severity == selected_severity)
        
        if selected_url_filter != 'all':
            query = query.filter(WASFinding.target_url.ilike(f"%{selected_url_filter}%"))
        
        query = query.options(
            subqueryload(WASFinding.plugin_compliance_mappings).subqueryload(PluginComplianceMapping.compliance_requirement)
        )
        
        if sort_by == 'severity':
            severity_order = case(
                (WASFinding.severity == 'critical', 4),
                (WASFinding.severity == 'high', 3),
                (WASFinding.severity == 'medium', 2),
                (WASFinding.severity == 'low', 1),
                else_=0
            )
            if sort_direction == 'asc':
                query = query.order_by(severity_order.asc())
            else:
                query = query.order_by(severity_order.desc())
        elif sort_by == 'subdomain' or sort_by == 'target_url':
            if sort_direction == 'asc':
                query = query.order_by(WASFinding.target_url.asc().nullslast())
            else:
                query = query.order_by(WASFinding.target_url.desc().nullsfirst())
        elif sort_by == 'last_detected':
            if sort_direction == 'asc':
                query = query.order_by(WASFinding.last_detected_at.asc().nullslast())
            else:
                query = query.order_by(WASFinding.last_detected_at.desc().nullsfirst())
        elif sort_by == 'vulnerability_name':
            if sort_direction == 'asc':
                query = query.order_by(WASFinding.vulnerability_name.asc().nullslast())
            else:
                query = query.order_by(WASFinding.vulnerability_name.desc().nullsfirst())
        else:
            query = query.order_by(
                case(
                    (WASFinding.severity == 'critical', 4),
                    (WASFinding.severity == 'high', 3),
                    (WASFinding.severity == 'medium', 2),
                    (WASFinding.severity == 'low', 1),
                    else_=0
                ).desc(),
                WASFinding.last_detected_at.desc().nullsfirst()
            )
        
        was_findings_list = query.all()
        
        all_urls_query = db.session.query(WASFinding.target_url).filter(
            WASFinding.target_url.isnot(None)
        ).distinct().all()
        
        available_domains = set()
        for url_tuple in all_urls_query:
            url = url_tuple[0]
            if url:
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    domain = parsed.netloc or parsed.path.split('/')[0]
                    if domain:
                        available_domains.add(domain)
                except:
                    available_domains.add(url)
        
        available_subdomains = sorted(list(available_domains))
        was_specific_grc_summary = get_grc_summary_for_findings(was_findings_list)
        
        return render_template(
            'was_findings.html',
            was_findings=was_findings_list,
            was_specific_grc_summary=was_specific_grc_summary,
            selected_severity=selected_severity,
            selected_status=selected_status,
            selected_subdomain=selected_url_filter,
            available_subdomains=available_subdomains,
            sort_by=sort_by,
            sort_direction=sort_direction
        )
    except Exception as e:
        current_app.logger.error(f"Error in was_findings: {e}")
        traceback.print_exc()
        return render_template('error.html', error=str(e)), 500


@main_bp.route('/executive_dashboard')
def executive_dashboard():
    try:
        current_app.logger.info("Loading executive dashboard")
        now = datetime.now(timezone.utc)
        thirty_days_ago = now - timedelta(days=30)
        sixty_days_ago = now - timedelta(days=60)
        
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
            'high': calculate_trend(severity_current['high'], severity_previous['high']),
            'medium': calculate_trend(severity_current['medium'], severity_previous['medium']),
            'low': calculate_trend(severity_current['low'], severity_previous['low'])
        }
        
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
        
        cloud_assets = {
            'aws': len(set([f.asset_uuid for f in current_findings if f.asset_aws_ec2_instance_id])),
            'azure': len(set([f.asset_uuid for f in current_findings if f.asset_azure_vm_id])),
            'gcp': len(set([f.asset_uuid for f in current_findings if f.asset_gcp_instance_id]))
        }
        total_cloud_assets = cloud_assets['aws'] + cloud_assets['azure'] + cloud_assets['gcp']
        
        attack_path_findings = len([f for f in current_findings if f.is_in_attack_path])
        attack_path_assets = len(set([f.asset_uuid for f in current_findings if f.is_in_attack_path]))
        
        grc_summary = get_grc_summary_for_findings(current_findings)
        
        # ========== IMPROVED COMPLIANCE SCORE CALCULATION ==========
        if grc_summary and len(grc_summary) > 0:
            total_grc_findings = sum(fw['total_findings'] for fw in grc_summary.values())
            total_requirements = sum(fw['requirements_count'] for fw in grc_summary.values())
            
            if total_requirements > 0 and total_current > 0:
                # Calculate percentage of findings that have compliance mappings
                compliance_coverage = (total_grc_findings / total_current) * 100
                
                # Calculate severity-weighted compliance impact
                critical_compliance = sum(fw['critical'] for fw in grc_summary.values())
                high_compliance = sum(fw['high'] for fw in grc_summary.values())
                
                # Weighted impact: more weight on critical/high severity
                compliance_impact = (
                    (critical_compliance * 3) + 
                    (high_compliance * 2) + 
                    (total_grc_findings - critical_compliance - high_compliance)
                ) / total_current
                
                # Score: Higher is better. Reduce score based on impact
                # If 10% of findings affect compliance heavily, score drops significantly
                compliance_score = max(0, min(100, 100 - (compliance_impact * 15)))
            else:
                # If we have requirements but no findings, perfect score
                compliance_score = 100
        else:
            # No GRC data means we can't calculate compliance - show as unknown (75)
            compliance_score = 75
            total_grc_findings = 0
            total_requirements = 0
        
        # ========== IMPROVED RISK SCORE CALCULATION ==========
        # Normalize by assets to get risk density
        if total_assets > 0:
            # Calculate findings per asset
            critical_per_asset = severity_current['critical'] / total_assets
            high_per_asset = severity_current['high'] / total_assets
            medium_per_asset = severity_current['medium'] / total_assets
            
            # Risk calculation: Based on severity density
            # Typical thresholds: <1 critical/asset = good, >3 = bad
            # <5 high/asset = good, >15 = bad
            
            # Critical risk component (0-50 points)
            critical_risk = min(50, critical_per_asset * 15)
            
            # High risk component (0-30 points)
            high_risk = min(30, high_per_asset * 5)
            
            # Medium risk component (0-15 points)  
            medium_risk = min(15, medium_per_asset * 2)
            
            # Total risk (0-95 base, can add +5 for attack paths)
            base_risk = critical_risk + high_risk + medium_risk
            
            # Add bonus risk if attack paths exist
            attack_path_bonus = 5 if attack_path_findings > 0 else 0
            
            risk_score = min(100, base_risk + attack_path_bonus)
        else:
            risk_score = 0
        
        current_app.logger.info(f"Risk Score Calculation: {risk_score:.1f} "
                               f"(Critical: {severity_current['critical']}, High: {severity_current['high']}, Assets: {total_assets})")
        current_app.logger.info(f"Compliance Score Calculation: {compliance_score:.1f} "
                               f"(GRC Findings: {total_grc_findings}/{total_current}, Requirements: {total_requirements})")
        
        plugin_stats = {}
        for finding in current_findings:
            plugin_key = finding.plugin_id
            if plugin_key not in plugin_stats:
                plugin_stats[plugin_key] = {
                    'plugin_name': finding.plugin_name,
                    'severity': finding.severity,
                    'asset_count': 0,
                    'vpr_score': finding.vpr_score
                }
            plugin_stats[plugin_key]['asset_count'] += 1
        
        top_vulns = sorted(plugin_stats.values(), key=lambda x: x['asset_count'], reverse=True)[:10]
        
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
                'week': f"Week {13-week}",
                'total': len(week_findings),
                'critical': len([f for f in week_findings if f.severity == 'critical']),
                'high': len([f for f in week_findings if f.severity == 'high'])
            })
        
        # ========== SLA TRACKING ==========
        # SLA: 30 days for Critical/High, 180 days for Medium/Low/Info
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
                    # Exceeding SLA
                    sla_compliance['exceeding_sla'] += 1
                    sla_compliance[f'{severity}_exceeding'] += 1
                    
                    sla_compliance['exceeding_findings'].append({
                        'plugin_name': finding.plugin_name,
                        'severity': finding.severity,
                        'asset_hostname': finding.asset_hostname or finding.asset_ipv4,
                        'age_days': age_days,
                        'sla_days': sla_days,
                        'days_overdue': age_days - sla_days,
                        'first_found': finding.first_found,
                        'vpr_score': finding.vpr_score
                    })
                else:
                    # Within SLA
                    sla_compliance['within_sla'] += 1

        # Sort exceeding findings by days overdue (most overdue first)
        sla_compliance['exceeding_findings'].sort(key=lambda x: x['days_overdue'], reverse=True)

        # Calculate compliance percentage
        if sla_compliance['total_findings'] > 0:
            sla_compliance['compliance_percentage'] = round(
                (sla_compliance['within_sla'] / sla_compliance['total_findings']) * 100, 1
            )
        else:
            sla_compliance['compliance_percentage'] = 100.0
        
        current_app.logger.info(f"SLA Compliance: {sla_compliance['compliance_percentage']}% "
                               f"({sla_compliance['within_sla']}/{sla_compliance['total_findings']} within SLA, "
                               f"{sla_compliance['exceeding_sla']} exceeding)")
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
                'gcp_findings': len([f for f in all_cloud_findings if f.cloud_provider and f.cloud_provider.upper() == 'GCP']),
                'aws_resources': len(set([f.resource_name for f in all_cloud_findings if f.cloud_provider and f.cloud_provider.upper() == 'AWS' and f.resource_name])),
                'azure_resources': len(set([f.resource_name for f in all_cloud_findings if f.cloud_provider and f.cloud_provider.upper() == 'AZURE' and f.resource_name])),
                'gcp_resources': len(set([f.resource_name for f in all_cloud_findings if f.cloud_provider and f.cloud_provider.upper() == 'GCP' and f.resource_name]))
            }
            
            top_cloud_findings = sorted(
                all_cloud_findings,
                key=lambda x: (
                    {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}.get(x.severity.lower() if x.severity else '', 0),
                    x.risk_score if x.risk_score else 0
                ),
                reverse=True
            )[:10]
            
            current_app.logger.info(f"Cloud Security: {cloud_summary['total_findings']} findings across {cloud_summary['total_resources']} resources")
            
        except Exception as cloud_error:
            current_app.logger.warning(f"Error loading cloud findings for executive dashboard: {cloud_error}")
            cloud_summary = {
                'total_findings': 0,
                'total_resources': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'aws_findings': 0,
                'azure_findings': 0,
                'gcp_findings': 0,
                'aws_resources': 0,
                'azure_resources': 0,
                'gcp_resources': 0
            }
            top_cloud_findings = []
        
        executive_data = {
            'generated_at': now.strftime('%Y-%m-%d %H:%M UTC'),
            'summary': {
                'total_findings': total_current,
                'critical_findings': severity_current['critical'],
                'high_findings': severity_current['high'],
                'total_assets': total_assets,
                'critical_assets': critical_assets,
                'cloud_assets': total_cloud_assets,
                'attack_path_findings': attack_path_findings,
                'attack_path_assets': attack_path_assets
            },
            'trends': trends,
            'severity_current': severity_current,
            'mttr': {
                'overall_days': mttr_days,
                'critical_days': mttr_critical,
                'findings_resolved': len(fixed_findings)
            },
            'risk_score': round(risk_score, 1),
            'compliance_score': round(compliance_score, 1),
            'grc_summary': grc_summary,
            'grc_stats': {
                'frameworks_affected': len(grc_summary),
                'total_findings': total_grc_findings,
                'total_requirements': total_requirements
            },
            'cloud_breakdown': cloud_assets,
            'top_vulnerabilities': top_vulns,
            'weekly_trends': weekly_trends,
            'nist_controls': get_nist_controls_list(current_findings),
            'cloud_summary': cloud_summary,
            'top_cloud_findings': top_cloud_findings,
            'sla_compliance': sla_compliance
        }
        
        return render_template('executive_dashboard.html', data=executive_data)
    except Exception as e:
        current_app.logger.error(f"Error loading executive dashboard: {e}")
        traceback.print_exc()
        return f"Error loading executive dashboard: {str(e)}", 500


@main_bp.route('/debug_cloud')
def debug_cloud():
    """Debug route to check what's in the CloudFinding table"""
    try:
        from sqlalchemy import inspect
        
        inspector = inspect(db.engine)
        columns = inspector.get_columns('cloud_finding')
        column_names = [col['name'] for col in columns]
        
        debug_info = {
            'total_count': db.session.query(CloudFinding).count(),
            'sample_findings': [],
            'unique_statuses': [],
            'unique_severities': [],
            'unique_providers': [],
            'table_columns': column_names
        }
        
        sample = db.session.query(CloudFinding).limit(10).all()
        for finding in sample:
            finding_dict = {}
            for col in column_names:
                if hasattr(finding, col):
                    value = getattr(finding, col)
                    if hasattr(value, 'isoformat'):
                        value = value.isoformat()
                    finding_dict[col] = value
            debug_info['sample_findings'].append(finding_dict)
        
        statuses = db.session.query(CloudFinding.status).distinct().all()
        debug_info['unique_statuses'] = [s[0] for s in statuses if s[0]]
        
        severities = db.session.query(CloudFinding.severity).distinct().all()
        debug_info['unique_severities'] = [s[0] for s in severities if s[0]]
        
        providers = db.session.query(CloudFinding.cloud_provider).distinct().all()
        debug_info['unique_providers'] = [p[0] for p in providers if p[0]]
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Cloud Findings Debug</title>
            <style>
                body {{
                    font-family: monospace;
                    padding: 20px;
                    background: #1a1a1a;
                    color: #00ff00;
                }}
                .section {{
                    margin: 20px 0;
                    padding: 15px;
                    background: #2a2a2a;
                    border-left: 4px solid #00ff00;
                }}
                h2 {{ color: #00aaff; }}
                pre {{
                    background: #000;
                    padding: 10px;
                    overflow-x: auto;
                    color: #00ff00;
                }}
                .stat {{
                    display: inline-block;
                    margin: 10px 20px 10px 0;
                    padding: 10px 15px;
                    background: #333;
                    border-radius: 5px;
                }}
                .good {{ color: #00ff00; }}
                .bad {{ color: #ff0000; }}
                .warning {{ color: #ffaa00; }}
            </style>
        </head>
        <body>
            <h1>CLOUD FINDINGS DEBUG</h1>
            
            <div class="section">
                <h2>Summary</h2>
                <div class="stat">
                    <strong>Total Cloud Findings:</strong>
                    <span class="{'good' if debug_info['total_count'] > 0 else 'bad'}">
                        {debug_info['total_count']}
                    </span>
                </div>
            </div>
            
            <div class="section">
                <h2>Unique Values</h2>
                <div class="stat">
                    <strong>Statuses:</strong> 
                    <span class="{'good' if debug_info['unique_statuses'] else 'warning'}">
                        {', '.join(debug_info['unique_statuses']) or 'None'}
                    </span>
                </div>
                <div class="stat">
                    <strong>Severities:</strong> 
                    <span class="{'good' if debug_info['unique_severities'] else 'warning'}">
                        {', '.join(debug_info['unique_severities']) or 'None'}
                    </span>
                </div>
                <div class="stat">
                    <strong>Providers:</strong> 
                    <span class="{'good' if debug_info['unique_providers'] else 'bad'}">
                        {', '.join(debug_info['unique_providers']) or 'NONE - THIS IS THE PROBLEM!'}
                    </span>
                </div>
            </div>
            
            <div class="section">
                <h2>Table Columns</h2>
                <pre>{', '.join(debug_info['table_columns'])}</pre>
                <p style="color: #ffaa00;">Check if 'cloud_provider' and 'resource_name' exist above!</p>
            </div>
            
            <div class="section">
                <h2>Sample Findings (First 10)</h2>
                <pre>{json.dumps(debug_info['sample_findings'], indent=2, default=str)}</pre>
            </div>
            
            <div class="section">
                <h2>DIAGNOSIS</h2>
                <ul>
                    <li class="{'good' if 'cloud_provider' in debug_info['table_columns'] else 'bad'}">
                        cloud_provider column: {'EXISTS' if 'cloud_provider' in debug_info['table_columns'] else 'MISSING - Need migration!'}
                    </li>
                    <li class="{'good' if 'resource_name' in debug_info['table_columns'] else 'warning'}">
                        resource_name column: {'EXISTS' if 'resource_name' in debug_info['table_columns'] else 'MISSING - Need migration!'}
                    </li>
                    <li class="{'good' if debug_info['unique_providers'] else 'bad'}">
                        Provider data: {'POPULATED' if debug_info['unique_providers'] else 'EMPTY - Need to re-ingest!'}
                    </li>
                </ul>
            </div>
        </body>
        </html>
        """
        return html
        
    except Exception as e:
        return f"""
        <html>
        <body style="font-family:monospace;background:#1a1a1a;color:#ff0000;padding:20px">
            <h1>Error in Cloud Debug</h1>
            <pre>{str(e)}</pre>
            <pre>{traceback.format_exc()}</pre>
        </body>
        </html>
        """, 500