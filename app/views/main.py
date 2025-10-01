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
from ..models import VulnerabilityFinding, AttackPathFinding, WASFinding, PluginComplianceMapping, ComplianceRequirement

# Create blueprint
main_bp = Blueprint('main', __name__)


def get_grc_summary_for_findings(findings):
    """Generate GRC compliance summary from findings"""
    grc_summary = defaultdict(lambda: {
        'total_findings': 0,
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'requirements': set()
    })
    
    for finding in findings:
        if hasattr(finding, 'plugin_compliance_mappings') and finding.plugin_compliance_mappings:
            for mapping in finding.plugin_compliance_mappings:
                if mapping.compliance_requirement:
                    framework = mapping.compliance_requirement.framework
                    grc_summary[framework]['total_findings'] += 1
                    grc_summary[framework]['requirements'].add(
                        mapping.compliance_requirement.requirement_id
                    )
                    
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


def get_dashboard_metrics():
    """Calculate dashboard summary metrics"""
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
        
        attack_path_count = base_query.filter(
            VulnerabilityFinding.is_in_attack_path == True
        ).count()
        
        cloud_counts = {
            'aws': base_query.filter(VulnerabilityFinding.asset_aws_ec2_instance_id.isnot(None)).count(),
            'azure': base_query.filter(VulnerabilityFinding.asset_azure_vm_id.isnot(None)).count(),
            'gcp': base_query.filter(VulnerabilityFinding.asset_gcp_instance_id.isnot(None)).count(),
        }
        
        top_assets_query = (
            base_query
            .with_entities(
                func.coalesce(VulnerabilityFinding.asset_hostname, VulnerabilityFinding.asset_ipv4, 'Unknown').label('asset'),
                func.count().label('count')
            )
            .group_by(func.coalesce(VulnerabilityFinding.asset_hostname, VulnerabilityFinding.asset_ipv4, 'Unknown'))
            .order_by(func.count().desc())
            .limit(5)
        )
        top_assets = [{'asset': row.asset, 'count': row.count} for row in top_assets_query.all()]

        top_plugins_query = (
            base_query
            .with_entities(
                VulnerabilityFinding.plugin_name.label('plugin'),
                func.count().label('count')
            )
            .group_by(VulnerabilityFinding.plugin_id, VulnerabilityFinding.plugin_name)
            .order_by(func.count().desc())
            .limit(5)
        )
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
            'top_plugins': top_plugins,
        }
        
    except Exception as e:
        current_app.logger.error(f"Error calculating dashboard metrics: {e}")
        return {
            'total_active_findings': 0,
            'severity_counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'attack_path_findings': 0,
            'cloud_counts': {'aws': 0, 'azure': 0, 'gcp': 0},
            'top_assets': [],
            'top_plugins': [],
        }


@main_bp.route('/debug_grc')
def debug_grc():
    """Debug endpoint to check GRC mappings"""
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
        
        sample_mappings = db.session.query(PluginComplianceMapping).join(
            ComplianceRequirement
        ).limit(20).all()
        
        for mapping in sample_mappings:
            debug_info['sample_mappings'].append({
                'plugin_id': mapping.plugin_id,
                'framework': mapping.compliance_requirement.framework if mapping.compliance_requirement else None,
                'requirement_id': mapping.compliance_requirement.requirement_id if mapping.compliance_requirement else None
            })
        
        mapped_plugin_ids = db.session.query(
            PluginComplianceMapping.plugin_id
        ).distinct().all()
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
        
        finding_plugin_ids = db.session.query(
            VulnerabilityFinding.plugin_id
        ).filter(
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
            subqueryload(VulnerabilityFinding.plugin_compliance_mappings).subqueryload(
                PluginComplianceMapping.compliance_requirement
            )
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
                        } for m in finding.plugin_compliance_mappings if m.compliance_requirement
                    ]
                })
                
                if len(examples_with_mappings) >= 10:
                    break
        
        debug_info['examples_with_grc'] = examples_with_mappings
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>GRC Mapping Debug</title>
            <style>
                body {{ font-family: monospace; padding: 20px; background: #1a1a1a; color: #00ff00; }}
                .section {{ margin: 20px 0; padding: 15px; background: #2a2a2a; border-left: 4px solid #00ff00; }}
                .good {{ color: #00ff00; }}
                .warning {{ color: #ffaa00; }}
                .bad {{ color: #ff0000; }}
                h2 {{ color: #00aaff; }}
                pre {{ background: #000; padding: 10px; overflow-x: auto; color: #00ff00; }}
                .stat {{ display: inline-block; margin: 10px 20px 10px 0; padding: 10px 15px; background: #333; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <h1>GRC MAPPING DEBUG REPORT</h1>
            <p>Generated: {debug_info['timestamp']}</p>
            <div class="section">
                <h2>GRC Statistics</h2>
                <div class="stat"><strong>Total Requirements:</strong> <span class="{'good' if total_requirements > 0 else 'bad'}">{total_requirements}</span></div>
                <div class="stat"><strong>Total Plugin Mappings:</strong> <span class="{'good' if total_mappings > 0 else 'bad'}">{total_mappings}</span></div>
            </div>
            <div class="section">
                <h2>Full JSON Data</h2>
                <pre>{json.dumps(debug_info, indent=2, default=str)}</pre>
            </div>
        </body>
        </html>
        """
        
        return html
        
    except Exception as e:
        return f"""
        <html>
        <body style="font-family: monospace; background: #1a1a1a; color: #ff0000; padding: 20px;">
            <h1>Error in GRC Debug</h1>
            <pre>{str(e)}</pre>
            <pre>{traceback.format_exc()}</pre>
        </body>
        </html>
        """, 500


@main_bp.route('/')
def dashboard():
    """Main dashboard route"""
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
            subqueryload(VulnerabilityFinding.plugin_compliance_mappings).subqueryload(
                PluginComplianceMapping.compliance_requirement
            )
        )
        
        findings = query.all()
        current_app.logger.info(f"Retrieved {len(findings)} filtered VM findings")
        
        vm_grc_summary = get_grc_summary_for_findings(findings)
        
        was_query = db.session.query(WASFinding).filter(
            WASFinding.status == 'Active'
        ).options(
            subqueryload(WASFinding.plugin_compliance_mappings).subqueryload(
                PluginComplianceMapping.compliance_requirement
            )
        )
        was_findings = was_query.all()
        
        was_grc_summary = get_grc_summary_for_findings(was_findings)
        
        attack_path_findings = db.session.query(AttackPathFinding).order_by(
            AttackPathFinding.path_risk_score.desc()
        ).limit(10).all()
        
        dashboard_data = get_dashboard_metrics()
        
        return render_template('index.html',
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
                             sort_direction=sort_direction)
        
    except Exception as e:
        current_app.logger.error(f"Dashboard error: {e}")
        traceback.print_exc()
        return f"Error loading dashboard: {str(e)}", 500


@main_bp.route('/grouped_findings')
def grouped_findings():
    """Grouped findings view"""
    try:
        selected_severity = request.args.get('severity', 'actionable')
        selected_state = request.args.get('state', 'active')
        selected_time_period = request.args.get('time_period', '30_days')
        
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
        
        query = query.options(
            subqueryload(VulnerabilityFinding.plugin_compliance_mappings).subqueryload(
                PluginComplianceMapping.compliance_requirement
            )
        )
        
        all_findings = query.all()
        
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
                    'last_found': finding.last_found
                }
            
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
            
            if finding.first_found and (not grouped_findings_dict[plugin_key]['first_found'] or 
                                      finding.first_found < grouped_findings_dict[plugin_key]['first_found']):
                grouped_findings_dict[plugin_key]['first_found'] = finding.first_found
            if finding.last_found and (not grouped_findings_dict[plugin_key]['last_found'] or 
                                     finding.last_found > grouped_findings_dict[plugin_key]['last_found']):
                grouped_findings_dict[plugin_key]['last_found'] = finding.last_found
        
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
        grouped_list = list(grouped_findings_dict.values())
        grouped_list.sort(key=lambda x: (severity_order.get(x['severity'], 0), x['asset_count']), reverse=True)
        
        return render_template('grouped_findings.html',
                             grouped_findings=grouped_list,
                             grouped_grc_summary=grouped_grc_summary,
                             selected_severity=selected_severity,
                             selected_state=selected_state,
                             selected_time_period=selected_time_period,
                             total_groups=len(grouped_list),
                             total_assets=sum(g['asset_count'] for g in grouped_list))
        
    except Exception as e:
        current_app.logger.error(f"Error in grouped_findings: {e}")
        traceback.print_exc()
        return render_template('error.html', error=str(e)), 500


@main_bp.route('/cloud_findings')
def cloud_findings():
    """Cloud findings view"""
    try:
        selected_cloud_provider = request.args.get('cloud_provider', 'all')
        selected_severity = request.args.get('severity', 'actionable')
        selected_time_period = request.args.get('time_period', '30_days')
        
        query = db.session.query(VulnerabilityFinding)
        
        cloud_filter = or_(
            VulnerabilityFinding.asset_aws_ec2_instance_id.isnot(None),
            VulnerabilityFinding.asset_azure_vm_id.isnot(None),
            VulnerabilityFinding.asset_gcp_instance_id.isnot(None)
        )
        query = query.filter(cloud_filter)
        
        if selected_cloud_provider == 'aws':
            query = query.filter(VulnerabilityFinding.asset_aws_ec2_instance_id.isnot(None))
        elif selected_cloud_provider == 'azure':
            query = query.filter(VulnerabilityFinding.asset_azure_vm_id.isnot(None))
        elif selected_cloud_provider == 'gcp':
            query = query.filter(VulnerabilityFinding.asset_gcp_instance_id.isnot(None))
        
        if selected_severity == 'actionable':
            query = query.filter(VulnerabilityFinding.severity.notin_(['info']))
        elif selected_severity in ['critical', 'high', 'medium', 'low']:
            query = query.filter(VulnerabilityFinding.severity == selected_severity)
        
        if selected_time_period == '30_days':
            thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
            query = query.filter(VulnerabilityFinding.last_found >= thirty_days_ago)
        elif selected_time_period == '7_days':
            seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
            query = query.filter(VulnerabilityFinding.last_found >= seven_days_ago)
        
        query = query.filter(VulnerabilityFinding.state.in_(['OPEN', 'REOPENED']))
        
        query = query.options(
            subqueryload(VulnerabilityFinding.plugin_compliance_mappings).subqueryload(
                PluginComplianceMapping.compliance_requirement
            )
        )
        
        severity_order = case(
            (VulnerabilityFinding.severity == 'critical', 4),
            (VulnerabilityFinding.severity == 'high', 3),
            (VulnerabilityFinding.severity == 'medium', 2),
            (VulnerabilityFinding.severity == 'low', 1),
            else_=0
        )
        query = query.order_by(severity_order.desc(), VulnerabilityFinding.last_found.desc())
        
        cloud_findings_list = query.all()
        
        cloud_grc_summary = get_grc_summary_for_findings(cloud_findings_list)
        
        cloud_stats = {
            'aws': len([f for f in cloud_findings_list if f.asset_aws_ec2_instance_id]),
            'azure': len([f for f in cloud_findings_list if f.asset_azure_vm_id]),
            'gcp': len([f for f in cloud_findings_list if f.asset_gcp_instance_id])
        }
        
        return render_template('cloud_findings.html',
                             cloud_findings=cloud_findings_list,
                             cloud_stats=cloud_stats,
                             cloud_grc_summary=cloud_grc_summary,
                             selected_cloud_provider=selected_cloud_provider,
                             selected_severity=selected_severity,
                             selected_time_period=selected_time_period)
        
    except Exception as e:
        current_app.logger.error(f"Error in cloud_findings: {e}")
        return render_template('error.html', error=str(e)), 500


@main_bp.route('/was_findings')
def was_findings():
    """WAS findings view"""
    try:
        selected_severity = request.args.get('severity', 'all')
        selected_status = request.args.get('status', 'active')
        
        query = db.session.query(WASFinding)
        
        if selected_status == 'active':
            query = query.filter(WASFinding.status == 'Active')
        elif selected_status == 'fixed':
            query = query.filter(WASFinding.status == 'Fixed')
        
        if selected_severity != 'all':
            query = query.filter(WASFinding.severity == selected_severity)
        
        query = query.options(
            subqueryload(WASFinding.plugin_compliance_mappings).subqueryload(
                PluginComplianceMapping.compliance_requirement
            )
        )
        
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
        
        was_specific_grc_summary = get_grc_summary_for_findings(was_findings_list)
        
        return render_template('was_findings.html',
                             was_findings=was_findings_list,
                             was_specific_grc_summary=was_specific_grc_summary,
                             selected_severity=selected_severity,
                             selected_status=selected_status)
        
    except Exception as e:
        current_app.logger.error(f"Error in was_findings: {e}")
        traceback.print_exc()
        return render_template('error.html', error=str(e)), 500


@main_bp.route('/executive_dashboard')
def executive_dashboard():
    """Executive dashboard with metrics and trends"""
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
            subqueryload(VulnerabilityFinding.plugin_compliance_mappings).subqueryload(
                PluginComplianceMapping.compliance_requirement
            )
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
        ).filter(
            VulnerabilityFinding.last_found >= thirty_days_ago
        ).scalar()
        
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
        
        if grc_summary:
            total_grc_findings = sum(fw['total_findings'] for fw in grc_summary.values())
            total_requirements = sum(fw['requirements_count'] for fw in grc_summary.values())
            
            if total_requirements > 0:
                findings_per_req = total_grc_findings / total_requirements
                compliance_score = max(0, min(100, 100 - (findings_per_req * 10)))
            else:
                compliance_score = 0
        else:
            compliance_score = 100
            total_grc_findings = 0
            total_requirements = 0
        
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
                    'asset_count': 0,
                    'vpr_score': finding.vpr_score
                }
            plugin_stats[plugin_key]['asset_count'] += 1
        
        top_vulns = sorted(
            plugin_stats.values(),
            key=lambda x: x['asset_count'],
            reverse=True
        )[:10]
        
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
            'weekly_trends': weekly_trends
        }
        
        return render_template('executive_dashboard.html', data=executive_data)
        
    except Exception as e:
        current_app.logger.error(f"Error loading executive dashboard: {e}")
        traceback.print_exc()
        return f"Error loading executive dashboard: {str(e)}", 500


@main_bp.route('/executive_dashboard/pdf')
def executive_dashboard_pdf():
    """Generate PDF export with ReportLab"""
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
        grc_summary = get_grc_summary_for_findings(current_findings)
        
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
        
        if grc_summary:
            elements.append(Paragraph("GRC Compliance Summary", heading_style))
            elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#3498db')))
            elements.append(Spacer(1, 0.2*inch))
            
            grc_data = [['Framework', 'Total Findings', 'Critical', 'High', 'Requirements']]
            for fw, data in list(grc_summary.items())[:6]:
                grc_data.append([fw, str(data['total_findings']), str(data['critical']), str(data['high']), str(data['requirements_count'])])
            
            grc_table = Table(grc_data, colWidths=[2*inch, 1.2*inch, 1*inch, 1*inch, 1.3*inch])
            grc_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
                ('FONTSIZE', (0, 1), (-1, -1), 9),
            ]))
            
            elements.append(grc_table)
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
        
        if grc_summary:
            summary_text += f"<br/><br/><b>Compliance Impact:</b> <b>{len(grc_summary)}</b> regulatory frameworks are impacted."
        
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
        return jsonify({'error': 'PDF generation requires ReportLab library', 'install': 'pip install reportlab', 'details': str(e)}), 500
    except Exception as e:
        current_app.logger.error(f"Error generating PDF: {e}")
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500