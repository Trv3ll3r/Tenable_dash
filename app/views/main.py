from flask import Blueprint, render_template, request, jsonify, current_app
from sqlalchemy.orm import subqueryload
from sqlalchemy import desc, func, case, or_
from datetime import datetime, timedelta, timezone
from collections import defaultdict
import json
import traceback

from ..database import db
from ..models import VulnerabilityFinding, AttackPathFinding, WASFinding, PluginComplianceMapping, ComplianceRequirement

# Create blueprint with the name your app expects
main_bp = Blueprint('main', __name__)

def get_grc_summary_for_findings(findings):
    """
    Generate GRC compliance summary from a list of findings.
    Returns a dictionary with framework names as keys and statistics as values.
    """
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
                    
                    # Count by severity
                    severity = (finding.severity or 'unknown').lower()
                    if severity in ['critical', 'high', 'medium', 'low']:
                        grc_summary[framework][severity] += 1
    
    # Convert sets to counts for template
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
    """Calculate dashboard summary metrics with error handling"""
    try:
        thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
        
        # Base query for active findings
        base_query = db.session.query(VulnerabilityFinding).filter(
            VulnerabilityFinding.state.in_(['OPEN', 'REOPENED']),
            VulnerabilityFinding.severity.notin_(['info']),
            VulnerabilityFinding.last_found >= thirty_days_ago
        )
        
        total_active = base_query.count()
        
        # Severity counts
        severity_counts = {}
        for sev in ['critical', 'high', 'medium', 'low']:
            count = base_query.filter(VulnerabilityFinding.severity == sev).count()
            severity_counts[sev] = count
        
        # Attack path findings
        attack_path_count = base_query.filter(
            VulnerabilityFinding.is_in_attack_path == True
        ).count()
        
        # Cloud counts
        cloud_counts = {
            'aws': base_query.filter(VulnerabilityFinding.asset_aws_ec2_instance_id.isnot(None)).count(),
            'azure': base_query.filter(VulnerabilityFinding.asset_azure_vm_id.isnot(None)).count(),
            'gcp': base_query.filter(VulnerabilityFinding.asset_gcp_instance_id.isnot(None)).count(),
        }
        
        # Top assets
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

        # Top plugins
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
    """Debug endpoint to check GRC mappings and matching"""
    try:
        debug_info = {
            'timestamp': datetime.now().isoformat(),
            'grc_statistics': {},
            'sample_mappings': [],
            'sample_findings': [],
            'matching_analysis': {}
        }
        
        # Get GRC statistics
        total_requirements = db.session.query(ComplianceRequirement).count()
        total_mappings = db.session.query(PluginComplianceMapping).count()
        
        debug_info['grc_statistics'] = {
            'total_requirements': total_requirements,
            'total_plugin_mappings': total_mappings
        }
        
        # Get sample of GRC mappings (first 20)
        sample_mappings = db.session.query(PluginComplianceMapping).join(
            ComplianceRequirement
        ).limit(20).all()
        
        for mapping in sample_mappings:
            debug_info['sample_mappings'].append({
                'plugin_id': mapping.plugin_id,
                'framework': mapping.compliance_requirement.framework if mapping.compliance_requirement else None,
                'requirement_id': mapping.compliance_requirement.requirement_id if mapping.compliance_requirement else None
            })
        
        # Get unique plugin IDs from mappings
        mapped_plugin_ids = db.session.query(
            PluginComplianceMapping.plugin_id
        ).distinct().all()
        mapped_plugin_ids = [pid[0] for pid in mapped_plugin_ids]
        
        debug_info['grc_statistics']['unique_plugins_mapped'] = len(mapped_plugin_ids)
        debug_info['grc_statistics']['sample_mapped_plugin_ids'] = mapped_plugin_ids[:20]
        
        # Get sample of findings with their plugin IDs (last 30 days, active)
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
        
        # Get unique plugin IDs from findings
        finding_plugin_ids = db.session.query(
            VulnerabilityFinding.plugin_id
        ).filter(
            VulnerabilityFinding.state.in_(['OPEN', 'REOPENED']),
            VulnerabilityFinding.last_found >= thirty_days_ago
        ).distinct().all()
        finding_plugin_ids = [pid[0] for pid in finding_plugin_ids]
        
        debug_info['grc_statistics']['unique_plugins_in_findings'] = len(finding_plugin_ids)
        debug_info['grc_statistics']['sample_finding_plugin_ids'] = finding_plugin_ids[:20]
        
        # Check for overlap
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
        
        # Get count of findings WITH GRC mappings
        findings_with_grc = db.session.query(VulnerabilityFinding).join(
            PluginComplianceMapping,
            VulnerabilityFinding.plugin_id == PluginComplianceMapping.plugin_id
        ).filter(
            VulnerabilityFinding.state.in_(['OPEN', 'REOPENED']),
            VulnerabilityFinding.last_found >= thirty_days_ago
        ).count()
        
        debug_info['matching_analysis']['findings_with_grc_mappings'] = findings_with_grc
        
        # Get some examples of findings WITH mappings
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
        
        # Create HTML response
        html = f"""
        <!DOCTYPE html>
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
            <h1>🔍 GRC MAPPING DEBUG REPORT</h1>
            <p>Generated: {debug_info['timestamp']}</p>
            
            <div class="section">
                <h2>📊 GRC Statistics</h2>
                <div class="stat">
                    <strong>Total Requirements:</strong> 
                    <span class="{'good' if total_requirements > 0 else 'bad'}">{total_requirements}</span>
                </div>
                <div class="stat">
                    <strong>Total Plugin Mappings:</strong> 
                    <span class="{'good' if total_mappings > 0 else 'bad'}">{total_mappings}</span>
                </div>
                <div class="stat">
                    <strong>Unique Plugins Mapped:</strong> 
                    <span class="{'good' if debug_info['grc_statistics']['unique_plugins_mapped'] > 0 else 'bad'}">
                        {debug_info['grc_statistics']['unique_plugins_mapped']}
                    </span>
                </div>
                <div class="stat">
                    <strong>Unique Plugins in Findings:</strong> 
                    <span class="{'good' if debug_info['grc_statistics']['unique_plugins_in_findings'] > 0 else 'bad'}">
                        {debug_info['grc_statistics']['unique_plugins_in_findings']}
                    </span>
                </div>
            </div>
            
            <div class="section">
                <h2>🔗 Matching Analysis</h2>
                <div class="stat">
                    <strong>Overlapping Plugin IDs:</strong> 
                    <span class="{'good' if debug_info['matching_analysis']['overlapping_plugins'] > 0 else 'warning'}">
                        {debug_info['matching_analysis']['overlapping_plugins']}
                    </span>
                </div>
                <div class="stat">
                    <strong>Overlap Percentage:</strong> 
                    <span class="{'good' if debug_info['matching_analysis']['overlap_percentage'] > 10 else 'warning' if debug_info['matching_analysis']['overlap_percentage'] > 0 else 'bad'}">
                        {debug_info['matching_analysis']['overlap_percentage']}%
                    </span>
                </div>
                <div class="stat">
                    <strong>Findings WITH GRC Mappings:</strong> 
                    <span class="{'good' if debug_info['matching_analysis']['findings_with_grc_mappings'] > 0 else 'bad'}">
                        {debug_info['matching_analysis']['findings_with_grc_mappings']}
                    </span>
                </div>
            </div>
            
            <div class="section">
                <h2>🎯 Diagnosis</h2>
                {"<p class='good'>✅ GRC mappings are working! Found " + str(debug_info['matching_analysis']['findings_with_grc_mappings']) + " findings with mappings.</p>" if debug_info['matching_analysis']['findings_with_grc_mappings'] > 0 else "<p class='bad'>❌ No findings match your GRC mappings. Check plugin IDs below.</p>"}
                {"<p class='warning'>⚠️  Low overlap rate. Your GRC JSON may need more plugin IDs.</p>" if debug_info['matching_analysis']['overlap_percentage'] < 20 and debug_info['matching_analysis']['overlap_percentage'] > 0 else ""}
            </div>
            
            <div class="section">
                <h2>📋 Sample GRC Mappings (First 20)</h2>
                <pre>{json.dumps(debug_info['sample_mappings'], indent=2)}</pre>
            </div>
            
            <div class="section">
                <h2>🐛 Sample Findings (First 20)</h2>
                <pre>{json.dumps(debug_info['sample_findings'], indent=2)}</pre>
            </div>
            
            {"<div class='section'><h2>✅ Examples of Findings WITH GRC Mappings</h2><pre>" + json.dumps(debug_info['examples_with_grc'], indent=2) + "</pre></div>" if debug_info['examples_with_grc'] else ""}
            
            <div class="section">
                <h2>🔢 Plugin ID Comparison</h2>
                <h3>Sample Mapped Plugin IDs (from GRC JSON):</h3>
                <pre>{json.dumps(debug_info['grc_statistics']['sample_mapped_plugin_ids'], indent=2)}</pre>
                
                <h3>Sample Finding Plugin IDs (from Tenable):</h3>
                <pre>{json.dumps(debug_info['grc_statistics']['sample_finding_plugin_ids'], indent=2)}</pre>
                
                <h3>Overlapping Plugin IDs (These SHOULD have GRC mappings):</h3>
                <pre>{json.dumps(debug_info['matching_analysis']['sample_overlapping_plugin_ids'], indent=2)}</pre>
            </div>
            
            <div class="section">
                <h2>📥 Full JSON Data</h2>
                <pre>{json.dumps(debug_info, indent=2)}</pre>
            </div>
        </body>
        </html>
        """
        
        return html
        
    except Exception as e:
        return f"""
        <html>
        <body style="font-family: monospace; background: #1a1a1a; color: #ff0000; padding: 20px;">
            <h1>❌ Error in GRC Debug</h1>
            <pre>{str(e)}</pre>
            <pre>{traceback.format_exc()}</pre>
        </body>
        </html>
        """, 500

@main_bp.route('/')
def dashboard():
    """Main dashboard route with GRC summaries"""
    try:
        current_app.logger.info(f"Dashboard request - Severity: {request.args.get('severity')}, State: {request.args.get('state')}, Period: {request.args.get('time_period')}")
        
        # Start with base query
        query = db.session.query(VulnerabilityFinding)
        
        # Get filter parameters
        selected_severity = request.args.get('severity', 'actionable')
        selected_state = request.args.get('state', 'active') 
        selected_time_period = request.args.get('time_period', '30_days')
        sort_by = request.args.get('sort_by', 'last_found')
        sort_direction = request.args.get('sort_direction', 'desc')
        
        # Apply state filtering
        if selected_state == 'active':
            query = query.filter(VulnerabilityFinding.state.in_(['OPEN', 'REOPENED']))
        elif selected_state == 'fixed':
            query = query.filter(VulnerabilityFinding.state == 'FIXED')
        
        # Apply severity filtering
        if selected_severity == 'actionable' or not selected_severity:
            query = query.filter(VulnerabilityFinding.severity.notin_(['info']))
        elif selected_severity in ['critical', 'high', 'medium', 'low']:
            query = query.filter(VulnerabilityFinding.severity == selected_severity)
        elif selected_severity == 'include_info':
            pass  # No severity filter
        
        # Apply time period filtering
        if selected_time_period == '30_days':
            thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
            query = query.filter(VulnerabilityFinding.last_found >= thirty_days_ago)
        elif selected_time_period == '7_days':
            seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
            query = query.filter(VulnerabilityFinding.last_found >= seven_days_ago)
        
        # Apply sorting
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
        
        # CRITICAL: Eager load GRC relationships
        query = query.options(
            subqueryload(VulnerabilityFinding.plugin_compliance_mappings).subqueryload(
                PluginComplianceMapping.compliance_requirement
            )
        )
        
        # Execute query
        findings = query.all()
        current_app.logger.info(f"Retrieved {len(findings)} filtered VM findings")
        
        # Generate GRC summary for VM findings
        vm_grc_summary = get_grc_summary_for_findings(findings)
        current_app.logger.info(f"VM GRC Summary: {len(vm_grc_summary)} frameworks affected")
        
        # Get WAS findings with GRC
        was_query = db.session.query(WASFinding).filter(
            WASFinding.status == 'Active'
        ).options(
            subqueryload(WASFinding.plugin_compliance_mappings).subqueryload(
                PluginComplianceMapping.compliance_requirement
            )
        )
        was_findings = was_query.all()
        
        # Generate GRC summary for WAS findings
        was_grc_summary = get_grc_summary_for_findings(was_findings)
        current_app.logger.info(f"WAS GRC Summary: {len(was_grc_summary)} frameworks affected")
        
        # Get attack path findings
        attack_path_findings = db.session.query(AttackPathFinding).order_by(
            AttackPathFinding.path_risk_score.desc()
        ).limit(10).all()
        
        # Get dashboard metrics
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
    """Grouped findings view with GRC summary"""
    try:
        # Get filter parameters
        selected_severity = request.args.get('severity', 'actionable')
        selected_state = request.args.get('state', 'active')
        selected_time_period = request.args.get('time_period', '30_days')
        
        # Build query with same filtering logic
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
        
        # CRITICAL: Load GRC mappings eagerly
        query = query.options(
            subqueryload(VulnerabilityFinding.plugin_compliance_mappings).subqueryload(
                PluginComplianceMapping.compliance_requirement
            )
        )
        
        all_findings = query.all()
        
        # Generate GRC summary for grouped view
        grouped_grc_summary = get_grc_summary_for_findings(all_findings)
        current_app.logger.info(f"Grouped GRC Summary: {len(grouped_grc_summary)} frameworks affected")
        
        # Group findings by plugin WITH GRC MAPPINGS
        grouped_findings = {}
        for finding in all_findings:
            plugin_key = f"{finding.plugin_id}_{finding.plugin_name or 'Unknown'}"
            
            if plugin_key not in grouped_findings:
                # Get GRC mappings for this plugin
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
                
                grouped_findings[plugin_key] = {
                    'plugin_id': finding.plugin_id,
                    'plugin_name': finding.plugin_name or 'Unknown Plugin',
                    'severity': finding.severity,
                    'vpr_score': finding.vpr_score,
                    'cvss_score': finding.cvss_v3_base_score,
                    'description': finding.description,
                    'solution': finding.solution,
                    'grc_mappings': grc_mappings,
                    'grc_frameworks': list(grc_frameworks),  # For summary display
                    'affected_assets': [],
                    'asset_count': 0,
                    'first_found': finding.first_found,
                    'last_found': finding.last_found
                }
            
            # Add asset to the group
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
            grouped_findings[plugin_key]['affected_assets'].append(asset_info)
            grouped_findings[plugin_key]['asset_count'] += 1
            
            # Update timeline
            if finding.first_found and (not grouped_findings[plugin_key]['first_found'] or 
                                      finding.first_found < grouped_findings[plugin_key]['first_found']):
                grouped_findings[plugin_key]['first_found'] = finding.first_found
            if finding.last_found and (not grouped_findings[plugin_key]['last_found'] or 
                                     finding.last_found > grouped_findings[plugin_key]['last_found']):
                grouped_findings[plugin_key]['last_found'] = finding.last_found
        
        # Convert to list and sort
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
        grouped_list = list(grouped_findings.values())
        grouped_list.sort(key=lambda x: (severity_order.get(x['severity'], 0), x['asset_count']), reverse=True)
        
        current_app.logger.info(f"Grouped {len(all_findings)} findings into {len(grouped_list)} unique vulnerabilities")
        
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
    """Cloud findings view - shows vulnerabilities on cloud assets with GRC"""
    try:
        # Get filter parameters
        selected_cloud_provider = request.args.get('cloud_provider', 'all')
        selected_severity = request.args.get('severity', 'actionable')
        selected_time_period = request.args.get('time_period', '30_days')
        
        # Build query for cloud findings
        query = db.session.query(VulnerabilityFinding)
        
        # Filter to only cloud assets
        cloud_filter = or_(
            VulnerabilityFinding.asset_aws_ec2_instance_id.isnot(None),
            VulnerabilityFinding.asset_azure_vm_id.isnot(None),
            VulnerabilityFinding.asset_gcp_instance_id.isnot(None)
        )
        query = query.filter(cloud_filter)
        
        # Apply cloud provider filtering
        if selected_cloud_provider == 'aws':
            query = query.filter(VulnerabilityFinding.asset_aws_ec2_instance_id.isnot(None))
        elif selected_cloud_provider == 'azure':
            query = query.filter(VulnerabilityFinding.asset_azure_vm_id.isnot(None))
        elif selected_cloud_provider == 'gcp':
            query = query.filter(VulnerabilityFinding.asset_gcp_instance_id.isnot(None))
        
        # Apply severity filtering
        if selected_severity == 'actionable':
            query = query.filter(VulnerabilityFinding.severity.notin_(['info']))
        elif selected_severity in ['critical', 'high', 'medium', 'low']:
            query = query.filter(VulnerabilityFinding.severity == selected_severity)
        
        # Apply time period filtering
        if selected_time_period == '30_days':
            thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
            query = query.filter(VulnerabilityFinding.last_found >= thirty_days_ago)
        elif selected_time_period == '7_days':
            seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
            query = query.filter(VulnerabilityFinding.last_found >= seven_days_ago)
        
        # Apply state filtering (active only for cloud findings)
        query = query.filter(VulnerabilityFinding.state.in_(['OPEN', 'REOPENED']))
        
        # Load GRC mappings
        query = query.options(
            subqueryload(VulnerabilityFinding.plugin_compliance_mappings).subqueryload(
                PluginComplianceMapping.compliance_requirement
            )
        )
        
        # Order by severity and last found
        severity_order = case(
            (VulnerabilityFinding.severity == 'critical', 4),
            (VulnerabilityFinding.severity == 'high', 3),
            (VulnerabilityFinding.severity == 'medium', 2),
            (VulnerabilityFinding.severity == 'low', 1),
            else_=0
        )
        query = query.order_by(severity_order.desc(), VulnerabilityFinding.last_found.desc())
        
        cloud_findings_list = query.all()
        
        # Generate GRC summary for cloud findings
        cloud_grc_summary = get_grc_summary_for_findings(cloud_findings_list)
        current_app.logger.info(f"Cloud GRC Summary: {len(cloud_grc_summary)} frameworks affected")
        
        # Calculate cloud provider stats
        cloud_stats = {
            'aws': len([f for f in cloud_findings_list if f.asset_aws_ec2_instance_id]),
            'azure': len([f for f in cloud_findings_list if f.asset_azure_vm_id]),
            'gcp': len([f for f in cloud_findings_list if f.asset_gcp_instance_id])
        }
        
        current_app.logger.info(f"Retrieved {len(cloud_findings_list)} cloud asset vulnerabilities")
        
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
    """WAS findings view with GRC summary"""
    try:
        # Get filter parameters
        selected_severity = request.args.get('severity', 'all')
        selected_status = request.args.get('status', 'active')
        
        # Build query for WAS findings
        query = db.session.query(WASFinding)
        
        # Apply status filtering
        if selected_status == 'active':
            query = query.filter(WASFinding.status == 'Active')
        elif selected_status == 'fixed':
            query = query.filter(WASFinding.status == 'Fixed')
        
        # Apply severity filtering
        if selected_severity != 'all':
            query = query.filter(WASFinding.severity == selected_severity)
        
        # CRITICAL: Load GRC mappings eagerly
        query = query.options(
            subqueryload(WASFinding.plugin_compliance_mappings).subqueryload(
                PluginComplianceMapping.compliance_requirement
            )
        )
        
        # Order by severity and last detected
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
        
        # Generate GRC summary for WAS findings
        was_specific_grc_summary = get_grc_summary_for_findings(was_findings_list)
        current_app.logger.info(f"WAS Specific GRC Summary: {len(was_specific_grc_summary)} frameworks affected")
        
        current_app.logger.info(f"Retrieved {len(was_findings_list)} WAS findings with GRC mappings")
        
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
    """Executive-level security dashboard with high-level metrics and trends"""
    try:
        current_app.logger.info("Loading executive dashboard")
        
        # Time periods for trend analysis
        now = datetime.now(timezone.utc)
        thirty_days_ago = now - timedelta(days=30)
        sixty_days_ago = now - timedelta(days=60)
        ninety_days_ago = now - timedelta(days=90)
        
        # Current period metrics (last 30 days)
        current_findings = db.session.query(VulnerabilityFinding).filter(
            VulnerabilityFinding.state.in_(['OPEN', 'REOPENED']),
            VulnerabilityFinding.severity.notin_(['info']),
            VulnerabilityFinding.last_found >= thirty_days_ago
        ).options(
            subqueryload(VulnerabilityFinding.plugin_compliance_mappings).subqueryload(
                PluginComplianceMapping.compliance_requirement
            )
        ).all()
        
        # Previous period metrics (30-60 days ago)
        previous_findings = db.session.query(VulnerabilityFinding).filter(
            VulnerabilityFinding.state.in_(['OPEN', 'REOPENED']),
            VulnerabilityFinding.severity.notin_(['info']),
            VulnerabilityFinding.last_found >= sixty_days_ago,
            VulnerabilityFinding.last_found < thirty_days_ago
        ).all()
        
        # Calculate key metrics
        total_current = len(current_findings)
        total_previous = len(previous_findings)
        
        # Severity breakdown current
        severity_current = {
            'critical': len([f for f in current_findings if f.severity == 'critical']),
            'high': len([f for f in current_findings if f.severity == 'high']),
            'medium': len([f for f in current_findings if f.severity == 'medium']),
            'low': len([f for f in current_findings if f.severity == 'low'])
        }
        
        # Severity breakdown previous
        severity_previous = {
            'critical': len([f for f in previous_findings if f.severity == 'critical']),
            'high': len([f for f in previous_findings if f.severity == 'high']),
            'medium': len([f for f in previous_findings if f.severity == 'medium']),
            'low': len([f for f in previous_findings if f.severity == 'low'])
        }
        
        # Calculate trends (percentage change)
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
        
        # Mean Time To Remediate (MTTR) - findings that were fixed in last 30 days
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
                mttr_critical = round(sum([
                    (f.fixed_at - f.first_found).days 
                    for f in fixed_findings 
                    if f.severity == 'critical' and f.first_found and f.fixed_at
                ]) / max(len([f for f in fixed_findings if f.severity == 'critical']), 1), 1)
            else:
                mttr_days = 0
                mttr_critical = 0
        else:
            mttr_days = 0
            mttr_critical = 0
        
        # Attack surface metrics
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
        
        # Cloud presence
        cloud_assets = {
            'aws': len(set([f.asset_uuid for f in current_findings if f.asset_aws_ec2_instance_id])),
            'azure': len(set([f.asset_uuid for f in current_findings if f.asset_azure_vm_id])),
            'gcp': len(set([f.asset_uuid for f in current_findings if f.asset_gcp_instance_id]))
        }
        total_cloud_assets = cloud_assets['aws'] + cloud_assets['azure'] + cloud_assets['gcp']
        
        # Attack path analysis
        attack_path_findings = len([f for f in current_findings if f.is_in_attack_path])
        attack_path_assets = len(set([f.asset_uuid for f in current_findings if f.is_in_attack_path]))
        
        # GRC Compliance Summary
        grc_summary = get_grc_summary_for_findings(current_findings)
        
        # Calculate compliance posture score (0-100)
        # Higher score = better (fewer findings relative to requirements)
        if grc_summary:
            total_grc_findings = sum(fw['total_findings'] for fw in grc_summary.values())
            total_requirements = sum(fw['requirements_count'] for fw in grc_summary.values())
            
            # Score: 100 - (findings per requirement ratio * 10)
            if total_requirements > 0:
                findings_per_req = total_grc_findings / total_requirements
                compliance_score = max(0, min(100, 100 - (findings_per_req * 10)))
            else:
                compliance_score = 0
        else:
            compliance_score = 100  # No frameworks = nothing to fail
            total_grc_findings = 0
            total_requirements = 0
        
        # Risk score calculation (0-100, higher = more risk)
        # Weighted by severity: critical=10, high=5, medium=2, low=1
        risk_points = (
            severity_current['critical'] * 10 +
            severity_current['high'] * 5 +
            severity_current['medium'] * 2 +
            severity_current['low'] * 1
        )
        
        # Normalize to 0-100 scale (assuming 100 risk points = 100% risk)
        risk_score = min(100, risk_points)
        
        # Top 10 vulnerabilities by asset count
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
        
        # Weekly trend data (last 12 weeks)
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
        
        current_app.logger.info(f"Executive dashboard loaded: {total_current} findings, Risk Score: {risk_score}")
        
        return render_template('executive_dashboard.html', data=executive_data)
        
    except Exception as e:
        current_app.logger.error(f"Error loading executive dashboard: {e}")
        traceback.print_exc()
        return f"Error loading executive dashboard: {str(e)}", 500

@main_bp.route('/executive_dashboard/pdf')
def executive_dashboard_pdf():
    """Generate PDF export of executive dashboard"""
    try:
        from weasyprint import HTML, CSS
        from flask import make_response
        import io
        
        current_app.logger.info("Generating executive dashboard PDF")
        
        # Get the same data as the dashboard
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
        
        def calculate_trend(current, previous):
            if previous == 0:
                return 100 if current > 0 else 0
            return round(((current - previous) / previous) * 100, 1)
        
        trends = {
            'total': calculate_trend(total_current, total_previous)
        }
        
        total_assets = db.session.query(
            func.count(func.distinct(VulnerabilityFinding.asset_uuid))
        ).filter(
            VulnerabilityFinding.last_found >= thirty_days_ago
        ).scalar()
        
        attack_path_findings = len([f for f in current_findings if f.is_in_attack_path])
        grc_summary = get_grc_summary_for_findings(current_findings)
        
        # Calculate risk score
        risk_points = (
            severity_current['critical'] * 10 +
            severity_current['high'] * 5 +
            severity_current['medium'] * 2 +
            severity_current['low'] * 1
        )
        risk_score = min(100, risk_points)
        
        # Generate HTML for PDF
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Executive Security Dashboard Report</title>
            <style>
                @page {{
                    size: A4;
                    margin: 2cm;
                }}
                body {{
                    font-family: 'Helvetica', 'Arial', sans-serif;
                    color: #333;
                    line-height: 1.6;
                }}
                .header {{
                    text-align: center;
                    border-bottom: 3px solid #2c3e50;
                    padding-bottom: 20px;
                    margin-bottom: 30px;
                }}
                .header h1 {{
                    color: #2c3e50;
                    margin: 0;
                    font-size: 28pt;
                }}
                .header p {{
                    color: #7f8c8d;
                    margin: 10px 0 0 0;
                }}
                .metric-grid {{
                    display: grid;
                    grid-template-columns: 1fr 1fr 1fr;
                    gap: 15px;
                    margin: 20px 0;
                }}
                .metric-card {{
                    border: 2px solid #ecf0f1;
                    border-radius: 8px;
                    padding: 15px;
                    text-align: center;
                }}
                .metric-card h3 {{
                    color: #7f8c8d;
                    font-size: 11pt;
                    margin: 0 0 10px 0;
                    text-transform: uppercase;
                }}
                .metric-card .value {{
                    font-size: 32pt;
                    font-weight: bold;
                    color: #2c3e50;
                    margin: 10px 0;
                }}
                .metric-card.critical .value {{ color: #e74c3c; }}
                .metric-card.high .value {{ color: #fd7e14; }}
                .metric-card.risk .value {{ color: #e74c3c; }}
                .metric-card.positive .value {{ color: #27ae60; }}
                .trend {{
                    font-size: 10pt;
                    color: #7f8c8d;
                }}
                .trend.up {{ color: #e74c3c; }}
                .trend.down {{ color: #27ae60; }}
                .section {{
                    margin: 30px 0;
                    page-break-inside: avoid;
                }}
                .section h2 {{
                    color: #2c3e50;
                    border-bottom: 2px solid #3498db;
                    padding-bottom: 10px;
                    font-size: 18pt;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin: 15px 0;
                }}
                th {{
                    background: #34495e;
                    color: white;
                    padding: 12px;
                    text-align: left;
                    font-size: 10pt;
                }}
                td {{
                    padding: 10px 12px;
                    border-bottom: 1px solid #ecf0f1;
                    font-size: 9pt;
                }}
                tr:nth-child(even) {{
                    background: #f8f9fa;
                }}
                .severity-badge {{
                    display: inline-block;
                    padding: 4px 12px;
                    border-radius: 4px;
                    color: white;
                    font-weight: bold;
                    font-size: 8pt;
                }}
                .severity-critical {{ background: #e74c3c; }}
                .severity-high {{ background: #fd7e14; }}
                .severity-medium {{ background: #f39c12; }}
                .severity-low {{ background: #3498db; }}
                .grc-grid {{
                    display: grid;
                    grid-template-columns: 1fr 1fr;
                    gap: 10px;
                    margin: 15px 0;
                }}
                .grc-card {{
                    border: 1px solid #3498db;
                    border-radius: 6px;
                    padding: 12px;
                }}
                .grc-card h4 {{
                    color: #3498db;
                    margin: 0 0 8px 0;
                    font-size: 11pt;
                }}
                .grc-stat {{
                    font-size: 9pt;
                    margin: 5px 0;
                }}
                .footer {{
                    margin-top: 40px;
                    padding-top: 20px;
                    border-top: 2px solid #ecf0f1;
                    text-align: center;
                    color: #7f8c8d;
                    font-size: 9pt;
                }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Executive Security Dashboard</h1>
                <p>Generated: {now.strftime('%B %d, %Y at %H:%M UTC')}</p>
                <p>Reporting Period: Last 30 Days</p>
            </div>
            
            <div class="metric-grid">
                <div class="metric-card critical">
                    <h3>Critical Findings</h3>
                    <div class="value">{severity_current['critical']}</div>
                    <div class="trend">Immediate Action Required</div>
                </div>
                <div class="metric-card high">
                    <h3>High Findings</h3>
                    <div class="value">{severity_current['high']}</div>
                    <div class="trend">High Priority</div>
                </div>
                <div class="metric-card">
                    <h3>Total Assets</h3>
                    <div class="value">{total_assets}</div>
                    <div class="trend">Under Management</div>
                </div>
            </div>
            
            <div class="metric-grid">
                <div class="metric-card risk">
                    <h3>Risk Score</h3>
                    <div class="value">{round(risk_score, 0)}/100</div>
                    <div class="trend">{'High Risk' if risk_score > 70 else 'Moderate Risk' if risk_score > 40 else 'Low Risk'}</div>
                </div>
                <div class="metric-card">
                    <h3>Attack Paths</h3>
                    <div class="value">{attack_path_findings}</div>
                    <div class="trend">Chained Vulnerabilities</div>
                </div>
                <div class="metric-card {'positive' if trends['total'] < 0 else ''}">
                    <h3>30-Day Trend</h3>
                    <div class="value">{trends['total']:+.0f}%</div>
                    <div class="trend {'down' if trends['total'] < 0 else 'up'}">vs. Previous Period</div>
                </div>
            </div>
            
            <div class="section">
                <h2>Severity Distribution</h2>
                <table>
                    <tr>
                        <th>Severity</th>
                        <th style="text-align: right;">Count</th>
                        <th style="text-align: right;">Percentage</th>
                    </tr>
                    <tr>
                        <td><span class="severity-badge severity-critical">CRITICAL</span></td>
                        <td style="text-align: right;">{severity_current['critical']}</td>
                        <td style="text-align: right;">{round(severity_current['critical']/max(total_current,1)*100, 1)}%</td>
                    </tr>
                    <tr>
                        <td><span class="severity-badge severity-high">HIGH</span></td>
                        <td style="text-align: right;">{severity_current['high']}</td>
                        <td style="text-align: right;">{round(severity_current['high']/max(total_current,1)*100, 1)}%</td>
                    </tr>
                    <tr>
                        <td><span class="severity-badge severity-medium">MEDIUM</span></td>
                        <td style="text-align: right;">{severity_current['medium']}</td>
                        <td style="text-align: right;">{round(severity_current['medium']/max(total_current,1)*100, 1)}%</td>
                    </tr>
                    <tr>
                        <td><span class="severity-badge severity-low">LOW</span></td>
                        <td style="text-align: right;">{severity_current['low']}</td>
                        <td style="text-align: right;">{round(severity_current['low']/max(total_current,1)*100, 1)}%</td>
                    </tr>
                </table>
            </div>
            
            {'<div class="section"><h2>GRC Compliance Summary</h2><div class="grc-grid">' + ''.join([
                f'<div class="grc-card"><h4>{fw}</h4>' +
                f'<div class="grc-stat"><strong>{data["total_findings"]}</strong> Total Findings</div>' +
                f'<div class="grc-stat"><strong>{data["critical"]}</strong> Critical | <strong>{data["high"]}</strong> High</div>' +
                f'<div class="grc-stat"><strong>{data["requirements_count"]}</strong> Requirements Affected</div></div>'
                for fw, data in list(grc_summary.items())[:4]
            ]) + '</div></div>' if grc_summary else ''}
            
            <div class="section">
                <h2>Executive Summary</h2>
                <p><strong>Security Posture:</strong> The organization currently has <strong>{total_current}</strong> active security findings across <strong>{total_assets}</strong> managed assets.</p>
                <p><strong>Critical Issues:</strong> There are <strong>{severity_current['critical']}</strong> critical vulnerabilities requiring immediate attention.</p>
                <p><strong>Trend Analysis:</strong> Findings have {'increased' if trends['total'] > 0 else 'decreased'} by <strong>{abs(trends['total']):.1f}%</strong> compared to the previous 30-day period.</p>
                {f'<p><strong>Attack Surface:</strong> <strong>{attack_path_findings}</strong> vulnerabilities are part of identified attack paths, representing elevated risk.</p>' if attack_path_findings > 0 else ''}
                {f'<p><strong>Compliance:</strong> <strong>{len(grc_summary)}</strong> regulatory frameworks are impacted by current vulnerabilities.</p>' if grc_summary else ''}
            </div>
            
            <div class="footer">
                <p><strong>Confidential - Executive Leadership</strong></p>
                <p>Tenable Vulnerability Management Dashboard | Generated by Security Operations</p>
            </div>
        </body>
        </html>
        """
        
        # Generate PDF
        pdf_file = HTML(string=html_content).write_pdf()
        
        # Create response
        response = make_response(pdf_file)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename=executive_security_report_{now.strftime("%Y%m%d")}.pdf'
        
        current_app.logger.info("Executive dashboard PDF generated successfully")
        return response
        
    except ImportError:
        return jsonify({
            'error': 'PDF generation requires WeasyPrint library',
            'install': 'pip install weasyprint'
        }), 500
    except Exception as e:
        current_app.logger.error(f"Error generating PDF: {e}")
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500