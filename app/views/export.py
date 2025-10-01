import io
import csv
from datetime import datetime, timedelta, timezone
from flask import Blueprint, make_response, current_app, request
from sqlalchemy.orm import subqueryload

from ..database import db
from ..models import VulnerabilityFinding, WASFinding, PluginComplianceMapping, ComplianceRequirement

# Create blueprint
export_bp = Blueprint('export', __name__)

def generate_csv_content(findings):
    """Generate CSV content for findings"""
    csv_buffer = io.StringIO()
    csv_writer = csv.writer(csv_buffer)

    # Enhanced header with GRC data
    header = [
        "Plugin Name", "Plugin ID", "Asset Hostname", "Asset IPv4", "Severity", "VPR Score",
        "CVSSv3 Base Score", "Description", "Solution", "First Found", "Last Found",
        "State", "Cloud Provider", "Attack Path Score", "Attack Path Involved", 
        "GRC Frameworks", "GRC Requirements", "Asset OS"
    ]
    csv_writer.writerow(header)

    for finding in findings:
        # Determine cloud provider
        cloud_provider = "N/A"
        if finding.asset_aws_ec2_instance_id:
            cloud_provider = "AWS"
        elif finding.asset_azure_vm_id:
            cloud_provider = "Azure"
        elif finding.asset_gcp_instance_id:
            cloud_provider = "GCP"

        # Compile GRC compliance data
        grc_frameworks = []
        grc_requirements = []
        
        if hasattr(finding, 'plugin_compliance_mappings') and finding.plugin_compliance_mappings:
            for mapping in finding.plugin_compliance_mappings:
                if mapping.compliance_requirement:
                    grc_frameworks.append(mapping.compliance_requirement.framework)
                    grc_requirements.append(f"{mapping.compliance_requirement.framework}: {mapping.compliance_requirement.requirement_id}")
        
        grc_frameworks_str = " | ".join(set(grc_frameworks)) if grc_frameworks else "N/A"
        grc_requirements_str = " | ".join(grc_requirements) if grc_requirements else "N/A"

        # Safely handle None values and long text
        description = finding.description or "No description"
        if len(description) > 500:
            description = description[:497] + "..."
            
        solution = finding.solution or "No solution"
        if len(solution) > 500:
            solution = solution[:497] + "..."

        row = [
            finding.plugin_name or "Unknown Plugin",
            finding.plugin_id or "",
            finding.asset_hostname or "",
            finding.asset_ipv4 or "",
            finding.severity or "",
            finding.vpr_score or "",
            finding.cvss_v3_base_score or "",
            description,
            solution,
            finding.first_found.isoformat() if finding.first_found else '',
            finding.last_found.isoformat() if finding.last_found else '',
            finding.state or "OPEN",
            cloud_provider,
            finding.attack_path_score or "",
            "Yes" if hasattr(finding, 'is_in_attack_path') and finding.is_in_attack_path else "No",
            grc_frameworks_str,
            grc_requirements_str,
            finding.asset_os or ""
        ]
        csv_writer.writerow(row)

    return csv_buffer.getvalue()

def generate_txt_content(findings):
    """Generate TXT format report for findings"""
    content = []
    content.append("=" * 80)
    content.append("TENABLE VULNERABILITY FINDINGS REPORT")
    content.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    content.append(f"Total Findings: {len(findings)}")
    content.append("=" * 80)
    content.append("")

    # Calculate summary statistics
    severity_counts = {}
    attack_path_count = 0
    cloud_count = 0
    grc_mapped_count = 0
    
    for finding in findings:
        severity = finding.severity or 'unknown'
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        if hasattr(finding, 'is_in_attack_path') and finding.is_in_attack_path:
            attack_path_count += 1
        if (finding.asset_aws_ec2_instance_id or 
            finding.asset_azure_vm_id or 
            finding.asset_gcp_instance_id):
            cloud_count += 1
        if hasattr(finding, 'plugin_compliance_mappings') and finding.plugin_compliance_mappings:
            grc_mapped_count += 1

    content.append("EXECUTIVE SUMMARY:")
    content.append("-" * 30)
    for severity in ['critical', 'high', 'medium', 'low']:
        count = severity_counts.get(severity, 0)
        content.append(f"{severity.upper():>12}: {count}")
    content.append("")
    content.append(f"ATTACK PATH FINDINGS: {attack_path_count}")
    content.append(f"CLOUD FINDINGS: {cloud_count}")
    content.append(f"GRC MAPPED FINDINGS: {grc_mapped_count}")
    content.append("")
    content.append("=" * 80)
    content.append("")

    for i, finding in enumerate(findings, 1):
        content.append(f"FINDING #{i}")
        content.append("-" * 40)
        content.append(f"Plugin Name: {finding.plugin_name}")
        content.append(f"Plugin ID: {finding.plugin_id}")
        content.append(f"Severity: {finding.severity}")
        
        if finding.vpr_score:
            content.append(f"VPR Score: {finding.vpr_score}")
        if finding.cvss_v3_base_score:
            content.append(f"CVSS v3 Base Score: {finding.cvss_v3_base_score}")
        if hasattr(finding, 'attack_path_score') and finding.attack_path_score:
            content.append(f"Attack Path Score: {finding.attack_path_score}")
        if hasattr(finding, 'asset_exposure_score') and finding.asset_exposure_score:
            content.append(f"Asset Exposure Score: {finding.asset_exposure_score}")
            
        content.append("")
        content.append("AFFECTED ASSET:")
        asset_id = (finding.asset_hostname or 
                   finding.asset_ipv4 or 
                   finding.asset_aws_ec2_instance_id or 
                   finding.asset_azure_vm_id or 
                   finding.asset_gcp_instance_id or 
                   'Unknown')
        content.append(f"  Asset: {asset_id}")
        
        if finding.asset_os:
            content.append(f"  Operating System: {finding.asset_os}")
            
        if finding.asset_aws_ec2_instance_id:
            content.append(f"  AWS EC2 Instance: {finding.asset_aws_ec2_instance_id}")
        if finding.asset_azure_vm_id:
            content.append(f"  Azure VM: {finding.asset_azure_vm_id}")
        if finding.asset_gcp_instance_id:
            content.append(f"  GCP Instance: {finding.asset_gcp_instance_id}")
            
        if hasattr(finding, 'business_criticality') and finding.business_criticality:
            content.append(f"  Business Criticality: {finding.business_criticality}")
            
        content.append("")
        
        if finding.description:
            content.append("DESCRIPTION:")
            desc_text = finding.description
            if len(desc_text) > 500:
                desc_text = desc_text[:500] + "..."
            content.append(desc_text)
            content.append("")
            
        if finding.solution:
            content.append("SOLUTION:")
            sol_text = finding.solution
            if len(sol_text) > 500:
                sol_text = sol_text[:500] + "..."
            content.append(sol_text)
            content.append("")
            
        if hasattr(finding, 'is_in_attack_path') and finding.is_in_attack_path:
            content.append("⚠️ PART OF ATTACK PATH")
            content.append("")
            
        # GRC COMPLIANCE MAPPINGS
        if hasattr(finding, 'plugin_compliance_mappings') and finding.plugin_compliance_mappings:
            content.append("GRC COMPLIANCE IMPACT:")
            for mapping in finding.plugin_compliance_mappings:
                if mapping.compliance_requirement:
                    content.append(f"  • {mapping.compliance_requirement.framework}: "
                                 f"{mapping.compliance_requirement.requirement_id}")
                    if mapping.compliance_requirement.description:
                        desc = mapping.compliance_requirement.description
                        if len(desc) > 100:
                            desc = desc[:100] + "..."
                        content.append(f"    {desc}")
            content.append("")
        else:
            content.append("GRC COMPLIANCE IMPACT: None configured")
            content.append("")
            
        content.append("TIMELINE:")
        if finding.first_found:
            content.append(f"  First Found: {finding.first_found.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        if finding.last_found:
            content.append(f"  Last Found: {finding.last_found.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        if hasattr(finding, 'fixed_at') and finding.fixed_at:
            content.append(f"  Fixed At: {finding.fixed_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
            
        content.append("")
        content.append("=" * 80)
        content.append("")

    return "\n".join(content)

@export_bp.route('/export_csv')
def export_csv():
    """Export all findings to CSV"""
    try:
        # Get all active findings excluding info
        findings = db.session.query(VulnerabilityFinding).options(
            subqueryload(VulnerabilityFinding.plugin_compliance_mappings).subqueryload(
                PluginComplianceMapping.compliance_requirement
            )
        ).filter(
            VulnerabilityFinding.state.in_(['OPEN', 'REOPENED']),
            VulnerabilityFinding.severity.notin_(['info'])
        ).order_by(VulnerabilityFinding.severity.desc()).all()
        
        csv_content = generate_csv_content(findings)
        
        response = make_response(csv_content)
        response.headers["Content-Disposition"] = f"attachment; filename=tenable_findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        response.headers["Content-type"] = "text/csv"
        return response
        
    except Exception as e:
        current_app.logger.error(f"Error during CSV export: {e}")
        return f"Error generating CSV report: {str(e)}", 500

@export_bp.route('/export_txt')
def export_txt():
    """Export all findings to TXT format"""
    try:
        findings = db.session.query(VulnerabilityFinding).options(
            subqueryload(VulnerabilityFinding.plugin_compliance_mappings).subqueryload(
                PluginComplianceMapping.compliance_requirement
            )
        ).filter(
            VulnerabilityFinding.state.in_(['OPEN', 'REOPENED']),
            VulnerabilityFinding.severity.notin_(['info'])
        ).order_by(VulnerabilityFinding.severity.desc()).all()
        
        txt_content = generate_txt_content(findings)
        
        response = make_response(txt_content)
        response.headers["Content-Disposition"] = f"attachment; filename=tenable_findings_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        response.headers["Content-type"] = "text/plain; charset=utf-8"
        return response
        
    except Exception as e:
        current_app.logger.error(f"Error during TXT export: {e}")
        return f"Error generating TXT report: {str(e)}", 500

@export_bp.route('/export_single_finding_txt/<int:finding_id>')
def export_single_finding_txt(finding_id):
    """Export single finding as TXT for tickets"""
    try:
        finding = db.session.query(VulnerabilityFinding).options(
            subqueryload(VulnerabilityFinding.plugin_compliance_mappings).subqueryload(
                PluginComplianceMapping.compliance_requirement
            )
        ).filter_by(id=finding_id).first()
        
        if not finding:
            return "Finding not found", 404

        txt_content = generate_txt_content([finding])
        
        response = make_response(txt_content)
        response.headers["Content-Disposition"] = f"attachment; filename=ticket_finding_{finding.id}_{finding.plugin_id}.txt"
        response.headers["Content-type"] = "text/plain; charset=utf-8"
        return response
        
    except Exception as e:
        current_app.logger.error(f"Error exporting single finding TXT {finding_id}: {e}")
        return f"Error exporting finding: {str(e)}", 500

@export_bp.route('/export_grouped_findings_txt')
def export_grouped_findings_txt():
    """Export grouped findings as TXT with GRC mappings"""
    try:
        # Get filter parameters (same as grouped_findings view)
        selected_severity = request.args.get('severity', 'actionable')
        selected_state = request.args.get('state', 'active')
        selected_time_period = request.args.get('time_period', '30_days')
        
        # Build query
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
        
        # Load GRC mappings
        query = query.options(
            subqueryload(VulnerabilityFinding.plugin_compliance_mappings).subqueryload(
                PluginComplianceMapping.compliance_requirement
            )
        )
        
        all_findings = query.all()
        
        # Group findings by plugin
        grouped_findings = {}
        for finding in all_findings:
            plugin_key = f"{finding.plugin_id}"
            
            if plugin_key not in grouped_findings:
                # Get GRC mappings for this plugin
                grc_mappings = []
                if hasattr(finding, 'plugin_compliance_mappings') and finding.plugin_compliance_mappings:
                    for mapping in finding.plugin_compliance_mappings:
                        if mapping.compliance_requirement:
                            grc_mappings.append({
                                'framework': mapping.compliance_requirement.framework,
                                'requirement_id': mapping.compliance_requirement.requirement_id,
                                'description': mapping.compliance_requirement.description
                            })
                
                grouped_findings[plugin_key] = {
                    'plugin_id': finding.plugin_id,
                    'plugin_name': finding.plugin_name or 'Unknown Plugin',
                    'severity': finding.severity,
                    'vpr_score': finding.vpr_score,
                    'description': finding.description,
                    'solution': finding.solution,
                    'grc_mappings': grc_mappings,
                    'affected_assets': [],
                    'asset_count': 0
                }
            
            # Add asset to group
            asset_str = finding.asset_hostname or finding.asset_ipv4 or 'Unknown'
            if finding.asset_aws_ec2_instance_id:
                asset_str += f" (AWS: {finding.asset_aws_ec2_instance_id})"
            elif finding.asset_azure_vm_id:
                asset_str += f" (Azure: {finding.asset_azure_vm_id})"
            elif finding.asset_gcp_instance_id:
                asset_str += f" (GCP: {finding.asset_gcp_instance_id})"
            
            grouped_findings[plugin_key]['affected_assets'].append(asset_str)
            grouped_findings[plugin_key]['asset_count'] += 1
        
        # Generate TXT content
        content = []
        content.append("=" * 80)
        content.append("TENABLE GROUPED VULNERABILITY FINDINGS REPORT")
        content.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        content.append(f"Total Unique Vulnerabilities: {len(grouped_findings)}")
        content.append(f"Total Affected Asset Instances: {sum(g['asset_count'] for g in grouped_findings.values())}")
        content.append("=" * 80)
        content.append("")
        
        # Sort by severity and asset count
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        sorted_groups = sorted(
            grouped_findings.values(),
            key=lambda x: (severity_order.get(x['severity'], 0), x['asset_count']),
            reverse=True
        )
        
        for i, group in enumerate(sorted_groups, 1):
            content.append(f"VULNERABILITY #{i}")
            content.append("-" * 40)
            content.append(f"Plugin Name: {group['plugin_name']}")
            content.append(f"Plugin ID: {group['plugin_id']}")
            content.append(f"Severity: {group['severity'] or 'Unknown'}")
            content.append(f"Affected Assets: {group['asset_count']}")
            
            if group['vpr_score']:
                content.append(f"VPR Score: {group['vpr_score']}")
            
            content.append("")
            content.append("AFFECTED ASSETS:")
            for asset in group['affected_assets'][:50]:  # Limit to first 50
                content.append(f"  • {asset}")
            if group['asset_count'] > 50:
                content.append(f"  ... and {group['asset_count'] - 50} more assets")
            
            content.append("")
            
            if group['description']:
                content.append("DESCRIPTION:")
                desc_text = group['description']
                if len(desc_text) > 500:
                    desc_text = desc_text[:500] + "..."
                content.append(desc_text)
                content.append("")
            
            if group['solution']:
                content.append("SOLUTION:")
                sol_text = group['solution']
                if len(sol_text) > 500:
                    sol_text = sol_text[:500] + "..."
                content.append(sol_text)
                content.append("")
            
            # GRC COMPLIANCE MAPPINGS
            if group['grc_mappings']:
                content.append("GRC COMPLIANCE IMPACT:")
                for mapping in group['grc_mappings']:
                    content.append(f"  • {mapping['framework']}: {mapping['requirement_id']}")
                    if mapping['description']:
                        desc = mapping['description']
                        if len(desc) > 100:
                            desc = desc[:100] + "..."
                        content.append(f"    {desc}")
                content.append("")
            else:
                content.append("GRC COMPLIANCE IMPACT: None configured")
                content.append("")
            
            content.append("=" * 80)
            content.append("")
        
        txt_content = "\n".join(content)
        response = make_response(txt_content)
        response.headers["Content-Disposition"] = f"attachment; filename=grouped_findings_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        response.headers["Content-type"] = "text/plain; charset=utf-8"
        return response
        
    except Exception as e:
        current_app.logger.error(f"Error exporting grouped findings: {e}")
        return f"Error exporting grouped findings: {str(e)}", 500

@export_bp.route('/export_was_findings_txt')
def export_was_findings_txt():
    """Export WAS findings as TXT with GRC mappings"""
    try:
        # Get filter parameters
        selected_severity = request.args.get('severity', 'all')
        selected_status = request.args.get('status', 'active')
        
        # Build query
        query = db.session.query(WASFinding)
        
        if selected_status == 'active':
            query = query.filter(WASFinding.status == 'Active')
        elif selected_status == 'fixed':
            query = query.filter(WASFinding.status == 'Fixed')
        
        if selected_severity != 'all':
            query = query.filter(WASFinding.severity == selected_severity)
        
        # Load GRC mappings
        query = query.options(
            subqueryload(WASFinding.plugin_compliance_mappings).subqueryload(
                PluginComplianceMapping.compliance_requirement
            )
        )
        
        was_findings = query.all()
        
        # Generate TXT content
        content = []
        content.append("=" * 80)
        content.append("TENABLE WEB APPLICATION SECURITY FINDINGS REPORT")
        content.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        content.append(f"Total WAS Findings: {len(was_findings)}")
        content.append("=" * 80)
        content.append("")
        
        # Calculate summary
        severity_counts = {}
        grc_mapped_count = 0
        
        for finding in was_findings:
            severity = finding.severity or 'unknown'
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            if hasattr(finding, 'plugin_compliance_mappings') and finding.plugin_compliance_mappings:
                grc_mapped_count += 1
        
        content.append("EXECUTIVE SUMMARY:")
        content.append("-" * 30)
        for severity in ['critical', 'high', 'medium', 'low']:
            count = severity_counts.get(severity, 0)
            content.append(f"{severity.upper():>12}: {count}")
        content.append(f"{'GRC MAPPED':>12}: {grc_mapped_count}")
        content.append("")
        content.append("=" * 80)
        content.append("")
        
        for i, finding in enumerate(was_findings, 1):
            content.append(f"WAS FINDING #{i}")
            content.append("-" * 40)
            content.append(f"Vulnerability Name: {finding.vulnerability_name or 'Unknown'}")
            
            if finding.vulnerability_id:
                content.append(f"Vulnerability ID: {finding.vulnerability_id}")
            
            content.append(f"Severity: {finding.severity or 'Unknown'}")
            content.append(f"Status: {finding.status or 'Active'}")
            
            content.append("")
            content.append("TARGET:")
            content.append(f"  URL: {finding.target_url or 'N/A'}")
            
            if finding.owasp_category:
                content.append(f"  OWASP Category: {finding.owasp_category}")
            
            if finding.cvss_v3_base_score:
                content.append(f"  CVSS v3 Score: {finding.cvss_v3_base_score}")
            
            content.append("")
            
            if finding.description:
                content.append("DESCRIPTION:")
                desc_text = finding.description
                if len(desc_text) > 500:
                    desc_text = desc_text[:500] + "..."
                content.append(desc_text)
                content.append("")
            
            if finding.solution:
                content.append("SOLUTION:")
                sol_text = finding.solution
                if len(sol_text) > 500:
                    sol_text = sol_text[:500] + "..."
                content.append(sol_text)
                content.append("")
            
            # GRC COMPLIANCE MAPPINGS
            if hasattr(finding, 'plugin_compliance_mappings') and finding.plugin_compliance_mappings:
                content.append("GRC COMPLIANCE IMPACT:")
                for mapping in finding.plugin_compliance_mappings:
                    if mapping.compliance_requirement:
                        content.append(f"  • {mapping.compliance_requirement.framework}: "
                                     f"{mapping.compliance_requirement.requirement_id}")
                        if mapping.compliance_requirement.description:
                            desc = mapping.compliance_requirement.description
                            if len(desc) > 100:
                                desc = desc[:100] + "..."
                            content.append(f"    {desc}")
                content.append("")
            else:
                content.append("GRC COMPLIANCE IMPACT: None configured")
                content.append("")
            
            content.append("TIMELINE:")
            if finding.first_detected_at:
                content.append(f"  First Detected: {finding.first_detected_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
            if finding.last_detected_at:
                content.append(f"  Last Detected: {finding.last_detected_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
            
            content.append("")
            content.append("=" * 80)
            content.append("")
        
        txt_content = "\n".join(content)
        response = make_response(txt_content)
        response.headers["Content-Disposition"] = f"attachment; filename=was_findings_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        response.headers["Content-type"] = "text/plain; charset=utf-8"
        return response
        
    except Exception as e:
        current_app.logger.error(f"Error exporting WAS findings: {e}")
        return f"Error exporting WAS findings: {str(e)}", 500

@export_bp.route('/export_single_grouped_finding_txt/<int:plugin_id>')
def export_single_grouped_finding_txt(plugin_id):
    """Export a single grouped finding (all instances of a vulnerability) as TXT"""
    try:
        # Get all findings for this plugin
        findings = db.session.query(VulnerabilityFinding).options(
            subqueryload(VulnerabilityFinding.plugin_compliance_mappings).subqueryload(
                PluginComplianceMapping.compliance_requirement
            )
        ).filter(
            VulnerabilityFinding.plugin_id == plugin_id,
            VulnerabilityFinding.state.in_(['OPEN', 'REOPENED'])
        ).all()
        
        if not findings:
            return "No findings found for this plugin", 404
        
        # Get plugin info from first finding
        first_finding = findings[0]
        
        # Generate grouped TXT content
        content = []
        content.append("=" * 80)
        content.append("TENABLE GROUPED VULNERABILITY TICKET")
        content.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        content.append("=" * 80)
        content.append("")
        
        content.append("VULNERABILITY DETAILS:")
        content.append("-" * 40)
        content.append(f"Plugin Name: {first_finding.plugin_name or 'Unknown'}")
        content.append(f"Plugin ID: {first_finding.plugin_id}")
        content.append(f"Severity: {first_finding.severity or 'Unknown'}")
        
        if first_finding.vpr_score:
            content.append(f"VPR Score: {first_finding.vpr_score}")
        if first_finding.cvss_v3_base_score:
            content.append(f"CVSS v3 Base Score: {first_finding.cvss_v3_base_score}")
        
        content.append("")
        content.append(f"AFFECTED ASSETS: {len(findings)} total")
        content.append("-" * 40)
        
        for i, finding in enumerate(findings, 1):
            asset_id = finding.asset_hostname or finding.asset_ipv4 or 'Unknown'
            content.append(f"{i}. {asset_id}")
            
            if finding.asset_aws_ec2_instance_id:
                content.append(f"   AWS EC2: {finding.asset_aws_ec2_instance_id}")
            if finding.asset_azure_vm_id:
                content.append(f"   Azure VM: {finding.asset_azure_vm_id}")
            if finding.asset_gcp_instance_id:
                content.append(f"   GCP: {finding.asset_gcp_instance_id}")
            if finding.asset_os:
                content.append(f"   OS: {finding.asset_os}")
        
        content.append("")
        
        if first_finding.description:
            content.append("DESCRIPTION:")
            content.append(first_finding.description)
            content.append("")
        
        if first_finding.solution:
            content.append("REMEDIATION STEPS:")
            content.append(first_finding.solution)
            content.append("")
        
        # GRC COMPLIANCE MAPPINGS
        if hasattr(first_finding, 'plugin_compliance_mappings') and first_finding.plugin_compliance_mappings:
            content.append("GRC COMPLIANCE IMPACT:")
            for mapping in first_finding.plugin_compliance_mappings:
                if mapping.compliance_requirement:
                    content.append(f"  • {mapping.compliance_requirement.framework}: "
                                 f"{mapping.compliance_requirement.requirement_id}")
                    if mapping.compliance_requirement.description:
                        desc = mapping.compliance_requirement.description
                        if len(desc) > 100:
                            desc = desc[:100] + "..."
                        content.append(f"    {desc}")
            content.append("")
        else:
            content.append("GRC COMPLIANCE IMPACT: None configured")
            content.append("")
        
        content.append("TIMELINE:")
        # Get earliest first_found and latest last_found
        first_dates = [f.first_found for f in findings if f.first_found]
        last_dates = [f.last_found for f in findings if f.last_found]
        
        if first_dates:
            content.append(f"  First Found: {min(first_dates).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        if last_dates:
            content.append(f"  Last Found: {max(last_dates).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        
        content.append("")
        content.append("=" * 80)
        
        txt_content = "\n".join(content)
        response = make_response(txt_content)
        response.headers["Content-Disposition"] = f"attachment; filename=grouped_ticket_{plugin_id}.txt"
        response.headers["Content-type"] = "text/plain; charset=utf-8"
        return response
        
    except Exception as e:
        current_app.logger.error(f"Error exporting grouped finding {plugin_id}: {e}")
        return f"Error exporting grouped finding: {str(e)}", 500

@export_bp.route('/export_single_was_finding_txt/<int:finding_id>')
def export_single_was_finding_txt(finding_id):
    """Export a single WAS finding as TXT for tickets"""
    try:
        finding = db.session.query(WASFinding).options(
            subqueryload(WASFinding.plugin_compliance_mappings).subqueryload(
                PluginComplianceMapping.compliance_requirement
            )
        ).filter_by(id=finding_id).first()
        
        if not finding:
            return "WAS Finding not found", 404
        
        # Generate ticket-ready text format
        content = []
        content.append("=" * 80)
        content.append("WEB APPLICATION SECURITY FINDING - TICKET")
        content.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        content.append("=" * 80)
        content.append("")
        
        content.append("VULNERABILITY DETAILS:")
        content.append("-" * 40)
        content.append(f"Finding ID: {finding.id}")
        content.append(f"Vulnerability Name: {finding.vulnerability_name or 'Unknown'}")
        
        if finding.vulnerability_id:
            content.append(f"Vulnerability ID: {finding.vulnerability_id}")
        
        content.append(f"Severity: {finding.severity or 'Unknown'}")
        content.append(f"Status: {finding.status or 'Active'}")
        
        content.append("")
        content.append("TARGET INFORMATION:")
        content.append(f"  URL: {finding.target_url or 'N/A'}")
        
        if finding.owasp_category:
            content.append(f"  OWASP Category: {finding.owasp_category}")
        
        if finding.cvss_v3_base_score:
            content.append(f"  CVSS v3 Score: {finding.cvss_v3_base_score}")
        
        content.append("")
        
        if finding.description:
            content.append("DESCRIPTION:")
            content.append(finding.description)
            content.append("")
        
        if finding.solution:
            content.append("REMEDIATION STEPS:")
            content.append(finding.solution)
            content.append("")
        
        # GRC COMPLIANCE MAPPINGS
        if hasattr(finding, 'plugin_compliance_mappings') and finding.plugin_compliance_mappings:
            content.append("GRC COMPLIANCE IMPACT:")
            for mapping in finding.plugin_compliance_mappings:
                if mapping.compliance_requirement:
                    content.append(f"  • {mapping.compliance_requirement.framework}: "
                                 f"{mapping.compliance_requirement.requirement_id}")
                    if mapping.compliance_requirement.description:
                        desc = mapping.compliance_requirement.description
                        if len(desc) > 100:
                            desc = desc[:100] + "..."
                        content.append(f"    {desc}")
            content.append("")
        else:
            content.append("GRC COMPLIANCE IMPACT: None configured")
            content.append("")
        
        content.append("TIMELINE:")
        if finding.first_detected_at:
            content.append(f"  First Detected: {finding.first_detected_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        if finding.last_detected_at:
            content.append(f"  Last Detected: {finding.last_detected_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        
        content.append("")
        content.append("=" * 80)
        
        txt_content = "\n".join(content)
        response = make_response(txt_content)
        response.headers["Content-Disposition"] = f"attachment; filename=was_ticket_{finding.id}.txt"
        response.headers["Content-type"] = "text/plain; charset=utf-8"
        return response
        
    except Exception as e:
        current_app.logger.error(f"Error exporting WAS finding {finding_id}: {e}")
        return f"Error exporting WAS finding: {str(e)}", 500