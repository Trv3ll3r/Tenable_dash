import io
import csv
from datetime import datetime, timedelta, timezone
from flask import Blueprint, make_response, current_app, request
from sqlalchemy.orm import subqueryload
from sqlalchemy import case
from collections import defaultdict
import traceback

from ..database import db
from ..models import VulnerabilityFinding, WASFinding, PluginComplianceMapping, ComplianceRequirement

# CREATE THE BLUEPRINT FIRST
export_bp = Blueprint('export', __name__)


def generate_csv_content(findings):
    """Generate CSV content for findings with enhanced NIST 800-53 columns"""
    csv_buffer = io.StringIO()
    csv_writer = csv.writer(csv_buffer)

    header = [
        "Plugin Name", "Plugin ID", "Asset Hostname", "Asset IPv4", "Severity", "VPR Score",
        "CVSSv3 Base Score", "Description", "Solution", "First Found", "Last Found",
        "State", "Cloud Provider", "Attack Path Score", "Attack Path Involved", 
        "NIST 800-53 Controls", "NIST Control Count", "PCI DSS Requirements", "SOC 2 Requirements",
        "GDPR Requirements", "All GRC Frameworks", "Total GRC Requirements", "Asset OS"
    ]
    csv_writer.writerow(header)

    for finding in findings:
        cloud_provider = "N/A"
        if finding.asset_aws_ec2_instance_id:
            cloud_provider = "AWS"
        elif finding.asset_azure_vm_id:
            cloud_provider = "Azure"
        elif finding.asset_gcp_instance_id:
            cloud_provider = "GCP"

        grc_by_framework = defaultdict(list)
        
        if hasattr(finding, 'plugin_compliance_mappings') and finding.plugin_compliance_mappings:
            for mapping in finding.plugin_compliance_mappings:
                if mapping.compliance_requirement:
                    framework = mapping.compliance_requirement.framework
                    req_id = mapping.compliance_requirement.requirement_id
                    grc_by_framework[framework].append(req_id)
        
        nist_controls = " | ".join(grc_by_framework.get('NIST 800-53', [])) if grc_by_framework.get('NIST 800-53') else "N/A"
        nist_count = len(grc_by_framework.get('NIST 800-53', []))
        pci_reqs = " | ".join(grc_by_framework.get('PCI DSS', [])) if grc_by_framework.get('PCI DSS') else "N/A"
        soc2_reqs = " | ".join(grc_by_framework.get('SOC 2', [])) if grc_by_framework.get('SOC 2') else "N/A"
        gdpr_reqs = " | ".join(grc_by_framework.get('GDPR', [])) if grc_by_framework.get('GDPR') else "N/A"
        
        all_frameworks = []
        for framework, reqs in grc_by_framework.items():
            all_frameworks.extend([f"{framework}:{req}" for req in reqs])
        all_grc_text = " | ".join(all_frameworks) if all_frameworks else "N/A"
        total_grc = len(all_frameworks)

        attack_path_involved = "Yes" if finding.is_in_attack_path else "No"

        csv_writer.writerow([
            finding.plugin_name or "N/A",
            finding.plugin_id or "N/A",
            finding.asset_hostname or "N/A",
            finding.asset_ipv4 or "N/A",
            finding.severity or "N/A",
            f"{finding.vpr_score:.2f}" if finding.vpr_score else "N/A",
            f"{finding.cvss_v3_base_score:.2f}" if finding.cvss_v3_base_score else "N/A",
            finding.description or "N/A",
            finding.solution or "N/A",
            finding.first_found.strftime("%Y-%m-%d") if finding.first_found else "N/A",
            finding.last_found.strftime("%Y-%m-%d") if finding.last_found else "N/A",
            finding.state or "N/A",
            cloud_provider,
            f"{finding.attack_path_score:.2f}" if finding.attack_path_score else "N/A",
            attack_path_involved,
            nist_controls,
            nist_count,
            pci_reqs,
            soc2_reqs,
            gdpr_reqs,
            all_grc_text,
            total_grc,
            finding.asset_os or "N/A"
        ])

    return csv_buffer.getvalue()


@export_bp.route('/export_csv')
def export_csv():
    """Export vulnerability findings to CSV"""
    try:
        findings = VulnerabilityFinding.query.options(
            subqueryload(VulnerabilityFinding.plugin_compliance_mappings)
                .subqueryload(PluginComplianceMapping.compliance_requirement)
        ).all()

        csv_content = generate_csv_content(findings)
        
        response = make_response(csv_content)
        response.headers["Content-Disposition"] = f"attachment; filename=vulnerability_findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        response.headers["Content-Type"] = "text/csv"
        return response
    except Exception as e:
        current_app.logger.error(f"Error generating CSV export: {str(e)}")
        current_app.logger.error(traceback.format_exc())
        return f"Error generating CSV: {str(e)}", 500


@export_bp.route('/export_txt')
def export_txt():
    """Export vulnerability findings to TXT format for ticketing"""
    try:
        findings = VulnerabilityFinding.query.options(
            subqueryload(VulnerabilityFinding.plugin_compliance_mappings)
                .subqueryload(PluginComplianceMapping.compliance_requirement)
        ).all()

        txt_content = []
        txt_content.append("=" * 80)
        txt_content.append("VULNERABILITY FINDINGS EXPORT")
        txt_content.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        txt_content.append(f"Total Findings: {len(findings)}")
        txt_content.append("=" * 80)
        txt_content.append("")

        for i, finding in enumerate(findings, 1):
            txt_content.append(f"FINDING #{i}")
            txt_content.append("-" * 80)
            txt_content.append(f"Plugin: {finding.plugin_name or 'N/A'} (ID: {finding.plugin_id or 'N/A'})")
            txt_content.append(f"Asset: {finding.asset_hostname or 'N/A'} ({finding.asset_ipv4 or 'N/A'})")
            txt_content.append(f"Severity: {finding.severity or 'N/A'}")
            txt_content.append(f"VPR Score: {finding.vpr_score:.2f}" if finding.vpr_score else "VPR Score: N/A")
            txt_content.append(f"CVSS Base Score: {finding.cvss_v3_base_score:.2f}" if finding.cvss_v3_base_score else "CVSS Base Score: N/A")
            txt_content.append(f"State: {finding.state or 'N/A'}")
            txt_content.append(f"First Found: {finding.first_found.strftime('%Y-%m-%d')}" if finding.first_found else "First Found: N/A")
            txt_content.append(f"Last Found: {finding.last_found.strftime('%Y-%m-%d')}" if finding.last_found else "Last Found: N/A")
            
            if finding.is_in_attack_path:
                txt_content.append(f"Attack Path Score: {finding.attack_path_score:.2f}" if finding.attack_path_score else "Attack Path Score: N/A")
            
            grc_by_framework = defaultdict(list)
            if hasattr(finding, 'plugin_compliance_mappings') and finding.plugin_compliance_mappings:
                for mapping in finding.plugin_compliance_mappings:
                    if mapping.compliance_requirement:
                        framework = mapping.compliance_requirement.framework
                        req_id = mapping.compliance_requirement.requirement_id
                        grc_by_framework[framework].append(req_id)
            
            if grc_by_framework:
                txt_content.append("\nCompliance Mappings:")
                for framework, reqs in sorted(grc_by_framework.items()):
                    txt_content.append(f"  {framework}: {', '.join(reqs)}")
            
            txt_content.append(f"\nDescription:\n{finding.description or 'N/A'}")
            txt_content.append(f"\nSolution:\n{finding.solution or 'N/A'}")
            txt_content.append("=" * 80)
            txt_content.append("")

        response = make_response("\n".join(txt_content))
        response.headers["Content-Disposition"] = f"attachment; filename=vulnerability_findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        response.headers["Content-Type"] = "text/plain"
        return response
    except Exception as e:
        current_app.logger.error(f"Error generating TXT export: {str(e)}")
        current_app.logger.error(traceback.format_exc())
        return f"Error generating TXT: {str(e)}", 500


@export_bp.route('/export_was_findings_csv')
def export_was_findings_csv():
    """Export WAS findings to CSV with URL filtering"""
    try:
        url_filter = request.args.get('subdomain', '').strip()  # Keep param name for compatibility
        
        query = WASFinding.query
        if url_filter:
            query = query.filter(WASFinding.target_url.ilike(f"%{url_filter}%"))
        
        was_findings = query.all()

        csv_buffer = io.StringIO()
        csv_writer = csv.writer(csv_buffer)

        header = [
            "Vulnerability Name", "Vulnerability ID", "Target URL", "Severity", "Status",
            "OWASP Category", "CVSS v3 Score", "Description", "Solution", 
            "First Detected", "Last Detected"
        ]
        csv_writer.writerow(header)

        for finding in was_findings:
            csv_writer.writerow([
                finding.vulnerability_name or "N/A",
                finding.vulnerability_id or "N/A",
                finding.target_url or "N/A",
                finding.severity or "N/A",
                finding.status or "N/A",
                finding.owasp_category or "N/A",
                finding.cvss_v3_base_score or "N/A",
                finding.description or "N/A",
                finding.solution or "N/A",
                finding.first_detected_at.strftime("%Y-%m-%d") if finding.first_detected_at else "N/A",
                finding.last_detected_at.strftime("%Y-%m-%d") if finding.last_detected_at else "N/A"
            ])

        response = make_response(csv_buffer.getvalue())
        filename = f"was_findings_{url_filter}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv" if url_filter else f"was_findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        response.headers["Content-Disposition"] = f"attachment; filename={filename}"
        response.headers["Content-Type"] = "text/csv"
        return response
    except Exception as e:
        current_app.logger.error(f"Error generating WAS CSV export: {str(e)}")
        current_app.logger.error(traceback.format_exc())
        return f"Error generating CSV: {str(e)}", 500


@export_bp.route('/export_was_findings_txt')
def export_was_findings_txt():
    """Export WAS findings to TXT format with URL filtering"""
    try:
        url_filter = request.args.get('subdomain', '').strip()  # Keep param name for compatibility
        
        query = WASFinding.query
        if url_filter:
            query = query.filter(WASFinding.target_url.ilike(f"%{url_filter}%"))
        
        was_findings = query.all()

        txt_content = []
        txt_content.append("=" * 80)
        txt_content.append("WEB APPLICATION SECURITY (WAS) FINDINGS EXPORT")
        if url_filter:
            txt_content.append(f"Filtered by URL pattern: {url_filter}")
        txt_content.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        txt_content.append(f"Total Findings: {len(was_findings)}")
        txt_content.append("=" * 80)
        txt_content.append("")

        for i, finding in enumerate(was_findings, 1):
            txt_content.append(f"WAS FINDING #{i}")
            txt_content.append("-" * 80)
            txt_content.append(f"Vulnerability: {finding.vulnerability_name or 'N/A'} (ID: {finding.vulnerability_id or 'N/A'})")
            txt_content.append(f"Target URL: {finding.target_url or 'N/A'}")
            txt_content.append(f"Severity: {finding.severity or 'N/A'}")
            txt_content.append(f"Status: {finding.status or 'N/A'}")
            txt_content.append(f"OWASP Category: {finding.owasp_category or 'N/A'}")
            txt_content.append(f"CVSS v3 Score: {finding.cvss_v3_base_score or 'N/A'}")
            txt_content.append(f"First Detected: {finding.first_detected_at.strftime('%Y-%m-%d')}" if finding.first_detected_at else "First Detected: N/A")
            txt_content.append(f"Last Detected: {finding.last_detected_at.strftime('%Y-%m-%d')}" if finding.last_detected_at else "Last Detected: N/A")
            txt_content.append(f"\nDescription:\n{finding.description or 'N/A'}")
            txt_content.append(f"\nSolution:\n{finding.solution or 'N/A'}")
            txt_content.append("=" * 80)
            txt_content.append("")

        response = make_response("\n".join(txt_content))
        filename = f"was_findings_{url_filter}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt" if url_filter else f"was_findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        response.headers["Content-Disposition"] = f"attachment; filename={filename}"
        response.headers["Content-Type"] = "text/plain"
        return response
    except Exception as e:
        current_app.logger.error(f"Error generating WAS TXT export: {str(e)}")
        current_app.logger.error(traceback.format_exc())
        return f"Error generating TXT: {str(e)}", 500


@export_bp.route('/export_grouped_findings_csv')
def export_grouped_findings_csv():
    """Export grouped findings (by plugin) with enhanced NIST data"""
    try:
        findings = VulnerabilityFinding.query.options(
            subqueryload(VulnerabilityFinding.plugin_compliance_mappings)
                .subqueryload(PluginComplianceMapping.compliance_requirement)
        ).all()

        grouped = defaultdict(lambda: {
            'plugin_name': '',
            'plugin_id': '',
            'severity': '',
            'assets': set(),
            'vpr_scores': [],
            'cvss_scores': [],
            'descriptions': set(),
            'solutions': set(),
            'states': set(),
            'first_found': None,
            'last_found': None,
            'grc_mappings': defaultdict(set)
        })

        for finding in findings:
            key = finding.plugin_id
            group = grouped[key]
            
            group['plugin_name'] = finding.plugin_name or "N/A"
            group['plugin_id'] = finding.plugin_id or "N/A"
            group['severity'] = finding.severity or "N/A"
            
            if finding.asset_hostname:
                group['assets'].add(finding.asset_hostname)
            
            if finding.vpr_score:
                group['vpr_scores'].append(finding.vpr_score)
            if finding.cvss_v3_base_score:
                group['cvss_scores'].append(finding.cvss_v3_base_score)
            
            if finding.description:
                group['descriptions'].add(finding.description)
            if finding.solution:
                group['solutions'].add(finding.solution)
            if finding.state:
                group['states'].add(finding.state)
            
            if finding.first_found:
                if not group['first_found'] or finding.first_found < group['first_found']:
                    group['first_found'] = finding.first_found
            if finding.last_found:
                if not group['last_found'] or finding.last_found > group['last_found']:
                    group['last_found'] = finding.last_found
            
            if hasattr(finding, 'plugin_compliance_mappings') and finding.plugin_compliance_mappings:
                for mapping in finding.plugin_compliance_mappings:
                    if mapping.compliance_requirement:
                        framework = mapping.compliance_requirement.framework
                        req_id = mapping.compliance_requirement.requirement_id
                        group['grc_mappings'][framework].add(req_id)

        csv_buffer = io.StringIO()
        csv_writer = csv.writer(csv_buffer)

        header = [
            "Plugin Name", "Plugin ID", "Severity", "Affected Assets Count", 
            "Affected Assets", "Avg VPR Score", "Avg CVSS Score", 
            "Description", "Solution", "States", "First Found", "Last Found",
            "NIST 800-53 Controls", "NIST Control Count", 
            "PCI DSS Requirements", "SOC 2 Requirements", "GDPR Requirements",
            "All Frameworks", "Total GRC Requirements"
        ]
        csv_writer.writerow(header)

        for plugin_id, group in sorted(grouped.items(), key=lambda x: x[1]['severity']):
            avg_vpr = sum(group['vpr_scores']) / len(group['vpr_scores']) if group['vpr_scores'] else 0
            avg_cvss = sum(group['cvss_scores']) / len(group['cvss_scores']) if group['cvss_scores'] else 0
            
            nist_controls = " | ".join(sorted(group['grc_mappings'].get('NIST 800-53', []))) if group['grc_mappings'].get('NIST 800-53') else "N/A"
            nist_count = len(group['grc_mappings'].get('NIST 800-53', []))
            pci_reqs = " | ".join(sorted(group['grc_mappings'].get('PCI DSS', []))) if group['grc_mappings'].get('PCI DSS') else "N/A"
            soc2_reqs = " | ".join(sorted(group['grc_mappings'].get('SOC 2', []))) if group['grc_mappings'].get('SOC 2') else "N/A"
            gdpr_reqs = " | ".join(sorted(group['grc_mappings'].get('GDPR', []))) if group['grc_mappings'].get('GDPR') else "N/A"
            
            all_frameworks = []
            for framework, reqs in group['grc_mappings'].items():
                all_frameworks.extend([f"{framework}:{req}" for req in sorted(reqs)])
            all_grc_text = " | ".join(all_frameworks) if all_frameworks else "N/A"
            total_grc = len(all_frameworks)

            csv_writer.writerow([
                group['plugin_name'],
                group['plugin_id'],
                group['severity'],
                len(group['assets']),
                " | ".join(sorted(group['assets'])) if group['assets'] else "N/A",
                f"{avg_vpr:.2f}",
                f"{avg_cvss:.2f}",
                " | ".join(group['descriptions']) if group['descriptions'] else "N/A",
                " | ".join(group['solutions']) if group['solutions'] else "N/A",
                " | ".join(group['states']) if group['states'] else "N/A",
                group['first_found'].strftime("%Y-%m-%d") if group['first_found'] else "N/A",
                group['last_found'].strftime("%Y-%m-%d") if group['last_found'] else "N/A",
                nist_controls,
                nist_count,
                pci_reqs,
                soc2_reqs,
                gdpr_reqs,
                all_grc_text,
                total_grc
            ])

        response = make_response(csv_buffer.getvalue())
        response.headers["Content-Disposition"] = f"attachment; filename=grouped_findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        response.headers["Content-Type"] = "text/csv"
        return response
    except Exception as e:
        current_app.logger.error(f"Error generating grouped CSV export: {str(e)}")
        current_app.logger.error(traceback.format_exc())
        return f"Error generating grouped CSV: {str(e)}", 500


@export_bp.route('/export_grouped_findings_txt')
def export_grouped_findings_txt():
    """Export grouped findings (by plugin) to TXT format"""
    try:
        findings = VulnerabilityFinding.query.options(
            subqueryload(VulnerabilityFinding.plugin_compliance_mappings)
                .subqueryload(PluginComplianceMapping.compliance_requirement)
        ).all()

        grouped = defaultdict(lambda: {
            'plugin_name': '',
            'plugin_id': '',
            'severity': '',
            'assets': set(),
            'vpr_scores': [],
            'cvss_scores': [],
            'descriptions': set(),
            'solutions': set(),
            'states': set(),
            'first_found': None,
            'last_found': None,
            'grc_mappings': defaultdict(set)
        })

        for finding in findings:
            key = finding.plugin_id
            group = grouped[key]
            
            group['plugin_name'] = finding.plugin_name or "N/A"
            group['plugin_id'] = finding.plugin_id or "N/A"
            group['severity'] = finding.severity or "N/A"
            
            if finding.asset_hostname:
                group['assets'].add(finding.asset_hostname)
            
            if finding.vpr_score:
                group['vpr_scores'].append(finding.vpr_score)
            if finding.cvss_v3_base_score:
                group['cvss_scores'].append(finding.cvss_v3_base_score)
            
            if finding.description:
                group['descriptions'].add(finding.description)
            if finding.solution:
                group['solutions'].add(finding.solution)
            if finding.state:
                group['states'].add(finding.state)
            
            if finding.first_found:
                if not group['first_found'] or finding.first_found < group['first_found']:
                    group['first_found'] = finding.first_found
            if finding.last_found:
                if not group['last_found'] or finding.last_found > group['last_found']:
                    group['last_found'] = finding.last_found
            
            if hasattr(finding, 'plugin_compliance_mappings') and finding.plugin_compliance_mappings:
                for mapping in finding.plugin_compliance_mappings:
                    if mapping.compliance_requirement:
                        framework = mapping.compliance_requirement.framework
                        req_id = mapping.compliance_requirement.requirement_id
                        group['grc_mappings'][framework].add(req_id)

        txt_content = []
        txt_content.append("=" * 80)
        txt_content.append("GROUPED VULNERABILITY FINDINGS EXPORT")
        txt_content.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        txt_content.append(f"Total Unique Findings: {len(grouped)}")
        txt_content.append("=" * 80)
        txt_content.append("")

        for i, (plugin_id, group) in enumerate(sorted(grouped.items(), key=lambda x: x[1]['severity']), 1):
            avg_vpr = sum(group['vpr_scores']) / len(group['vpr_scores']) if group['vpr_scores'] else 0
            avg_cvss = sum(group['cvss_scores']) / len(group['cvss_scores']) if group['cvss_scores'] else 0
            
            txt_content.append(f"GROUPED FINDING #{i}")
            txt_content.append("-" * 80)
            txt_content.append(f"Plugin: {group['plugin_name']} (ID: {group['plugin_id']})")
            txt_content.append(f"Severity: {group['severity']}")
            txt_content.append(f"Affected Assets: {len(group['assets'])}")
            txt_content.append(f"Average VPR Score: {avg_vpr:.2f}")
            txt_content.append(f"Average CVSS Score: {avg_cvss:.2f}")
            txt_content.append(f"States: {' | '.join(group['states']) if group['states'] else 'N/A'}")
            txt_content.append(f"First Found: {group['first_found'].strftime('%Y-%m-%d')}" if group['first_found'] else "First Found: N/A")
            txt_content.append(f"Last Found: {group['last_found'].strftime('%Y-%m-%d')}" if group['last_found'] else "Last Found: N/A")
            
            if group['grc_mappings']:
                txt_content.append("\nCompliance Mappings:")
                for framework, reqs in sorted(group['grc_mappings'].items()):
                    txt_content.append(f"  {framework}: {', '.join(sorted(reqs))}")
            
            txt_content.append(f"\nAffected Assets:")
            for asset in sorted(group['assets']):
                txt_content.append(f"  - {asset}")
            
            txt_content.append(f"\nDescription:")
            for desc in group['descriptions']:
                txt_content.append(f"  {desc}")
            
            txt_content.append(f"\nSolution:")
            for sol in group['solutions']:
                txt_content.append(f"  {sol}")
            
            txt_content.append("=" * 80)
            txt_content.append("")

        response = make_response("\n".join(txt_content))
        response.headers["Content-Disposition"] = f"attachment; filename=grouped_findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        response.headers["Content-Type"] = "text/plain"
        return response
    except Exception as e:
        current_app.logger.error(f"Error generating grouped TXT export: {str(e)}")
        current_app.logger.error(traceback.format_exc())
        return f"Error generating grouped TXT: {str(e)}", 500


@export_bp.route('/export_single_grouped_finding_txt/<int:plugin_id>')
def export_single_grouped_finding_txt(plugin_id):
    """Export a single grouped finding (all findings for a specific plugin_id) as TXT for ticketing"""
    try:
        # Get all findings for this plugin_id
        findings = VulnerabilityFinding.query.filter(
            VulnerabilityFinding.plugin_id == plugin_id
        ).options(
            subqueryload(VulnerabilityFinding.plugin_compliance_mappings)
                .subqueryload(PluginComplianceMapping.compliance_requirement)
        ).all()
        
        if not findings:
            return "No findings found for this plugin", 404
        
        # Use first finding for vulnerability details
        first_finding = findings[0]
        
        # Collect GRC mappings
        grc_by_framework = defaultdict(set)
        if hasattr(first_finding, 'plugin_compliance_mappings') and first_finding.plugin_compliance_mappings:
            for mapping in first_finding.plugin_compliance_mappings:
                if mapping.compliance_requirement:
                    framework = mapping.compliance_requirement.framework
                    req_id = mapping.compliance_requirement.requirement_id
                    grc_by_framework[framework].add(req_id)
        
        # Generate TXT content
        txt_content = []
        txt_content.append("=" * 80)
        txt_content.append("VULNERABILITY REPORT - GROUPED FINDING")
        txt_content.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        txt_content.append("=" * 80)
        txt_content.append("")
        txt_content.append(f"Plugin ID: {first_finding.plugin_id}")
        txt_content.append(f"Vulnerability: {first_finding.plugin_name or 'Unknown'}")
        txt_content.append(f"Severity: {(first_finding.severity or 'unknown').upper()}")
        txt_content.append(f"VPR Score: {first_finding.vpr_score:.2f}" if first_finding.vpr_score else "VPR Score: N/A")
        txt_content.append(f"CVSS v3 Score: {first_finding.cvss_v3_base_score:.2f}" if first_finding.cvss_v3_base_score else "CVSS v3 Score: N/A")
        txt_content.append("")
        
        if grc_by_framework:
            txt_content.append("COMPLIANCE MAPPINGS:")
            txt_content.append("-" * 80)
            for framework, reqs in sorted(grc_by_framework.items()):
                txt_content.append(f"{framework}: {', '.join(sorted(reqs))}")
            txt_content.append("")
        
        txt_content.append(f"AFFECTED ASSETS ({len(findings)}):")
        txt_content.append("-" * 80)
        for finding in findings:
            asset_name = finding.asset_hostname or finding.asset_ipv4 or 'Unknown'
            txt_content.append(f"  • {asset_name}")
            if finding.asset_ipv4 and finding.asset_hostname:
                txt_content.append(f"    IP: {finding.asset_ipv4}")
            if finding.asset_os:
                txt_content.append(f"    OS: {finding.asset_os}")
            if finding.asset_aws_ec2_instance_id:
                txt_content.append(f"    AWS Instance: {finding.asset_aws_ec2_instance_id}")
            elif finding.asset_azure_vm_id:
                txt_content.append(f"    Azure VM: {finding.asset_azure_vm_id}")
            elif finding.asset_gcp_instance_id:
                txt_content.append(f"    GCP Instance: {finding.asset_gcp_instance_id}")
            txt_content.append(f"    State: {finding.state or 'N/A'}")
            txt_content.append(f"    Last Found: {finding.last_found.strftime('%Y-%m-%d')}" if finding.last_found else "    Last Found: N/A")
            txt_content.append("")
        
        txt_content.append("=" * 80)
        txt_content.append("VULNERABILITY DETAILS")
        txt_content.append("=" * 80)
        txt_content.append("")
        txt_content.append(f"Description:\n{first_finding.description or 'N/A'}")
        txt_content.append("")
        txt_content.append(f"Solution:\n{first_finding.solution or 'N/A'}")
        txt_content.append("")
        txt_content.append("=" * 80)
        
        response = make_response("\n".join(txt_content))
        response.headers["Content-Disposition"] = f"attachment; filename=grouped_finding_plugin_{plugin_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        response.headers["Content-Type"] = "text/plain"
        return response
    except Exception as e:
        current_app.logger.error(f"Error generating single grouped finding TXT: {str(e)}")
        current_app.logger.error(traceback.format_exc())
        return f"Error generating TXT: {str(e)}", 500


@export_bp.route('/export_single_grouped_finding_csv/<int:plugin_id>')
def export_single_grouped_finding_csv(plugin_id):
    """Export a single grouped finding (all findings for a specific plugin_id) as CSV"""
    try:
        # Get all findings for this plugin_id
        findings = VulnerabilityFinding.query.filter(
            VulnerabilityFinding.plugin_id == plugin_id
        ).options(
            subqueryload(VulnerabilityFinding.plugin_compliance_mappings)
                .subqueryload(PluginComplianceMapping.compliance_requirement)
        ).all()
        
        if not findings:
            return "No findings found for this plugin", 404
        
        csv_content = generate_csv_content(findings)
        
        response = make_response(csv_content)
        response.headers["Content-Disposition"] = f"attachment; filename=grouped_finding_plugin_{plugin_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        response.headers["Content-Type"] = "text/csv"
        return response
    except Exception as e:
        current_app.logger.error(f"Error generating single grouped finding CSV: {str(e)}")
        current_app.logger.error(traceback.format_exc())
        return f"Error generating CSV: {str(e)}", 500


@export_bp.route('/export_nist_focused_csv')
def export_nist_focused_csv():
    """Export findings with NIST 800-53 mappings only"""
    try:
        findings = VulnerabilityFinding.query.options(
            subqueryload(VulnerabilityFinding.plugin_compliance_mappings)
                .subqueryload(PluginComplianceMapping.compliance_requirement)
        ).all()

        # Filter to only findings with NIST mappings
        nist_findings = []
        for finding in findings:
            if hasattr(finding, 'plugin_compliance_mappings') and finding.plugin_compliance_mappings:
                for mapping in finding.plugin_compliance_mappings:
                    if mapping.compliance_requirement and mapping.compliance_requirement.framework == 'NIST 800-53':
                        nist_findings.append(finding)
                        break

        csv_buffer = io.StringIO()
        csv_writer = csv.writer(csv_buffer)

        header = [
            "Plugin Name", "Plugin ID", "Asset Hostname", "Asset IPv4", "Severity", 
            "VPR Score", "CVSSv3 Base Score", "NIST 800-53 Controls", "NIST Control Count",
            "Description", "Solution", "First Found", "Last Found", "State"
        ]
        csv_writer.writerow(header)

        for finding in nist_findings:
            nist_controls = []
            if hasattr(finding, 'plugin_compliance_mappings') and finding.plugin_compliance_mappings:
                for mapping in finding.plugin_compliance_mappings:
                    if mapping.compliance_requirement and mapping.compliance_requirement.framework == 'NIST 800-53':
                        nist_controls.append(mapping.compliance_requirement.requirement_id)

            nist_text = " | ".join(sorted(nist_controls)) if nist_controls else "N/A"
            nist_count = len(nist_controls)

            csv_writer.writerow([
                finding.plugin_name or "N/A",
                finding.plugin_id or "N/A",
                finding.asset_hostname or "N/A",
                finding.asset_ipv4 or "N/A",
                finding.severity or "N/A",
                f"{finding.vpr_score:.2f}" if finding.vpr_score else "N/A",
                f"{finding.cvss_v3_base_score:.2f}" if finding.cvss_v3_base_score else "N/A",
                nist_text,
                nist_count,
                finding.description or "N/A",
                finding.solution or "N/A",
                finding.first_found.strftime("%Y-%m-%d") if finding.first_found else "N/A",
                finding.last_found.strftime("%Y-%m-%d") if finding.last_found else "N/A",
                finding.state or "N/A"
            ])

        response = make_response(csv_buffer.getvalue())
        response.headers["Content-Disposition"] = f"attachment; filename=nist_focused_findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        response.headers["Content-Type"] = "text/csv"
        return response
    except Exception as e:
        current_app.logger.error(f"Error generating NIST-focused CSV export: {str(e)}")
        current_app.logger.error(traceback.format_exc())
        return f"Error generating NIST CSV: {str(e)}", 500


@export_bp.route('/export_single_finding_csv/<int:finding_id>')
def export_single_finding_csv(finding_id):
    """Export a single vulnerability finding to CSV"""
    try:
        finding = VulnerabilityFinding.query.options(
            subqueryload(VulnerabilityFinding.plugin_compliance_mappings)
                .subqueryload(PluginComplianceMapping.compliance_requirement)
        ).get_or_404(finding_id)

        csv_content = generate_csv_content([finding])
        
        response = make_response(csv_content)
        response.headers["Content-Disposition"] = f"attachment; filename=finding_{finding_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        response.headers["Content-Type"] = "text/csv"
        return response
    except Exception as e:
        current_app.logger.error(f"Error generating single finding CSV: {str(e)}")
        current_app.logger.error(traceback.format_exc())
        return f"Error generating CSV: {str(e)}", 500


@export_bp.route('/export_single_finding_txt/<int:finding_id>')
def export_single_finding_txt(finding_id):
    """Export a single vulnerability finding to TXT format"""
    try:
        finding = VulnerabilityFinding.query.options(
            subqueryload(VulnerabilityFinding.plugin_compliance_mappings)
                .subqueryload(PluginComplianceMapping.compliance_requirement)
        ).get_or_404(finding_id)

        txt_content = []
        txt_content.append("=" * 80)
        txt_content.append("VULNERABILITY FINDING DETAILS")
        txt_content.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        txt_content.append("=" * 80)
        txt_content.append("")
        txt_content.append(f"Plugin: {finding.plugin_name or 'N/A'} (ID: {finding.plugin_id or 'N/A'})")
        txt_content.append(f"Asset: {finding.asset_hostname or 'N/A'} ({finding.asset_ipv4 or 'N/A'})")
        txt_content.append(f"Severity: {finding.severity or 'N/A'}")
        txt_content.append(f"VPR Score: {finding.vpr_score:.2f}" if finding.vpr_score else "VPR Score: N/A")
        txt_content.append(f"CVSS Base Score: {finding.cvss_v3_base_score:.2f}" if finding.cvss_v3_base_score else "CVSS Base Score: N/A")
        txt_content.append(f"State: {finding.state or 'N/A'}")
        txt_content.append(f"First Found: {finding.first_found.strftime('%Y-%m-%d')}" if finding.first_found else "First Found: N/A")
        txt_content.append(f"Last Found: {finding.last_found.strftime('%Y-%m-%d')}" if finding.last_found else "Last Found: N/A")
        
        if finding.is_in_attack_path:
            txt_content.append(f"Attack Path Score: {finding.attack_path_score:.2f}" if finding.attack_path_score else "Attack Path Score: N/A")
        
        grc_by_framework = defaultdict(list)
        if hasattr(finding, 'plugin_compliance_mappings') and finding.plugin_compliance_mappings:
            for mapping in finding.plugin_compliance_mappings:
                if mapping.compliance_requirement:
                    framework = mapping.compliance_requirement.framework
                    req_id = mapping.compliance_requirement.requirement_id
                    grc_by_framework[framework].append(req_id)
        
        if grc_by_framework:
            txt_content.append("\nCompliance Mappings:")
            for framework, reqs in sorted(grc_by_framework.items()):
                txt_content.append(f"  {framework}: {', '.join(reqs)}")
        
        txt_content.append(f"\nDescription:\n{finding.description or 'N/A'}")
        txt_content.append(f"\nSolution:\n{finding.solution or 'N/A'}")
        txt_content.append("=" * 80)

        response = make_response("\n".join(txt_content))
        response.headers["Content-Disposition"] = f"attachment; filename=finding_{finding_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        response.headers["Content-Type"] = "text/plain"
        return response
    except Exception as e:
        current_app.logger.error(f"Error generating single finding TXT: {str(e)}")
        current_app.logger.error(traceback.format_exc())
        return f"Error generating TXT: {str(e)}", 500


@export_bp.route('/export_single_was_finding_csv/<int:finding_id>')
def export_single_was_finding_csv(finding_id):
    """Export a single WAS finding to CSV"""
    try:
        finding = WASFinding.query.get_or_404(finding_id)

        csv_buffer = io.StringIO()
        csv_writer = csv.writer(csv_buffer)

        header = [
            "Vulnerability Name", "Vulnerability ID", "Target URL", "Severity", "Status",
            "OWASP Category", "CVSS v3 Score", "Description", "Solution", 
            "First Detected", "Last Detected"
        ]
        csv_writer.writerow(header)

        csv_writer.writerow([
            finding.vulnerability_name or "N/A",
            finding.vulnerability_id or "N/A",
            finding.target_url or "N/A",
            finding.severity or "N/A",
            finding.status or "N/A",
            finding.owasp_category or "N/A",
            finding.cvss_v3_base_score or "N/A",
            finding.description or "N/A",
            finding.solution or "N/A",
            finding.first_detected_at.strftime("%Y-%m-%d") if finding.first_detected_at else "N/A",
            finding.last_detected_at.strftime("%Y-%m-%d") if finding.last_detected_at else "N/A"
        ])

        response = make_response(csv_buffer.getvalue())
        response.headers["Content-Disposition"] = f"attachment; filename=was_finding_{finding_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        response.headers["Content-Type"] = "text/csv"
        return response
    except Exception as e:
        current_app.logger.error(f"Error generating single WAS finding CSV: {str(e)}")
        current_app.logger.error(traceback.format_exc())
        return f"Error generating CSV: {str(e)}", 500


@export_bp.route('/export_single_was_finding_txt/<int:finding_id>')
def export_single_was_finding_txt(finding_id):
    """Export a single WAS finding to TXT format"""
    try:
        finding = WASFinding.query.get_or_404(finding_id)

        txt_content = []
        txt_content.append("=" * 80)
        txt_content.append("WEB APPLICATION SECURITY (WAS) FINDING DETAILS")
        txt_content.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        txt_content.append("=" * 80)
        txt_content.append("")
        txt_content.append(f"Vulnerability: {finding.vulnerability_name or 'N/A'} (ID: {finding.vulnerability_id or 'N/A'})")
        txt_content.append(f"Target URL: {finding.target_url or 'N/A'}")
        txt_content.append(f"Severity: {finding.severity or 'N/A'}")
        txt_content.append(f"Status: {finding.status or 'N/A'}")
        txt_content.append(f"OWASP Category: {finding.owasp_category or 'N/A'}")
        txt_content.append(f"CVSS v3 Score: {finding.cvss_v3_base_score or 'N/A'}")
        txt_content.append(f"First Detected: {finding.first_detected_at.strftime('%Y-%m-%d')}" if finding.first_detected_at else "First Detected: N/A")
        txt_content.append(f"Last Detected: {finding.last_detected_at.strftime('%Y-%m-%d')}" if finding.last_detected_at else "Last Detected: N/A")
        txt_content.append(f"\nDescription:\n{finding.description or 'N/A'}")
        txt_content.append(f"\nSolution:\n{finding.solution or 'N/A'}")
        txt_content.append("=" * 80)

        response = make_response("\n".join(txt_content))
        response.headers["Content-Disposition"] = f"attachment; filename=was_finding_{finding_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        response.headers["Content-Type"] = "text/plain"
        return response
    except Exception as e:
        current_app.logger.error(f"Error generating single WAS finding TXT: {str(e)}")
        current_app.logger.error(traceback.format_exc())
        return f"Error generating TXT: {str(e)}", 500