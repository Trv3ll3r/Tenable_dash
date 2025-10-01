"""
Reporting Service - Generate formatted text reports
"""

from datetime import datetime


def generate_findings_txt(findings):
    """Generate comprehensive TXT format report for findings"""
    content = []
    content.append("=" * 80)
    content.append("TENABLE ONE ENHANCED VULNERABILITY FINDINGS REPORT")
    content.append("=" * 80)
    content.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    content.append(f"Total Findings: {len(findings)}")
    content.append("=" * 80)
    content.append("")

    # Group findings by compliance framework
    framework_findings = {}
    unmapped_count = 0
    
    for finding in findings:
        if finding.plugin_compliance_mappings:
            for mapping in finding.plugin_compliance_mappings:
                if mapping.compliance_requirement:
                    framework = mapping.compliance_requirement.framework
                    if framework not in framework_findings:
                        framework_findings[framework] = []
                    framework_findings[framework].append({
                        'finding': finding,
                        'requirement': mapping.compliance_requirement
                    })
        else:
            unmapped_count += 1
    
    # Summary by framework
    if framework_findings:
        content.append("COMPLIANCE FRAMEWORK SUMMARY:")
        content.append("-" * 40)
        for framework, mappings in framework_findings.items():
            content.append(f"{framework}: {len(mappings)} findings")
        content.append(f"Unmapped Findings: {unmapped_count}")
        content.append("")
    
    # Detailed findings by framework
    for framework, mappings in framework_findings.items():
        content.append(f"{framework.upper()} COMPLIANCE FINDINGS:")
        content.append("=" * 50)
        content.append("")
        
        # Group by requirement
        req_groups = {}
        for mapping in mappings:
            req_id = mapping['requirement'].requirement_id
            if req_id not in req_groups:
                req_groups[req_id] = {
                    'requirement': mapping['requirement'],
                    'findings': []
                }
            req_groups[req_id]['findings'].append(mapping['finding'])
        
        for req_id, group in req_groups.items():
            requirement = group['requirement']
            findings_list = group['findings']
            
            content.append(f"Requirement: {req_id}")
            if requirement.description:
                content.append(f"Description: {requirement.description}")
            content.append(f"Affected Findings: {len(findings_list)}")
            content.append("")
            
            # List findings for this requirement
            for finding in findings_list[:5]:  # Limit to first 5 for brevity
                content.append(f"  • {finding.plugin_name} on {finding.asset_display_name}")
                content.append(f"    Severity: {finding.severity}, State: {finding.state}")
            
            if len(findings_list) > 5:
                content.append(f"  ... and {len(findings_list) - 5} more findings")
            
            content.append("")
            content.append("-" * 30)
            content.append("")
    
    if unmapped_count > 0:
        content.append("UNMAPPED FINDINGS:")
        content.append("=" * 30)
        content.append(f"{unmapped_count} findings do not have GRC compliance mappings.")
        content.append("Consider adding compliance mappings for complete coverage.")
        content.append("")
    
    content.append("COMPLIANCE RECOMMENDATIONS:")
    content.append("-" * 40)
    content.append("1. Prioritize findings mapped to multiple compliance frameworks")
    content.append("2. Address critical/high severity compliance-related findings first")
    content.append("3. Establish regular compliance reporting cadence")
    content.append("4. Map unmapped findings to relevant compliance requirements")
    content.append("")
    content.append("=" * 70)
    
    return "\n".join(content)
    severity_counts = {}
    attack_path_count = 0
    cloud_count = 0
    grc_mapped_count = 0
    
    for finding in findings:
        severity = finding.severity or 'unknown'
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        if finding.is_in_attack_path:
            attack_path_count += 1
        
        if finding.cloud_provider:
            cloud_count += 1
            
        if finding.plugin_compliance_mappings:
            grc_mapped_count += 1

    # Executive summary
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
    
    # Risk analysis
    critical_high = severity_counts.get('critical', 0) + severity_counts.get('high', 0)
    total_actionable = sum(severity_counts.get(sev, 0) for sev in ['critical', 'high', 'medium', 'low'])
    
    content.append("RISK ANALYSIS:")
    content.append("-" * 30)
    content.append(f"Critical + High Severity: {critical_high} ({critical_high/total_actionable*100:.1f}% of total)" if total_actionable > 0 else "Critical + High Severity: 0 (0% of total)")
    content.append(f"Attack Path Exposure: {attack_path_count} findings in attack paths")
    content.append(f"Cloud Infrastructure Risk: {cloud_count} cloud-hosted assets affected")
    content.append("")
    content.append("=" * 80)
    content.append("")

    # Individual findings
    for i, finding in enumerate(findings, 1):
        content.append(f"FINDING #{i}")
        content.append("-" * 40)
        
        # Basic information
        content.append(f"Plugin Name: {finding.plugin_name or 'Unknown Plugin'}")
        content.append(f"Plugin ID: {finding.plugin_id}")
        content.append(f"Severity: {finding.severity or 'Unknown'}")
        
        # Scoring information
        if finding.vpr_score:
            content.append(f"VPR Score: {finding.vpr_score}")
        if finding.cvss_v3_base_score:
            content.append(f"CVSS v3 Base Score: {finding.cvss_v3_base_score}")
        if finding.attack_path_score:
            content.append(f"Attack Path Score: {finding.attack_path_score}")
        if finding.asset_exposure_score:
            content.append(f"Asset Exposure Score: {finding.asset_exposure_score}")
            
        content.append("")
        
        # Affected asset information
        content.append("AFFECTED ASSET:")
        content.append(f"  Asset: {finding.asset_display_name}")
        
        if finding.asset_ipv4:
            content.append(f"  IP Address: {finding.asset_ipv4}")
        if finding.asset_os:
            content.append(f"  Operating System: {finding.asset_os}")
            
        # Cloud information
        if finding.cloud_provider:
            content.append(f"  Cloud Provider: {finding.cloud_provider}")
            if finding.asset_aws_ec2_instance_id:
                content.append(f"  AWS EC2 Instance: {finding.asset_aws_ec2_instance_id}")
            elif finding.asset_azure_vm_id:
                content.append(f"  Azure VM: {finding.asset_azure_vm_id}")
            elif finding.asset_gcp_instance_id:
                content.append(f"  GCP Instance: {finding.asset_gcp_instance_id}")
            
        if finding.business_criticality:
            content.append(f"  Business Criticality: {finding.business_criticality}")
            
        content.append("")
        
        # Vulnerability details
        if finding.description:
            content.append("DESCRIPTION:")
            desc_text = finding.description
            # Truncate very long descriptions
            if len(desc_text) > 600:
                desc_text = desc_text[:600] + "...\n[DESCRIPTION TRUNCATED]"
            content.append(desc_text)
            content.append("")
            
        if finding.solution:
            content.append("REMEDIATION:")
            sol_text = finding.solution
            # Truncate very long solutions
            if len(sol_text) > 600:
                sol_text = sol_text[:600] + "...\n[SOLUTION TRUNCATED]"
            content.append(sol_text)
            content.append("")
            
        # Special indicators
        if finding.is_in_attack_path:
            content.append("⚠️  CRITICAL: This finding is part of an attack path!")
            if finding.attack_path_score:
                content.append(f"    Attack Path Risk Score: {finding.attack_path_score}")
            content.append("")
            
        if finding.exploit_available:
            content.append("🚨 EXPLOIT AVAILABLE - Prioritize remediation")
            if finding.exploit_code_maturity:
                content.append(f"    Exploit Maturity: {finding.exploit_code_maturity}")
            content.append("")
            
        # GRC compliance mappings
        if finding.plugin_compliance_mappings:
            content.append("COMPLIANCE REQUIREMENTS:")
            for mapping in finding.plugin_compliance_mappings:
                if mapping.compliance_requirement:
                    content.append(f"  • {mapping.compliance_requirement.framework}: "
                                 f"{mapping.compliance_requirement.requirement_id}")
                    if mapping.compliance_requirement.description:
                        desc = mapping.compliance_requirement.description
                        # Truncate long descriptions
                        if len(desc) > 120:
                            desc = desc[:120] + "..."
                        content.append(f"    {desc}")
            content.append("")
        else:
            content.append("COMPLIANCE MAPPINGS: None configured")
            content.append("")
            
        # Timeline information
        content.append("DISCOVERY TIMELINE:")
        if finding.first_found:
            content.append(f"  First Found: {finding.first_found.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        if finding.last_found:
            content.append(f"  Last Found: {finding.last_found.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        if finding.fixed_at:
            content.append(f"  Fixed At: {finding.fixed_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        content.append(f"  Current State: {finding.state or 'OPEN'}")
            
        # Publication dates
        if finding.vuln_publication_date:
            content.append(f"  Vulnerability Published: {finding.vuln_publication_date.strftime('%Y-%m-%d')}")
        if finding.patch_publication_date:
            content.append(f"  Patch Published: {finding.patch_publication_date.strftime('%Y-%m-%d')}")
            
        content.append("")
        content.append("=" * 80)
        content.append("")

    # Report footer
    content.append("REPORT NOTES:")
    content.append("-" * 30)
    content.append("• This report includes only active, actionable findings (excludes informational)")
    content.append("• VPR scores range from 0.1 to 10.0 (higher = more urgent)")
    content.append("• CVSS v3 scores range from 0.0 to 10.0 (higher = more severe)")
    content.append("• Attack Path findings indicate vulnerabilities that could be chained together")
    content.append("• Cloud findings show vulnerabilities in AWS, Azure, or GCP infrastructure")
    content.append("• GRC mappings show compliance framework requirements related to each finding")
    content.append("")
    content.append(f"Report generated by Tenable One Enhanced Dashboard")
    content.append(f"Generation time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    content.append("=" * 80)

    return "\n".join(content)


def generate_executive_summary_txt(dashboard_data):
    """Generate executive summary report"""
    content = []
    content.append("=" * 60)
    content.append("TENABLE ONE EXECUTIVE SECURITY SUMMARY")
    content.append("=" * 60)
    content.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    content.append("")
    
    # Overall metrics
    total_findings = dashboard_data.get('total_active_findings', 0)
    severity_counts = dashboard_data.get('severity_counts', {})
    
    content.append("SECURITY POSTURE OVERVIEW:")
    content.append("-" * 40)
    content.append(f"Total Active Findings: {total_findings}")
    content.append("")
    
    content.append("Risk Distribution:")
    for severity in ['critical', 'high', 'medium', 'low']:
        count = severity_counts.get(severity, 0)
        percentage = (count / total_findings * 100) if total_findings > 0 else 0
        content.append(f"  {severity.capitalize():>8}: {count:>4} ({percentage:>5.1f}%)")
    
    content.append("")
    
    # Attack path analysis
    attack_path_count = dashboard_data.get('attack_path_findings', 0)
    if attack_path_count > 0:
        content.append("ATTACK PATH ANALYSIS:")
        content.append("-" * 40)
        content.append(f"Findings in Attack Paths: {attack_path_count}")
        attack_path_percentage = (attack_path_count / total_findings * 100) if total_findings > 0 else 0
        content.append(f"Attack Path Exposure: {attack_path_percentage:.1f}% of total findings")
        content.append("")
    
    # Cloud security
    cloud_counts = dashboard_data.get('cloud_counts', {})
    total_cloud = sum(cloud_counts.values())
    
    if total_cloud > 0:
        content.append("CLOUD SECURITY SUMMARY:")
        content.append("-" * 40)
        content.append(f"Total Cloud Findings: {total_cloud}")
        content.append("By Provider:")
        for provider, count in cloud_counts.items():
            if count > 0:
                content.append(f"  {provider.upper()}: {count}")
        content.append("")
    
    # Top risks
    top_assets = dashboard_data.get('top_assets', [])
    top_plugins = dashboard_data.get('top_plugins', [])
    
    if top_assets:
        content.append("TOP 5 ASSETS BY FINDING COUNT:")
        content.append("-" * 40)
        for i, asset in enumerate(top_assets[:5], 1):
            content.append(f"{i}. {asset['asset']}: {asset['count']} findings")
        content.append("")
    
    if top_plugins:
        content.append("TOP 5 VULNERABILITY TYPES:")
        content.append("-" * 40)
        for i, plugin in enumerate(top_plugins[:5], 1):
            content.append(f"{i}. {plugin['plugin']}: {plugin['count']} instances")
        content.append("")
    
    # Recommendations
    content.append("KEY RECOMMENDATIONS:")
    content.append("-" * 40)
    
    critical_count = severity_counts.get('critical', 0)
    high_count = severity_counts.get('high', 0)
    
    if critical_count > 0:
        content.append(f"1. URGENT: Address {critical_count} critical severity findings immediately")
    
    if high_count > 0:
        content.append(f"2. HIGH PRIORITY: Plan remediation for {high_count} high severity findings")
    
    if attack_path_count > 0:
        content.append(f"3. ATTACK PATHS: Review {attack_path_count} findings that could be chained in attacks")
    
    if total_cloud > 0:
        content.append(f"4. CLOUD SECURITY: Assess {total_cloud} cloud infrastructure vulnerabilities")
    
    if not any([critical_count, high_count, attack_path_count]):
        content.append("1. Continue monitoring for new vulnerabilities")
        content.append("2. Maintain current security practices")
        content.append("3. Regular vulnerability assessments recommended")
    
    content.append("")
    content.append("=" * 60)
    
    return "\n".join(content)


def generate_compliance_report_txt(findings):
    """Generate GRC compliance-focused report"""
    content = []
    content.append("=" * 70)
    content.append("GOVERNANCE, RISK & COMPLIANCE (GRC) FINDINGS REPORT")
    content.append("=" * 70)
    content.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    content.append("")
    
    #