"""
Data Processing Module - Clean data transformation and database operations
Updated to include CloudFindingProcessor for Ermetic data with intelligent cloud provider detection
"""

import json
from datetime import datetime, timezone
from sqlalchemy.exc import IntegrityError
from flask import current_app

from app.database import db
from app.models import (
    VulnerabilityFinding, 
    AttackPathFinding, 
    WASFinding, 
    ContainerSecurityFinding,
    CloudFinding,
    ComplianceRequirement,
    PluginComplianceMapping
)


def safe_timestamp_to_datetime(timestamp_val):
    """Safely convert various timestamp formats to datetime"""
    if timestamp_val is None:
        return None
    
    # Handle string timestamps
    if isinstance(timestamp_val, str):
        try:
            return datetime.fromisoformat(timestamp_val.replace('Z', '+00:00'))
        except ValueError:
            pass
    
    # Handle numeric timestamps
    try:
        ts_int = int(timestamp_val)
        # Handle millisecond timestamps
        if ts_int > 1_000_000_000_000:
            ts_int //= 1000
        return datetime.fromtimestamp(ts_int, tz=timezone.utc)
    except (ValueError, TypeError):
        return None


def extract_cloud_metadata(asset_data):
    """Extract cloud provider metadata from asset data"""
    cloud_info = {
        'provider': None,
        'instance_id': None,
        'is_cloud': False
    }
    
    # Check for explicit cloud fields
    if asset_data.get('aws_ec2_instance_id'):
        cloud_info.update({
            'provider': 'AWS',
            'instance_id': asset_data.get('aws_ec2_instance_id'),
            'is_cloud': True
        })
    elif asset_data.get('azure_vm_id'):
        cloud_info.update({
            'provider': 'Azure', 
            'instance_id': asset_data.get('azure_vm_id'),
            'is_cloud': True
        })
    elif asset_data.get('gcp_instance_id'):
        cloud_info.update({
            'provider': 'GCP',
            'instance_id': asset_data.get('gcp_instance_id'),
            'is_cloud': True
        })
    else:
        # Check hostname for cloud patterns
        hostname = asset_data.get('hostname', '').lower()
        cloud_patterns = [
            ('amazonaws.com', 'AWS'),
            ('ec2.internal', 'AWS'),
            ('cloudapp.azure.com', 'Azure'),
            ('compute.internal', 'GCP')
        ]
        
        for pattern, provider in cloud_patterns:
            if pattern in hostname:
                cloud_info.update({
                    'provider': provider,
                    'instance_id': hostname,
                    'is_cloud': True
                })
                break
    
    return cloud_info


class VulnerabilityProcessor:
    """Process vulnerability findings for database storage"""
    
    @staticmethod
    def process_finding(finding_data):
        """
        Process a single vulnerability finding from Tenable API
        
        Args:
            finding_data (dict): Raw finding data from Tenable API
            
        Returns:
            bool: True if processed successfully, False otherwise
        """
        try:
            # Extract core data
            plugin_data = finding_data.get('plugin', {})
            asset_data = finding_data.get('asset', {})
            
            plugin_id = plugin_data.get('id')
            asset_uuid = asset_data.get('uuid')
            
            if not all([plugin_id, asset_uuid]):
                current_app.logger.warning(f"Skipping finding - missing plugin_id or asset_uuid")
                return False
            
            # Create unique internal ID
            finding_uuid = finding_data.get('uuid')
            last_found_raw = finding_data.get('last_found')
            
            internal_finding_id = (finding_uuid or 
                                 f"{plugin_id}-{asset_uuid}-{last_found_raw}")
            
            # Check if finding already exists
            existing_finding = db.session.query(VulnerabilityFinding).filter_by(
                internal_finding_id=internal_finding_id
            ).first()
            
            # Extract cloud metadata
            cloud_info = extract_cloud_metadata(asset_data)
            
            # Build finding attributes
            finding_attrs = VulnerabilityProcessor._build_finding_attributes(
                finding_data, plugin_data, asset_data, cloud_info, internal_finding_id
            )
            
            if existing_finding:
                # Update existing finding
                for key, value in finding_attrs.items():
                    setattr(existing_finding, key, value)
                current_app.logger.debug(f"Updated finding: {internal_finding_id}")
            else:
                # Create new finding
                new_finding = VulnerabilityFinding(**finding_attrs)
                db.session.add(new_finding)
                current_app.logger.debug(f"Added finding: {internal_finding_id}")
            
            db.session.commit()
            return True
            
        except IntegrityError:
            db.session.rollback()
            current_app.logger.warning(f"Integrity error for finding: {finding_data.get('uuid', 'Unknown')}")
            return False
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error processing finding: {e}")
            return False
    
    @staticmethod
    def _build_finding_attributes(finding_data, plugin_data, asset_data, cloud_info, internal_finding_id):
        """Build attributes dictionary for vulnerability finding"""
        
        # Extract attack path data
        attack_path_data = finding_data.get('attack_path', {})
        
        # Extract exposure data
        exposure_data = finding_data.get('exposure', {}) or asset_data.get('exposure', {})
        
        # Build asset tags including cloud info
        asset_tags = asset_data.get('tags', [])
        if cloud_info['is_cloud']:
            asset_tags.append(f"cloud_provider:{cloud_info['provider']}")
        
        return {
            # Core identification
            'plugin_id': plugin_data.get('id'),
            'plugin_name': plugin_data.get('name'),
            'asset_uuid': asset_data.get('uuid'),
            'finding_uuid': finding_data.get('uuid'),
            'internal_finding_id': internal_finding_id,
            
            # Asset information
            'asset_hostname': asset_data.get('hostname'),
            'asset_ipv4': asset_data.get('ipv4'),
            'asset_ipv6': asset_data.get('ipv6'),
            'asset_os': asset_data.get('os'),
            'asset_tags': json.dumps(asset_tags),
            'asset_network_id': asset_data.get('network_id'),
            
            # Cloud metadata
            'asset_aws_ec2_instance_id': asset_data.get('aws_ec2_instance_id'),
            'asset_azure_vm_id': asset_data.get('azure_vm_id'),
            'asset_gcp_instance_id': asset_data.get('gcp_instance_id'),
            
            # Vulnerability details
            'severity': finding_data.get('severity'),
            'vpr_score': plugin_data.get('vpr', {}).get('score'),
            'cvss_v3_base_score': plugin_data.get('cvss3_base_score') or plugin_data.get('cvss_v3_base_score'),
            'cvss_v3_vector': json.dumps(plugin_data.get('cvss3_vector')) if isinstance(plugin_data.get('cvss3_vector'), dict) else plugin_data.get('cvss3_vector'),
            'cvss3_temporal_score': plugin_data.get('cvss3_temporal_score'),
            'description': plugin_data.get('description'),
            'solution': plugin_data.get('solution'),
            'synopsis': plugin_data.get('synopsis'),
            'see_also': json.dumps(plugin_data.get('see_also')) if isinstance(plugin_data.get('see_also'), list) else plugin_data.get('see_also'),
            
            # Dates
            'vuln_publication_date': safe_timestamp_to_datetime(plugin_data.get('vuln_publication_date')),
            'patch_publication_date': safe_timestamp_to_datetime(plugin_data.get('patch_publication_date')),
            
            # Exploit information
            'exploit_available': plugin_data.get('exploit_available', False),
            'exploit_code_maturity': plugin_data.get('exploit_code_maturity'),
            'risk_factor': plugin_data.get('risk_factor'),
            
            # Attack path information
            'is_in_attack_path': bool(attack_path_data.get('in_path', False)),
            'attack_path_score': attack_path_data.get('score'),
            'attack_path_exposure_score': attack_path_data.get('exposure_score'),
            'attack_path_details': json.dumps(attack_path_data) if attack_path_data else None,
            
            # Asset exposure
            'asset_exposure_score': exposure_data.get('score') or exposure_data.get('exposure_score'),
            'business_criticality': exposure_data.get('business_criticality'),
            'exposure_confidence': exposure_data.get('confidence'),
            
            # Discovery timeline
            'first_found': safe_timestamp_to_datetime(finding_data.get('first_found')),
            'last_found': safe_timestamp_to_datetime(finding_data.get('last_found')),
            'fixed_at': safe_timestamp_to_datetime(finding_data.get('fixed_at')),
            'state': finding_data.get('state', 'OPEN').upper()
        }


class AttackPathProcessor:
    """Process attack path findings"""
    
    @staticmethod
    def process_finding(attack_path_data):
        """Process attack path finding for database storage"""
        try:
            path_id = attack_path_data.get('id')
            if not path_id:
                current_app.logger.warning("Skipping attack path - no ID provided")
                return False
            
            existing_path = db.session.query(AttackPathFinding).filter_by(path_id=path_id).first()
            
            path_attrs = {
                'path_id': path_id,
                'attack_path_name': attack_path_data.get('name'),
                'attack_path_description': attack_path_data.get('description'),
                'path_risk_score': attack_path_data.get('risk_score'),
                'path_length': attack_path_data.get('path_length'),
                'assets_in_path': json.dumps(attack_path_data.get('assets', [])),
                'critical_assets_in_path': json.dumps(attack_path_data.get('critical_assets', [])),
                'first_detected': safe_timestamp_to_datetime(attack_path_data.get('created_at')),
                'last_updated': safe_timestamp_to_datetime(attack_path_data.get('updated_at')),
                'status': attack_path_data.get('status', 'ACTIVE').upper()
            }
            
            if existing_path:
                for key, value in path_attrs.items():
                    setattr(existing_path, key, value)
            else:
                new_path = AttackPathFinding(**path_attrs)
                db.session.add(new_path)
            
            db.session.commit()
            return True
            
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error processing attack path: {e}")
            return False


class WASProcessor:
    """Process WAS findings"""
    
    @staticmethod
    def process_finding(was_finding_data):
        """Process WAS finding for database storage"""
        try:
            finding_detail = was_finding_data.get('finding', {})
            
            # Create composite ID
            finding_uuid = was_finding_data.get('uuid')
            scan_id = was_finding_data.get('scan', {}).get('scan_id')
            plugin_id = finding_detail.get('plugin_id')
            target_url = finding_detail.get('uri')
            
            composite_id = finding_uuid or f"WAS-{scan_id}-{plugin_id}-{target_url}"
            
            if not composite_id:
                current_app.logger.warning("Skipping WAS finding - no composite ID")
                return False
            
            existing_finding = db.session.query(WASFinding).filter_by(
                composite_finding_id=composite_id
            ).first()
            
            # Determine status
            remediation_status = was_finding_data.get('remediation', {}).get('status', '').lower()
            status = 'Fixed' if remediation_status == 'fixed' else 'Active'
            
            was_attrs = {
                'scan_uuid': scan_id,
                'finding_id': finding_uuid,
                'composite_finding_id': composite_id,
                'vulnerability_id': str(plugin_id) if plugin_id else None,
                'vulnerability_name': finding_detail.get('name', 'Unknown WAS Vulnerability'),
                'target_url': target_url or 'Unknown URL',
                'severity': finding_detail.get('risk_factor', '').lower(),
                'status': status,
                'owasp_category': WASProcessor._extract_owasp_category(finding_detail),
                'cvss_v3_base_score': WASProcessor._extract_cvss_score(finding_detail),
                'description': finding_detail.get('description'),
                'solution': finding_detail.get('solution'),
                'first_detected_at': safe_timestamp_to_datetime(finding_detail.get('first_detected_at')),
                'last_detected_at': safe_timestamp_to_datetime(finding_detail.get('last_detected_at'))
            }
            
            if existing_finding:
                for key, value in was_attrs.items():
                    setattr(existing_finding, key, value)
            else:
                new_finding = WASFinding(**was_attrs)
                db.session.add(new_finding)
            
            db.session.commit()
            return True
            
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error processing WAS finding: {e}")
            return False
    
    @staticmethod
    def _extract_owasp_category(finding_detail):
        """Extract OWASP category from finding detail"""
        owasp_data = finding_detail.get('owasp', [])
        if isinstance(owasp_data, list) and owasp_data:
            if isinstance(owasp_data[0], dict):
                return owasp_data[0].get('category')
        return None
    
    @staticmethod
    def _extract_cvss_score(finding_detail):
        """Extract CVSS score from finding detail"""
        cvss_data = finding_detail.get('cvssv3', {})
        if isinstance(cvss_data, dict):
            score = cvss_data.get('base_score')
            return str(score) if score is not None else None
        return None


class CloudFindingProcessor:
    """Process cloud security findings from Ermetic/Tenable Cloud Security"""
    
    @staticmethod
    def process_finding(finding_data):
        """
        Process and save a cloud security finding from Ermetic
        """
        try:
            finding_id = finding_data.get('id', '')
            
            if not finding_id:
                current_app.logger.warning("Cloud finding missing ID, skipping")
                return False
            
            # DEBUG: Log the entire finding structure
            current_app.logger.debug(f"Processing cloud finding {finding_id}")
            current_app.logger.debug(f"  Finding keys: {list(finding_data.keys())}")
            
            # Extract resource information
            resource = finding_data.get('resource', {})
            current_app.logger.debug(f"  Resource keys: {list(resource.keys())}")
            current_app.logger.debug(f"  Resource data: {resource}")
            
            # Check if finding already exists
            existing = CloudFinding.query.filter_by(finding_id=finding_id).first()
            
            # Extract and normalize cloud provider with intelligent detection
            cloud_provider = resource.get('cloud_provider', 'Unknown')
            current_app.logger.debug(f"  Initial cloud_provider from resource: '{cloud_provider}'")
            
            # If Unknown, try to infer from resource_id or other fields
            if cloud_provider == 'Unknown' or not cloud_provider:
                resource_id = resource.get('id', '')
                resource_name = resource.get('name', '')
                account_id = resource.get('account_id', '')
                
                # Check for AWS patterns
                if resource_id.startswith('arn:aws:') or 'amazonaws' in resource_name.lower():
                    cloud_provider = 'AWS'
                    current_app.logger.debug(f"  Detected AWS from resource_id/name")
                
                # Check for Azure patterns
                elif '/subscriptions/' in resource_id or '/resourceGroups/' in resource_id:
                    cloud_provider = 'AZURE'
                    current_app.logger.debug(f"  Detected Azure from resource_id pattern")
                elif 'microsoft.' in resource_id.lower():
                    cloud_provider = 'AZURE'
                    current_app.logger.debug(f"  Detected Azure from Microsoft resource")
                
                # Check for GCP patterns
                elif 'gcp' in resource_id.lower() or 'google' in resource_id.lower():
                    cloud_provider = 'GCP'
                    current_app.logger.debug(f"  Detected GCP from resource_id")
                
                # Check account_id format for additional hints
                elif account_id and len(account_id) == 12 and account_id.isdigit():
                    cloud_provider = 'AWS'
                    current_app.logger.debug(f"  Detected AWS from 12-digit account_id")
                elif account_id and len(account_id) == 36 and account_id.count('-') == 4:
                    cloud_provider = 'AZURE'
                    current_app.logger.debug(f"  Detected Azure from UUID-style subscription")
            
            # Normalize to uppercase
            if cloud_provider and cloud_provider != 'Unknown':
                cloud_provider = cloud_provider.upper()
            
            current_app.logger.info(f"  Final cloud_provider for DB: '{cloud_provider}'")
            
            # Extract compliance frameworks
            compliance_frameworks = finding_data.get('compliance_frameworks', [])
            if isinstance(compliance_frameworks, list):
                compliance_json = json.dumps(compliance_frameworks)
            else:
                compliance_json = json.dumps([])
            
            # Build finding attributes
            finding_attrs = {
                'finding_id': finding_id,
                'title': finding_data.get('title', 'Cloud Security Finding'),
                'description': finding_data.get('description', ''),
                'severity': finding_data.get('severity', 'Medium'),
                'status': finding_data.get('status', 'Open'),
                'cloud_provider': cloud_provider,
                'resource_type': resource.get('type', ''),
                'resource_id': resource.get('id', ''),
                'resource_name': resource.get('name', 'Unknown'),
                'region': resource.get('region', ''),
                'account_id': resource.get('account_id', ''),
                'policy_violated': finding_data.get('policy_violated', ''),
                'risk_score': float(finding_data.get('risk_score', 5.0)),
                'category': finding_data.get('policy_violated', ''),
                'compliance_frameworks': compliance_json,
                'remediation': finding_data.get('remediation', ''),
                'first_detected_at': safe_timestamp_to_datetime(finding_data.get('created_at')),
                'last_detected_at': safe_timestamp_to_datetime(finding_data.get('updated_at')),
                'updated_at': datetime.now(timezone.utc),
                'raw_data': json.dumps(finding_data)  # Store for debugging
            }
            
            if existing:
                # Update existing finding
                for key, value in finding_attrs.items():
                    if key != 'finding_id':
                        setattr(existing, key, value)
                current_app.logger.info(f"Updated cloud finding: {finding_id} (Provider: {cloud_provider}, Resource: {resource.get('name')})")
            else:
                # Create new finding
                finding_attrs['created_at'] = datetime.now(timezone.utc)
                new_finding = CloudFinding(**finding_attrs)
                db.session.add(new_finding)
                current_app.logger.info(f"Created cloud finding: {finding_id} (Provider: {cloud_provider}, Resource: {resource.get('name')})")
            
            db.session.commit()
            return True
            
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error processing cloud finding: {e}")
            import traceback
            current_app.logger.error(traceback.format_exc())
            return False