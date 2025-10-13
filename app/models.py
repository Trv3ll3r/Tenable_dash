from .database import db
from sqlalchemy import (Integer, String, DateTime, Text, Boolean, 
                       Float, UniqueConstraint, ForeignKey, func)
from sqlalchemy.orm import relationship

# Enhanced VulnerabilityFinding with new fields for Tenable One
class VulnerabilityFinding(db.Model):
    __tablename__ = 'vulnerability_findings'

    id = db.Column(Integer, primary_key=True)
    plugin_id = db.Column(Integer, nullable=False)
    plugin_name = db.Column(String)
    asset_uuid = db.Column(String, nullable=False)
    
    finding_uuid = db.Column(String, nullable=True)
    internal_finding_id = db.Column(String, nullable=False, unique=True)
    
    # Asset information
    asset_hostname = db.Column(String)
    asset_ipv4 = db.Column(String)
    asset_ipv6 = db.Column(String)
    asset_os = db.Column(String)
    asset_tags = db.Column(Text)  # JSON string of asset tags
    asset_network_id = db.Column(String)
    asset_aws_ec2_instance_id = db.Column(String)
    asset_azure_vm_id = db.Column(String)
    asset_gcp_instance_id = db.Column(String)
    
    # Vulnerability details
    severity = db.Column(String)
    vpr_score = db.Column(Float)
    cvss_v3_base_score = db.Column(Float)
    cvss_v3_vector = db.Column(String)
    cvss3_temporal_score = db.Column(Float)
    description = db.Column(Text)
    
    solution = db.Column(Text)
    synopsis = db.Column(Text)
    see_also = db.Column(Text)
    vuln_publication_date = db.Column(DateTime)
    patch_publication_date = db.Column(DateTime)
    exploit_available = db.Column(Boolean)
    exploit_code_maturity = db.Column(String)
    risk_factor = db.Column(String)
    
    # Attack path information (new for Tenable One)
    attack_path_score = db.Column(Float)
    attack_path_exposure_score = db.Column(Float)
    is_in_attack_path = db.Column(Boolean, default=False)
    attack_path_details = db.Column(Text)  # JSON string
    
    # Asset exposure (new for Tenable One)
    asset_exposure_score = db.Column(Float)
    business_criticality = db.Column(String)
    exposure_confidence = db.Column(String)
    
    # Discovery information
    first_found = db.Column(DateTime)
    last_found = db.Column(DateTime)
    fixed_at = db.Column(DateTime)
    state = db.Column(String)  # OPEN, REOPENED, FIXED
    
    # Record keeping
    record_created_at = db.Column(DateTime, default=func.now())
    record_updated_at = db.Column(DateTime, default=func.now(), onupdate=func.now())

    __table_args__ = (
        UniqueConstraint('plugin_id', 'asset_uuid', 'last_found', 
                        name='_plugin_asset_last_found_uc'),
    )

    plugin_compliance_mappings = relationship(
        'PluginComplianceMapping',
        primaryjoin="foreign(VulnerabilityFinding.plugin_id) == PluginComplianceMapping.plugin_id",
        back_populates='finding_plugin',
        viewonly=True,
        uselist=True
    )

class AttackPathFinding(db.Model):
    __tablename__ = 'attack_path_findings'
    
    id = db.Column(Integer, primary_key=True)
    path_id = db.Column(String, nullable=False, unique=True)
    attack_path_name = db.Column(String)
    attack_path_description = db.Column(Text)
    path_risk_score = db.Column(Float)
    path_length = db.Column(Integer)
    first_detected = db.Column(DateTime)
    last_updated = db.Column(DateTime)
    status = db.Column(String)

class ComplianceRequirement(db.Model):
    __tablename__ = 'compliance_requirements'
    id = db.Column(Integer, primary_key=True)
    framework = db.Column(String, nullable=False)
    version = db.Column(String, nullable=True)
    requirement_id = db.Column(String, nullable=False, unique=True)
    description = db.Column(Text, nullable=True)

    plugin_mappings_to_requirements = relationship(
        'PluginComplianceMapping',
        back_populates='compliance_requirement',
        uselist=True
    )

class PluginComplianceMapping(db.Model):
    __tablename__ = 'plugin_compliance_mappings'
    id = db.Column(Integer, primary_key=True)
    plugin_id = db.Column(Integer, nullable=False)
    compliance_requirement_id = db.Column(Integer, ForeignKey('compliance_requirements.id'), nullable=False)

    __table_args__ = (UniqueConstraint('plugin_id', 'compliance_requirement_id', name='_plugin_compliance_uc'),)

    compliance_requirement = relationship('ComplianceRequirement', back_populates='plugin_mappings_to_requirements')
    finding_plugin = relationship('VulnerabilityFinding', primaryjoin="PluginComplianceMapping.plugin_id == foreign(VulnerabilityFinding.plugin_id)", back_populates='plugin_compliance_mappings', viewonly=True)

class WASFinding(db.Model):
    __tablename__ = 'was_findings'

    id = db.Column(Integer, primary_key=True)
    composite_finding_id = db.Column(String, nullable=False, unique=True)
    vulnerability_id = db.Column(String)
    vulnerability_name = db.Column(String, nullable=False)
    target_url = db.Column(String, nullable=False)
    severity = db.Column(String)
    status = db.Column(String)
    first_detected_at = db.Column(DateTime)
    last_detected_at = db.Column(DateTime)

    plugin_compliance_mappings = relationship(
        'PluginComplianceMapping',
        primaryjoin="foreign(WASFinding.vulnerability_id) == PluginComplianceMapping.plugin_id",
        back_populates='was_finding_plugin',
        viewonly=True,
        uselist=True
    )

# Container Security Finding model (optional - can be added later if needed)
class ContainerSecurityFinding(db.Model):
    __tablename__ = 'container_security_findings'
    
    id = db.Column(Integer, primary_key=True)
    finding_id = db.Column(String, nullable=False, unique=True)
    
    # Container information
    container_id = db.Column(String)
    container_name = db.Column(String)
    image_name = db.Column(String)
    image_tag = db.Column(String)
    image_digest = db.Column(String)
    
    # Vulnerability details
    vulnerability_id = db.Column(String)
    vulnerability_name = db.Column(String)
    severity = db.Column(String)
    cvss_score = db.Column(Float)
    description = db.Column(Text)
    
    # Package information
    package_name = db.Column(String)
    package_version = db.Column(String)
    fixed_version = db.Column(String)
    
    # Discovery information
    first_detected = db.Column(DateTime)
    last_seen = db.Column(DateTime)
    status = db.Column(String)
    
    # Record keeping
    record_created_at = db.Column(DateTime, default=func.now())
    record_updated_at = db.Column(DateTime, default=func.now(), onupdate=func.now())

# Add missing relationship to PluginComplianceMapping for WAS findings
PluginComplianceMapping.was_finding_plugin = relationship('WASFinding', primaryjoin="PluginComplianceMapping.plugin_id == foreign(WASFinding.vulnerability_id)", back_populates='plugin_compliance_mappings', viewonly=True)