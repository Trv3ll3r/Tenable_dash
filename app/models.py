from app.database import db
from sqlalchemy import Integer, String, DateTime, Text, Boolean, Float, ForeignKey, func, UniqueConstraint
from sqlalchemy.orm import relationship

class VulnerabilityFinding(db.Model):
    """Enhanced vulnerability finding model with Tenable One features"""
    __tablename__ = 'vulnerability_findings'

    id = db.Column(Integer, primary_key=True)
    
    # Core identification
    plugin_id = db.Column(Integer, nullable=False)
    plugin_name = db.Column(String(500))
    asset_uuid = db.Column(String(100), nullable=False)
    finding_uuid = db.Column(String(100), nullable=True)
    internal_finding_id = db.Column(String(200), nullable=False, unique=True)
    
    # Asset information
    asset_hostname = db.Column(String(255))
    asset_ipv4 = db.Column(String(45))
    asset_ipv6 = db.Column(String(45))
    asset_os = db.Column(String(255))
    asset_tags = db.Column(Text)  # JSON string
    asset_network_id = db.Column(String(100))
    
    # Cloud provider metadata
    asset_aws_ec2_instance_id = db.Column(String(100))
    asset_azure_vm_id = db.Column(String(100))
    asset_gcp_instance_id = db.Column(String(100))
    
    # Vulnerability details
    severity = db.Column(String(20))
    vpr_score = db.Column(Float)
    cvss_v3_base_score = db.Column(Float)
    cvss_v3_vector = db.Column(String(200))
    cvss3_temporal_score = db.Column(Float)
    description = db.Column(Text)
    solution = db.Column(Text)
    synopsis = db.Column(Text)
    see_also = db.Column(Text)
    
    # Dates
    vuln_publication_date = db.Column(DateTime)
    patch_publication_date = db.Column(DateTime)
    
    # Exploit information
    exploit_available = db.Column(Boolean, default=False)
    exploit_code_maturity = db.Column(String(50))
    risk_factor = db.Column(String(20))
    
    # Attack path information (Tenable One)
    attack_path_score = db.Column(Float)
    attack_path_exposure_score = db.Column(Float)
    is_in_attack_path = db.Column(Boolean, default=False)
    attack_path_details = db.Column(Text)  # JSON string
    
    # Asset exposure (Tenable One)
    asset_exposure_score = db.Column(Float)
    business_criticality = db.Column(String(50))
    exposure_confidence = db.Column(String(50))
    
    # Discovery timeline
    first_found = db.Column(DateTime)
    last_found = db.Column(DateTime)
    fixed_at = db.Column(DateTime)
    state = db.Column(String(20), default='OPEN')  # OPEN, REOPENED, FIXED
    
    # Ticket tracking
    ticket_created = db.Column(Boolean, default=False, nullable=True)
    
    # Record metadata
    record_created_at = db.Column(DateTime, default=func.now())
    record_updated_at = db.Column(DateTime, default=func.now(), onupdate=func.now())

    # Table constraints
    __table_args__ = (
        UniqueConstraint('plugin_id', 'asset_uuid', 'last_found', name='_plugin_asset_last_found_uc'),
    )

    # Relationships
    plugin_compliance_mappings = relationship(
        'PluginComplianceMapping',
        primaryjoin="foreign(VulnerabilityFinding.plugin_id) == PluginComplianceMapping.plugin_id",
        back_populates='finding_plugin',
        viewonly=True,
        uselist=True
    )

    def __repr__(self):
        return f"<VulnerabilityFinding(id={self.id}, plugin='{self.plugin_name}', asset='{self.asset_hostname or self.asset_ipv4}')>"

    @property
    def cloud_provider(self):
        """Get cloud provider for this asset"""
        if self.asset_aws_ec2_instance_id:
            return 'AWS'
        elif self.asset_azure_vm_id:
            return 'Azure'
        elif self.asset_gcp_instance_id:
            return 'GCP'
        return None

    @property
    def asset_display_name(self):
        """Get best display name for asset"""
        return (self.asset_hostname or 
                self.asset_ipv4 or 
                self.asset_aws_ec2_instance_id or 
                self.asset_azure_vm_id or 
                self.asset_gcp_instance_id or 
                'Unknown Asset')


class AttackPathFinding(db.Model):
    """Attack path findings for Tenable One"""
    __tablename__ = 'attack_path_findings'
    
    id = db.Column(Integer, primary_key=True)
    path_id = db.Column(String(100), nullable=False, unique=True)
    
    # Path information
    attack_path_name = db.Column(String(500))
    attack_path_description = db.Column(Text)
    
    # Risk metrics
    path_risk_score = db.Column(Float)
    path_likelihood_score = db.Column(Float)
    path_impact_score = db.Column(Float)
    path_length = db.Column(Integer)
    
    # Path details
    source_type = db.Column(String(100))
    target_type = db.Column(String(100))
    attack_techniques = db.Column(Text)  # JSON string
    path_nodes = db.Column(Text)  # JSON string
    
    # Asset involvement
    assets_in_path = db.Column(Text)  # JSON string of asset UUIDs
    critical_assets_in_path = db.Column(Text)  # JSON string
    
    # Timeline
    first_detected = db.Column(DateTime)
    last_updated = db.Column(DateTime)
    status = db.Column(String(20), default='ACTIVE')  # ACTIVE, MITIGATED, etc.
    
    # Record metadata
    record_created_at = db.Column(DateTime, default=func.now())
    record_updated_at = db.Column(DateTime, default=func.now(), onupdate=func.now())

    def __repr__(self):
        return f"<AttackPathFinding(id={self.id}, name='{self.attack_path_name}', risk_score={self.path_risk_score})>"


class WASFinding(db.Model):
    """Web Application Security findings"""
    __tablename__ = 'was_findings'

    id = db.Column(Integer, primary_key=True)
    
    # Identification
    scan_uuid = db.Column(String(100))
    finding_id = db.Column(String(100))
    composite_finding_id = db.Column(String(200), nullable=False, unique=True)
    vulnerability_id = db.Column(String(100))  # Maps to plugin_id for GRC mapping
    
    # Vulnerability details
    vulnerability_name = db.Column(String(500), nullable=False)
    target_url = db.Column(Text, nullable=False)
    severity = db.Column(String(20))
    status = db.Column(String(50))
    owasp_category = db.Column(String(100))
    cvss_v3_base_score = db.Column(String(10))
    
    # Content
    description = db.Column(Text)
    solution = db.Column(Text)
    
    # Timeline
    first_detected_at = db.Column(DateTime)
    last_detected_at = db.Column(DateTime)
    
    # Record metadata
    record_created_at = db.Column(DateTime, default=func.now())
    record_updated_at = db.Column(DateTime, default=func.now(), onupdate=func.now())

    # Relationships
    plugin_compliance_mappings = relationship(
        'PluginComplianceMapping',
        primaryjoin="foreign(WASFinding.vulnerability_id) == PluginComplianceMapping.plugin_id",
        back_populates='was_finding_plugin',
        viewonly=True,
        uselist=True
    )

    def __repr__(self):
        return f"<WASFinding(id={self.id}, name='{self.vulnerability_name}', url='{self.target_url[:50]}...')>"


class ContainerSecurityFinding(db.Model):
    """Container security findings"""
    __tablename__ = 'container_security_findings'
    
    id = db.Column(Integer, primary_key=True)
    finding_id = db.Column(String(100), nullable=False, unique=True)
    
    # Container information
    container_id = db.Column(String(100))
    container_name = db.Column(String(255))
    image_name = db.Column(String(500))
    image_tag = db.Column(String(100))
    image_digest = db.Column(String(100))
    
    # Vulnerability details
    vulnerability_id = db.Column(String(100))
    vulnerability_name = db.Column(String(500))
    severity = db.Column(String(20))
    cvss_score = db.Column(Float)
    description = db.Column(Text)
    
    # Package information
    package_name = db.Column(String(255))
    package_version = db.Column(String(100))
    fixed_version = db.Column(String(100))
    
    # Discovery information
    first_detected = db.Column(DateTime)
    last_seen = db.Column(DateTime)
    status = db.Column(String(20), default='ACTIVE')
    
    # Record metadata
    record_created_at = db.Column(DateTime, default=func.now())
    record_updated_at = db.Column(DateTime, default=func.now(), onupdate=func.now())

    def __repr__(self):
        return f"<ContainerSecurityFinding(id={self.id}, vuln='{self.vulnerability_name}', container='{self.container_name}')>"


class ComplianceRequirement(db.Model):
    """GRC compliance requirements"""
    __tablename__ = 'compliance_requirements'
    
    id = db.Column(Integer, primary_key=True)
    framework = db.Column(String(100), nullable=False)
    version = db.Column(String(50))
    requirement_id = db.Column(String(200), nullable=False, unique=True)
    description = db.Column(Text)

    # Relationships
    plugin_mappings_to_requirements = relationship(
        'PluginComplianceMapping',
        back_populates='compliance_requirement',
        uselist=True
    )

    def __repr__(self):
        return f"<ComplianceRequirement(id={self.id}, framework='{self.framework}', req_id='{self.requirement_id}')>"


class PluginComplianceMapping(db.Model):
    """Mapping between plugins and compliance requirements"""
    __tablename__ = 'plugin_compliance_mappings'
    
    id = db.Column(Integer, primary_key=True)
    plugin_id = db.Column(Integer, nullable=False)
    compliance_requirement_id = db.Column(Integer, ForeignKey('compliance_requirements.id'), nullable=False)

    # Table constraints
    __table_args__ = (
        UniqueConstraint('plugin_id', 'compliance_requirement_id', name='_plugin_compliance_uc'),
    )

    # Relationships
    compliance_requirement = relationship(
        'ComplianceRequirement',
        back_populates='plugin_mappings_to_requirements'
    )
    
    finding_plugin = relationship(
        'VulnerabilityFinding',
        primaryjoin="PluginComplianceMapping.plugin_id == foreign(VulnerabilityFinding.plugin_id)",
        back_populates='plugin_compliance_mappings',
        viewonly=True
    )
    
    was_finding_plugin = relationship(
        'WASFinding',
        primaryjoin="PluginComplianceMapping.plugin_id == foreign(WASFinding.vulnerability_id)",
        back_populates='plugin_compliance_mappings',
        viewonly=True
    )

    def __repr__(self):
        return f"<PluginComplianceMapping(plugin_id={self.plugin_id}, req_id={self.compliance_requirement_id})>"


class CloudFinding(db.Model):
    """Model for cloud security findings from Ermetic"""
    
    __tablename__ = 'cloud_findings'
    
    # Primary key
    id = db.Column(Integer, primary_key=True)
    finding_id = db.Column(String(255), unique=True, nullable=False, index=True)
    
    # Finding details
    title = db.Column(String(500))
    description = db.Column(Text)
    severity = db.Column(String(50))  # critical, high, medium, low, info
    status = db.Column(String(50))    # active, resolved, suppressed, in_progress
    
    # Cloud resource details
    cloud_provider = db.Column(String(50))  # aws, azure, gcp
    resource_type = db.Column(String(100))  # S3Bucket, EC2Instance, IAMRole, etc.
    resource_id = db.Column(String(500))    # Cloud resource identifier
    region = db.Column(String(100))         # us-east-1, westus, etc.
    account_id = db.Column(String(100))     # AWS Account, Azure Subscription, GCP Project
    
    # Risk and categorization
    risk_score = db.Column(Float)           # 0-10 risk score
    category = db.Column(String(100))       # misconfiguration, vulnerability, compliance, exposure
    
    # Remediation
    remediation = db.Column(Text)           # Remediation steps
    
    # Timestamps
    first_detected_at = db.Column(DateTime)
    last_detected_at = db.Column(DateTime)
    created_at = db.Column(DateTime, default=func.now())
    updated_at = db.Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Store raw data for debugging
    raw_data = db.Column(Text)
    
    # Record metadata
    record_created_at = db.Column(DateTime, default=func.now())
    record_updated_at = db.Column(DateTime, default=func.now(), onupdate=func.now())
    
    def __repr__(self):
        return f'<CloudFinding {self.finding_id}: {self.title} ({self.severity})>'
    
    def to_dict(self):
        """Convert finding to dictionary"""
        return {
            'id': self.id,
            'finding_id': self.finding_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'status': self.status,
            'cloud_provider': self.cloud_provider,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'region': self.region,
            'account_id': self.account_id,
            'risk_score': self.risk_score,
            'category': self.category,
            'remediation': self.remediation,
            'first_detected_at': self.first_detected_at.isoformat() if self.first_detected_at else None,
            'last_detected_at': self.last_detected_at.isoformat() if self.last_detected_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }