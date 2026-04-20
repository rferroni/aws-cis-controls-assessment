"""Data models for CIS Controls and AWS Config rule specifications."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from enum import Enum


class ComplianceStatus(Enum):
    """Compliance status enumeration."""
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    ERROR = "ERROR"
    INSUFFICIENT_PERMISSIONS = "INSUFFICIENT_PERMISSIONS"


class ImplementationGroup(Enum):
    """CIS Controls Implementation Groups."""
    IG1 = "IG1"
    IG2 = "IG2"
    IG3 = "IG3"


@dataclass
class ConfigRule:
    """AWS Config rule specification for CIS Control assessment."""
    name: str
    control_id: str
    resource_types: List[str]
    parameters: Dict[str, Any] = field(default_factory=dict)
    implementation_group: str = "IG1"
    description: str = ""
    remediation_guidance: str = ""
    
    def __post_init__(self):
        """Validate ConfigRule after initialization."""
        if not self.name:
            raise ValueError("ConfigRule name cannot be empty")
        if not self.control_id:
            raise ValueError("ConfigRule control_id cannot be empty")
        if not self.resource_types:
            raise ValueError("ConfigRule must have at least one resource type")


@dataclass
class CISControl:
    """CIS Control definition with associated Config rules."""
    control_id: str
    title: str
    implementation_group: str
    config_rules: List[ConfigRule] = field(default_factory=list)
    weight: float = 1.0
    
    def __post_init__(self):
        """Validate CISControl after initialization."""
        if not self.control_id:
            raise ValueError("CISControl control_id cannot be empty")
        if not self.title:
            raise ValueError("CISControl title cannot be empty")
        if self.implementation_group not in [ig.value for ig in ImplementationGroup]:
            raise ValueError(f"Invalid implementation group: {self.implementation_group}")


@dataclass
class ComplianceResult:
    """Individual resource compliance evaluation result."""
    resource_id: str
    resource_type: str
    compliance_status: ComplianceStatus
    evaluation_reason: str
    config_rule_name: str
    region: str
    timestamp: datetime = field(default_factory=datetime.now)
    remediation_guidance: Optional[str] = None
    
    def __post_init__(self):
        """Validate ComplianceResult after initialization."""
        if not self.resource_id:
            raise ValueError("ComplianceResult resource_id cannot be empty")
        if not self.resource_type:
            raise ValueError("ComplianceResult resource_type cannot be empty")
        if not isinstance(self.compliance_status, ComplianceStatus):
            raise ValueError("ComplianceResult compliance_status must be ComplianceStatus enum")


@dataclass
class ControlScore:
    """CIS Control compliance score."""
    control_id: str
    title: str
    implementation_group: str
    total_resources: int
    compliant_resources: int
    compliance_percentage: float
    config_rules_evaluated: List[str] = field(default_factory=list)
    findings: List[ComplianceResult] = field(default_factory=list)
    
    def __post_init__(self):
        """Calculate compliance percentage if not provided."""
        if self.total_resources > 0:
            calculated_percentage = (self.compliant_resources / self.total_resources) * 100
            if abs(self.compliance_percentage - calculated_percentage) > 0.01:
                self.compliance_percentage = calculated_percentage


@dataclass
class IGScore:
    """Implementation Group compliance score."""
    implementation_group: str
    total_controls: int
    compliant_controls: int
    compliance_percentage: float
    control_scores: Dict[str, ControlScore] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate IGScore after initialization."""
        if self.implementation_group not in [ig.value for ig in ImplementationGroup]:
            raise ValueError(f"Invalid implementation group: {self.implementation_group}")


@dataclass
class AssessmentResult:
    """Complete assessment result."""
    account_id: str
    regions_assessed: List[str]
    timestamp: datetime
    overall_score: float
    aws_config_score: float = 0.0  # AWS Config Conformance Pack style score
    ig_scores: Dict[str, IGScore] = field(default_factory=dict)
    total_resources_evaluated: int = 0
    assessment_duration: Optional[timedelta] = None
    
    def __post_init__(self):
        """Validate AssessmentResult after initialization."""
        if not self.account_id:
            raise ValueError("AssessmentResult account_id cannot be empty")
        if not self.regions_assessed:
            raise ValueError("AssessmentResult must assess at least one region")


@dataclass
class RemediationGuidance:
    """Remediation guidance for non-compliant resources."""
    config_rule_name: str
    control_id: str
    remediation_steps: List[str]
    aws_documentation_link: str
    priority: str = "MEDIUM"  # HIGH, MEDIUM, LOW
    estimated_effort: str = "Unknown"
    
    def __post_init__(self):
        """Validate RemediationGuidance after initialization."""
        if self.priority not in ["HIGH", "MEDIUM", "LOW"]:
            raise ValueError(f"Invalid priority: {self.priority}")


@dataclass
class CoverageMetrics:
    """CIS Controls coverage metrics for Implementation Groups."""
    implementation_group: str
    total_safeguards: int
    covered_safeguards: int
    coverage_percentage: float
    implemented_rules: int
    safeguard_details: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Calculate coverage percentage if not provided."""
        if self.total_safeguards > 0:
            calculated_percentage = (self.covered_safeguards / self.total_safeguards) * 100
            if abs(self.coverage_percentage - calculated_percentage) > 0.01:
                self.coverage_percentage = calculated_percentage


@dataclass
class ComplianceSummary:
    """Executive summary of compliance assessment."""
    overall_compliance_percentage: float
    ig1_compliance_percentage: float
    ig2_compliance_percentage: float
    ig3_compliance_percentage: float
    top_risk_areas: List[str] = field(default_factory=list)
    remediation_priorities: List[RemediationGuidance] = field(default_factory=list)
    compliance_trend: Optional[str] = None
    coverage_metrics: Dict[str, CoverageMetrics] = field(default_factory=dict)