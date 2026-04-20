"""Scoring Engine for calculating CIS Controls compliance scores."""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from collections import defaultdict

from aws_cis_assessment.core.models import (
    ComplianceResult, ComplianceStatus, ControlScore, IGScore, 
    AssessmentResult, ComplianceSummary, RemediationGuidance
)

logger = logging.getLogger(__name__)


class ScoringEngine:
    """Calculate compliance scores based on Config rule evaluation results."""
    
    def __init__(self, control_weights: Optional[Dict[str, float]] = None,
                 ig_weights: Optional[Dict[str, float]] = None):
        """Initialize scoring engine with optional custom weights.
        
        Args:
            control_weights: Optional dictionary mapping control IDs to weights
            ig_weights: Optional dictionary mapping IG names to weights
        """
        # Default control weights based on CIS Controls importance
        self.control_weights = control_weights or {
            '1.1': 1.0,  # Asset Inventory - foundational
            '3.3': 1.5,  # Data Access Control - critical
            '4.1': 1.2,  # Secure Configuration - important
            '5.2': 1.3,  # Password Management - important
            '3.10': 1.4, # Encryption in Transit - critical
            '3.11': 1.4, # Encryption at Rest - critical
            '7.1': 1.1,  # Vulnerability Management - important
            '3.14': 1.2, # Sensitive Data Logging - important
            '12.8': 1.3, # Network Segmentation - important
            '13.1': 1.2, # Network Monitoring - important
        }
        
        # Default IG weights - higher IGs have more weight
        self.ig_weights = ig_weights or {
            'IG1': 1.0,
            'IG2': 1.5,
            'IG3': 2.0
        }
        
        logger.info("ScoringEngine initialized with control and IG weights")
    
    def calculate_aws_config_style_score(self, ig_scores: Dict[str, IGScore]) -> float:
        """Calculate compliance score using AWS Config Conformance Pack approach.
        
        This is a simple unweighted calculation:
        Score = Total Compliant Resources / Total Resources
        
        Args:
            ig_scores: Dictionary of IG scores
            
        Returns:
            Unweighted compliance percentage (0-100)
        """
        total_compliant = 0
        total_resources = 0
        
        # Sum all compliant and total resources across all IGs and controls
        for ig_score in ig_scores.values():
            for control_score in ig_score.control_scores.values():
                total_compliant += control_score.compliant_resources
                total_resources += control_score.total_resources
        
        if total_resources > 0:
            aws_config_score = (total_compliant / total_resources) * 100
        else:
            aws_config_score = 0.0
        
        logger.info(f"AWS Config style score: {aws_config_score:.1f}% "
                   f"({total_compliant}/{total_resources} resources compliant)")
        return aws_config_score
    
    def calculate_control_score(self, control_id: str, rule_results: List[ComplianceResult],
                              control_title: str = "", implementation_group: str = "") -> ControlScore:
        """Calculate compliance score for individual CIS Control.
        
        Args:
            control_id: CIS Control identifier (e.g., '1.1', '3.3')
            rule_results: List of ComplianceResult objects for this control
            control_title: Optional title for the control
            implementation_group: Optional IG designation
            
        Returns:
            ControlScore object with calculated compliance metrics
        """
        if not rule_results:
            return ControlScore(
                control_id=control_id,
                title=control_title or f"CIS Control {control_id}",
                implementation_group=implementation_group,
                total_resources=0,
                compliant_resources=0,
                compliance_percentage=0.0,
                config_rules_evaluated=[],
                findings=[]
            )
        
        # Filter out error results for scoring (but keep them in findings)
        scorable_results = [r for r in rule_results 
                           if r.compliance_status in [ComplianceStatus.COMPLIANT, 
                                                     ComplianceStatus.NON_COMPLIANT,
                                                     ComplianceStatus.NOT_APPLICABLE]]
        
        # Calculate basic metrics
        total_resources = len(scorable_results)
        compliant_resources = sum(1 for r in scorable_results 
                                if r.compliance_status == ComplianceStatus.COMPLIANT)
        
        # Calculate compliance percentage
        if total_resources > 0:
            compliance_percentage = (compliant_resources / total_resources) * 100
        else:
            compliance_percentage = 0.0
        
        # Get unique config rules evaluated
        config_rules_evaluated = list(set(r.config_rule_name for r in rule_results))
        
        # Apply control-specific weighting if needed
        control_weight = self.control_weights.get(control_id, 1.0)
        weighted_compliance = compliance_percentage * control_weight
        
        logger.debug(f"Control {control_id}: {compliant_resources}/{total_resources} "
                    f"({compliance_percentage:.1f}%) compliant, weight: {control_weight}")
        
        return ControlScore(
            control_id=control_id,
            title=control_title or f"CIS Control {control_id}",
            implementation_group=implementation_group,
            total_resources=total_resources,
            compliant_resources=compliant_resources,
            compliance_percentage=compliance_percentage,
            config_rules_evaluated=config_rules_evaluated,
            findings=rule_results
        )
    
    def calculate_ig_score(self, implementation_group: str, 
                          control_scores: Dict[str, ControlScore]) -> IGScore:
        """Calculate Implementation Group compliance score.
        
        Args:
            implementation_group: IG1, IG2, or IG3
            control_scores: Dictionary mapping control IDs to ControlScore objects
            
        Returns:
            IGScore object with calculated IG-level metrics
        """
        if not control_scores:
            return IGScore(
                implementation_group=implementation_group,
                total_controls=0,
                compliant_controls=0,
                compliance_percentage=0.0,
                control_scores={}
            )
        
        total_controls = len(control_scores)
        
        # Calculate weighted average compliance
        total_weighted_score = 0.0
        total_weight = 0.0
        compliant_controls = 0
        
        for control_id, control_score in control_scores.items():
            control_weight = self.control_weights.get(control_id, 1.0)
            total_weighted_score += control_score.compliance_percentage * control_weight
            total_weight += control_weight
            
            # Consider control compliant if >= 80% compliance
            if control_score.compliance_percentage >= 80.0:
                compliant_controls += 1
        
        # Calculate overall IG compliance percentage
        if total_weight > 0:
            ig_compliance_percentage = total_weighted_score / total_weight
        else:
            ig_compliance_percentage = 0.0
        
        logger.info(f"IG {implementation_group}: {compliant_controls}/{total_controls} "
                   f"controls compliant, overall: {ig_compliance_percentage:.1f}%")
        
        return IGScore(
            implementation_group=implementation_group,
            total_controls=total_controls,
            compliant_controls=compliant_controls,
            compliance_percentage=ig_compliance_percentage,
            control_scores=control_scores
        )
    
    def calculate_overall_score(self, ig_scores: Dict[str, IGScore]) -> float:
        """Calculate overall compliance score across all Implementation Groups.
        
        Args:
            ig_scores: Dictionary mapping IG names to IGScore objects
            
        Returns:
            Overall compliance percentage (0-100)
        """
        if not ig_scores:
            return 0.0
        
        # Calculate weighted average across IGs
        total_weighted_score = 0.0
        total_weight = 0.0
        
        for ig_name, ig_score in ig_scores.items():
            ig_weight = self.ig_weights.get(ig_name, 1.0)
            total_weighted_score += ig_score.compliance_percentage * ig_weight
            total_weight += ig_weight
        
        if total_weight > 0:
            overall_score = total_weighted_score / total_weight
        else:
            overall_score = 0.0
        
        logger.info(f"Overall compliance score: {overall_score:.1f}%")
        return overall_score
    
    def generate_compliance_summary(self, assessment_result: AssessmentResult) -> ComplianceSummary:
        """Generate executive summary of compliance status.
        
        Args:
            assessment_result: Complete assessment result
            
        Returns:
            ComplianceSummary with executive-level metrics and recommendations
        """
        # Extract IG-specific compliance percentages
        ig1_compliance = assessment_result.ig_scores.get('IG1', IGScore('IG1', 0, 0, 0.0)).compliance_percentage
        ig2_compliance = assessment_result.ig_scores.get('IG2', IGScore('IG2', 0, 0, 0.0)).compliance_percentage
        ig3_compliance = assessment_result.ig_scores.get('IG3', IGScore('IG3', 0, 0, 0.0)).compliance_percentage
        
        # Identify top risk areas (controls with lowest compliance)
        top_risk_areas = self._identify_risk_areas(assessment_result.ig_scores)
        
        # Generate remediation priorities
        remediation_priorities = self._generate_remediation_priorities(assessment_result.ig_scores)
        
        # Determine compliance trend (would require historical data)
        compliance_trend = self._determine_compliance_trend(assessment_result)
        
        # Calculate coverage metrics for each IG
        coverage_metrics = self._calculate_coverage_metrics(assessment_result.ig_scores)
        
        return ComplianceSummary(
            overall_compliance_percentage=assessment_result.overall_score,
            ig1_compliance_percentage=ig1_compliance,
            ig2_compliance_percentage=ig2_compliance,
            ig3_compliance_percentage=ig3_compliance,
            top_risk_areas=top_risk_areas,
            remediation_priorities=remediation_priorities,
            compliance_trend=compliance_trend,
            coverage_metrics=coverage_metrics
        )
    
    def _identify_risk_areas(self, ig_scores: Dict[str, IGScore], 
                           max_risk_areas: int = 5) -> List[str]:
        """Identify top risk areas based on lowest compliance scores.
        
        Args:
            ig_scores: Dictionary of IG scores
            max_risk_areas: Maximum number of risk areas to return
            
        Returns:
            List of risk area descriptions
        """
        risk_areas = []
        
        # Collect all control scores across IGs
        all_control_scores = []
        for ig_score in ig_scores.values():
            for control_id, control_score in ig_score.control_scores.items():
                all_control_scores.append((control_id, control_score))
        
        # Sort by compliance percentage (lowest first)
        all_control_scores.sort(key=lambda x: x[1].compliance_percentage)
        
        # Generate risk area descriptions
        for control_id, control_score in all_control_scores[:max_risk_areas]:
            if control_score.compliance_percentage < 80.0:  # Only include non-compliant controls
                risk_description = f"Control {control_id} ({control_score.title}): " \
                                 f"{control_score.compliance_percentage:.1f}% compliant"
                risk_areas.append(risk_description)
        
        return risk_areas
    
    def _generate_remediation_priorities(self, ig_scores: Dict[str, IGScore],
                                       max_priorities: int = 10) -> List[RemediationGuidance]:
        """Generate prioritized remediation guidance.
        
        Args:
            ig_scores: Dictionary of IG scores
            max_priorities: Maximum number of remediation items to return
            
        Returns:
            List of RemediationGuidance objects prioritized by impact
        """
        remediation_priorities = []
        
        # Collect non-compliant findings across all controls
        non_compliant_findings = []
        for ig_score in ig_scores.values():
            for control_score in ig_score.control_scores.values():
                for finding in control_score.findings:
                    if finding.compliance_status == ComplianceStatus.NON_COMPLIANT:
                        non_compliant_findings.append((control_score, finding))
        
        # Group by config rule and prioritize
        rule_findings = defaultdict(list)
        for control_score, finding in non_compliant_findings:
            rule_findings[finding.config_rule_name].append((control_score, finding))
        
        # Generate remediation guidance for top rules
        for rule_name, findings in list(rule_findings.items())[:max_priorities]:
            control_score, sample_finding = findings[0]
            
            # Determine priority based on control weight and number of affected resources
            control_weight = self.control_weights.get(control_score.control_id, 1.0)
            affected_resources = len(findings)
            
            if control_weight >= 1.4 or affected_resources >= 10:
                priority = "HIGH"
            elif control_weight >= 1.2 or affected_resources >= 5:
                priority = "MEDIUM"
            else:
                priority = "LOW"
            
            # Generate basic remediation steps
            remediation_steps = self._generate_remediation_steps(rule_name)
            
            remediation_guidance = RemediationGuidance(
                config_rule_name=rule_name,
                control_id=control_score.control_id,
                remediation_steps=remediation_steps,
                aws_documentation_link=f"https://docs.aws.amazon.com/config/latest/developerguide/{rule_name}.html",
                priority=priority,
                estimated_effort=self._estimate_remediation_effort(rule_name, affected_resources)
            )
            
            remediation_priorities.append(remediation_guidance)
        
        # Sort by priority (HIGH, MEDIUM, LOW)
        priority_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        remediation_priorities.sort(key=lambda x: priority_order.get(x.priority, 3))
        
        return remediation_priorities
    
    def _generate_remediation_steps(self, rule_name: str) -> List[str]:
        """Generate basic remediation steps for a Config rule.
        
        Args:
            rule_name: AWS Config rule name
            
        Returns:
            List of remediation step descriptions
        """
        # Basic remediation steps based on rule patterns
        if 'iam' in rule_name:
            return [
                "Review IAM policies and permissions",
                "Remove unnecessary privileges",
                "Enable MFA where required",
                "Update password policies if applicable"
            ]
        elif 'encrypt' in rule_name:
            return [
                "Enable encryption for the identified resources",
                "Use AWS KMS for key management",
                "Update resource configurations to require encryption",
                "Verify encryption settings are applied"
            ]
        elif 's3' in rule_name:
            return [
                "Review S3 bucket policies and ACLs",
                "Remove public access if not required",
                "Enable appropriate S3 security features",
                "Update bucket configurations"
            ]
        elif 'vpc' in rule_name or 'security-group' in rule_name:
            return [
                "Review network security group rules",
                "Remove overly permissive rules",
                "Implement principle of least privilege",
                "Update VPC configurations as needed"
            ]
        else:
            return [
                f"Review {rule_name} configuration",
                "Apply AWS security best practices",
                "Update resource settings to meet compliance requirements",
                "Verify changes resolve the compliance issue"
            ]
    
    def _estimate_remediation_effort(self, rule_name: str, affected_resources: int) -> str:
        """Estimate effort required for remediation.
        
        Args:
            rule_name: AWS Config rule name
            affected_resources: Number of affected resources
            
        Returns:
            Effort estimate string
        """
        # Base effort on rule complexity and resource count
        if affected_resources <= 5:
            base_effort = "Low"
        elif affected_resources <= 20:
            base_effort = "Medium"
        else:
            base_effort = "High"
        
        # Adjust for rule complexity
        complex_rules = ['iam-password-policy', 'vpc-sg-open-only-to-authorized-ports', 
                        'multi-region-cloudtrail-enabled']
        
        if rule_name in complex_rules:
            if base_effort == "Low":
                base_effort = "Medium"
            elif base_effort == "Medium":
                base_effort = "High"
        
        return base_effort
    
    def _determine_compliance_trend(self, assessment_result: AssessmentResult) -> Optional[str]:
        """Determine compliance trend (requires historical data).
        
        Args:
            assessment_result: Current assessment result
            
        Returns:
            Trend description or None if no historical data available
        """
        # This would require historical assessment data to implement properly
        # For now, return None to indicate no trend data available
        return None
    
    def _calculate_coverage_metrics(self, ig_scores: Dict[str, IGScore]) -> Dict[str, 'CoverageMetrics']:
        """Calculate CIS Controls coverage metrics for each Implementation Group.
        
        Dynamically counts unique safeguard (control) IDs from the YAML configs
        and applies cumulative logic per CIS Controls v8.1:
        - IG1: only IG1 safeguards
        - IG2: IG1 + IG2 safeguards (cumulative)
        - IG3: IG1 + IG2 + IG3 safeguards (cumulative)
        
        Total safeguard counts per CIS Controls v8.1 spec:
        - IG1: 56, IG2: 74 (cumulative), IG3: 153 (cumulative)
        
        Args:
            ig_scores: Dictionary of IG scores with control assessments
            
        Returns:
            Dictionary mapping IG names to CoverageMetrics objects
        """
        from aws_cis_assessment.core.models import CoverageMetrics
        
        # CIS Controls v8.1 total safeguard counts (cumulative)
        total_safeguards = {
            'IG1': 56,
            'IG2': 74,
            'IG3': 153
        }
        
        # Dynamically count unique safeguard IDs from YAML configs
        # Each control ID in the YAML represents a CIS safeguard
        safeguard_ids_per_ig = {}
        try:
            from aws_cis_assessment.config.config_loader import ConfigRuleLoader
            config_loader = ConfigRuleLoader()
            for ig_name in ['IG1', 'IG2', 'IG3']:
                rules_by_control = config_loader.load_rules_for_ig(ig_name)
                safeguard_ids_per_ig[ig_name] = set(rules_by_control.keys())
        except Exception as e:
            logger.warning(f"Could not load YAML configs for coverage calculation: {e}")
            safeguard_ids_per_ig = {'IG1': set(), 'IG2': set(), 'IG3': set()}
        
        # Apply cumulative logic: IG2 includes IG1, IG3 includes IG1+IG2
        cumulative_safeguards = {
            'IG1': safeguard_ids_per_ig.get('IG1', set()),
            'IG2': safeguard_ids_per_ig.get('IG1', set()) | safeguard_ids_per_ig.get('IG2', set()),
            'IG3': safeguard_ids_per_ig.get('IG1', set()) | safeguard_ids_per_ig.get('IG2', set()) | safeguard_ids_per_ig.get('IG3', set()),
        }
        
        # Count unique rules from assessment data per IG
        rules_per_ig = {}
        for ig_name, ig_score in ig_scores.items():
            unique_rules = set()
            for control_score in ig_score.control_scores.values():
                if hasattr(control_score, 'config_rules_evaluated'):
                    unique_rules.update(control_score.config_rules_evaluated)
            rules_per_ig[ig_name] = unique_rules
        
        # Apply cumulative logic to rules as well
        cumulative_rules = {
            'IG1': rules_per_ig.get('IG1', set()),
            'IG2': rules_per_ig.get('IG1', set()) | rules_per_ig.get('IG2', set()),
            'IG3': rules_per_ig.get('IG1', set()) | rules_per_ig.get('IG2', set()) | rules_per_ig.get('IG3', set()),
        }
        
        coverage_metrics = {}
        
        for ig_name, ig_score in ig_scores.items():
            if ig_name not in total_safeguards:
                continue
            
            total = total_safeguards[ig_name]
            covered = len(cumulative_safeguards.get(ig_name, set()))
            rules = len(cumulative_rules.get(ig_name, set()))
            
            # Calculate coverage percentage
            coverage_pct = (covered / total * 100) if total > 0 else 0.0
            
            # Build safeguard details
            safeguard_details = {
                'total_safeguards': total,
                'covered_safeguards': covered,
                'implemented_rules': rules,
                'controls_assessed': len(ig_score.control_scores),
                'coverage_description': self._get_coverage_description(ig_name, coverage_pct)
            }
            
            coverage_metrics[ig_name] = CoverageMetrics(
                implementation_group=ig_name,
                total_safeguards=total,
                covered_safeguards=covered,
                coverage_percentage=coverage_pct,
                implemented_rules=rules,
                safeguard_details=safeguard_details
            )
        
        return coverage_metrics
    
    def _get_coverage_description(self, ig_name: str, coverage_pct: float) -> str:
        """Get human-readable coverage description.
        
        Args:
            ig_name: Implementation Group name
            coverage_pct: Coverage percentage
            
        Returns:
            Description of coverage level
        """
        if coverage_pct >= 75:
            return f"Comprehensive coverage of {ig_name} safeguards"
        elif coverage_pct >= 50:
            return f"Good coverage of {ig_name} safeguards"
        elif coverage_pct >= 25:
            return f"Moderate coverage of {ig_name} safeguards"
        else:
            return f"Limited coverage of {ig_name} safeguards"
    
    def calculate_resource_count_by_status(self, ig_scores: Dict[str, IGScore]) -> Dict[str, int]:
        """Calculate resource counts by compliance status across all IGs.
        
        Args:
            ig_scores: Dictionary of IG scores
            
        Returns:
            Dictionary mapping status names to resource counts
        """
        status_counts = defaultdict(int)
        
        for ig_score in ig_scores.values():
            for control_score in ig_score.control_scores.values():
                for finding in control_score.findings:
                    status_counts[finding.compliance_status.value] += 1
        
        return dict(status_counts)
    
    def get_control_weights(self) -> Dict[str, float]:
        """Get current control weights.
        
        Returns:
            Dictionary mapping control IDs to weights
        """
        return self.control_weights.copy()
    
    def get_ig_weights(self) -> Dict[str, float]:
        """Get current IG weights.
        
        Returns:
            Dictionary mapping IG names to weights
        """
        return self.ig_weights.copy()
    
    def update_control_weights(self, new_weights: Dict[str, float]):
        """Update control weights.
        
        Args:
            new_weights: Dictionary mapping control IDs to new weights
        """
        self.control_weights.update(new_weights)
        logger.info(f"Updated control weights: {new_weights}")
    
    def update_ig_weights(self, new_weights: Dict[str, float]):
        """Update IG weights.
        
        Args:
            new_weights: Dictionary mapping IG names to new weights
        """
        self.ig_weights.update(new_weights)
        logger.info(f"Updated IG weights: {new_weights}")