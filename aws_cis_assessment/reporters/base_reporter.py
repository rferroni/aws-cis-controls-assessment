"""Base Report Generator for CIS Controls compliance assessment reports."""

import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from datetime import datetime
from pathlib import Path

from aws_cis_assessment.core.models import (
    AssessmentResult, ComplianceSummary, RemediationGuidance,
    IGScore, ControlScore, ComplianceResult
)

logger = logging.getLogger(__name__)


class ReportGenerator(ABC):
    """Abstract base class for generating compliance assessment reports."""
    
    def __init__(self, template_dir: Optional[str] = None):
        """Initialize report generator with optional template directory.
        
        Args:
            template_dir: Optional path to custom report templates
        """
        self.template_dir = Path(template_dir) if template_dir else None
        self.report_metadata = {}
        logger.info(f"Initialized {self.__class__.__name__} with template_dir: {template_dir}")
    
    @abstractmethod
    def generate_report(self, assessment_result: AssessmentResult, 
                       compliance_summary: ComplianceSummary,
                       output_path: Optional[str] = None) -> str:
        """Generate compliance assessment report.
        
        Args:
            assessment_result: Complete assessment result data
            compliance_summary: Executive summary of compliance status
            output_path: Optional path to save the report
            
        Returns:
            Generated report content as string
        """
        pass
    
    @abstractmethod
    def get_supported_formats(self) -> List[str]:
        """Get list of supported output formats.
        
        Returns:
            List of supported format strings (e.g., ['json', 'html', 'csv'])
        """
        pass
    
    def set_report_metadata(self, metadata: Dict[str, Any]):
        """Set additional metadata for the report.
        
        Args:
            metadata: Dictionary containing report metadata
        """
        self.report_metadata.update(metadata)
        logger.debug(f"Updated report metadata: {metadata}")
    
    def get_report_metadata(self) -> Dict[str, Any]:
        """Get current report metadata.
        
        Returns:
            Dictionary containing current report metadata
        """
        return self.report_metadata.copy()
    
    def _prepare_report_data(self, assessment_result: AssessmentResult,
                           compliance_summary: ComplianceSummary) -> Dict[str, Any]:
        """Prepare standardized data structure for report generation.
        
        Args:
            assessment_result: Complete assessment result data
            compliance_summary: Executive summary of compliance status
            
        Returns:
            Dictionary containing standardized report data
        """
        # Calculate additional metrics - deduplicate resources across IGs
        # Since IG2 includes IG1 and IG3 includes IG1+IG2, we need to count unique resources
        # Use IG1 as the source of truth since it contains all unique evaluations
        # (controls in higher IGs are the same controls, just evaluated again)
        
        # Collect unique resources by (resource_id, resource_type, region, config_rule_name)
        unique_resources = {}
        
        for ig_name, ig_score in assessment_result.ig_scores.items():
            for control_id, control in ig_score.control_scores.items():
                for finding in control.findings:
                    # Create unique key for each resource evaluation
                    resource_key = (
                        finding.resource_id,
                        finding.resource_type,
                        finding.region,
                        finding.config_rule_name
                    )
                    # Store the finding (last one wins, but they should be identical)
                    unique_resources[resource_key] = finding
        
        # Now count from unique resources
        total_resources = len(unique_resources)
        total_compliant = sum(
            1 for finding in unique_resources.values()
            if finding.compliance_status.value == 'COMPLIANT'
        )
        total_non_compliant = sum(
            1 for finding in unique_resources.values()
            if finding.compliance_status.value == 'NON_COMPLIANT'
        )
        
        # Prepare standardized data structure
        report_data = {
            'metadata': {
                'report_generated_at': datetime.now().isoformat(),
                'assessment_timestamp': assessment_result.timestamp.isoformat(),
                'account_id': assessment_result.account_id,
                'regions_assessed': assessment_result.regions_assessed,
                'assessment_duration': str(assessment_result.assessment_duration) if assessment_result.assessment_duration else None,
                'total_resources_evaluated': assessment_result.total_resources_evaluated,
                **self.report_metadata
            },
            'executive_summary': {
                'overall_compliance_percentage': compliance_summary.overall_compliance_percentage,
                'aws_config_style_score': assessment_result.aws_config_score,  # Add AWS Config score
                'score_difference': compliance_summary.overall_compliance_percentage - assessment_result.aws_config_score,  # Show difference
                'ig1_compliance_percentage': compliance_summary.ig1_compliance_percentage,
                'ig2_compliance_percentage': compliance_summary.ig2_compliance_percentage,
                'ig3_compliance_percentage': compliance_summary.ig3_compliance_percentage,
                'total_resources': total_resources,
                'compliant_resources': total_compliant,
                'non_compliant_resources': total_non_compliant,
                'top_risk_areas': compliance_summary.top_risk_areas,
                'compliance_trend': compliance_summary.compliance_trend,
                'coverage_metrics': self._prepare_coverage_metrics_data(compliance_summary.coverage_metrics)
            },
            'implementation_groups': self._prepare_ig_data(assessment_result.ig_scores),
            'remediation_priorities': self._prepare_remediation_data(compliance_summary.remediation_priorities),
            'detailed_findings': self._prepare_findings_data(assessment_result.ig_scores)
        }
        
        return report_data
    
    def _prepare_ig_data(self, ig_scores: Dict[str, IGScore]) -> Dict[str, Any]:
        """Prepare Implementation Group data for reporting.
        
        Args:
            ig_scores: Dictionary of IG scores
            
        Returns:
            Dictionary containing IG data structured for reporting
        """
        ig_data = {}
        
        for ig_name, ig_score in ig_scores.items():
            ig_data[ig_name] = {
                'implementation_group': ig_score.implementation_group,
                'total_controls': ig_score.total_controls,
                'compliant_controls': ig_score.compliant_controls,
                'compliance_percentage': ig_score.compliance_percentage,
                'controls': self._prepare_control_data(ig_score.control_scores)
            }
        
        return ig_data
    
    def _prepare_control_data(self, control_scores: Dict[str, ControlScore]) -> Dict[str, Any]:
        """Prepare Control data for reporting.
        
        Args:
            control_scores: Dictionary of control scores
            
        Returns:
            Dictionary containing control data structured for reporting
        """
        control_data = {}
        
        for control_id, control_score in control_scores.items():
            control_data[control_id] = {
                'control_id': control_score.control_id,
                'title': control_score.title,
                'implementation_group': control_score.implementation_group,
                'total_resources': control_score.total_resources,
                'compliant_resources': control_score.compliant_resources,
                'compliance_percentage': control_score.compliance_percentage,
                'config_rules_evaluated': control_score.config_rules_evaluated,
                'findings_count': len(control_score.findings),
                'non_compliant_findings': [
                    self._prepare_finding_data(finding) 
                    for finding in control_score.findings 
                    if finding.compliance_status.value == 'NON_COMPLIANT'
                ],
                'compliant_findings': [
                    self._prepare_finding_data(finding) 
                    for finding in control_score.findings 
                    if finding.compliance_status.value == 'COMPLIANT'
                ]
            }
        
        return control_data
    
    def _prepare_finding_data(self, finding: ComplianceResult) -> Dict[str, Any]:
        """Prepare individual finding data for reporting.
        
        Args:
            finding: ComplianceResult object
            
        Returns:
            Dictionary containing finding data structured for reporting
        """
        return {
            'resource_id': finding.resource_id,
            'resource_type': finding.resource_type,
            'compliance_status': finding.compliance_status.value,
            'evaluation_reason': finding.evaluation_reason,
            'config_rule_name': finding.config_rule_name,
            'region': finding.region,
            'timestamp': finding.timestamp.isoformat(),
            'remediation_guidance': finding.remediation_guidance
        }
    
    def _prepare_remediation_data(self, remediation_priorities: List[RemediationGuidance]) -> List[Dict[str, Any]]:
        """Prepare remediation guidance data for reporting.
        
        Args:
            remediation_priorities: List of RemediationGuidance objects
            
        Returns:
            List of dictionaries containing remediation data structured for reporting
        """
        remediation_data = []
        
        for guidance in remediation_priorities:
            remediation_data.append({
                'config_rule_name': guidance.config_rule_name,
                'control_id': guidance.control_id,
                'priority': guidance.priority,
                'estimated_effort': guidance.estimated_effort,
                'remediation_steps': guidance.remediation_steps,
                'aws_documentation_link': guidance.aws_documentation_link
            })
        
        return remediation_data
    
    def _prepare_coverage_metrics_data(self, coverage_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare coverage metrics data for reporting.
        
        Args:
            coverage_metrics: Dictionary of CoverageMetrics objects by IG
            
        Returns:
            Dictionary containing coverage metrics structured for reporting
        """
        coverage_data = {}
        
        for ig_name, metrics in coverage_metrics.items():
            # Handle both CoverageMetrics objects and dictionaries
            if hasattr(metrics, '__dict__'):
                metrics_dict = metrics.__dict__
            else:
                metrics_dict = metrics
            
            coverage_data[ig_name] = {
                'implementation_group': metrics_dict.get('implementation_group', ig_name),
                'total_safeguards': metrics_dict.get('total_safeguards', 0),
                'covered_safeguards': metrics_dict.get('covered_safeguards', 0),
                'coverage_percentage': metrics_dict.get('coverage_percentage', 0.0),
                'implemented_rules': metrics_dict.get('implemented_rules', 0),
                'safeguard_details': metrics_dict.get('safeguard_details', {})
            }
        
        return coverage_data
    
    def _prepare_findings_data(self, ig_scores: Dict[str, IGScore]) -> Dict[str, Any]:
        """Prepare detailed findings data for reporting.
        
        Args:
            ig_scores: Dictionary of IG scores
            
        Returns:
            Dictionary containing findings data structured for reporting
        """
        findings_data = {}
        
        for ig_name, ig_score in ig_scores.items():
            ig_findings = {}
            for control_id, control_score in ig_score.control_scores.items():
                control_findings = []
                for finding in control_score.findings:
                    control_findings.append(self._prepare_finding_data(finding))
                ig_findings[control_id] = control_findings
            findings_data[ig_name] = ig_findings
        
        return findings_data
    
    def _validate_report_data(self, report_data: Dict[str, Any]) -> bool:
        """Validate report data structure for consistency.
        
        Args:
            report_data: Prepared report data dictionary
            
        Returns:
            True if data is valid, False otherwise
        """
        required_sections = ['metadata', 'executive_summary', 'implementation_groups', 
                           'remediation_priorities', 'detailed_findings']
        
        for section in required_sections:
            if section not in report_data:
                logger.error(f"Missing required section in report data: {section}")
                return False
        
        # Validate metadata section
        metadata = report_data['metadata']
        required_metadata = ['report_generated_at', 'assessment_timestamp', 'account_id']
        for field in required_metadata:
            if field not in metadata:
                logger.error(f"Missing required metadata field: {field}")
                return False
        
        # Validate executive summary
        summary = report_data['executive_summary']
        required_summary_fields = ['overall_compliance_percentage', 'total_resources']
        for field in required_summary_fields:
            if field not in summary:
                logger.error(f"Missing required executive summary field: {field}")
                return False
        
        logger.debug("Report data validation passed")
        return True
    
    def _save_report_to_file(self, content: str, output_path: str) -> bool:
        """Save report content to file.
        
        Args:
            content: Report content to save
            output_path: Path where to save the report
            
        Returns:
            True if saved successfully, False otherwise
        """
        try:
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(content)
            
            logger.info(f"Report saved to: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save report to {output_path}: {e}")
            return False
    
    def validate_assessment_data(self, assessment_result: AssessmentResult,
                               compliance_summary: ComplianceSummary) -> bool:
        """Validate input assessment data before report generation.
        
        Args:
            assessment_result: Assessment result to validate
            compliance_summary: Compliance summary to validate
            
        Returns:
            True if data is valid, False otherwise
        """
        if not assessment_result.account_id:
            logger.error("Assessment result missing account_id")
            return False
        
        if not assessment_result.regions_assessed:
            logger.error("Assessment result missing regions_assessed")
            return False
        
        if not assessment_result.ig_scores:
            logger.error("Assessment result missing ig_scores")
            return False
        
        # Validate compliance summary
        if compliance_summary.overall_compliance_percentage < 0 or compliance_summary.overall_compliance_percentage > 100:
            logger.error(f"Invalid overall compliance percentage: {compliance_summary.overall_compliance_percentage}")
            return False
        
        logger.debug("Assessment data validation passed")
        return True


class ReportTemplateEngine:
    """Template engine for generating formatted reports."""
    
    def __init__(self, template_dir: Optional[str] = None):
        """Initialize template engine.
        
        Args:
            template_dir: Optional path to custom templates
        """
        self.template_dir = Path(template_dir) if template_dir else None
        self.templates = {}
        logger.info(f"Initialized ReportTemplateEngine with template_dir: {template_dir}")
    
    def load_template(self, template_name: str) -> str:
        """Load template content from file or built-in templates.
        
        Args:
            template_name: Name of the template to load
            
        Returns:
            Template content as string
        """
        # Check for custom template first
        if self.template_dir:
            custom_template_path = self.template_dir / f"{template_name}.template"
            if custom_template_path.exists():
                with open(custom_template_path, 'r', encoding='utf-8') as f:
                    template_content = f.read()
                logger.debug(f"Loaded custom template: {template_name}")
                return template_content
        
        # Fall back to built-in templates
        built_in_template = self._get_builtin_template(template_name)
        if built_in_template:
            logger.debug(f"Using built-in template: {template_name}")
            return built_in_template
        
        logger.warning(f"Template not found: {template_name}")
        return ""
    
    def _get_builtin_template(self, template_name: str) -> Optional[str]:
        """Get built-in template content.
        
        Args:
            template_name: Name of the built-in template
            
        Returns:
            Template content or None if not found
        """
        builtin_templates = {
            'executive_summary': """
# Executive Summary

**Overall Compliance:** {overall_compliance_percentage:.1f}%
**Assessment Date:** {assessment_timestamp}
**AWS Account:** {account_id}

## Implementation Group Compliance
- **IG1 (Essential Cyber Hygiene):** {ig1_compliance_percentage:.1f}%
- **IG2 (Enhanced Security):** {ig2_compliance_percentage:.1f}%
- **IG3 (Advanced Security):** {ig3_compliance_percentage:.1f}%

## Resource Summary
- **Total Resources Evaluated:** {total_resources}
- **Compliant Resources:** {compliant_resources}
- **Non-Compliant Resources:** {non_compliant_resources}

## Top Risk Areas
{top_risk_areas}
""",
            'control_detail': """
## Control {control_id}: {title}

**Implementation Group:** {implementation_group}
**Compliance:** {compliant_resources}/{total_resources} ({compliance_percentage:.1f}%)
**Config Rules:** {config_rules_evaluated}

### Non-Compliant Resources
{non_compliant_findings}
""",
            'remediation_guidance': """
# Remediation Priorities

{remediation_items}
"""
        }
        
        return builtin_templates.get(template_name)
    
    def render_template(self, template_content: str, data: Dict[str, Any]) -> str:
        """Render template with provided data.
        
        Args:
            template_content: Template content with placeholders
            data: Data dictionary for template substitution
            
        Returns:
            Rendered template content
        """
        try:
            # Simple template rendering using string formatting
            # For more complex templating, could integrate Jinja2 or similar
            rendered_content = template_content.format(**data)
            logger.debug("Template rendered successfully")
            return rendered_content
            
        except KeyError as e:
            logger.error(f"Template rendering failed - missing key: {e}")
            return template_content
        except Exception as e:
            logger.error(f"Template rendering failed: {e}")
            return template_content