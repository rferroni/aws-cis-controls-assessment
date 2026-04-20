"""JSON Reporter for CIS Controls compliance assessment reports."""

import json
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path

from aws_cis_assessment.reporters.base_reporter import ReportGenerator
from aws_cis_assessment.core.models import (
    AssessmentResult, ComplianceSummary, RemediationGuidance,
    IGScore, ControlScore, ComplianceResult
)

logger = logging.getLogger(__name__)


class JSONReporter(ReportGenerator):
    """JSON format reporter for compliance assessment results.
    
    Generates structured JSON output with detailed compliance results,
    resource-level findings, assessment metadata, and remediation guidance.
    Designed for machine-readable integration with other tools.
    """
    
    def __init__(self, template_dir: Optional[str] = None, indent: int = 2):
        """Initialize JSON reporter.
        
        Args:
            template_dir: Optional path to custom report templates
            indent: JSON indentation level for pretty printing (default: 2)
        """
        super().__init__(template_dir)
        self.indent = indent
        logger.info(f"Initialized JSONReporter with indent={indent}")
    
    def generate_report(self, assessment_result: AssessmentResult, 
                       compliance_summary: ComplianceSummary,
                       output_path: Optional[str] = None) -> str:
        """Generate JSON format compliance assessment report.
        
        Args:
            assessment_result: Complete assessment result data
            compliance_summary: Executive summary of compliance status
            output_path: Optional path to save the JSON report
            
        Returns:
            JSON formatted report content as string
        """
        logger.info(f"Generating JSON report for account {assessment_result.account_id}")
        
        # Validate input data
        if not self.validate_assessment_data(assessment_result, compliance_summary):
            logger.error("Assessment data validation failed")
            return ""
        
        # Prepare structured report data
        report_data = self._prepare_report_data(assessment_result, compliance_summary)
        
        # Validate prepared data
        if not self._validate_report_data(report_data):
            logger.error("Report data validation failed")
            return ""
        
        # Enhance JSON-specific data structure
        json_report_data = self._enhance_json_structure(report_data)
        
        try:
            # Generate JSON content with proper formatting
            json_content = json.dumps(
                json_report_data, 
                indent=self.indent, 
                default=self._json_serializer,
                ensure_ascii=False,
                sort_keys=True
            )
            
            logger.info(f"Generated JSON report with {len(json_content)} characters")
            
            # Save to file if path provided
            if output_path:
                if self._save_report_to_file(json_content, output_path):
                    logger.info(f"JSON report saved to {output_path}")
                else:
                    logger.error(f"Failed to save JSON report to {output_path}")
            
            return json_content
            
        except Exception as e:
            logger.error(f"Failed to generate JSON report: {e}")
            return ""
    
    def get_supported_formats(self) -> List[str]:
        """Get list of supported output formats.
        
        Returns:
            List containing 'json' format
        """
        return ['json']
    
    def _enhance_json_structure(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance report data structure for JSON-specific requirements.
        
        Args:
            report_data: Base report data from parent class
            
        Returns:
            Enhanced data structure optimized for JSON output
        """
        # Create enhanced JSON structure
        json_data = {
            "report_format": "json",
            "report_version": "1.0",
            "schema_version": "2024.1",
            **report_data
        }
        
        # Add JSON-specific metadata
        json_data["metadata"]["report_format"] = "json"
        json_data["metadata"]["machine_readable"] = True
        json_data["metadata"]["api_version"] = "v1"
        
        # Enhance executive summary with additional computed metrics
        exec_summary = json_data["executive_summary"]
        
        # Add compliance grade based on overall percentage
        overall_pct = exec_summary["overall_compliance_percentage"]
        exec_summary["compliance_grade"] = self._calculate_compliance_grade(overall_pct)
        
        # Add risk level assessment
        exec_summary["risk_level"] = self._calculate_risk_level(overall_pct)
        
        # Add resource efficiency metrics
        total_resources = exec_summary["total_resources"]
        compliant_resources = exec_summary["compliant_resources"]
        non_compliant_resources = exec_summary["non_compliant_resources"]
        
        if total_resources > 0:
            exec_summary["compliance_ratio"] = compliant_resources / total_resources
            exec_summary["non_compliance_ratio"] = non_compliant_resources / total_resources
        else:
            exec_summary["compliance_ratio"] = 0.0
            exec_summary["non_compliance_ratio"] = 0.0
        
        # Enhance Implementation Group data with additional metrics
        for ig_name, ig_data in json_data["implementation_groups"].items():
            ig_data["compliance_status"] = self._get_compliance_status(ig_data["compliance_percentage"])
            ig_data["controls_compliance_ratio"] = (
                ig_data["compliant_controls"] / ig_data["total_controls"] 
                if ig_data["total_controls"] > 0 else 0.0
            )
            
            # Enhance control data
            for control_id, control_data in ig_data["controls"].items():
                control_data["compliance_status"] = self._get_compliance_status(
                    control_data["compliance_percentage"]
                )
                control_data["risk_score"] = self._calculate_control_risk_score(control_data)
                
                # Add finding statistics
                total_findings = len(control_data.get("non_compliant_findings", []))
                control_data["findings_summary"] = {
                    "total_non_compliant": total_findings,
                    "has_findings": total_findings > 0,
                    "severity_distribution": self._analyze_finding_severity(
                        control_data.get("non_compliant_findings", [])
                    )
                }
        
        # Enhance remediation priorities with additional context
        for remediation in json_data["remediation_priorities"]:
            remediation["priority_score"] = self._calculate_priority_score(remediation)
            remediation["effort_category"] = self._categorize_effort(remediation["estimated_effort"])
        
        # Add assessment statistics
        json_data["assessment_statistics"] = self._generate_assessment_statistics(json_data)
        
        # Add data quality metrics
        json_data["data_quality"] = self._assess_data_quality(json_data)
        
        return json_data
    
    def _json_serializer(self, obj) -> str:
        """Custom JSON serializer for non-standard types.
        
        Args:
            obj: Object to serialize
            
        Returns:
            String representation of the object
        """
        # Handle datetime objects
        if hasattr(obj, 'isoformat'):
            return obj.isoformat()
        
        # Handle timedelta objects
        if hasattr(obj, 'total_seconds'):
            return f"{obj.total_seconds():.2f}s"
        
        # Handle enum objects
        if hasattr(obj, 'value'):
            return obj.value
        
        # Default string representation
        return str(obj)
    
    def _calculate_compliance_grade(self, compliance_percentage: float) -> str:
        """Calculate compliance grade based on percentage.
        
        Args:
            compliance_percentage: Compliance percentage (0-100)
            
        Returns:
            Compliance grade (A, B, C, D, F)
        """
        if compliance_percentage >= 95.0:
            return "A"
        elif compliance_percentage >= 85.0:
            return "B"
        elif compliance_percentage >= 75.0:
            return "C"
        elif compliance_percentage >= 60.0:
            return "D"
        else:
            return "F"
    
    def _calculate_risk_level(self, compliance_percentage: float) -> str:
        """Calculate risk level based on compliance percentage.
        
        Args:
            compliance_percentage: Compliance percentage (0-100)
            
        Returns:
            Risk level (LOW, MEDIUM, HIGH, CRITICAL)
        """
        if compliance_percentage >= 90.0:
            return "LOW"
        elif compliance_percentage >= 75.0:
            return "MEDIUM"
        elif compliance_percentage >= 50.0:
            return "HIGH"
        else:
            return "CRITICAL"
    
    def _get_compliance_status(self, compliance_percentage: float) -> str:
        """Get compliance status based on percentage.
        
        Args:
            compliance_percentage: Compliance percentage (0-100)
            
        Returns:
            Compliance status (EXCELLENT, GOOD, FAIR, POOR, CRITICAL)
        """
        if compliance_percentage >= 95.0:
            return "EXCELLENT"
        elif compliance_percentage >= 80.0:
            return "GOOD"
        elif compliance_percentage >= 60.0:
            return "FAIR"
        elif compliance_percentage >= 40.0:
            return "POOR"
        else:
            return "CRITICAL"
    
    def _calculate_control_risk_score(self, control_data: Dict[str, Any]) -> float:
        """Calculate risk score for a control based on compliance and findings.
        
        Args:
            control_data: Control data dictionary
            
        Returns:
            Risk score (0.0 to 10.0, higher is riskier)
        """
        compliance_pct = control_data.get("compliance_percentage", 100.0)
        total_resources = control_data.get("total_resources", 0)
        non_compliant_findings = len(control_data.get("non_compliant_findings", []))
        
        # Base risk from non-compliance
        base_risk = (100.0 - compliance_pct) / 10.0  # 0-10 scale
        
        # Amplify risk based on number of affected resources
        if total_resources > 0:
            resource_factor = min(non_compliant_findings / total_resources, 1.0)
            base_risk *= (1.0 + resource_factor)
        
        # Cap at 10.0
        return min(base_risk, 10.0)
    
    def _analyze_finding_severity(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Analyze severity distribution of findings.
        
        Args:
            findings: List of finding dictionaries
            
        Returns:
            Dictionary with severity counts
        """
        severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        
        for finding in findings:
            # Simple severity assessment based on resource type and compliance status
            resource_type = finding.get("resource_type", "")
            
            # High severity for security-critical resources
            if any(critical in resource_type.lower() for critical in 
                   ["iam", "security", "kms", "cloudtrail", "guardduty"]):
                severity_counts["HIGH"] += 1
            # Medium severity for network and data resources
            elif any(medium in resource_type.lower() for medium in 
                     ["vpc", "s3", "rds", "ec2", "elb", "api"]):
                severity_counts["MEDIUM"] += 1
            # Low severity for others
            else:
                severity_counts["LOW"] += 1
        
        return severity_counts
    
    def _calculate_priority_score(self, remediation: Dict[str, Any]) -> int:
        """Calculate numeric priority score for remediation item.
        
        Args:
            remediation: Remediation guidance dictionary
            
        Returns:
            Priority score (1-10, higher is more urgent)
        """
        priority = remediation.get("priority", "MEDIUM")
        effort = remediation.get("estimated_effort", "Unknown")
        
        # Base score from priority
        priority_scores = {"HIGH": 8, "MEDIUM": 5, "LOW": 2}
        base_score = priority_scores.get(priority, 5)
        
        # Adjust based on effort (lower effort = higher priority)
        effort_adjustments = {
            "Low": 2, "Medium": 0, "High": -2, "Unknown": 0
        }
        effort_adjustment = effort_adjustments.get(effort, 0)
        
        final_score = base_score + effort_adjustment
        return max(1, min(final_score, 10))  # Clamp to 1-10 range
    
    def _categorize_effort(self, estimated_effort: str) -> str:
        """Categorize effort level.
        
        Args:
            estimated_effort: Effort estimation string
            
        Returns:
            Effort category (MINIMAL, MODERATE, SIGNIFICANT, EXTENSIVE)
        """
        effort_lower = estimated_effort.lower()
        
        if "low" in effort_lower or "minimal" in effort_lower:
            return "MINIMAL"
        elif "medium" in effort_lower or "moderate" in effort_lower:
            return "MODERATE"
        elif "high" in effort_lower or "significant" in effort_lower:
            return "SIGNIFICANT"
        else:
            return "EXTENSIVE"
    
    def _generate_assessment_statistics(self, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive assessment statistics.
        
        Args:
            json_data: Enhanced JSON report data
            
        Returns:
            Dictionary containing assessment statistics
        """
        metadata = json_data["metadata"]
        exec_summary = json_data["executive_summary"]
        ig_data = json_data["implementation_groups"]
        
        # Calculate IG statistics
        ig_stats = {}
        for ig_name, ig_info in ig_data.items():
            ig_stats[ig_name] = {
                "total_controls": ig_info["total_controls"],
                "compliant_controls": ig_info["compliant_controls"],
                "compliance_percentage": ig_info["compliance_percentage"],
                "controls_at_risk": ig_info["total_controls"] - ig_info["compliant_controls"]
            }
        
        # Calculate control distribution
        all_controls = []
        for ig_info in ig_data.values():
            all_controls.extend(ig_info["controls"].values())
        
        control_distribution = {
            "total_controls_evaluated": len(all_controls),
            "fully_compliant_controls": len([c for c in all_controls if c["compliance_percentage"] >= 100.0]),
            "mostly_compliant_controls": len([c for c in all_controls if 80.0 <= c["compliance_percentage"] < 100.0]),
            "partially_compliant_controls": len([c for c in all_controls if 50.0 <= c["compliance_percentage"] < 80.0]),
            "non_compliant_controls": len([c for c in all_controls if c["compliance_percentage"] < 50.0])
        }
        
        # Calculate regional coverage
        regions_assessed = metadata.get("regions_assessed", [])
        regional_stats = {
            "total_regions": len(regions_assessed),
            "regions_list": regions_assessed,
            "multi_region_assessment": len(regions_assessed) > 1
        }
        
        return {
            "implementation_groups": ig_stats,
            "control_distribution": control_distribution,
            "regional_coverage": regional_stats,
            "assessment_scope": {
                "total_resources_evaluated": exec_summary["total_resources"],
                "resources_per_region": (
                    exec_summary["total_resources"] / len(regions_assessed) 
                    if regions_assessed else 0
                ),
                "assessment_duration": metadata.get("assessment_duration"),
                "resources_per_minute": self._calculate_resources_per_minute(
                    exec_summary["total_resources"], 
                    metadata.get("assessment_duration")
                )
            }
        }
    
    def _calculate_resources_per_minute(self, total_resources: int, duration_str: Optional[str]) -> float:
        """Calculate resources processed per minute.
        
        Args:
            total_resources: Total number of resources evaluated
            duration_str: Duration string (e.g., "1800.00s")
            
        Returns:
            Resources per minute rate
        """
        if not duration_str or total_resources == 0:
            return 0.0
        
        try:
            # Extract seconds from duration string
            if duration_str.endswith('s'):
                seconds = float(duration_str[:-1])
                minutes = seconds / 60.0
                return total_resources / minutes if minutes > 0 else 0.0
        except (ValueError, TypeError):
            pass
        
        return 0.0
    
    def _assess_data_quality(self, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """Assess data quality metrics for the assessment.
        
        Args:
            json_data: Enhanced JSON report data
            
        Returns:
            Dictionary containing data quality metrics
        """
        metadata = json_data["metadata"]
        exec_summary = json_data["executive_summary"]
        ig_data = json_data["implementation_groups"]
        
        # Calculate completeness metrics
        total_expected_igs = 3  # IG1, IG2, IG3
        actual_igs = len(ig_data)
        ig_completeness = actual_igs / total_expected_igs
        
        # Calculate data consistency
        total_resources_from_summary = exec_summary["total_resources"]
        total_resources_from_metadata = metadata.get("total_resources_evaluated", 0)
        
        resource_consistency = (
            1.0 if total_resources_from_summary == total_resources_from_metadata
            else 0.8  # Slight inconsistency
        )
        
        # Calculate assessment coverage
        regions_assessed = len(metadata.get("regions_assessed", []))
        region_coverage_score = min(regions_assessed / 3.0, 1.0)  # Assume 3 regions is good coverage
        
        # Overall quality score
        quality_components = [ig_completeness, resource_consistency, region_coverage_score]
        overall_quality = sum(quality_components) / len(quality_components)
        
        return {
            "overall_quality_score": round(overall_quality, 3),
            "completeness": {
                "implementation_groups": ig_completeness,
                "expected_igs": total_expected_igs,
                "actual_igs": actual_igs
            },
            "consistency": {
                "resource_count_consistency": resource_consistency,
                "metadata_alignment": 1.0 if metadata.get("account_id") else 0.0
            },
            "coverage": {
                "regional_coverage_score": region_coverage_score,
                "regions_assessed": regions_assessed
            },
            "data_freshness": {
                "assessment_timestamp": metadata.get("assessment_timestamp"),
                "report_generation_timestamp": metadata.get("report_generated_at")
            }
        }
    
    def set_json_formatting(self, indent: int = 2, sort_keys: bool = True, 
                           ensure_ascii: bool = False) -> None:
        """Configure JSON formatting options.
        
        Args:
            indent: Number of spaces for indentation
            sort_keys: Whether to sort dictionary keys
            ensure_ascii: Whether to escape non-ASCII characters
        """
        self.indent = indent
        self.sort_keys = sort_keys
        self.ensure_ascii = ensure_ascii
        logger.debug(f"Updated JSON formatting: indent={indent}, sort_keys={sort_keys}, ensure_ascii={ensure_ascii}")
    
    def validate_json_output(self, json_content: str) -> bool:
        """Validate that the generated JSON is well-formed.
        
        Args:
            json_content: JSON content string to validate
            
        Returns:
            True if JSON is valid, False otherwise
        """
        try:
            json.loads(json_content)
            logger.debug("JSON validation passed")
            return True
        except json.JSONDecodeError as e:
            logger.error(f"JSON validation failed: {e}")
            return False
    
    def extract_summary_data(self, json_content: str) -> Optional[Dict[str, Any]]:
        """Extract summary data from generated JSON report.
        
        Args:
            json_content: JSON report content
            
        Returns:
            Dictionary containing summary data or None if extraction fails
        """
        try:
            data = json.loads(json_content)
            return {
                "account_id": data["metadata"]["account_id"],
                "overall_compliance": data["executive_summary"]["overall_compliance_percentage"],
                "compliance_grade": data["executive_summary"]["compliance_grade"],
                "risk_level": data["executive_summary"]["risk_level"],
                "total_resources": data["executive_summary"]["total_resources"],
                "assessment_date": data["metadata"]["assessment_timestamp"],
                "ig_scores": {
                    "IG1": data["executive_summary"]["ig1_compliance_percentage"],
                    "IG2": data["executive_summary"]["ig2_compliance_percentage"],
                    "IG3": data["executive_summary"]["ig3_compliance_percentage"]
                }
            }
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Failed to extract summary data: {e}")
            return None