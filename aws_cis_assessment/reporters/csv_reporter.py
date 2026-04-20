"""CSV Reporter for CIS Controls compliance assessment reports."""

import csv
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path
from io import StringIO
from datetime import datetime

from aws_cis_assessment.reporters.base_reporter import ReportGenerator
from aws_cis_assessment.core.models import (
    AssessmentResult, ComplianceSummary, RemediationGuidance,
    IGScore, ControlScore, ComplianceResult
)

logger = logging.getLogger(__name__)


class CSVReporter(ReportGenerator):
    """CSV format reporter for compliance assessment results.
    
    Generates spreadsheet-compatible output with flat structure suitable
    for data analysis and filtering. Supports multiple CSV files for
    summary, detailed findings, and remediation guidance with proper
    escaping and formatting for Excel compatibility.
    """
    
    def __init__(self, template_dir: Optional[str] = None, 
                 generate_multiple_files: bool = True,
                 excel_compatible: bool = True):
        """Initialize CSV reporter.
        
        Args:
            template_dir: Optional path to custom report templates
            generate_multiple_files: Whether to generate separate CSV files for different data types
            excel_compatible: Whether to use Excel-compatible formatting
        """
        super().__init__(template_dir)
        self.generate_multiple_files = generate_multiple_files
        self.excel_compatible = excel_compatible
        self.csv_dialect = 'excel' if excel_compatible else 'unix'
        logger.info(f"Initialized CSVReporter with multiple_files={generate_multiple_files}, excel_compatible={excel_compatible}")
    
    def generate_report(self, assessment_result: AssessmentResult, 
                       compliance_summary: ComplianceSummary,
                       output_path: Optional[str] = None) -> str:
        """Generate CSV format compliance assessment report.
        
        Args:
            assessment_result: Complete assessment result data
            compliance_summary: Executive summary of compliance status
            output_path: Optional path to save the CSV report(s)
            
        Returns:
            CSV formatted report content as string (summary CSV if multiple files)
        """
        logger.info(f"Generating CSV report for account {assessment_result.account_id}")
        
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
        
        # Enhance CSV-specific data structure
        csv_report_data = self._enhance_csv_structure(report_data)
        
        try:
            if self.generate_multiple_files:
                # Generate multiple CSV files
                csv_files = self._generate_multiple_csv_files(csv_report_data)
                
                # Save files if output path provided
                if output_path:
                    self._save_multiple_csv_files(csv_files, output_path)
                
                # Return summary CSV content
                return csv_files.get('summary', '')
            else:
                # Generate single comprehensive CSV
                csv_content = self._generate_single_csv_file(csv_report_data)
                
                # Save to file if path provided
                if output_path:
                    if self._save_report_to_file(csv_content, output_path):
                        logger.info(f"CSV report saved to {output_path}")
                    else:
                        logger.error(f"Failed to save CSV report to {output_path}")
                
                return csv_content
                
        except Exception as e:
            logger.error(f"Failed to generate CSV report: {e}")
            return ""
    
    def get_supported_formats(self) -> List[str]:
        """Get list of supported output formats.
        
        Returns:
            List containing 'csv' format
        """
        return ['csv']
    
    def _enhance_csv_structure(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance report data structure for CSV-specific requirements.
        
        Args:
            report_data: Base report data from parent class
            
        Returns:
            Enhanced data structure optimized for CSV output
        """
        # Create enhanced CSV structure
        csv_data = {
            "report_format": "csv",
            "report_version": "1.0",
            "excel_compatible": self.excel_compatible,
            **report_data
        }
        
        # Add CSV-specific metadata
        csv_data["metadata"]["report_format"] = "csv"
        csv_data["metadata"]["flat_structure"] = True
        csv_data["metadata"]["multiple_files"] = self.generate_multiple_files
        
        # Flatten nested structures for CSV compatibility
        csv_data["flattened_data"] = self._flatten_data_structures(csv_data)
        
        return csv_data
    
    def _flatten_data_structures(self, csv_data: Dict[str, Any]) -> Dict[str, Any]:
        """Flatten nested data structures for CSV compatibility.
        
        Args:
            csv_data: Enhanced CSV report data
            
        Returns:
            Dictionary containing flattened data structures
        """
        flattened = {}
        
        # Flatten executive summary
        exec_summary = csv_data["executive_summary"]
        flattened["summary_records"] = [{
            "metric": "Overall Compliance",
            "value": exec_summary.get("overall_compliance_percentage", 0),
            "unit": "percentage",
            "category": "executive_summary"
        }, {
            "metric": "IG1 Compliance",
            "value": exec_summary.get("ig1_compliance_percentage", 0),
            "unit": "percentage",
            "category": "implementation_group"
        }, {
            "metric": "IG2 Compliance",
            "value": exec_summary.get("ig2_compliance_percentage", 0),
            "unit": "percentage",
            "category": "implementation_group"
        }, {
            "metric": "IG3 Compliance",
            "value": exec_summary.get("ig3_compliance_percentage", 0),
            "unit": "percentage",
            "category": "implementation_group"
        }, {
            "metric": "Total Resources",
            "value": exec_summary.get("total_resources", 0),
            "unit": "count",
            "category": "resource_summary"
        }, {
            "metric": "Compliant Resources",
            "value": exec_summary.get("compliant_resources", 0),
            "unit": "count",
            "category": "resource_summary"
        }, {
            "metric": "Non-Compliant Resources",
            "value": exec_summary.get("non_compliant_resources", 0),
            "unit": "count",
            "category": "resource_summary"
        }]
        
        # Flatten Implementation Group data
        flattened["ig_records"] = []
        for ig_name, ig_data in csv_data["implementation_groups"].items():
            flattened["ig_records"].append({
                "implementation_group": ig_name,
                "total_controls": ig_data["total_controls"],
                "compliant_controls": ig_data["compliant_controls"],
                "compliance_percentage": ig_data["compliance_percentage"],
                "controls_at_risk": ig_data["total_controls"] - ig_data["compliant_controls"]
            })
        
        # Flatten Control data
        flattened["control_records"] = []
        for ig_name, ig_data in csv_data["implementation_groups"].items():
            for control_id, control_data in ig_data["controls"].items():
                flattened["control_records"].append({
                    "implementation_group": ig_name,
                    "control_id": control_id,
                    "control_title": control_data.get("title", ""),
                    "total_resources": control_data["total_resources"],
                    "compliant_resources": control_data["compliant_resources"],
                    "compliance_percentage": control_data["compliance_percentage"],
                    "non_compliant_count": len(control_data.get("non_compliant_findings", [])),
                    "config_rules_evaluated": "; ".join(control_data["config_rules_evaluated"]),
                    "findings_count": control_data["findings_count"]
                })
        
        # Flatten detailed findings
        flattened["findings_records"] = []
        for ig_name, ig_findings in csv_data["detailed_findings"].items():
            for control_id, control_findings in ig_findings.items():
                for finding in control_findings:
                    flattened["findings_records"].append({
                        "implementation_group": ig_name,
                        "control_id": control_id,
                        "resource_id": finding["resource_id"],
                        "resource_type": finding["resource_type"],
                        "compliance_status": finding["compliance_status"],
                        "evaluation_reason": finding["evaluation_reason"],
                        "config_rule_name": finding["config_rule_name"],
                        "region": finding["region"],
                        "timestamp": finding["timestamp"],
                        "remediation_guidance": finding.get("remediation_guidance", "")
                    })
        
        # Flatten remediation guidance
        flattened["remediation_records"] = []
        for remediation in csv_data["remediation_priorities"]:
            flattened["remediation_records"].append({
                "config_rule_name": remediation["config_rule_name"],
                "control_id": remediation["control_id"],
                "priority": remediation["priority"],
                "estimated_effort": remediation["estimated_effort"],
                "remediation_steps": " | ".join(remediation["remediation_steps"]),
                "aws_documentation_link": remediation["aws_documentation_link"]
            })
        
        return flattened
    
    def _generate_multiple_csv_files(self, csv_data: Dict[str, Any]) -> Dict[str, str]:
        """Generate multiple CSV files for different data types.
        
        Args:
            csv_data: Enhanced CSV report data
            
        Returns:
            Dictionary containing CSV content for different file types
        """
        csv_files = {}
        
        # Generate summary CSV
        csv_files["summary"] = self._generate_summary_csv(csv_data)
        
        # Generate detailed findings CSV
        csv_files["findings"] = self._generate_findings_csv(csv_data)
        
        # Generate remediation CSV
        csv_files["remediation"] = self._generate_remediation_csv(csv_data)
        
        # Generate controls CSV
        csv_files["controls"] = self._generate_controls_csv(csv_data)
        
        # Generate implementation groups CSV
        csv_files["implementation_groups"] = self._generate_ig_csv(csv_data)
        
        logger.info(f"Generated {len(csv_files)} CSV files")
        return csv_files
    
    def _generate_summary_csv(self, csv_data: Dict[str, Any]) -> str:
        """Generate summary CSV content.
        
        Args:
            csv_data: Enhanced CSV report data
            
        Returns:
            Summary CSV content as string
        """
        output = StringIO()
        writer = csv.writer(output, dialect=self.csv_dialect)
        
        # Write header
        writer.writerow([
            "Metric",
            "Value",
            "Unit",
            "Category"
        ])
        
        # Write summary records
        for record in csv_data["flattened_data"]["summary_records"]:
            writer.writerow([
                record["metric"],
                record["value"],
                record["unit"],
                record["category"]
            ])
        
        # Add metadata section
        writer.writerow([])  # Empty row
        writer.writerow(["Metadata", "", "", ""])
        writer.writerow(["Account ID", csv_data["metadata"].get("account_id", ""), "text", "metadata"])
        writer.writerow(["Assessment Date", csv_data["metadata"].get("assessment_timestamp", ""), "datetime", "metadata"])
        writer.writerow(["Report Generated", csv_data["metadata"].get("report_generated_at", ""), "datetime", "metadata"])
        writer.writerow(["Regions Assessed", "; ".join(csv_data["metadata"].get("regions_assessed", [])), "text", "metadata"])
        writer.writerow(["Assessment Duration", csv_data["metadata"].get("assessment_duration", ""), "text", "metadata"])
        
        content = output.getvalue()
        output.close()
        return content
    
    def _generate_findings_csv(self, csv_data: Dict[str, Any]) -> str:
        """Generate detailed findings CSV content.
        
        Args:
            csv_data: Enhanced CSV report data
            
        Returns:
            Findings CSV content as string
        """
        output = StringIO()
        writer = csv.writer(output, dialect=self.csv_dialect)
        
        # Write header
        writer.writerow([
            "Implementation Group",
            "Control ID",
            "Resource ID",
            "Resource Type",
            "Compliance Status",
            "Evaluation Reason",
            "Config Rule Name",
            "Region",
            "Timestamp",
            "Remediation Guidance"
        ])
        
        # Write findings records
        for record in csv_data["flattened_data"]["findings_records"]:
            writer.writerow([
                record["implementation_group"],
                record["control_id"],
                record["resource_id"],
                record["resource_type"],
                record["compliance_status"],
                record["evaluation_reason"],
                record["config_rule_name"],
                record["region"],
                record["timestamp"],
                record["remediation_guidance"]
            ])
        
        content = output.getvalue()
        output.close()
        return content
    
    def _generate_remediation_csv(self, csv_data: Dict[str, Any]) -> str:
        """Generate remediation guidance CSV content.
        
        Args:
            csv_data: Enhanced CSV report data
            
        Returns:
            Remediation CSV content as string
        """
        output = StringIO()
        writer = csv.writer(output, dialect=self.csv_dialect)
        
        # Write header
        writer.writerow([
            "Config Rule Name",
            "Control ID",
            "Priority",
            "Estimated Effort",
            "Remediation Steps",
            "AWS Documentation Link"
        ])
        
        # Write remediation records
        for record in csv_data["flattened_data"]["remediation_records"]:
            writer.writerow([
                record["config_rule_name"],
                record["control_id"],
                record["priority"],
                record["estimated_effort"],
                record["remediation_steps"],
                record["aws_documentation_link"]
            ])
        
        content = output.getvalue()
        output.close()
        return content
    
    def _generate_controls_csv(self, csv_data: Dict[str, Any]) -> str:
        """Generate controls CSV content.
        
        Args:
            csv_data: Enhanced CSV report data
            
        Returns:
            Controls CSV content as string
        """
        output = StringIO()
        writer = csv.writer(output, dialect=self.csv_dialect)
        
        # Write header
        writer.writerow([
            "Implementation Group",
            "Control ID",
            "Control Title",
            "Total Resources",
            "Compliant Resources",
            "Compliance Percentage",
            "Non-Compliant Count",
            "Config Rules Evaluated",
            "Total Findings"
        ])
        
        # Write control records
        for record in csv_data["flattened_data"]["control_records"]:
            writer.writerow([
                record["implementation_group"],
                record["control_id"],
                record["control_title"],
                record["total_resources"],
                record["compliant_resources"],
                record["compliance_percentage"],
                record["non_compliant_count"],
                record["config_rules_evaluated"],
                record["findings_count"]
            ])
        
        content = output.getvalue()
        output.close()
        return content
    
    def _generate_ig_csv(self, csv_data: Dict[str, Any]) -> str:
        """Generate Implementation Groups CSV content.
        
        Args:
            csv_data: Enhanced CSV report data
            
        Returns:
            Implementation Groups CSV content as string
        """
        output = StringIO()
        writer = csv.writer(output, dialect=self.csv_dialect)
        
        # Write header
        writer.writerow([
            "Implementation Group",
            "Total Controls",
            "Compliant Controls",
            "Compliance Percentage",
            "Controls at Risk"
        ])
        
        # Write IG records
        for record in csv_data["flattened_data"]["ig_records"]:
            writer.writerow([
                record["implementation_group"],
                record["total_controls"],
                record["compliant_controls"],
                record["compliance_percentage"],
                record["controls_at_risk"]
            ])
        
        content = output.getvalue()
        output.close()
        return content
    
    def _generate_single_csv_file(self, csv_data: Dict[str, Any]) -> str:
        """Generate single comprehensive CSV file.
        
        Args:
            csv_data: Enhanced CSV report data
            
        Returns:
            Comprehensive CSV content as string
        """
        output = StringIO()
        writer = csv.writer(output, dialect=self.csv_dialect)
        
        # Write executive summary section
        writer.writerow(["EXECUTIVE SUMMARY"])
        writer.writerow([
            "Metric",
            "Value",
            "Unit",
            "Category"
        ])
        
        for record in csv_data["flattened_data"]["summary_records"]:
            writer.writerow([
                record["metric"],
                record["value"],
                record["unit"],
                record["category"]
            ])
        
        # Add separator
        writer.writerow([])
        writer.writerow([])
        
        # Write metadata section
        writer.writerow(["METADATA"])
        writer.writerow([
            "Field",
            "Value"
        ])
        
        metadata = csv_data["metadata"]
        writer.writerow(["Account ID", metadata.get("account_id", "")])
        writer.writerow(["Assessment Date", metadata.get("assessment_timestamp", "")])
        writer.writerow(["Report Generated", metadata.get("report_generated_at", "")])
        writer.writerow(["Regions Assessed", "; ".join(metadata.get("regions_assessed", []))])
        writer.writerow(["Assessment Duration", metadata.get("assessment_duration", "")])
        writer.writerow(["Total Resources Evaluated", metadata.get("total_resources_evaluated", 0)])
        
        # Add separator
        writer.writerow([])
        writer.writerow([])
        
        # Write Implementation Groups section
        writer.writerow(["IMPLEMENTATION GROUPS"])
        writer.writerow([
            "Implementation Group",
            "Total Controls",
            "Compliant Controls",
            "Compliance Percentage",
            "Controls at Risk"
        ])
        
        for record in csv_data["flattened_data"]["ig_records"]:
            writer.writerow([
                record["implementation_group"],
                record["total_controls"],
                record["compliant_controls"],
                record["compliance_percentage"],
                record["controls_at_risk"]
            ])
        
        # Add separator
        writer.writerow([])
        writer.writerow([])
        
        # Write Controls section
        writer.writerow(["CONTROLS"])
        writer.writerow([
            "Implementation Group",
            "Control ID",
            "Control Title",
            "Total Resources",
            "Compliant Resources",
            "Compliance Percentage",
            "Non-Compliant Count",
            "Config Rules Evaluated",
            "Total Findings"
        ])
        
        for record in csv_data["flattened_data"]["control_records"]:
            writer.writerow([
                record["implementation_group"],
                record["control_id"],
                record["control_title"],
                record["total_resources"],
                record["compliant_resources"],
                record["compliance_percentage"],
                record["non_compliant_count"],
                record["config_rules_evaluated"],
                record["findings_count"]
            ])
        
        # Add separator
        writer.writerow([])
        writer.writerow([])
        
        # Write Detailed Findings section (limited to first 1000 for single file)
        writer.writerow(["DETAILED FINDINGS (Limited to 1000 records)"])
        writer.writerow([
            "Implementation Group",
            "Control ID",
            "Resource ID",
            "Resource Type",
            "Compliance Status",
            "Evaluation Reason",
            "Config Rule Name",
            "Region",
            "Timestamp",
            "Remediation Guidance"
        ])
        
        findings_records = csv_data["flattened_data"]["findings_records"][:1000]  # Limit for single file
        for record in findings_records:
            writer.writerow([
                record["implementation_group"],
                record["control_id"],
                record["resource_id"],
                record["resource_type"],
                record["compliance_status"],
                record["evaluation_reason"],
                record["config_rule_name"],
                record["region"],
                record["timestamp"],
                record["remediation_guidance"]
            ])
        
        # Add separator
        writer.writerow([])
        writer.writerow([])
        
        # Write Remediation section
        writer.writerow(["REMEDIATION GUIDANCE"])
        writer.writerow([
            "Config Rule Name",
            "Control ID",
            "Priority",
            "Estimated Effort",
            "Remediation Steps",
            "AWS Documentation Link"
        ])
        
        for record in csv_data["flattened_data"]["remediation_records"]:
            writer.writerow([
                record["config_rule_name"],
                record["control_id"],
                record["priority"],
                record["estimated_effort"],
                record["remediation_steps"],
                record["aws_documentation_link"]
            ])
        
        content = output.getvalue()
        output.close()
        return content
    
    def _save_multiple_csv_files(self, csv_files: Dict[str, str], base_output_path: str) -> bool:
        """Save multiple CSV files to disk.
        
        Args:
            csv_files: Dictionary of CSV content by file type
            base_output_path: Base path for saving files
            
        Returns:
            True if all files saved successfully, False otherwise
        """
        try:
            base_path = Path(base_output_path)
            base_dir = base_path.parent
            base_name = base_path.stem
            
            # Create output directory if it doesn't exist
            base_dir.mkdir(parents=True, exist_ok=True)
            
            saved_files = []
            for file_type, content in csv_files.items():
                file_path = base_dir / f"{base_name}_{file_type}.csv"
                
                with open(file_path, 'w', encoding='utf-8', newline='') as f:
                    f.write(content)
                
                saved_files.append(str(file_path))
                logger.info(f"Saved {file_type} CSV to: {file_path}")
            
            logger.info(f"Successfully saved {len(saved_files)} CSV files")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save multiple CSV files: {e}")
            return False
    
    def set_csv_options(self, generate_multiple_files: bool = True, 
                       excel_compatible: bool = True,
                       custom_dialect: Optional[str] = None) -> None:
        """Configure CSV generation options.
        
        Args:
            generate_multiple_files: Whether to generate separate CSV files
            excel_compatible: Whether to use Excel-compatible formatting
            custom_dialect: Custom CSV dialect to use
        """
        self.generate_multiple_files = generate_multiple_files
        self.excel_compatible = excel_compatible
        
        if custom_dialect:
            self.csv_dialect = custom_dialect
        else:
            self.csv_dialect = 'excel' if excel_compatible else 'unix'
        
        logger.debug(f"Updated CSV options: multiple_files={generate_multiple_files}, "
                    f"excel_compatible={excel_compatible}, dialect={self.csv_dialect}")
    
    def validate_csv_output(self, csv_content: str) -> bool:
        """Validate that the generated CSV is well-formed.
        
        Args:
            csv_content: CSV content string to validate
            
        Returns:
            True if CSV is valid, False otherwise
        """
        try:
            # Try to parse the CSV content
            reader = csv.reader(StringIO(csv_content), dialect=self.csv_dialect)
            rows = list(reader)
            
            if not rows:
                logger.error("CSV validation failed: no rows found")
                return False
            
            # Check that all rows have consistent column counts (allowing for empty rows)
            non_empty_rows = [row for row in rows if any(cell.strip() for cell in row)]
            if not non_empty_rows:
                logger.error("CSV validation failed: no non-empty rows found")
                return False
            
            # Get expected column count from first non-empty row
            expected_cols = len(non_empty_rows[0])
            
            # Allow some flexibility for section headers and separators
            inconsistent_rows = 0
            for i, row in enumerate(non_empty_rows):
                if len(row) != expected_cols:
                    inconsistent_rows += 1
            
            # Allow up to 20% of rows to have different column counts (for headers/separators)
            if inconsistent_rows > len(non_empty_rows) * 0.2:
                logger.warning(f"CSV validation warning: {inconsistent_rows} rows have inconsistent column counts")
            
            logger.debug("CSV validation passed")
            return True
            
        except csv.Error as e:
            logger.error(f"CSV validation failed: {e}")
            return False
        except Exception as e:
            logger.error(f"CSV validation failed with unexpected error: {e}")
            return False
    
    def extract_summary_data(self, csv_content: str) -> Optional[Dict[str, Any]]:
        """Extract summary data from generated CSV report.
        
        Args:
            csv_content: CSV report content
            
        Returns:
            Dictionary containing summary data or None if extraction fails
        """
        try:
            reader = csv.reader(StringIO(csv_content), dialect=self.csv_dialect)
            rows = list(reader)
            
            summary_data = {}
            
            # Look for summary data in the CSV
            for i, row in enumerate(rows):
                if len(row) >= 2:
                    metric = row[0].strip()
                    value = row[1].strip()
                    
                    if metric == "Overall Compliance":
                        try:
                            summary_data["overall_compliance"] = float(value)
                        except ValueError:
                            pass
                    elif metric == "Account ID":
                        summary_data["account_id"] = value
                    elif metric == "Total Resources":
                        try:
                            summary_data["total_resources"] = int(value)
                        except ValueError:
                            pass
                    elif metric == "Assessment Date":
                        summary_data["assessment_date"] = value
            
            return summary_data if summary_data else None
            
        except Exception as e:
            logger.error(f"Failed to extract summary data from CSV: {e}")
            return None
    
    def get_file_extensions(self) -> List[str]:
        """Get list of file extensions used by this reporter.
        
        Returns:
            List of file extensions
        """
        if self.generate_multiple_files:
            return [
                "_summary.csv",
                "_findings.csv", 
                "_remediation.csv",
                "_controls.csv",
                "_implementation_groups.csv"
            ]
        else:
            return [".csv"]
    
    def estimate_file_sizes(self, assessment_result: AssessmentResult) -> Dict[str, int]:
        """Estimate file sizes for the generated CSV files.
        
        Args:
            assessment_result: Assessment result to analyze
            
        Returns:
            Dictionary mapping file types to estimated sizes in bytes
        """
        # Rough estimates based on typical data sizes
        total_findings = sum(
            sum(len(control.findings) for control in ig.control_scores.values())
            for ig in assessment_result.ig_scores.values()
        )
        
        total_controls = sum(
            len(ig.control_scores) for ig in assessment_result.ig_scores.values()
        )
        
        estimates = {
            "summary": 2000,  # Small summary file
            "implementation_groups": 500,  # Very small IG summary
            "controls": total_controls * 150,  # ~150 bytes per control
            "findings": total_findings * 200,  # ~200 bytes per finding
            "remediation": len(assessment_result.ig_scores) * 300  # ~300 bytes per remediation item
        }
        
        if not self.generate_multiple_files:
            estimates = {"single_file": sum(estimates.values())}
        
        return estimates