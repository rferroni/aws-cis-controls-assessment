"""HTML Reporter for CIS Controls compliance assessment reports."""

import logging
from typing import Dict, Any, List, Optional
from pathlib import Path
import base64
from datetime import datetime

from aws_cis_assessment.reporters.base_reporter import ReportGenerator
from aws_cis_assessment.core.models import (
    AssessmentResult, ComplianceSummary, RemediationGuidance,
    IGScore, ControlScore, ComplianceResult
)

logger = logging.getLogger(__name__)


class HTMLReporter(ReportGenerator):
    """HTML format reporter for compliance assessment results.
    
    Generates interactive web-based reports with executive dashboard,
    compliance summaries, charts, detailed drill-down capabilities,
    and responsive design for mobile and desktop viewing.
    
    Features:
        - Executive dashboard with key compliance metrics
        - Implementation Groups section showing unique controls per IG
        - Control display names combining control ID and AWS Config rule name
        - IG membership badges indicating which IGs include each control
        - Consolidated detailed findings (deduplicated across IGs)
        - Interactive charts and collapsible sections
        - Resource details with filtering and export capabilities
        - Responsive design for mobile and desktop
        - Print-friendly layout
    
    Display Format Examples:
        Control cards show formatted names like:
        - "1.5: root-account-hardware-mfa-enabled"
        - "2.1: IAM Password Policy (iam-password-policy)"
        
        IG badges indicate membership:
        - Blue badge (IG1) for foundational controls
        - Green badge (IG2) for enhanced security controls
        - Purple badge (IG3) for advanced security controls
    
    CSS Classes for Custom Styling:
        - .ig-badge-1: Blue badge for IG1 controls
        - .ig-badge-2: Green badge for IG2 controls
        - .ig-badge-3: Purple badge for IG3 controls
        - .control-display-name: Formatted control name display
        - .control-display-name.truncated: Truncated names with tooltip
        - .ig-membership-badges: Container for IG membership badges
        - .ig-membership-badge: Individual IG badge element
        - .ig-explanation: Informational box explaining IG cumulative nature
        - .ig-scope: Scope description for each IG section
    
    Backward Compatibility:
        - Works with existing AssessmentResult data structures
        - Gracefully falls back to control ID only if config_rule_name is missing
        - Preserves all existing sections and functionality
        - Maintains existing CSS classes for compatibility
    """
    
    def __init__(self, template_dir: Optional[str] = None, include_charts: bool = True):
        """Initialize HTML reporter.
        
        Args:
            template_dir: Optional path to custom report templates
            include_charts: Whether to include interactive charts (default: True)
        """
        super().__init__(template_dir)
        self.include_charts = include_charts
        self._control_titles_cache = {}  # Cache for control titles from YAML
        logger.info(f"Initialized HTMLReporter with charts={include_charts}")
    
    def generate_report(self, assessment_result: AssessmentResult, 
                       compliance_summary: ComplianceSummary,
                       output_path: Optional[str] = None) -> str:
        """Generate HTML format compliance assessment report.
        
        Args:
            assessment_result: Complete assessment result data
            compliance_summary: Executive summary of compliance status
            output_path: Optional path to save the HTML report
            
        Returns:
            HTML formatted report content as string
        """
        # Handle None inputs
        if assessment_result is None or compliance_summary is None:
            logger.error("Assessment result or compliance summary is None")
            return ""
            
        logger.info(f"Generating HTML report for account {assessment_result.account_id}")
        
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
        
        # Enhance HTML-specific data structure
        html_report_data = self._enhance_html_structure(report_data)
        
        try:
            # Generate HTML content
            html_content = self._generate_html_content(html_report_data)
            
            logger.info(f"Generated HTML report with {len(html_content)} characters")
            
            # Save to file if path provided
            if output_path:
                if self._save_report_to_file(html_content, output_path):
                    logger.info(f"HTML report saved to {output_path}")
                else:
                    logger.error(f"Failed to save HTML report to {output_path}")
            
            return html_content
            
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {e}")
            return ""
    
    def get_supported_formats(self) -> List[str]:
        """Get list of supported output formats.
        
        Returns:
            List containing 'html' format
        """
        return ['html']
    
    def _enhance_html_structure(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance report data structure for HTML-specific requirements.
        
        Args:
            report_data: Base report data from parent class
            
        Returns:
            Enhanced data structure optimized for HTML output
        """
        # Create enhanced HTML structure
        html_data = {
            "report_format": "html",
            "report_version": "1.0",
            "include_charts": self.include_charts,
            **report_data
        }
        
        # Add HTML-specific metadata
        html_data["metadata"]["report_format"] = "html"
        html_data["metadata"]["interactive"] = True
        html_data["metadata"]["responsive_design"] = True
        
        # Enhance executive summary with visual indicators
        exec_summary = html_data["executive_summary"]
        exec_summary["compliance_grade"] = self._calculate_compliance_grade(
            exec_summary["overall_compliance_percentage"]
        )
        exec_summary["risk_level"] = self._calculate_risk_level(
            exec_summary["overall_compliance_percentage"]
        )
        exec_summary["status_color"] = self._get_status_color(
            exec_summary["overall_compliance_percentage"]
        )
        
        # Add chart data for Implementation Groups
        html_data["chart_data"] = self._prepare_chart_data(html_data)
        
        # Add coverage metrics if available
        if "coverage_metrics" in report_data.get("executive_summary", {}):
            html_data["coverage_metrics"] = self._prepare_coverage_metrics(
                report_data["executive_summary"]["coverage_metrics"]
            )
        
        # Enhance Implementation Group data with visual elements
        for ig_name, ig_data in html_data["implementation_groups"].items():
            ig_data["status_color"] = self._get_status_color(ig_data["compliance_percentage"])
            ig_data["progress_width"] = ig_data["compliance_percentage"]
            
            # Enhance control data with visual indicators
            for control_id, control_data in ig_data["controls"].items():
                control_data["status_color"] = self._get_status_color(
                    control_data["compliance_percentage"]
                )
                control_data["progress_width"] = control_data["compliance_percentage"]
                control_data["severity_badge"] = self._get_severity_badge(control_data)
                
                # Enrich control metadata with display name, IG badges, etc.
                enriched_control = self._enrich_control_metadata(
                    control_data, 
                    control_id, 
                    ig_name, 
                    html_data["implementation_groups"]
                )
                # Update control_data with enriched metadata
                ig_data["controls"][control_id] = enriched_control
                
                # Process findings for display
                enriched_control["display_findings"] = self._prepare_findings_for_display(
                    enriched_control.get("non_compliant_findings", [])
                )
        
        # Enhance remediation priorities with visual elements
        for remediation in html_data["remediation_priorities"]:
            remediation["priority_badge"] = self._get_priority_badge(remediation["priority"])
            remediation["effort_badge"] = self._get_effort_badge(remediation["estimated_effort"])
        
        # Add navigation structure
        html_data["navigation"] = self._build_navigation_structure(html_data)
        
        return html_data
    
    def _generate_html_content(self, html_data: Dict[str, Any]) -> str:
        """Generate complete HTML content from data.
        
        Args:
            html_data: Enhanced HTML report data
            
        Returns:
            Complete HTML document as string
        """
        # Build HTML document sections
        html_head = self._generate_html_head(html_data)
        html_body = self._generate_html_body(html_data)
        
        # Combine into complete document
        html_content = f"""<!DOCTYPE html>
<html lang="en">
{html_head}
{html_body}
</html>"""
        
        return html_content
    
    def _generate_html_head(self, html_data: Dict[str, Any]) -> str:
        """Generate HTML head section with styles and scripts.
        
        Args:
            html_data: Enhanced HTML report data
            
        Returns:
            HTML head section as string
        """
        metadata = html_data["metadata"]
        exec_summary = html_data["executive_summary"]
        
        # Include Chart.js if charts are enabled
        chart_script = ""
        if self.include_charts:
            chart_script = '<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>'
        
        head_content = f"""<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CIS Controls Compliance Report - {metadata.get('account_id', 'Unknown')}</title>
    <meta name="description" content="AWS CIS Controls compliance assessment report">
    <meta name="author" content="AWS CIS Assessment Tool">
    <meta name="report-date" content="{metadata.get('report_generated_at', '')}">
    
    {chart_script}
    
    <style>
        {self._get_css_styles()}
    </style>
    
    <script>
        {self._get_javascript_code(html_data)}
    </script>
</head>"""
        
        return head_content
    
    def _generate_html_body(self, html_data: Dict[str, Any]) -> str:
        """Generate HTML body section with content.
        
        Modified in v1.1.2 to remove Detailed Findings and Remediation sections.
        
        Args:
            html_data: Enhanced HTML report data
            
        Returns:
            HTML body section as string
        """
        # Generate main content sections
        header = self._generate_header(html_data)
        navigation = self._generate_navigation(html_data)
        executive_dashboard = self._generate_executive_dashboard(html_data)
        controls_overview = self._generate_controls_overview_section(html_data)
        resource_details = self._generate_resource_details_section(html_data)
        footer = self._generate_footer(html_data)
        
        body_content = f"""<body>
    <div class="container">
        {header}
        {navigation}
        {executive_dashboard}
        {controls_overview}
        {resource_details}
        {footer}
    </div>
    
    <script>
        // Initialize interactive features after DOM load
        document.addEventListener('DOMContentLoaded', function() {{
            initializeCharts();
            initializeInteractivity();
        }});
    </script>
</body>"""
        
        return body_content
    
    def _get_css_styles(self) -> str:
        """Get CSS styles for the HTML report.
        
        Returns:
            CSS styles as string
        """
        return """
        /* Reset and base styles */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: white;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
            min-height: 100vh;
        }
        
        /* Header styles */
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: 300;
        }
        
        .header .subtitle {
            font-size: 1.2em;
            opacity: 0.9;
        }
        
        /* Navigation styles */
        .navigation {
            background-color: #2c3e50;
            border-radius: 8px;
            margin-bottom: 30px;
            overflow: hidden;
        }
        
        .nav-list {
            display: flex;
            list-style: none;
            flex-wrap: wrap;
        }
        
        .nav-item {
            flex: 1;
            min-width: 150px;
        }
        
        .nav-link {
            display: block;
            padding: 15px 20px;
            color: white;
            text-decoration: none;
            text-align: center;
            transition: background-color 0.3s;
            border-right: 1px solid #34495e;
        }
        
        .nav-link:hover, .nav-link.active {
            background-color: #3498db;
        }
        
        /* Dashboard styles */
        .dashboard {
            margin-bottom: 40px;
        }
        
        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .metric-card {
            background: white;
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            border-left: 4px solid #3498db;
            transition: transform 0.2s;
        }
        
        .metric-card:hover {
            transform: translateY(-2px);
        }
        
        .metric-card.excellent { border-left-color: #27ae60; }
        .metric-card.good { border-left-color: #2ecc71; }
        .metric-card.fair { border-left-color: #f39c12; }
        .metric-card.poor { border-left-color: #e67e22; }
        .metric-card.critical { border-left-color: #e74c3c; }
        
        .metric-value {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .metric-label {
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .metric-trend {
            font-size: 0.8em;
            margin-top: 10px;
            padding: 5px 10px;
            border-radius: 15px;
            display: inline-block;
        }
        
        .trend-up { background-color: #d5f4e6; color: #27ae60; }
        .trend-down { background-color: #ffeaa7; color: #e17055; }
        .trend-stable { background-color: #e3f2fd; color: #2196f3; }
        
        /* Progress bars */
        .progress-container {
            background-color: #ecf0f1;
            border-radius: 10px;
            height: 20px;
            margin: 10px 0;
            overflow: hidden;
        }
        
        .progress-bar {
            height: 100%;
            border-radius: 10px;
            transition: width 0.8s ease-in-out;
            position: relative;
        }
        
        .progress-bar.excellent { background-color: #27ae60; }
        .progress-bar.good { background-color: #2ecc71; }
        .progress-bar.fair { background-color: #f39c12; }
        .progress-bar.poor { background-color: #e67e22; }
        .progress-bar.critical { background-color: #e74c3c; }
        
        .progress-text {
            position: absolute;
            right: 10px;
            top: 50%;
            transform: translateY(-50%);
            color: white;
            font-weight: bold;
            font-size: 0.8em;
        }
        
        /* Coverage Metrics Section */
        .coverage-metrics-section {
            margin: 30px 0;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 10px;
        }
        
        .coverage-intro {
            color: #666;
            margin-bottom: 20px;
            font-size: 0.95em;
        }
        
        .coverage-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 20px;
        }
        
        .coverage-card {
            background: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            border-left: 5px solid #3498db;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .coverage-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        
        .coverage-card.excellent { border-left-color: #27ae60; }
        .coverage-card.good { border-left-color: #2ecc71; }
        .coverage-card.fair { border-left-color: #f39c12; }
        .coverage-card.poor { border-left-color: #e67e22; }
        .coverage-card.critical { border-left-color: #e74c3c; }
        
        .coverage-card h4 {
            margin: 0 0 15px 0;
            color: #2c3e50;
            font-size: 1.2em;
        }
        
        .coverage-value {
            font-size: 2.5em;
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 15px;
        }
        
        .coverage-details {
            color: #666;
            font-size: 0.9em;
        }
        
        .coverage-details p {
            margin: 8px 0;
        }
        
        .coverage-description {
            margin-top: 12px;
            padding-top: 12px;
            border-top: 1px solid #e0e0e0;
            font-style: italic;
            color: #555;
        }
        
        /* Implementation Groups */
        .ig-section {
            margin-bottom: 40px;
        }
        
        .ig-header {
            background: linear-gradient(90deg, #74b9ff 0%, #0984e3 100%);
            color: white;
            padding: 20px;
            border-radius: 10px 10px 0 0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .ig-title {
            font-size: 1.5em;
            font-weight: 600;
        }
        
        .ig-score {
            font-size: 2em;
            font-weight: bold;
        }
        
        .ig-content {
            background: white;
            border: 1px solid #ddd;
            border-top: none;
            border-radius: 0 0 10px 10px;
            padding: 20px;
        }
        
        .controls-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 20px;
        }
        
        .control-card {
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            padding: 20px;
            background: #fafafa;
            transition: box-shadow 0.2s;
        }
        
        .control-card:hover {
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        
        .control-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .control-id {
            font-weight: bold;
            color: #2c3e50;
        }
        
        .control-title {
            font-size: 0.9em;
            color: #666;
            margin-bottom: 10px;
        }
        
        /* Control display name styles */
        .control-display-name {
            font-weight: 600;
            color: #2c3e50;
            margin-bottom: 5px;
            font-size: 0.95em;
        }
        
        .control-display-name.truncated {
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            cursor: help;
        }
        
        /* IG membership badges */
        .ig-membership-badges {
            display: flex;
            gap: 5px;
            margin-top: 5px;
            margin-bottom: 10px;
        }
        
        .ig-membership-badge {
            font-size: 0.7em;
            padding: 2px 6px;
            border-radius: 10px;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .ig-badge-1 { 
            background-color: #3498db; 
            color: white; 
        } /* Blue for IG1 */
        
        .ig-badge-2 { 
            background-color: #27ae60; 
            color: white; 
        } /* Green for IG2 */
        
        .ig-badge-3 { 
            background-color: #9b59b6; 
            color: white; 
        } /* Purple for IG3 */
        
        .ig-badge-default {
            background-color: #95a5a6;
            color: white;
        }
        
        /* Badges */
        .badge {
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 0.75em;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .badge.high { background-color: #e74c3c; color: white; }
        .badge.medium { background-color: #f39c12; color: white; }
        .badge.low { background-color: #27ae60; color: white; }
        
        .badge.effort-minimal { background-color: #2ecc71; color: white; }
        .badge.effort-moderate { background-color: #f39c12; color: white; }
        .badge.effort-significant { background-color: #e67e22; color: white; }
        .badge.effort-extensive { background-color: #e74c3c; color: white; }
        
        .badge.compliant { background-color: #27ae60; color: white; }
        .badge.non_compliant { background-color: #e74c3c; color: white; }
        
        /* Inheritance indicators */
        .inheritance-note {
            color: #666;
            font-style: italic;
            display: block;
            margin-top: 5px;
        }
        
        .ig-explanation {
            background-color: #e8f4fd;
            border-left: 4px solid #3498db;
            padding: 15px;
            margin-bottom: 30px;
            border-radius: 5px;
        }
        
        .ig-scope {
            color: #666;
            font-size: 0.9em;
            margin-top: 5px;
        }
        
        /* Resource Details Section */
        .resource-details {
            margin-bottom: 40px;
        }
        
        .resource-summary {
            margin-bottom: 30px;
        }
        
        .resource-stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .resource-stat-card {
            background: white;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-left: 4px solid #3498db;
        }
        
        .resource-stat-card.compliant {
            border-left-color: #27ae60;
        }
        
        .resource-stat-card.non-compliant {
            border-left-color: #e74c3c;
        }
        
        .stat-value {
            font-size: 2em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .stat-label {
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .resource-type-breakdown {
            margin-bottom: 30px;
        }
        
        .resource-type-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }
        
        .resource-type-stat {
            background: white;
            border-radius: 8px;
            padding: 15px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .resource-type-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        
        .resource-type-name {
            font-weight: 600;
            color: #2c3e50;
        }
        
        .resource-type-count {
            font-size: 0.9em;
            color: #666;
        }
        
        .resource-table-container {
            margin-bottom: 20px;
        }
        
        .pagination-controls {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 10px 0;
            flex-wrap: wrap;
        }
        .pagination-controls button {
            padding: 6px 14px;
            border: 1px solid #ddd;
            border-radius: 4px;
            background: white;
            cursor: pointer;
            font-size: 13px;
        }
        .pagination-controls button:hover:not(:disabled) {
            background: #f0f0f0;
        }
        .pagination-controls button:disabled {
            opacity: 0.4;
            cursor: default;
        }
        .pagination-controls .page-size-label {
            margin-left: 10px;
            font-size: 13px;
            color: #666;
        }
        .pagination-controls .resource-count {
            margin-left: auto;
            font-size: 13px;
            color: #888;
        }
        .pagination-bottom {
            border-top: 1px solid #eee;
            margin-top: 5px;
        }
        
        .resource-filters {
            display: flex;
            gap: 15px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        
        .search-input, .filter-select {
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
        }
        
        .search-input {
            flex: 1;
            min-width: 200px;
        }
        
        .filter-select {
            min-width: 150px;
        }
        
        .resource-table {
            font-size: 0.9em;
        }
        
        .resource-table th {
            cursor: pointer;
            user-select: none;
        }
        
        .resource-table th:hover {
            background-color: #2c3e50;
        }
        
        /* Resource ID column width constraint - increased to 220px in v1.1.2 */
        .resource-table td:first-child {
            max-width: 220px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        
        .resource-table td:first-child:hover {
            overflow: visible;
            white-space: normal;
            word-wrap: break-word;
        }
        
        /* Resource Type column width constraint - added in v1.1.2 (reduced by 20%) */
        .resource-table td:nth-child(2) {
            max-width: 150px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        
        .resource-table td:nth-child(2):hover {
            overflow: visible;
            white-space: normal;
            word-wrap: break-word;
        }
        
        /* Visual frames around each resource row */
        .resource-row {
            border: 1px solid #e0e0e0;
            border-radius: 4px;
        }
        
        .resource-row:hover {
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        .resource-row.compliant {
            background-color: #f8fff8;
        }
        
        .resource-row.non_compliant {
            background-color: #fff8f8;
        }
        
        .evaluation-reason {
            max-width: 300px;
            word-wrap: break-word;
            font-size: 0.85em;
        }
        
        .resource-export {
            text-align: center;
            margin-top: 20px;
        }
        
        .export-btn {
            background-color: #3498db;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            margin: 0 10px;
            font-size: 14px;
            transition: background-color 0.3s;
        }
        
        .export-btn:hover {
            background-color: #2980b9;
        }
        
        /* Tables */
        .findings-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .findings-table th {
            background-color: #34495e;
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }
        
        .findings-table td {
            padding: 12px 15px;
            border-bottom: 1px solid #eee;
        }
        
        .findings-table tr:hover {
            background-color: #f8f9fa;
        }
        
        /* Collapsible sections */
        .collapsible {
            cursor: pointer;
            padding: 15px;
            background-color: #f1f2f6;
            border: none;
            text-align: left;
            outline: none;
            font-size: 1em;
            width: 100%;
            border-radius: 5px;
            margin-bottom: 5px;
            transition: background-color 0.3s;
        }
        
        .collapsible:hover {
            background-color: #ddd;
        }
        
        .collapsible.active {
            background-color: #3498db;
            color: white;
        }
        
        .collapsible-content {
            padding: 0 15px;
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease-out;
            background-color: white;
            border-radius: 0 0 5px 5px;
        }
        
        .collapsible-content.active {
            max-height: 1000px;
            padding: 15px;
        }
        
        /* Charts */
        .chart-container {
            position: relative;
            height: 400px;
            margin: 20px 0;
            background: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        /* Footer */
        .footer {
            margin-top: 50px;
            padding: 30px;
            background-color: #2c3e50;
            color: white;
            border-radius: 10px;
            text-align: center;
        }
        
        .footer-content {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .footer-section h4 {
            margin-bottom: 10px;
            color: #3498db;
        }
        
        /* Responsive design */
        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            .header h1 {
                font-size: 2em;
            }
            
            .nav-list {
                flex-direction: column;
            }
            
            .nav-link {
                border-right: none;
                border-bottom: 1px solid #34495e;
            }
            
            .dashboard-grid {
                grid-template-columns: 1fr;
            }
            
            .controls-grid {
                grid-template-columns: 1fr;
            }
            
            .ig-header {
                flex-direction: column;
                text-align: center;
                gap: 10px;
            }
            
            .findings-table {
                font-size: 0.8em;
            }
            
            .findings-table th,
            .findings-table td {
                padding: 8px;
            }
        }
        
        @media (max-width: 480px) {
            .header h1 {
                font-size: 1.5em;
            }
            
            .metric-value {
                font-size: 2em;
            }
            
            .chart-container {
                height: 300px;
                padding: 10px;
            }
        }
        
        /* Score Comparison Styles */
        .score-comparison-section {
            background: white;
            border-radius: 8px;
            padding: 25px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .comparison-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .comparison-card {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            border: 2px solid #e9ecef;
        }
        
        .comparison-card h4 {
            margin: 0 0 15px 0;
            color: #2c3e50;
            font-size: 1.1em;
        }
        
        .comparison-value {
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
        }
        
        .comparison-card.weighted .comparison-value {
            color: #3498db;
        }
        
        .comparison-card.aws-config .comparison-value {
            color: #9b59b6;
        }
        
        .comparison-features {
            list-style: none;
            padding: 0;
            margin: 15px 0 0 0;
        }
        
        .comparison-features li {
            padding: 5px 0;
            color: #666;
            font-size: 0.9em;
        }
        
        .comparison-features li:before {
            content: "✓ ";
            color: #27ae60;
            font-weight: bold;
            margin-right: 5px;
        }
        
        .score-difference {
            background: #fff3cd;
            border: 1px solid #ffc107;
            border-radius: 8px;
            padding: 15px;
            margin-top: 20px;
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .diff-icon {
            font-size: 2em;
            flex-shrink: 0;
        }
        
        .diff-content {
            flex-grow: 1;
        }
        
        .diff-content strong {
            display: block;
            margin-bottom: 5px;
            color: #856404;
        }
        
        .diff-content p {
            margin: 0;
            color: #856404;
            font-size: 0.9em;
        }
        
        .score-difference.neutral {
            background: #d1ecf1;
            border-color: #17a2b8;
        }
        
        .score-difference.neutral .diff-content strong,
        .score-difference.neutral .diff-content p {
            color: #0c5460;
        }
        
        .score-difference.warning {
            background: #fff3cd;
            border-color: #ffc107;
        }
        
        .score-difference.warning .diff-content strong,
        .score-difference.warning .diff-content p {
            color: #856404;
        }
        
        .score-difference.positive {
            background: #d4edda;
            border-color: #28a745;
        }
        
        .score-difference.positive .diff-content strong,
        .score-difference.positive .diff-content p {
            color: #155724;
        }
        
        .methodology-note {
            background: #e7f3ff;
            border-left: 4px solid #3498db;
            padding: 15px;
            margin-top: 20px;
            border-radius: 4px;
        }
        
        .methodology-note h5 {
            margin: 0 0 10px 0;
            color: #2c3e50;
            font-size: 1em;
        }
        
        .methodology-note p {
            margin: 5px 0;
            color: #555;
            font-size: 0.9em;
            line-height: 1.6;
        }
        
        .methodology-note a {
            color: #3498db;
            text-decoration: none;
            font-weight: 500;
        }
        
        .methodology-note a:hover {
            text-decoration: underline;
        }
        
        /* Remediation Section Styles */
        .remediation {
            margin-bottom: 40px;
        }
        
        .remediation-list {
            display: flex;
            flex-direction: column;
            gap: 20px;
        }
        
        .remediation-item {
            background: white;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            transition: box-shadow 0.2s;
        }
        
        .remediation-item:hover {
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        
        .remediation-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 15px;
            padding-bottom: 15px;
            border-bottom: 2px solid #f0f0f0;
        }
        
        .remediation-header h4 {
            margin: 0;
            color: #2c3e50;
            font-size: 1.1em;
            flex: 1;
        }
        
        .remediation-badges {
            display: flex;
            gap: 10px;
            flex-shrink: 0;
            margin-left: 15px;
        }
        
        .remediation-content {
            color: #555;
        }
        
        .remediation-content h5 {
            margin: 15px 0 10px 0;
            color: #2c3e50;
            font-size: 1em;
        }
        
        .remediation-content ol {
            margin: 10px 0;
            padding-left: 25px;
        }
        
        .remediation-content ol li {
            margin: 8px 0;
            line-height: 1.6;
        }
        
        .remediation-content p {
            margin: 15px 0 5px 0;
        }
        
        .remediation-content a {
            color: #3498db;
            text-decoration: none;
            font-weight: 500;
        }
        
        .remediation-content a:hover {
            text-decoration: underline;
        }
        
        @media (max-width: 768px) {
            .remediation-header {
                flex-direction: column;
                gap: 10px;
            }
            
            .remediation-badges {
                margin-left: 0;
            }
            
            .comparison-grid {
                grid-template-columns: 1fr;
            }
            
            .comparison-value {
                font-size: 2em;
            }
        }
        
        /* Controls Overview Section */
        .controls-overview { margin-bottom: 30px; }
        .controls-overview h2 { color: #2c3e50; margin-bottom: 5px; }
        .section-description { color: #7f8c8d; margin-bottom: 20px; font-size: 14px; }
        
        .co-summary {
            display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 20px;
        }
        .co-summary-card {
            background: #f8f9fa; border-radius: 8px; padding: 15px; text-align: center;
            border-left: 4px solid #3498db;
        }
        .co-card-good { border-left-color: #27ae60; }
        .co-card-attention { border-left-color: #e74c3c; }
        .co-summary-value { font-size: 28px; font-weight: 700; color: #2c3e50; }
        .co-summary-label { font-size: 12px; color: #7f8c8d; text-transform: uppercase; letter-spacing: 0.5px; }
        
        .co-filters {
            display: flex; align-items: center; gap: 12px; margin-bottom: 15px; flex-wrap: wrap;
        }
        .co-ig-filters { display: flex; gap: 4px; }
        .co-ig-btn {
            padding: 6px 14px; border: 1px solid #ddd; background: #fff; border-radius: 4px;
            cursor: pointer; font-size: 13px; transition: all 0.2s;
        }
        .co-ig-btn:hover { background: #f0f0f0; }
        .co-ig-btn.active { background: #3498db; color: #fff; border-color: #3498db; }
        .co-select {
            padding: 6px 10px; border: 1px solid #ddd; border-radius: 4px; font-size: 13px; background: #fff;
        }
        .co-search {
            padding: 6px 12px; border: 1px solid #ddd; border-radius: 4px; font-size: 13px;
            flex: 1; min-width: 200px;
        }
        
        .co-table-wrapper { overflow-x: auto; }
        .co-table {
            width: 100%; border-collapse: collapse; font-size: 13px; table-layout: fixed;
        }
        .co-table thead th {
            background: #2c3e50; color: #fff; padding: 10px 6px; text-align: left;
            font-weight: 600; white-space: nowrap; position: sticky; top: 0;
        }
        .co-sortable { cursor: pointer; user-select: none; }
        .co-sortable:hover { background: #34495e; }
        .co-table tbody tr {
            border-bottom: 1px solid #eee; transition: background 0.15s;
        }
        .co-table tbody tr:hover { background: #eaf2f8; }
        .co-table td { padding: 9px 6px; overflow: hidden; text-overflow: ellipsis; }
        .co-table th:nth-child(1), .co-table td:nth-child(1) { width: 5%; }
        .co-table th:nth-child(2), .co-table td:nth-child(2) { width: 27%; }
        .co-table th:nth-child(3), .co-table td:nth-child(3) { width: 4%; text-align: center; }
        .co-table th:nth-child(4), .co-table td:nth-child(4) { width: 30%; }
        .co-table th:nth-child(5), .co-table td:nth-child(5) { width: 7%; }
        .co-table th:nth-child(6), .co-table td:nth-child(6) { width: 7%; }
        .co-table th:nth-child(7), .co-table td:nth-child(7) { width: 5%; }
        .co-table th:nth-child(8), .co-table td:nth-child(8) { width: 15%; }
        .co-control-id { font-weight: 600; color: #2c3e50; white-space: nowrap; }
        .co-control-id a { color: #2980b9; text-decoration: none; cursor: pointer; }
        .co-control-id a:hover { text-decoration: underline; }
        .co-safeguard-name { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .co-safeguard-name span, .co-rules-cell span { display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; cursor: default; }
        .co-rules-cell { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-size: 12px; color: #555; }
        .co-numeric { text-align: right; white-space: nowrap; }
        .co-compliant { color: #27ae60; }
        .co-non-compliant { color: #e74c3c; }
        
        .ig-tag {
            display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 11px;
            font-weight: 600; color: #fff;
        }
        .ig-tag-ig1 { background: #3498db; }
        .ig-tag-ig2 { background: #9b59b6; }
        .ig-tag-ig3 { background: #e67e22; }
        
        .co-compliance-cell { display: flex; align-items: center; gap: 8px; justify-content: flex-end; }
        .co-compliance-bar-bg {
            width: 80px; height: 8px; background: #ecf0f1; border-radius: 4px; overflow: hidden;
        }
        .co-compliance-bar-fill { height: 100%; border-radius: 4px; transition: width 0.3s; }
        .co-compliance-pct { font-weight: 600; font-size: 13px; min-width: 48px; text-align: right; }
        
        @media (max-width: 768px) {
            .co-summary { grid-template-columns: repeat(2, 1fr); }
            .co-filters { flex-direction: column; align-items: stretch; }
            .co-safeguard-name { max-width: 150px; }
            .co-rules-cell { max-width: 120px; }
        }
        
        /* Print styles */
        @media print {
            .navigation {
                display: none;
            }
            
            .container {
                box-shadow: none;
                max-width: none;
            }
            
            .collapsible-content {
                max-height: none !important;
                padding: 15px !important;
            }
            
            .chart-container {
                break-inside: avoid;
            }
            
            .co-filters { display: none; }
        }
        """
    
    def _get_javascript_code(self, html_data: Dict[str, Any]) -> str:
        """Get JavaScript code for interactive features.
        
        Args:
            html_data: Enhanced HTML report data
            
        Returns:
            JavaScript code as string
        """
        chart_data_json = str(html_data.get("chart_data", {})).replace("'", '"')
        
        return f"""
        // Chart data
        const chartData = {chart_data_json};
        
        // Initialize charts
        function initializeCharts() {{
            if (typeof Chart === 'undefined') {{
                console.log('Chart.js not loaded, skipping chart initialization');
                return;
            }}
            
            // Risk Distribution Chart
            const riskChartCtx = document.getElementById('riskDistributionChart');
            if (riskChartCtx) {{
                new Chart(riskChartCtx, {{
                    type: 'pie',
                    data: chartData.riskDistribution,
                    options: {{
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {{
                            legend: {{
                                position: 'right'
                            }},
                            title: {{
                                display: true,
                                text: 'Risk Level Distribution'
                            }}
                        }}
                    }}
                }});
            }}
        }}
        
        // Initialize interactive features
        function initializeInteractivity() {{
            // Collapsible sections
            const collapsibles = document.querySelectorAll('.collapsible');
            collapsibles.forEach(function(collapsible) {{
                collapsible.addEventListener('click', function() {{
                    this.classList.toggle('active');
                    const content = this.nextElementSibling;
                    content.classList.toggle('active');
                }});
            }});
            
            // Navigation smooth scrolling
            const navLinks = document.querySelectorAll('.nav-link');
            navLinks.forEach(function(link) {{
                link.addEventListener('click', function(e) {{
                    e.preventDefault();
                    const targetId = this.getAttribute('href').substring(1);
                    const targetElement = document.getElementById(targetId);
                    if (targetElement) {{
                        targetElement.scrollIntoView({{
                            behavior: 'smooth',
                            block: 'start'
                        }});
                        
                        // Update active nav item
                        navLinks.forEach(nl => nl.classList.remove('active'));
                        this.classList.add('active');
                    }}
                }});
            }});
            
            // Progress bar animations
            const progressBars = document.querySelectorAll('.progress-bar');
            const observer = new IntersectionObserver(function(entries) {{
                entries.forEach(function(entry) {{
                    if (entry.isIntersecting) {{
                        const progressBar = entry.target;
                        const width = progressBar.getAttribute('data-width');
                        progressBar.style.width = width + '%';
                    }}
                }});
            }});
            
            progressBars.forEach(function(bar) {{
                observer.observe(bar);
            }});
            
            // Table sorting
            const tables = document.querySelectorAll('.findings-table');
            tables.forEach(function(table) {{
                const headers = table.querySelectorAll('th');
                headers.forEach(function(header, index) {{
                    header.style.cursor = 'pointer';
                    header.addEventListener('click', function() {{
                        sortTable(table, index);
                    }});
                }});
            }});
        }}
        
        // Table sorting function
        function sortTable(table, columnIndex) {{
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr'));
            
            const isNumeric = rows.every(row => {{
                const cell = row.cells[columnIndex];
                return cell && !isNaN(parseFloat(cell.textContent));
            }});
            
            rows.sort(function(a, b) {{
                const aVal = a.cells[columnIndex].textContent.trim();
                const bVal = b.cells[columnIndex].textContent.trim();
                
                if (isNumeric) {{
                    return parseFloat(aVal) - parseFloat(bVal);
                }} else {{
                    return aVal.localeCompare(bVal);
                }}
            }});
            
            rows.forEach(function(row) {{
                tbody.appendChild(row);
            }});
        }}
        
        // Search functionality for detailed findings
        function searchFindings(searchTerm) {{
            const term = searchTerm.toLowerCase();
            const controlSections = document.querySelectorAll('.collapsible-content');
            
            controlSections.forEach(function(section) {{
                const rows = section.querySelectorAll('.findings-table tbody tr');
                let visibleCount = 0;
                
                rows.forEach(function(row) {{
                    const cells = row.querySelectorAll('td');
                    if (cells.length === 0) return;
                    
                    // Search across: resource ID, resource type, region, evaluation reason, config rule name
                    const resourceId = cells[0] ? cells[0].textContent.toLowerCase() : '';
                    const resourceType = cells[1] ? cells[1].textContent.toLowerCase() : '';
                    const region = cells[2] ? cells[2].textContent.toLowerCase() : '';
                    const configRule = cells[4] ? cells[4].textContent.toLowerCase() : '';
                    const evaluationReason = cells[5] ? cells[5].textContent.toLowerCase() : '';
                    
                    const matches = resourceId.includes(term) || 
                                  resourceType.includes(term) ||
                                  region.includes(term) ||
                                  configRule.includes(term) ||
                                  evaluationReason.includes(term);
                    
                    if (matches || term === '') {{
                        row.style.display = '';
                        visibleCount++;
                    }} else {{
                        row.style.display = 'none';
                    }}
                }});
                
                // Update the count in the collapsible button if it exists
                const collapsibleBtn = section.previousElementSibling;
                if (collapsibleBtn && collapsibleBtn.classList.contains('collapsible')) {{
                    const originalText = collapsibleBtn.textContent.split('(')[0].trim();
                    const totalCount = rows.length;
                    if (term === '') {{
                        collapsibleBtn.textContent = `${{originalText}} (${{totalCount}} findings)`;
                    }} else {{
                        collapsibleBtn.textContent = `${{originalText}} (${{visibleCount}} of ${{totalCount}} findings)`;
                    }}
                }}
            }});
        }}
        
        // Export functionality
        function exportToCSV() {{
            const tables = document.querySelectorAll('.findings-table');
            let csvContent = '';
            let headersAdded = false;
            
            tables.forEach(function(table) {{
                const rows = table.querySelectorAll('tr');
                rows.forEach(function(row, index) {{
                    // Add headers only once (from first table)
                    if (index === 0) {{
                        if (!headersAdded) {{
                            const cells = row.querySelectorAll('th');
                            if (cells.length > 0) {{
                                const rowData = Array.from(cells).map(cell => 
                                    '"' + cell.textContent.replace(/"/g, '""') + '"'
                                ).join(',');
                                csvContent += rowData + '\\n';
                                headersAdded = true;
                            }}
                        }}
                    }} else {{
                        // Add data rows (skip header rows from subsequent tables)
                        const cells = row.querySelectorAll('td');
                        if (cells.length > 0) {{
                            const rowData = Array.from(cells).map(cell => 
                                '"' + cell.textContent.replace(/"/g, '""') + '"'
                            ).join(',');
                            csvContent += rowData + '\\n';
                        }}
                    }}
                }});
            }});
            
            const blob = new Blob([csvContent], {{ type: 'text/csv' }});
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'cis-compliance-findings.csv';
            a.click();
            window.URL.revokeObjectURL(url);
        }}
        
        // Resource filtering functionality (updated in v1.1.2 to support Control filter)
        function filterResources() {{
            const searchTerm = document.getElementById('resourceSearch').value.toLowerCase();
            const statusFilter = document.getElementById('statusFilter').value;
            const typeFilter = document.getElementById('typeFilter').value;
            const controlFilter = document.getElementById('controlFilter').value;
            const rows = document.querySelectorAll('#resourceTable tbody tr');
            
            rows.forEach(function(row) {{
                const cells = row.querySelectorAll('td');
                const resourceId = cells[0].textContent.toLowerCase();
                const resourceType = cells[1].textContent;
                const status = cells[3].textContent.includes('COMPLIANT') ? 
                    (cells[3].textContent.includes('NON_COMPLIANT') ? 'NON_COMPLIANT' : 'COMPLIANT') : 'NON_COMPLIANT';
                const controlId = cells[4].textContent;
                const evaluationReason = cells[6].textContent.toLowerCase();
                
                const matchesSearch = resourceId.includes(searchTerm) || 
                                    resourceType.toLowerCase().includes(searchTerm) ||
                                    evaluationReason.includes(searchTerm);
                const matchesStatus = !statusFilter || status === statusFilter;
                const matchesType = !typeFilter || resourceType === typeFilter;
                const matchesControl = !controlFilter || controlId === controlFilter;
                
                row.style.display = (matchesSearch && matchesStatus && matchesType && matchesControl) ? '' : 'none';
            }});
        }}
        
        // Resource table sorting
        function sortResourceTable(columnIndex) {{
            const table = document.getElementById('resourceTable');
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr'));
            
            const isNumeric = columnIndex === 3; // Status column - sort by compliance status
            
            rows.sort(function(a, b) {{
                const aVal = a.cells[columnIndex].textContent.trim();
                const bVal = b.cells[columnIndex].textContent.trim();
                
                if (columnIndex === 3) {{ // Status column - COMPLIANT before NON_COMPLIANT
                    const aCompliant = aVal.includes('✓');
                    const bCompliant = bVal.includes('✓');
                    return bCompliant - aCompliant;
                }} else {{
                    return aVal.localeCompare(bVal);
                }}
            }});
            
            rows.forEach(function(row) {{
                tbody.appendChild(row);
            }});
        }}
        
        // Export resources to CSV (updated in v1.1.2 with ARN, aggregate filtering, and port truncation)
        function exportResourcesToCSV() {{
            const table = document.getElementById('resourceTable');
            const rows = table.querySelectorAll('tr');
            let csvContent = '';
            
            // Excluded aggregate row IDs (v1.1.2)
            const excludedIds = ['5631', '6460', '629'];
            
            // Helper function to truncate port lists (v1.1.2)
            function truncatePortList(text) {{
                // Match port list patterns like [0, 1, 2, 3, ...]
                const portListRegex = /\\[(\\d+(?:,\\s*\\d+)*)\\]/g;
                
                return text.replace(portListRegex, function(match, ports) {{
                    const portArray = ports.split(',').map(p => p.trim());
                    if (portArray.length > 10) {{
                        const truncated = portArray.slice(0, 10).join(', ');
                        return `[${{truncated}}, ...]`;
                    }}
                    return match;
                }});
            }}
            
            rows.forEach(function(row, index) {{
                const cells = row.querySelectorAll('th, td');
                
                // Handle header row - change "Resource ID" to "Resource ARN"
                if (index === 0) {{
                    const headerData = Array.from(cells).map((cell, cellIndex) => {{
                        let headerText = cell.textContent.replace(/\\s+/g, ' ').trim();
                        // Replace "Resource ID" with "Resource ARN" in header
                        if (cellIndex === 0 && headerText.includes('Resource ID')) {{
                            headerText = headerText.replace('Resource ID', 'Resource ARN');
                        }}
                        return '"' + headerText.replace(/"/g, '""') + '"';
                    }}).join(',');
                    csvContent += headerData + '\\n';
                }} else if (cells.length > 0) {{
                    // Get resource ID to check if it should be excluded
                    const resourceIdCell = cells[0];
                    const resourceId = resourceIdCell.textContent.replace(/\\s+/g, ' ').trim();
                    
                    // Skip aggregate rows (v1.1.2)
                    if (excludedIds.includes(resourceId)) {{
                        return;
                    }}
                    
                    // Get ARN from data attribute or fall back to resource ID
                    const resourceArn = resourceIdCell.getAttribute('data-arn') || resourceId;
                    
                    const rowData = Array.from(cells).map((cell, cellIndex) => {{
                        let cellText = cell.textContent.replace(/\\s+/g, ' ').trim();
                        
                        // Use ARN for first column instead of Resource ID (v1.1.2)
                        if (cellIndex === 0) {{
                            cellText = resourceArn;
                        }}
                        
                        // Apply port list truncation to evaluation reason column (v1.1.2)
                        if (cellIndex === 6) {{
                            cellText = truncatePortList(cellText);
                        }}
                        
                        return '"' + cellText.replace(/"/g, '""') + '"';
                    }}).join(',');
                    csvContent += rowData + '\\n';
                }}
            }});
            
            // Add UTF-8 BOM to ensure proper encoding in Excel and other tools
            const blob = new Blob(['\ufeff' + csvContent], {{ type: 'text/csv;charset=utf-8;' }});
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'cis-compliance-resources.csv';
            a.click();
            window.URL.revokeObjectURL(url);
        }}
        
        // Export resources to JSON
        function exportResourcesToJSON() {{
            const table = document.getElementById('resourceTable');
            const headers = Array.from(table.querySelectorAll('thead th')).map(th => th.textContent.trim());
            const rows = Array.from(table.querySelectorAll('tbody tr'));
            
            const data = rows.map(row => {{
                const cells = Array.from(row.querySelectorAll('td'));
                const rowData = {{}};
                headers.forEach((header, index) => {{
                    rowData[header] = cells[index] ? cells[index].textContent.replace(/\\s+/g, ' ').trim() : '';
                }});
                return rowData;
            }});
            
            const jsonContent = JSON.stringify(data, null, 2);
            const blob = new Blob([jsonContent], {{ type: 'application/json' }});
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'cis-compliance-resources.json';
            a.click();
            window.URL.revokeObjectURL(url);
        }}
        
        // Toggle scoring details
        function toggleScoringDetails() {{
            const detailsSection = document.getElementById('scoringDetails');
            if (detailsSection) {{
                if (detailsSection.style.display === 'none') {{
                    detailsSection.style.display = 'block';
                }} else {{
                    detailsSection.style.display = 'none';
                }}
            }}
        }}
        
        // ---- Controls Overview: Filtering ----
        var coActiveIG = '';
        
        function filterCOByIG(btn, ig) {{
            coActiveIG = ig;
            document.querySelectorAll('.co-ig-btn').forEach(function(b) {{ b.classList.remove('active'); }});
            btn.classList.add('active');
            filterControlsOverview();
        }}
        
        function filterControlsOverview() {{
            try {{
                var rows = document.querySelectorAll('#coTableBody tr');
                var statusVal = document.getElementById('coStatusFilter').value;
                var ruleVal = (document.getElementById('coRuleFilter').value || '').toLowerCase();
                var searchVal = (document.getElementById('coSearchInput').value || '').toLowerCase();
                var visibleCount = 0, compliantCount = 0, attentionCount = 0, complianceSum = 0;
                
                rows.forEach(function(row) {{
                    var ig = row.getAttribute('data-ig') || '';
                    var pct = parseFloat(row.getAttribute('data-compliance')) || 0;
                    var rules = (row.getAttribute('data-rules') || '').toLowerCase();
                    var controlId = (row.querySelector('.co-control-id') || {{}}).textContent || '';
                    var safeguardName = (row.querySelector('.co-safeguard-name') || {{}}).textContent || '';
                    var show = true;
                    
                    // IG filter
                    if (coActiveIG && ig !== coActiveIG) show = false;
                    // Status filter
                    if (statusVal === 'compliant' && pct < 100) show = false;
                    if (statusVal === 'attention' && pct >= 100) show = false;
                    // Rule dropdown filter
                    if (ruleVal && rules.indexOf(ruleVal) === -1) show = false;
                    // Text search (includes control ID, safeguard name, and rules)
                    if (searchVal && controlId.toLowerCase().indexOf(searchVal) === -1 && safeguardName.toLowerCase().indexOf(searchVal) === -1 && rules.indexOf(searchVal) === -1) show = false;
                    
                    row.style.display = show ? '' : 'none';
                    if (show) {{
                        visibleCount++;
                        complianceSum += pct;
                        if (pct >= 100) compliantCount++;
                        else attentionCount++;
                    }}
                }});
                
                // Update summary header
                var el;
                el = document.getElementById('coTotalControls'); if (el) el.textContent = visibleCount;
                el = document.getElementById('coFullyCompliant'); if (el) el.textContent = compliantCount;
                el = document.getElementById('coNeedsAttention'); if (el) el.textContent = attentionCount;
                el = document.getElementById('coAvgCompliance'); if (el) el.textContent = (visibleCount > 0 ? (complianceSum / visibleCount).toFixed(1) : '0.0') + '%';
            }} catch(e) {{ console.error('filterControlsOverview error:', e); }}
        }}
        
        // ---- Controls Overview: Sorting ----
        var coSortCol = -1;
        var coSortAsc = true;
        
        function sortControlsOverviewTable(colIndex) {{
            try {{
                var table = document.getElementById('controlsOverviewTable');
                var tbody = table.querySelector('tbody');
                var rows = Array.from(tbody.querySelectorAll('tr'));
                
                if (coSortCol === colIndex) {{ coSortAsc = !coSortAsc; }}
                else {{ coSortCol = colIndex; coSortAsc = true; }}
                
                rows.sort(function(a, b) {{
                    var aText = a.cells[colIndex].textContent.trim();
                    var bText = b.cells[colIndex].textContent.trim();
                    
                    // Control ID column (0): alphanumeric sort
                    if (colIndex === 0) {{
                        var aParts = aText.split('.').map(Number);
                        var bParts = bText.split('.').map(Number);
                        for (var i = 0; i < Math.max(aParts.length, bParts.length); i++) {{
                            var av = aParts[i] || 0, bv = bParts[i] || 0;
                            if (av !== bv) return coSortAsc ? av - bv : bv - av;
                        }}
                        return 0;
                    }}
                    
                    // Numeric columns (3-7): Rules, Compliant, Non-Compliant, Total, Compliance%
                    if (colIndex >= 3) {{
                        var aNum = parseFloat(aText.replace('%', '')) || 0;
                        var bNum = parseFloat(bText.replace('%', '')) || 0;
                        return coSortAsc ? aNum - bNum : bNum - aNum;
                    }}
                    
                    // String columns (1=Name, 2=IG)
                    return coSortAsc ? aText.localeCompare(bText) : bText.localeCompare(aText);
                }});
                
                rows.forEach(function(row) {{ tbody.appendChild(row); }});
            }} catch(e) {{ console.error('sortControlsOverviewTable error:', e); }}
        }}
        
        // ---- Controls Overview: Row click → Resource Details ----
        function onControlRowClick(controlId) {{
            try {{
                var controlFilter = document.getElementById('controlFilter');
                if (controlFilter) {{
                    controlFilter.value = controlId;
                    if (typeof filterResources === 'function') filterResources();
                }}
                var target = document.getElementById('resource-details');
                if (target) target.scrollIntoView({{ behavior: 'smooth', block: 'start' }});
            }} catch(e) {{ console.error('onControlRowClick error:', e); }}
        }}
        
        // ---- Resource Table Pagination ----
        var currentPage = 1;
        var pageSize = 10;
        
        function getVisibleRows() {{
            var rows = Array.from(document.querySelectorAll('#resourceTable tbody tr'));
            return rows.filter(function(r) {{ return r.style.display !== 'none' || r.getAttribute('data-hidden-by-filter') !== 'true'; }});
        }}
        
        function applyPagination() {{
            var rows = Array.from(document.querySelectorAll('#resourceTable tbody tr'));
            var filteredRows = rows.filter(function(r) {{ return r.getAttribute('data-hidden-by-filter') !== 'true'; }});
            var totalFiltered = filteredRows.length;
            
            if (pageSize === 0) {{
                // Show all
                filteredRows.forEach(function(r) {{ r.style.display = ''; }});
                updatePaginationUI(totalFiltered, totalFiltered);
                return;
            }}
            
            var totalPages = Math.ceil(totalFiltered / pageSize) || 1;
            if (currentPage > totalPages) currentPage = totalPages;
            if (currentPage < 1) currentPage = 1;
            
            var start = (currentPage - 1) * pageSize;
            var end = start + pageSize;
            
            filteredRows.forEach(function(r, i) {{
                r.style.display = (i >= start && i < end) ? '' : 'none';
            }});
            
            updatePaginationUI(totalFiltered, totalPages);
        }}
        
        function updatePaginationUI(totalFiltered, totalPages) {{
            var pageInfoText = pageSize === 0 ? 'Showing all' : 'Page ' + currentPage + ' of ' + totalPages;
            var el;
            el = document.getElementById('pageInfo'); if (el) el.textContent = pageInfoText;
            el = document.getElementById('pageInfoBottom'); if (el) el.textContent = pageInfoText;
            el = document.getElementById('prevPageBtn'); if (el) el.disabled = (currentPage <= 1 || pageSize === 0);
            el = document.getElementById('prevPageBtnBottom'); if (el) el.disabled = (currentPage <= 1 || pageSize === 0);
            el = document.getElementById('nextPageBtn'); if (el) el.disabled = (currentPage >= totalPages || pageSize === 0);
            el = document.getElementById('nextPageBtnBottom'); if (el) el.disabled = (currentPage >= totalPages || pageSize === 0);
            el = document.getElementById('resourceCount'); if (el) el.textContent = totalFiltered + ' resources';
        }}
        
        function changePage(delta) {{
            currentPage += delta;
            applyPagination();
        }}
        
        function changePageSize(newSize) {{
            pageSize = parseInt(newSize);
            currentPage = 1;
            applyPagination();
        }}
        
        // Override filterResources to integrate with pagination
        var _origFilterResources = filterResources;
        filterResources = function() {{
            var searchTerm = document.getElementById('resourceSearch').value.toLowerCase();
            var statusFilter = document.getElementById('statusFilter').value;
            var typeFilter = document.getElementById('typeFilter').value;
            var controlFilter = document.getElementById('controlFilter').value;
            var rows = document.querySelectorAll('#resourceTable tbody tr');
            
            rows.forEach(function(row) {{
                var cells = row.querySelectorAll('td');
                if (cells.length === 0) return;
                var resourceId = cells[0].textContent.toLowerCase();
                var resourceType = cells[1].textContent;
                var status = cells[3].textContent.includes('NON_COMPLIANT') ? 'NON_COMPLIANT' : 'COMPLIANT';
                var controlId = cells[4].textContent;
                var evaluationReason = cells[6].textContent.toLowerCase();
                
                var matchesSearch = resourceId.includes(searchTerm) || 
                                    resourceType.toLowerCase().includes(searchTerm) ||
                                    evaluationReason.includes(searchTerm);
                var matchesStatus = !statusFilter || status === statusFilter;
                var matchesType = !typeFilter || resourceType === typeFilter;
                var matchesControl = !controlFilter || controlId === controlFilter;
                
                if (matchesSearch && matchesStatus && matchesType && matchesControl) {{
                    row.removeAttribute('data-hidden-by-filter');
                }} else {{
                    row.setAttribute('data-hidden-by-filter', 'true');
                    row.style.display = 'none';
                }}
            }});
            
            currentPage = 1;
            applyPagination();
        }};
        
        // Initialize pagination on load
        document.addEventListener('DOMContentLoaded', function() {{
            setTimeout(applyPagination, 100);
        }});
        """
    
    def _generate_header(self, html_data: Dict[str, Any]) -> str:
        """Generate header section.
        
        Args:
            html_data: Enhanced HTML report data
            
        Returns:
            Header HTML as string
        """
        metadata = html_data["metadata"]
        exec_summary = html_data["executive_summary"]
        
        return f"""
        <header class="header">
            <h1>CIS Controls Compliance Report</h1>
            <div class="subtitle">
                AWS Account: {metadata.get('account_id', 'Unknown')} | 
                Assessment Date: {datetime.fromisoformat(metadata.get('assessment_timestamp', '')).strftime('%B %d, %Y') if metadata.get('assessment_timestamp') else 'Unknown'} |
                Overall Compliance: {exec_summary.get('overall_compliance_percentage', 0):.1f}%
            </div>
        </header>
        """
    
    def _generate_navigation(self, html_data: Dict[str, Any]) -> str:
        """Generate navigation section.
        
        Args:
            html_data: Enhanced HTML report data
            
        Returns:
            Navigation HTML as string
        """
        nav_items = html_data.get("navigation", {}).get("sections", [])
        
        nav_links = ""
        for item in nav_items:
            nav_links += f'<li class="nav-item"><a href="#{item["id"]}" class="nav-link">{item["title"]}</a></li>'
        
        return f"""
        <nav class="navigation">
            <ul class="nav-list">
                {nav_links}
            </ul>
        </nav>
        """
    
    def _generate_executive_dashboard(self, html_data: Dict[str, Any]) -> str:
        """Generate executive dashboard section.
        
        Modified in v1.1.1 to remove pie chart (igComplianceChart) and bar chart 
        (complianceTrendChart), keeping only risk distribution chart.
        
        Args:
            html_data: Enhanced HTML report data
            
        Returns:
            Dashboard HTML as string
        """
        exec_summary = html_data["executive_summary"]
        metadata = html_data["metadata"]
        
        # Generate metric cards
        overall_status = self._get_status_class(exec_summary.get("overall_compliance_percentage", 0))
        aws_config_score = exec_summary.get('aws_config_style_score', 0)
        score_diff = exec_summary.get('score_difference', 0)
        
        metric_cards = f"""
        <div class="metric-card {overall_status}">
            <div class="metric-value">{exec_summary.get('overall_compliance_percentage', 0):.1f}%</div>
            <div class="metric-label">Weighted Compliance Score</div>
            <div class="metric-trend trend-stable">Grade: {exec_summary.get('compliance_grade', 'N/A')}</div>
        </div>
        
        <div class="metric-card">
            <div class="metric-value">{aws_config_score:.1f}%</div>
            <div class="metric-label">AWS Config Style Score</div>
            <div class="metric-trend trend-stable">Unweighted</div>
        </div>
        
        <div class="metric-card">
            <div class="metric-value">{exec_summary.get('total_resources', 0):,}</div>
            <div class="metric-label">Resource Evaluations</div>
            <div class="metric-trend trend-up">Across {len(metadata.get('regions_assessed', []))} regions and multiple controls</div>
        </div>
        
        <div class="metric-card">
            <div class="metric-value">{exec_summary.get('compliant_resources', 0):,}</div>
            <div class="metric-label">Compliant Evaluations</div>
            <div class="metric-trend trend-up">{(exec_summary.get('compliant_resources', 0) / max(exec_summary.get('total_resources', 1), 1) * 100):.1f}% of evaluations</div>
        </div>
        """
        
        # Add scoring comparison section
        score_comparison = self._generate_score_comparison_section(
            exec_summary.get('overall_compliance_percentage', 0),
            aws_config_score,
            score_diff
        )
        
        # Generate IG progress bars
        ig_progress = ""
        for ig in ['ig1', 'ig2', 'ig3']:
            ig_key = f"{ig}_compliance_percentage"
            ig_value = exec_summary.get(ig_key, 0)
            ig_status = self._get_status_class(ig_value)
            ig_name = ig.upper()
            
            ig_progress += f"""
            <div class="ig-progress">
                <div class="ig-progress-header">
                    <span>{ig_name} Compliance</span>
                    <span>{ig_value:.1f}%</span>
                </div>
                <div class="progress-container">
                    <div class="progress-bar {ig_status}" data-width="{self._get_display_width(ig_value)}">
                        <span class="progress-text">{ig_value:.1f}%</span>
                    </div>
                </div>
            </div>
            """
        
        # Generate coverage metrics section
        coverage_section = self._generate_coverage_metrics_section(html_data.get("coverage_metrics", {}))
        
        return f"""
        <section id="dashboard" class="dashboard">
            <h2>Executive Dashboard</h2>
            <div class="dashboard-grid">
                {metric_cards}
            </div>
            
            {score_comparison}
            
            {coverage_section}
        </section>
        """
    
    def _generate_implementation_groups_section(self, html_data: Dict[str, Any]) -> str:
        """Generate Implementation Groups section with unique controls per IG.
        
        Args:
            html_data: Enhanced HTML report data
            
        Returns:
            Implementation Groups HTML as string
        """
        ig_sections = ""
        
        # Define which controls are unique to each IG to avoid duplication
        unique_controls = self._get_unique_controls_per_ig(html_data["implementation_groups"])
        
        for ig_name, ig_data in html_data["implementation_groups"].items():
            controls_html = ""
            
            # Only show controls that are unique to this IG or inherited controls for context
            controls_to_show = unique_controls.get(ig_name, {})
            
            # Sort controls numerically (1.1, 1.5, 2.2, 3.3, ... not random dict order)
            sorted_control_ids = sorted(controls_to_show.keys(), key=lambda cid: self._sort_control_id(cid))
            
            for control_id in sorted_control_ids:
                control_data = controls_to_show[control_id]
                findings_count = len(control_data.get("non_compliant_findings", []))
                status_class = self._get_status_class(control_data["compliance_percentage"])
                
                # Get display name (enriched in _enhance_html_structure)
                display_name = control_data.get('display_name', control_id)
                needs_truncation = control_data.get('needs_truncation', False)
                
                # Always show full safeguard title as tooltip on hover
                # Card shows "CIS Control X.Y" as visible text, tooltip shows the full title
                tooltip_text = display_name if display_name != control_id else ''
                card_label = f"CIS Control {control_id}"
                title_attr = f' title="{tooltip_text}"' if tooltip_text else ''
                display_name_class = 'control-display-name'
                
                # Get IG membership badges
                originating_ig = control_data.get('originating_ig', 'IG1')
                ig_badge_class = control_data.get('ig_badge_class', 'ig-badge-1')
                
                # Build IG membership badges HTML
                ig_badges_html = f'<span class="ig-membership-badge {ig_badge_class}">{originating_ig}</span>'
                
                # Add inheritance indicator for inherited controls
                inheritance_indicator = ""
                if ig_name != "IG1" and control_id in unique_controls.get("IG1", {}):
                    inheritance_indicator = f'<small class="inheritance-note">Inherited from IG1</small>'
                elif ig_name == "IG3" and control_id in unique_controls.get("IG2", {}):
                    inheritance_indicator = f'<small class="inheritance-note">Inherited from IG2</small>'
                
                controls_html += f"""
                <div class="control-card">
                    <div class="control-header">
                        <div class="{display_name_class}"{title_attr}>{card_label}</div>
                        <div class="badge {control_data.get('severity_badge', 'medium')}">{findings_count} Issues</div>
                    </div>
                    <div class="ig-membership-badges">
                        {ig_badges_html}
                    </div>
                    {inheritance_indicator}
                    <div class="progress-container">
                        <div class="progress-bar {status_class}" data-width="{self._get_display_width(control_data['compliance_percentage'])}">
                            <span class="progress-text">{control_data['compliance_percentage']:.1f}%</span>
                        </div>
                    </div>
                    <div class="control-stats">
                        <small>{control_data['compliant_resources']}/{control_data['total_resources']} resources compliant</small>
                    </div>
                </div>
                """
            
            ig_status_class = self._get_status_class(ig_data["compliance_percentage"])
            
            # Show summary of what this IG includes
            ig_description = self._get_ig_description_with_inheritance(ig_name)
            
            ig_sections += f"""
            <div class="ig-section">
                <div class="ig-header">
                    <div class="ig-title">{ig_name} - {ig_description}</div>
                    <div class="ig-score">{ig_data['compliance_percentage']:.1f}%</div>
                </div>
                <div class="ig-content">
                    <div class="ig-summary">
                        <p><strong>{ig_data['compliant_controls']}</strong> of <strong>{ig_data['total_controls']}</strong> controls are compliant</p>
                        <p class="ig-scope">{self._get_ig_scope_description(ig_name, len(controls_to_show))}</p>
                    </div>
                    <div class="controls-grid">
                        {controls_html}
                    </div>
                </div>
            </div>
            """
        
        return f"""
        <section id="implementation-groups" class="implementation-groups">
            <h2>Implementation Groups</h2>
            <div class="ig-explanation">
                <p><strong>Note:</strong> Implementation Groups are cumulative. IG2 includes all IG1 controls plus additional ones. IG3 includes all IG1 and IG2 controls plus advanced controls.</p>
            </div>
            {ig_sections}
        </section>
        """
    
    
    
    def _generate_footer(self, html_data: Dict[str, Any]) -> str:
        """Generate footer section.
        
        Args:
            html_data: Enhanced HTML report data
            
        Returns:
            Footer HTML as string
        """
        metadata = html_data["metadata"]
        
        return f"""
        <footer class="footer">
            <div class="footer-content">
                <div class="footer-section">
                    <h4>Report Information</h4>
                    <p>Generated: {datetime.fromisoformat(metadata.get('report_generated_at', '')).strftime('%B %d, %Y at %I:%M %p') if metadata.get('report_generated_at') else 'Unknown'}</p>
                    <p>Assessment Duration: {metadata.get('assessment_duration', 'Unknown')}</p>
                    <p>Report Version: {html_data.get('report_version', '1.0')}</p>
                </div>
                <div class="footer-section">
                    <h4>Assessment Scope</h4>
                    <p>AWS Account: {metadata.get('account_id', 'Unknown')}</p>
                    <p>Regions: {', '.join(metadata.get('regions_assessed', []))}</p>
                </div>
                <div class="footer-section">
                    <h4>About CIS Controls</h4>
                    <p>The CIS Controls are a prioritized set of cybersecurity best practices developed by the Center for Internet Security.</p>
                    <p>This report evaluates AWS configurations against CIS Controls Implementation Groups.</p>
                </div>
            </div>
            <div class="footer-bottom">
                <p>&copy; {datetime.now().year} AWS CIS Assessment Tool. Generated with HTML Reporter v{html_data.get('report_version', '1.1.2')}</p>
            </div>
        </footer>
        """
    
    def _prepare_chart_data(self, html_data: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare data for charts.
        
        Args:
            html_data: Enhanced HTML report data
            
        Returns:
            Chart data dictionary
        """
        exec_summary = html_data["executive_summary"]
        
        # Implementation Groups compliance chart
        ig_compliance = {
            "labels": ["IG1", "IG2", "IG3"],
            "datasets": [{
                "data": [
                    exec_summary.get("ig1_compliance_percentage", 0),
                    exec_summary.get("ig2_compliance_percentage", 0),
                    exec_summary.get("ig3_compliance_percentage", 0)
                ],
                "backgroundColor": ["#3498db", "#2ecc71", "#e74c3c"],
                "borderWidth": 2,
                "borderColor": "#fff"
            }]
        }
        
        # Compliance trend chart
        compliance_trend = {
            "labels": ["IG1", "IG2", "IG3"],
            "datasets": [{
                "label": "Compliance %",
                "data": [
                    exec_summary.get("ig1_compliance_percentage", 0),
                    exec_summary.get("ig2_compliance_percentage", 0),
                    exec_summary.get("ig3_compliance_percentage", 0)
                ],
                "backgroundColor": ["#3498db", "#2ecc71", "#e74c3c"],
                "borderColor": ["#2980b9", "#27ae60", "#c0392b"],
                "borderWidth": 1
            }]
        }
        
        # Risk distribution chart
        total_resources = exec_summary.get("total_resources", 1)
        compliant = exec_summary.get("compliant_resources", 0)
        non_compliant = exec_summary.get("non_compliant_resources", 0)
        
        risk_distribution = {
            "labels": ["Compliant", "Non-Compliant"],
            "datasets": [{
                "data": [compliant, non_compliant],
                "backgroundColor": ["#27ae60", "#e74c3c"],
                "borderWidth": 2,
                "borderColor": "#fff"
            }]
        }
        
        return {
            "igCompliance": ig_compliance,
            "complianceTrend": compliance_trend,
            "riskDistribution": risk_distribution
        }
    
    def _prepare_coverage_metrics(self, coverage_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare coverage metrics for HTML display.
        
        Args:
            coverage_metrics: Coverage metrics from ComplianceSummary
            
        Returns:
            Formatted coverage metrics dictionary
        """
        formatted_metrics = {}
        
        for ig_name, metrics in coverage_metrics.items():
            # Handle both CoverageMetrics objects and dictionaries
            if hasattr(metrics, '__dict__'):
                metrics_dict = metrics.__dict__
            else:
                metrics_dict = metrics
            
            formatted_metrics[ig_name] = {
                'coverage_percentage': metrics_dict.get('coverage_percentage', 0),
                'total_safeguards': metrics_dict.get('total_safeguards', 0),
                'covered_safeguards': metrics_dict.get('covered_safeguards', 0),
                'implemented_rules': metrics_dict.get('implemented_rules', 0),
                'safeguard_details': metrics_dict.get('safeguard_details', {})
            }
        
        return formatted_metrics
    
    def _build_navigation_structure(self, html_data: Dict[str, Any]) -> Dict[str, Any]:
        """Build navigation structure for the report.
        
        Modified in v1.1.2 to remove Detailed Findings and Remediation sections.
        
        Args:
            html_data: Enhanced HTML report data
            
        Returns:
            Navigation structure dictionary
        """
        return {
            "sections": [
                {"id": "dashboard", "title": "Dashboard"},
                {"id": "controls-overview", "title": "Controls Overview"},
                {"id": "resource-details", "title": "Resource Details"}
            ]
        }
    
    def _calculate_compliance_grade(self, compliance_percentage: float) -> str:
        """Calculate compliance grade based on percentage."""
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
        """Calculate risk level based on compliance percentage."""
        if compliance_percentage >= 90.0:
            return "LOW"
        elif compliance_percentage >= 75.0:
            return "MEDIUM"
        elif compliance_percentage >= 50.0:
            return "HIGH"
        else:
            return "CRITICAL"
    
    def _get_status_color(self, compliance_percentage: float) -> str:
        """Get status color based on compliance percentage."""
        if compliance_percentage >= 90.0:
            return "#27ae60"  # Green
        elif compliance_percentage >= 75.0:
            return "#f39c12"  # Orange
        elif compliance_percentage >= 50.0:
            return "#e67e22"  # Dark orange
        else:
            return "#e74c3c"  # Red
    
    def _get_display_width(self, actual_percentage: float) -> float:
        """Calculate display width for progress bars.
        
        Ensures minimum 5% width for visibility when actual percentage is 0%.
        This prevents progress bars from being invisible for non-compliant controls.
        
        Args:
            actual_percentage: Actual compliance percentage (0-100)
            
        Returns:
            Display width with minimum 5% for visibility
        """
        return max(5.0, actual_percentage)
    
    def _get_status_class(self, compliance_percentage: float) -> str:
        """Get CSS status class based on compliance percentage."""
        if compliance_percentage >= 95.0:
            return "excellent"
        elif compliance_percentage >= 80.0:
            return "good"
        elif compliance_percentage >= 60.0:
            return "fair"
        elif compliance_percentage >= 40.0:
            return "poor"
        else:
            return "critical"
    
    def _get_severity_badge(self, control_data: Dict[str, Any]) -> str:
        """Get severity badge class for control."""
        findings_count = len(control_data.get("non_compliant_findings", []))
        if findings_count > 10:
            return "high"
        elif findings_count > 3:
            return "medium"
        else:
            return "low"
    
    def _get_priority_badge(self, priority: str) -> str:
        """Get priority badge class ensuring single value.
        
        Modified in v1.1.1 to normalize priority values and handle duplicates.
        Fixes issues like "High High" → "high" and "High Medium" → "high".
        
        Args:
            priority: Priority string (may contain multiple values like "High High" or "High Medium")
            
        Returns:
            Single priority class: 'high', 'medium', or 'low'
        """
        # Extract first priority if multiple exist
        priority_lower = priority.lower().strip()
        
        # Handle multiple priorities (take first one)
        if ' ' in priority_lower:
            priority_lower = priority_lower.split()[0]
        
        # Normalize to standard values
        if 'high' in priority_lower:
            return 'high'
        elif 'medium' in priority_lower or 'med' in priority_lower:
            return 'medium'
        elif 'low' in priority_lower:
            return 'low'
        else:
            return 'medium'  # Default fallback
    
    def _get_effort_badge(self, effort: str) -> str:
        """Get effort badge class."""
        effort_lower = effort.lower()
        if "low" in effort_lower or "minimal" in effort_lower:
            return "effort-minimal"
        elif "medium" in effort_lower or "moderate" in effort_lower:
            return "effort-moderate"
        elif "high" in effort_lower or "significant" in effort_lower:
            return "effort-significant"
        else:
            return "effort-extensive"
    
    def _get_ig_description(self, ig_name: str) -> str:
        """Get Implementation Group description."""
        descriptions = {
            "IG1": "Essential Cyber Hygiene",
            "IG2": "Enhanced Security",
            "IG3": "Advanced Security"
        }
        return descriptions.get(ig_name, "Unknown Implementation Group")
    
    def _prepare_findings_for_display(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Prepare findings for HTML display."""
        display_findings = []
        for finding in findings:
            display_finding = finding.copy()
            # Truncate long resource IDs for display
            if len(display_finding["resource_id"]) > 50:
                display_finding["resource_id_display"] = display_finding["resource_id"][:47] + "..."
            else:
                display_finding["resource_id_display"] = display_finding["resource_id"]
            display_findings.append(display_finding)
        return display_findings
    
    def _generate_score_comparison_section(self, weighted_score: float, 
                                          aws_config_score: float, 
                                          score_diff: float) -> str:
        """Generate scoring methodology comparison section.
        
        Modified in v1.1.1 to remove "our approach" phrase, "Reflects actual security 
        posture" text, and score difference warning for cleaner presentation.
        
        Args:
            weighted_score: Weighted compliance score
            aws_config_score: AWS Config Conformance Pack style score
            score_diff: Difference between the two scores (not displayed)
            
        Returns:
            HTML section comparing the two scoring approaches
        """
        return f"""
        <div class="score-comparison-section">
            <h3>Scoring Methodology Comparison</h3>
            <div class="comparison-grid">
                <div class="comparison-card">
                    <h4>Weighted Score</h4>
                    <div class="comparison-value">{weighted_score:.1f}%</div>
                    <p class="comparison-description">
                        Uses risk-based weighting where critical controls (encryption, access control) 
                        have higher impact on the overall score.
                    </p>
                    <ul class="comparison-features">
                        <li>Prioritizes critical security controls</li>
                        <li>Prevents resource count skew</li>
                        <li>Guides remediation priorities</li>
                    </ul>
                </div>
                
                <div class="comparison-card">
                    <h4>AWS Config Style Score</h4>
                    <div class="comparison-value">{aws_config_score:.1f}%</div>
                    <p class="comparison-description">
                        Simple unweighted calculation: compliant resources divided by total resources. 
                        All rules treated equally regardless of security criticality.
                    </p>
                    <ul class="comparison-features">
                        <li>Simple and straightforward</li>
                        <li>Easy to audit</li>
                        <li>Resource-level tracking</li>
                    </ul>
                </div>
            </div>
        </div>
        """
    
    def _generate_coverage_metrics_section(self, coverage_metrics: Dict[str, Any]) -> str:
        """Generate CIS Controls coverage metrics section.
        
        Args:
            coverage_metrics: Dictionary of coverage metrics by IG
            
        Returns:
            HTML section displaying coverage metrics
        """
        if not coverage_metrics:
            return ""
        
        coverage_cards = ""
        for ig_name in ['IG1', 'IG2', 'IG3']:
            metrics = coverage_metrics.get(ig_name)
            if not metrics:
                continue
            
            coverage_pct = metrics.get('coverage_percentage', 0)
            total_safeguards = metrics.get('total_safeguards', 0)
            covered_safeguards = metrics.get('covered_safeguards', 0)
            implemented_rules = metrics.get('implemented_rules', 0)
            description = metrics.get('safeguard_details', {}).get('coverage_description', '')
            
            status_class = self._get_status_class(coverage_pct)
            
            coverage_cards += f"""
            <div class="coverage-card {status_class}">
                <h4>{ig_name} Coverage</h4>
                <div class="coverage-value">{coverage_pct:.1f}%</div>
                <div class="coverage-details">
                    <p><strong>{covered_safeguards}</strong> of <strong>{total_safeguards}</strong> safeguards covered</p>
                    <p><strong>{implemented_rules}</strong> rules implemented</p>
                    <p class="coverage-description">{description}</p>
                </div>
            </div>
            """
        
        if not coverage_cards:
            return ""
        
        return f"""
        <div class="coverage-metrics-section">
            <h3>CIS Controls v8.1 Coverage</h3>
            <p class="coverage-intro">
                This assessment implements rules that cover CIS Controls v8.1 safeguards across Implementation Groups.
                Coverage indicates the percentage of safeguards that have at least one assessment rule.
            </p>
            <div class="coverage-grid">
                {coverage_cards}
            </div>
        </div>
        """
    
    def set_chart_options(self, include_charts: bool = True) -> None:
        """Configure chart inclusion options.
        
        Args:
            include_charts: Whether to include interactive charts
        """
        self.include_charts = include_charts
        logger.debug(f"Updated chart options: include_charts={include_charts}")
    
    def validate_html_output(self, html_content: str) -> bool:
        """Validate that the generated HTML is well-formed.
        
        Args:
            html_content: HTML content string to validate
            
        Returns:
            True if HTML appears valid, False otherwise
        """
        # Basic HTML validation checks
        required_elements = ['<!DOCTYPE html>', '<html', '<head>', '<body>', '</html>']
        
        for element in required_elements:
            if element not in html_content:
                logger.error(f"HTML validation failed: missing {element}")
                return False
        
        # Check for balanced tags (basic check)
        open_tags = html_content.count('<div')
        close_tags = html_content.count('</div>')
        
        if abs(open_tags - close_tags) > 5:  # Allow some tolerance
            logger.warning(f"HTML validation warning: unbalanced div tags ({open_tags} open, {close_tags} close)")
        
        logger.debug("HTML validation passed")
        return True
    
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
        
        # Allow empty IG scores for HTML reporter (can handle empty data)
        # if not assessment_result.ig_scores:
        #     logger.error("Assessment result missing ig_scores")
        #     return False
        
        # Validate compliance summary
        if compliance_summary.overall_compliance_percentage < 0 or compliance_summary.overall_compliance_percentage > 100:
            logger.error(f"Invalid overall compliance percentage: {compliance_summary.overall_compliance_percentage}")
            return False
        
        logger.debug("Assessment data validation passed")
        return True
    
    def extract_summary_data(self, html_content: str) -> Optional[Dict[str, Any]]:
        """Extract summary data from generated HTML report.
        
        Args:
            html_content: HTML report content
            
        Returns:
            Dictionary containing summary data or None if extraction fails
        """
        try:
            # Simple extraction using string parsing
            # In a production system, would use proper HTML parsing
            
            summary_data = {}
            
            # Extract account ID
            if 'AWS Account:' in html_content:
                start = html_content.find('AWS Account:') + len('AWS Account:')
                end = html_content.find('|', start)
                if end > start:
                    summary_data['account_id'] = html_content[start:end].strip()
            
            # Extract overall compliance
            if 'Overall Compliance:' in html_content:
                start = html_content.find('Overall Compliance:') + len('Overall Compliance:')
                end = html_content.find('%', start)
                if end > start:
                    try:
                        summary_data['overall_compliance'] = float(html_content[start:end].strip())
                    except ValueError:
                        pass
            
            return summary_data if summary_data else None
            
        except Exception as e:
            logger.error(f"Failed to extract summary data from HTML: {e}")
            return None
    def _get_unique_controls_per_ig(self, implementation_groups: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """Get unique controls per Implementation Group to avoid duplication.
        
        Filters controls to show only those unique to each IG level, eliminating
        redundancy in the Implementation Groups section. IG2 shows only controls
        not in IG1, and IG3 shows only controls not in IG1 or IG2.
        
        Args:
            implementation_groups: Implementation groups data with all controls
            
        Returns:
            Dictionary mapping IG names to their unique controls:
            - IG1: All IG1 controls (foundational)
            - IG2: Only controls unique to IG2 (not in IG1)
            - IG3: Only controls unique to IG3 (not in IG1 or IG2)
        
        Examples:
            Input:
            {
                'IG1': {'controls': {'1.1': {...}, '1.5': {...}}},
                'IG2': {'controls': {'1.1': {...}, '1.5': {...}, '5.2': {...}}},
                'IG3': {'controls': {'1.1': {...}, '1.5': {...}, '5.2': {...}, '13.1': {...}}}
            }
            
            Output:
            {
                'IG1': {'1.1': {...}, '1.5': {...}},  # All IG1 controls
                'IG2': {'5.2': {...}},                 # Only 5.2 is unique to IG2
                'IG3': {'13.1': {...}}                 # Only 13.1 is unique to IG3
            }
        
        Rationale:
            - Eliminates duplicate control cards across IG sections
            - Users see each control once in its originating IG
            - Reduces visual clutter and improves report readability
            - IG membership badges show which IGs include each control
        
        Notes:
            - IG1 controls are always shown in full (foundational set)
            - Higher IGs show only their incremental additions
            - Cumulative nature is explained in the IG explanation box
            - Used by _generate_implementation_groups_section()
        """
        unique_controls = {}
        
        # IG1 controls are always unique to IG1
        if "IG1" in implementation_groups:
            unique_controls["IG1"] = implementation_groups["IG1"]["controls"]
        
        # IG2 unique controls (excluding IG1 controls)
        if "IG2" in implementation_groups:
            ig1_control_ids = set(implementation_groups.get("IG1", {}).get("controls", {}).keys())
            ig2_unique = {}
            for control_id, control_data in implementation_groups["IG2"]["controls"].items():
                if control_id not in ig1_control_ids:
                    ig2_unique[control_id] = control_data
            unique_controls["IG2"] = ig2_unique
        
        # IG3 unique controls (excluding IG1 and IG2 controls)
        if "IG3" in implementation_groups:
            ig1_control_ids = set(implementation_groups.get("IG1", {}).get("controls", {}).keys())
            ig2_control_ids = set(implementation_groups.get("IG2", {}).get("controls", {}).keys())
            ig3_unique = {}
            for control_id, control_data in implementation_groups["IG3"]["controls"].items():
                if control_id not in ig1_control_ids and control_id not in ig2_control_ids:
                    ig3_unique[control_id] = control_data
            unique_controls["IG3"] = ig3_unique
        
        return unique_controls
    
    def _get_ig_description_with_inheritance(self, ig_name: str) -> str:
        """Get IG description with inheritance information.
        
        Args:
            ig_name: Implementation Group name
            
        Returns:
            Description string with inheritance info
        """
        descriptions = {
            "IG1": "Essential Cyber Hygiene",
            "IG2": "Enhanced Security (includes IG1)",
            "IG3": "Advanced Security (includes IG1 + IG2)"
        }
        return descriptions.get(ig_name, "Unknown Implementation Group")
    
    def _get_ig_scope_description(self, ig_name: str, unique_controls_count: int) -> str:
        """Get scope description for an Implementation Group.
        
        Args:
            ig_name: Implementation Group name
            unique_controls_count: Number of unique controls in this IG
            
        Returns:
            Scope description string
        """
        if ig_name == "IG1":
            return f"Showing {unique_controls_count} foundational controls essential for all organizations."
        elif ig_name == "IG2":
            return f"Showing {unique_controls_count} additional controls beyond IG1 for enhanced security."
        elif ig_name == "IG3":
            return f"Showing {unique_controls_count} advanced controls beyond IG1 and IG2 for comprehensive security."
        else:
            return f"Showing {unique_controls_count} controls for this implementation group."
    def _generate_resource_details_section(self, html_data: Dict[str, Any]) -> str:
        """Generate comprehensive resource details section.
        
        Args:
            html_data: Enhanced HTML report data
            
        Returns:
            Resource details HTML as string
        """
        # Collect all resources from all IGs and controls
        all_resources = []
        resource_ids_seen = set()
        
        for ig_name, ig_data in html_data["implementation_groups"].items():
            for control_id, control_data in ig_data["controls"].items():
                # Add both compliant and non-compliant findings
                for finding in control_data.get("non_compliant_findings", []):
                    resource_key = f"{finding['resource_id']}_{finding['resource_type']}_{finding['region']}"
                    if resource_key not in resource_ids_seen:
                        all_resources.append({
                            "resource_id": finding["resource_id"],
                            "resource_type": finding["resource_type"],
                            "region": finding["region"],
                            "compliance_status": finding["compliance_status"],
                            "evaluation_reason": finding["evaluation_reason"],
                            "config_rule_name": finding["config_rule_name"],
                            "control_id": control_id,
                            "implementation_group": ig_name
                        })
                        resource_ids_seen.add(resource_key)
                
                # Add compliant findings (we need to get these from the detailed findings)
                for finding in control_data.get("compliant_findings", []):
                    resource_key = f"{finding['resource_id']}_{finding['resource_type']}_{finding['region']}"
                    if resource_key not in resource_ids_seen:
                        all_resources.append({
                            "resource_id": finding["resource_id"],
                            "resource_type": finding["resource_type"],
                            "region": finding["region"],
                            "compliance_status": finding["compliance_status"],
                            "evaluation_reason": finding.get("evaluation_reason", "Resource is compliant"),
                            "config_rule_name": finding["config_rule_name"],
                            "control_id": control_id,
                            "implementation_group": ig_name
                        })
                        resource_ids_seen.add(resource_key)
        
        # Sort resources by compliance status (non-compliant first), then by resource type
        all_resources.sort(key=lambda x: (x["compliance_status"] == "COMPLIANT", x["resource_type"], x["resource_id"]))
        
        # Generate resource table rows
        resource_rows = ""
        for resource in all_resources:
            status_class = "compliant" if resource["compliance_status"] == "COMPLIANT" else "non_compliant"
            status_text = "COMPLIANT" if resource["compliance_status"] == "COMPLIANT" else "NON_COMPLIANT"
            
            # Construct pseudo-ARN for CSV export (v1.1.2)
            # Format: arn:aws:service:region:account:resource-type/resource-id
            # Since we don't have account ID in resource data, we'll use a placeholder
            resource_arn = f"arn:aws:{resource['resource_type'].split('::')[1].lower() if '::' in resource['resource_type'] else 'unknown'}:{resource['region']}:*:{resource['resource_id']}"
            
            resource_rows += f"""
            <tr class="resource-row {status_class}">
                <td data-arn="{resource_arn}"><code>{resource['resource_id']}</code></td>
                <td>{resource['resource_type']}</td>
                <td>{resource['region']}</td>
                <td>
                    <span class="badge {status_class}">
                        {status_text}
                    </span>
                </td>
                <td>{resource['control_id']}</td>
                <td>{resource['config_rule_name']}</td>
                <td class="evaluation-reason">{resource['evaluation_reason']}</td>
            </tr>
            """
        
        # Calculate summary statistics
        total_resources = len(all_resources)
        compliant_resources = len([r for r in all_resources if r["compliance_status"] == "COMPLIANT"])
        non_compliant_resources = total_resources - compliant_resources
        compliance_percentage = (compliant_resources / total_resources * 100) if total_resources > 0 else 0
        
        # Extract unique Control IDs for filter dropdown (v1.1.2)
        unique_control_ids = sorted(set(r["control_id"] for r in all_resources), key=self._sort_control_id)
        control_filter_options = ""
        for control_id in unique_control_ids:
            control_filter_options += f'<option value="{control_id}">{control_id}</option>'
        
        # Generate resource type breakdown
        resource_type_stats = {}
        for resource in all_resources:
            resource_type = resource["resource_type"]
            if resource_type not in resource_type_stats:
                resource_type_stats[resource_type] = {"total": 0, "compliant": 0}
            resource_type_stats[resource_type]["total"] += 1
            if resource["compliance_status"] == "COMPLIANT":
                resource_type_stats[resource_type]["compliant"] += 1
        
        resource_type_breakdown = ""
        for resource_type, stats in sorted(resource_type_stats.items()):
            type_compliance = (stats["compliant"] / stats["total"] * 100) if stats["total"] > 0 else 0
            status_class = self._get_status_class(type_compliance)
            # Ensure minimum width of 5% for visibility when compliance is 0%
            display_width = self._get_display_width(type_compliance)
            
            resource_type_breakdown += f"""
            <div class="resource-type-stat">
                <div class="resource-type-header">
                    <span class="resource-type-name">{resource_type}</span>
                    <span class="resource-type-count">{stats['compliant']}/{stats['total']}</span>
                </div>
                <div class="progress-container">
                    <div class="progress-bar {status_class}" data-width="{display_width}">
                        <span class="progress-text">{type_compliance:.1f}%</span>
                    </div>
                </div>
            </div>
            """
        
        return f"""
        <section id="resource-details" class="resource-details">
            <h2>Resource Details</h2>
            
            <div class="resource-summary">
                <div class="resource-stats-grid">
                    <div class="resource-stat-card">
                        <div class="stat-value">{total_resources}</div>
                        <div class="stat-label">Total Resources</div>
                    </div>
                    <div class="resource-stat-card compliant">
                        <div class="stat-value">{compliant_resources}</div>
                        <div class="stat-label">Compliant</div>
                    </div>
                    <div class="resource-stat-card non-compliant">
                        <div class="stat-value">{non_compliant_resources}</div>
                        <div class="stat-label">Non-Compliant</div>
                    </div>
                    <div class="resource-stat-card">
                        <div class="stat-value">{compliance_percentage:.1f}%</div>
                        <div class="stat-label">Compliance Rate</div>
                    </div>
                </div>
            </div>
            
            <div class="resource-table-container">
                <div class="resource-filters">
                    <input type="text" id="resourceSearch" placeholder="Search resources..." onkeyup="filterResources()" class="search-input">
                    <select id="statusFilter" onchange="filterResources()" class="filter-select">
                        <option value="">All Status</option>
                        <option value="COMPLIANT">Compliant Only</option>
                        <option value="NON_COMPLIANT">Non-Compliant Only</option>
                    </select>
                    <select id="typeFilter" onchange="filterResources()" class="filter-select">
                        <option value="">All Types</option>
                        {self._generate_resource_type_options(resource_type_stats)}
                    </select>
                    <select id="controlFilter" onchange="filterResources()" class="filter-select">
                        <option value="">All Controls</option>
                        {control_filter_options}
                    </select>
                </div>
                
                <div class="pagination-controls" id="paginationControls">
                    <button onclick="changePage(-1)" id="prevPageBtn" disabled>&laquo; Previous</button>
                    <span id="pageInfo">Page 1</span>
                    <button onclick="changePage(1)" id="nextPageBtn">Next &raquo;</button>
                    <span class="page-size-label">Show:</span>
                    <select id="pageSizeSelect" onchange="changePageSize(this.value)" class="filter-select">
                        <option value="10" selected>10</option>
                        <option value="25">25</option>
                        <option value="50">50</option>
                        <option value="100">100</option>
                        <option value="0">All</option>
                    </select>
                    <span id="resourceCount" class="resource-count">{total_resources} resources</span>
                </div>
                
                <table class="findings-table resource-table" id="resourceTable">
                    <thead>
                        <tr>
                            <th onclick="sortResourceTable(0)">Resource ID</th>
                            <th onclick="sortResourceTable(1)">Resource Type</th>
                            <th onclick="sortResourceTable(2)">Region</th>
                            <th onclick="sortResourceTable(3)">Status</th>
                            <th onclick="sortResourceTable(4)">Control</th>
                            <th onclick="sortResourceTable(5)">Config Rule</th>
                            <th>Evaluation Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        {resource_rows}
                    </tbody>
                </table>
                
                <div class="pagination-controls pagination-bottom" id="paginationControlsBottom">
                    <button onclick="changePage(-1)" id="prevPageBtnBottom" disabled>&laquo; Previous</button>
                    <span id="pageInfoBottom">Page 1</span>
                    <button onclick="changePage(1)" id="nextPageBtnBottom">Next &raquo;</button>
                </div>
            </div>
        </section>
        """
    
    def _generate_resource_type_options(self, resource_type_stats: Dict[str, Dict[str, int]]) -> str:
        """Generate option elements for resource type filter.
        
        Args:
            resource_type_stats: Resource type statistics
            
        Returns:
            HTML option elements
        """
        options = ""
        for resource_type in sorted(resource_type_stats.keys()):
            options += f'<option value="{resource_type}">{resource_type}</option>'
        return options
    
    def _load_control_titles(self) -> Dict[str, str]:
        """Load control titles from YAML configuration files.
        
        Returns:
            Dictionary mapping control IDs to their titles
        """
        if self._control_titles_cache:
            return self._control_titles_cache
        
        from aws_cis_assessment.config.config_loader import ConfigRuleLoader
        
        try:
            loader = ConfigRuleLoader()
            all_controls = loader.get_all_controls()
            
            # Build a map of control_id -> title
            # Since controls can appear in multiple IGs, we'll use the first title we find
            for unique_key, control in all_controls.items():
                control_id = control.control_id
                if control_id not in self._control_titles_cache and control.title:
                    self._control_titles_cache[control_id] = control.title
            
            logger.info(f"Loaded {len(self._control_titles_cache)} control titles from YAML")
        except Exception as e:
            logger.warning(f"Failed to load control titles from YAML: {e}")
            self._control_titles_cache = {}
        
        return self._control_titles_cache
    
    def _format_control_display_name(self, control_id: str, config_rule_name: str, title: Optional[str] = None) -> str:
        """Format control display name combining ID and title.
        
        Creates a human-readable display name that shows both the control identifier
        and the control title from the YAML configuration, making it easier for users 
        to understand what each control is about without looking up documentation.
        
        Args:
            control_id: Control identifier (e.g., "1.5", "2.1")
            config_rule_name: AWS Config rule name (e.g., "root-account-hardware-mfa-enabled")
            title: Optional human-readable title for the control (if not provided, loads from YAML)
            
        Returns:
            Formatted string for display in the following formats:
            - With title: "{control_id}: {title}"
            - Without title: "{control_id}: {config_rule_name}"
            - Fallback (no rule name): "{control_id}"
        
        Examples:
            >>> _format_control_display_name("1.1", "eip-attached")
            "1.1: Establish and Maintain Detailed Enterprise Asset Inventory"
            
            >>> _format_control_display_name("3.3", "s3-bucket-ssl-requests-only")
            "3.3: Configure Data Access Control Lists"
            
            >>> _format_control_display_name("3.1", "")
            "3.1"
        
        Notes:
            - Loads control titles from YAML configuration files
            - Gracefully handles missing titles by falling back to config_rule_name
            - Used in both Implementation Groups and Detailed Findings sections
            - Display names longer than 50 characters are truncated with tooltips
        """
        # Load control titles from YAML if not already loaded
        if not title:
            control_titles = self._load_control_titles()
            title = control_titles.get(control_id)
        
        # If we have a title, use it
        if title:
            return f"{control_id}: {title}"
        
        # Fallback to config_rule_name if no title
        if config_rule_name:
            return f"{control_id}: {config_rule_name}"
        
        # Last resort: just the control_id
        return control_id
    
    def _get_ig_badge_class(self, ig_name: str) -> str:
        """Get CSS class for IG badge styling.
        
        Returns the appropriate CSS class for styling Implementation Group badges
        with consistent color coding across the report.
        
        Args:
            ig_name: Implementation Group name (IG1, IG2, or IG3)
            
        Returns:
            CSS class name for the badge:
            - 'ig-badge-1' for IG1 (blue styling)
            - 'ig-badge-2' for IG2 (green styling)
            - 'ig-badge-3' for IG3 (purple styling)
            - 'ig-badge-default' for unknown IGs (gray styling)
        
        Examples:
            >>> _get_ig_badge_class("IG1")
            "ig-badge-1"
            
            >>> _get_ig_badge_class("IG2")
            "ig-badge-2"
            
            >>> _get_ig_badge_class("UNKNOWN")
            "ig-badge-default"
        
        CSS Styling:
            .ig-badge-1 { background-color: #3498db; color: white; }  /* Blue */
            .ig-badge-2 { background-color: #27ae60; color: white; }  /* Green */
            .ig-badge-3 { background-color: #9b59b6; color: white; }  /* Purple */
        
        Notes:
            - Used consistently across Implementation Groups and Detailed Findings sections
            - Provides visual hierarchy for IG levels
            - Can be customized via CSS for different color schemes
        """
        badge_classes = {
            'IG1': 'ig-badge-1',  # Blue
            'IG2': 'ig-badge-2',  # Green
            'IG3': 'ig-badge-3'   # Purple
        }
        return badge_classes.get(ig_name, 'ig-badge-default')
    
    def _enrich_control_metadata(self, control_data: Dict[str, Any], control_id: str, ig_name: str, 
                                 all_igs: Dict[str, Any]) -> Dict[str, Any]:
        """Add display metadata to control data for enhanced HTML presentation.
        
        Enriches control data with additional fields needed for improved display,
        including formatted names, IG membership badges, and truncation indicators.
        
        Modified in v1.1.2 to remove duplicate Control ID prefix from display names.
        
        Args:
            control_data: Existing control data dictionary
            control_id: Control identifier (e.g., "1.5")
            ig_name: Implementation Group name (e.g., "IG1")
            all_igs: All implementation groups data for determining originating IG
            
        Returns:
            Enhanced control data with additional fields:
            - display_name: Formatted name without duplicate Control ID prefix
            - originating_ig: Which IG introduced this control (IG1, IG2, or IG3)
            - ig_badge_class: CSS class for IG badge styling
            - needs_truncation: Boolean indicating if display name exceeds 50 characters
        
        Examples:
            Input control_data:
            {
                'control_id': '1.5',
                'config_rule_name': 'root-account-hardware-mfa-enabled',
                'compliance_percentage': 0.0,
                'total_resources': 1
            }
            
            Output enriched data (includes all input fields plus):
            {
                ...original fields...,
                'display_name': 'root-account-hardware-mfa-enabled',  # No "1.5:" prefix
                'originating_ig': 'IG1',
                'ig_badge_class': 'ig-badge-1',
                'needs_truncation': False
            }
        
        Notes:
            - Called during _enhance_html_structure() for each control
            - Truncation threshold is 50 characters
            - Gracefully handles missing config_rule_name
            - Originating IG is determined by checking IG1, IG2, IG3 in order
            - v1.1.2: Removes duplicate Control ID prefix from display names
        """
        enriched = control_data.copy()
        
        # Get title - prefer YAML title over generic fallback like "CIS Control X.Y"
        title = control_data.get('title')
        if title and title.startswith('CIS Control '):
            title = None  # Ignore generic fallback, let _format_control_display_name look up YAML
        
        # Format display name
        display_name = self._format_control_display_name(
            control_id,
            control_data.get('config_rule_name', ''),
            title
        )
        
        # Remove duplicate Control ID prefix if present (v1.1.2 improvement)
        # Check if display_name starts with "control_id: "
        prefix = f"{control_id}: "
        if display_name.startswith(prefix):
            display_name = display_name[len(prefix):]
        
        enriched['display_name'] = display_name
        
        # Determine originating IG (which IG introduced this control)
        originating_ig = self._determine_originating_ig(control_id, all_igs)
        enriched['originating_ig'] = originating_ig
        
        # Get badge class for the originating IG
        enriched['ig_badge_class'] = self._get_ig_badge_class(originating_ig)
        
        # Check if truncation is needed (threshold: 50 characters)
        enriched['needs_truncation'] = len(enriched['display_name']) > 50
        
        return enriched
    
    def _determine_originating_ig(self, control_id: str, all_igs: Dict[str, Any]) -> str:
        """Determine which Implementation Group introduced a control.
        
        Args:
            control_id: Control identifier
            all_igs: All implementation groups data
            
        Returns:
            Name of the IG that introduced this control (IG1, IG2, or IG3)
        """
        # Check in order: IG1, IG2, IG3
        # The first IG that contains the control is the originating IG
        for ig_name in ['IG1', 'IG2', 'IG3']:
            if ig_name in all_igs:
                if control_id in all_igs[ig_name].get('controls', {}):
                    return ig_name
        
        # Default to IG1 if not found
        return 'IG1'
    
    def _consolidate_findings_by_control(self, implementation_groups: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """Consolidate findings from all IGs, grouped by control ID only.
        
        This method deduplicates findings across Implementation Groups so that each
        finding appears only once in the Detailed Findings section, eliminating
        redundancy when a control appears in multiple IGs.
        
        Args:
            implementation_groups: Implementation groups data with controls and findings
            
        Returns:
            Dictionary mapping control_id -> consolidated control data with:
            - findings: List of deduplicated non-compliant findings
            - member_igs: List of IGs that include this control (e.g., ["IG1", "IG2"])
            - config_rule_name: AWS Config rule name for the control
            - title: Human-readable title for the control
            
            Results are sorted by control ID in alphanumeric order.
        
        Examples:
            Input: Control "1.5" appears in IG1, IG2, and IG3 with same findings
            Output: Single entry for "1.5" with:
            {
                '1.5': {
                    'findings': [...deduplicated findings...],
                    'member_igs': ['IG1', 'IG2', 'IG3'],
                    'config_rule_name': 'root-account-hardware-mfa-enabled',
                    'title': 'Root Account Hardware MFA'
                }
            }
        
        Deduplication Strategy:
            - Uses (resource_id, control_id, region) tuple as unique key
            - Prevents same resource from appearing multiple times
            - Preserves all unique findings across IGs
        
        Sorting:
            - Controls are sorted alphanumerically (1.1, 1.2, ..., 1.10, 2.1, ...)
            - Uses _sort_control_id() helper for proper numeric sorting
        
        Notes:
            - Eliminates "IG1 Detailed Findings", "IG2 Detailed Findings" subsections
            - Each control appears once with IG membership indicators
            - Improves report readability and reduces redundancy
        """
        consolidated = {}
        seen_findings = set()  # Track (resource_id, control_id, region) tuples for deduplication
        
        for ig_name, ig_data in implementation_groups.items():
            for control_id, control_data in ig_data.get('controls', {}).items():
                # Initialize control entry if not exists
                if control_id not in consolidated:
                    consolidated[control_id] = {
                        'findings': [],
                        'member_igs': [],
                        'config_rule_name': control_data.get('config_rule_name', ''),
                        'title': control_data.get('title', f'CIS Control {control_id}')
                    }
                
                # Track which IGs include this control
                consolidated[control_id]['member_igs'].append(ig_name)
                
                # Add non-compliant findings (deduplicated)
                for finding in control_data.get('non_compliant_findings', []):
                    finding_key = (finding.get('resource_id', ''), control_id, finding.get('region', ''))
                    if finding_key not in seen_findings:
                        consolidated[control_id]['findings'].append(finding)
                        seen_findings.add(finding_key)
        
        # Sort by control ID using alphanumeric sorting
        return dict(sorted(consolidated.items(), key=lambda x: self._sort_control_id(x[0])))
    
    def _get_control_ig_membership(self, control_id: str, implementation_groups: Dict[str, Any]) -> List[str]:
        """Determine which Implementation Groups include a specific control.
        
        Checks all Implementation Groups (IG1, IG2, IG3) to identify which ones
        contain the specified control, enabling display of IG membership badges.
        
        Args:
            control_id: Control identifier (e.g., "1.5", "2.1")
            implementation_groups: All IG data from the assessment
            
        Returns:
            List of IG names that include this control, in order.
            Examples:
            - ["IG1", "IG2", "IG3"] for a control in all IGs
            - ["IG1", "IG2"] for a control in IG1 and IG2 only
            - ["IG3"] for a control unique to IG3
            - [] for a control not found in any IG
        
        Examples:
            >>> _get_control_ig_membership("1.5", implementation_groups)
            ["IG1", "IG2", "IG3"]  # Control 1.5 is in all IGs
            
            >>> _get_control_ig_membership("5.2", implementation_groups)
            ["IG2", "IG3"]  # Control 5.2 is only in IG2 and IG3
        
        Notes:
            - Used to display IG membership badges in Detailed Findings section
            - Helps users understand which IGs require remediation for each control
            - Checks IGs in order: IG1, IG2, IG3
        """
        member_igs = []
        for ig_name in ['IG1', 'IG2', 'IG3']:
            if ig_name in implementation_groups:
                if control_id in implementation_groups[ig_name].get('controls', {}):
                    member_igs.append(ig_name)
        return member_igs
    
    def _sort_control_id(self, control_id: str) -> tuple:
        """Helper for alphanumeric sorting of control IDs.
        
        Converts control IDs like "1.1", "1.10", "2.1" into tuples of integers
        for proper alphanumeric sorting. This ensures controls are displayed in
        the correct order (1.1, 1.2, ..., 1.9, 1.10, 2.1, ...) rather than
        lexicographic order (1.1, 1.10, 1.2, ...).
        
        Args:
            control_id: Control identifier (e.g., "1.1", "1.10", "2.1")
            
        Returns:
            Tuple of integers for sorting (e.g., (1, 1), (1, 10), (2, 1))
            Returns (0, 0) for non-standard control IDs as fallback
        
        Examples:
            >>> _sort_control_id("1.1")
            (1, 1)
            
            >>> _sort_control_id("1.10")
            (1, 10)
            
            >>> _sort_control_id("2.1")
            (2, 1)
            
            >>> _sort_control_id("invalid")
            (0, 0)  # Fallback for non-standard IDs
        
        Sorting Behavior:
            Without this helper:
            ["1.1", "1.10", "1.2", "2.1"]  # Incorrect lexicographic order
            
            With this helper:
            ["1.1", "1.2", "1.10", "2.1"]  # Correct numeric order
        
        Notes:
            - Used in _consolidate_findings_by_control() for sorting
            - Handles multi-level control IDs (e.g., "1.2.3" -> (1, 2, 3))
            - Gracefully handles malformed control IDs
        """
        try:
            # Split by '.' and convert to integers
            parts = control_id.split('.')
            return tuple(int(part) for part in parts)
        except (ValueError, AttributeError):
            # Fallback for non-standard control IDs
            return (0, 0)
    def _build_controls_overview_data(self, html_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Build deduplicated, sorted list of control summaries for the Controls Overview table.

        Iterates implementation groups in IG1→IG2→IG3 order, recording each control
        only on first encounter (giving the originating/lowest IG). Collects per-control
        metrics into a flat list of dictionaries.

        Args:
            html_data: Enhanced HTML report data containing implementation_groups

        Returns:
            Sorted list of control summary dicts with keys: control_id, safeguard_name,
            implementation_group, num_rules, compliant_resources, non_compliant_resources,
            total_resources, compliance_percentage, status_class
        """
        # CIS Controls v8.1 official safeguard names
        cis_safeguard_names = {
            "1.1": "Establish and Maintain Detailed Enterprise Asset Inventory",
            "1.2": "Address Unauthorized Assets",
            "1.3": "Utilize an Active Discovery Tool",
            "1.4": "Use Dynamic Host Configuration Protocol (DHCP) Logging to Update Enterprise Asset Inventory",
            "1.5": "Use a Passive Asset Discovery Tool",
            "2.1": "Establish and Maintain a Software Inventory",
            "2.2": "Ensure Authorized Software is Currently Supported",
            "2.3": "Address Unauthorized Software",
            "2.4": "Utilize Automated Software Inventory Tools",
            "2.5": "Allowlist Authorized Software",
            "2.6": "Allowlist Authorized Libraries",
            "2.7": "Allowlist Authorized Scripts",
            "3.1": "Establish and Maintain a Data Management Process",
            "3.2": "Establish and Maintain a Data Inventory",
            "3.3": "Configure Data Access Control Lists",
            "3.4": "Enforce Data Retention",
            "3.5": "Securely Dispose of Data",
            "3.6": "Encrypt Data on End-User Devices",
            "3.7": "Establish and Maintain a Data Classification Scheme",
            "3.8": "Document Data Flows",
            "3.9": "Encrypt Data on Removable Media",
            "3.10": "Encrypt Sensitive Data in Transit",
            "3.11": "Encrypt Sensitive Data at Rest",
            "3.12": "Segment Data Processing and Storage Based on Sensitivity",
            "3.13": "Deploy a Data Loss Prevention Solution",
            "3.14": "Log Sensitive Data Access",
            "4.1": "Establish and Maintain a Secure Configuration Process",
            "4.2": "Establish and Maintain a Secure Configuration Process for Network Infrastructure",
            "4.3": "Configure Automatic Session Locking on Enterprise Assets",
            "4.4": "Implement and Manage a Firewall on Servers",
            "4.5": "Implement and Manage a Firewall on End-User Devices",
            "4.6": "Securely Manage Enterprise Assets and Software",
            "4.7": "Manage Default Accounts on Enterprise Assets and Software",
            "4.8": "Uninstall or Disable Unnecessary Services on Enterprise Assets and Applications",
            "4.9": "Configure Trusted DNS Servers on Enterprise Assets",
            "4.10": "Enforce Automatic Device Lockout on Portable End-User Devices",
            "4.11": "Enforce Remote Wipe Capability on Portable End-User Devices",
            "4.12": "Separate Enterprise Workspaces on Mobile End-User Devices",
            "5.1": "Establish and Maintain an Inventory of Accounts",
            "5.2": "Use Unique Passwords",
            "5.3": "Disable Dormant Accounts",
            "5.4": "Restrict Administrator Privileges to Dedicated Administrator Accounts",
            "5.5": "Establish and Maintain an Inventory of Service Accounts",
            "5.6": "Centralize Account Management",
            "6.1": "Establish an Access Granting Process",
            "6.2": "Establish an Access Revoking Process",
            "6.3": "Require MFA for Externally-Exposed Applications",
            "6.4": "Require MFA for Remote Network Access",
            "6.5": "Require MFA for Administrative Access",
            "6.6": "Establish and Maintain an Inventory of Authentication and Authorization Systems",
            "6.7": "Centralize Access Control",
            "6.8": "Define and Maintain Role-Based Access Control",
            "7.1": "Establish and Maintain a Vulnerability Management Process",
            "7.2": "Establish and Maintain a Remediation Process",
            "7.3": "Perform Automated Operating System Patch Management",
            "7.4": "Perform Automated Application Patch Management",
            "7.5": "Perform Automated Vulnerability Scans of Internal Enterprise Assets",
            "7.6": "Perform Automated Vulnerability Scans of Externally-Exposed Enterprise Assets",
            "7.7": "Remediate Detected Vulnerabilities",
            "8.1": "Establish and Maintain an Audit Log Management Process",
            "8.2": "Collect Audit Logs",
            "8.3": "Ensure Adequate Audit Log Storage",
            "8.4": "Standardize Time Synchronization",
            "8.5": "Collect Detailed Audit Logs",
            "8.6": "Collect DNS Query Audit Logs",
            "8.7": "Collect URL Request Audit Logs",
            "8.8": "Collect Command-Line Audit Logs",
            "8.9": "Centralize Audit Logs",
            "8.10": "Retain Audit Logs",
            "8.11": "Conduct Audit Log Reviews",
            "8.12": "Collect Service Provider Logs",
            "9.1": "Ensure Use of Only Fully Supported Browsers and Email Clients",
            "9.2": "Use DNS Filtering Services",
            "9.3": "Maintain and Enforce Network-Based URL Filters",
            "9.4": "Restrict Unnecessary or Unauthorized Browser and Email Client Extensions",
            "9.5": "Implement DMARC",
            "9.6": "Block Unnecessary File Types",
            "9.7": "Deploy and Maintain Email Server Anti-Malware Protections",
            "10.1": "Deploy and Maintain Anti-Malware Software",
            "10.2": "Configure Automatic Anti-Malware Signature Updates",
            "10.3": "Disable Autorun and Autoplay for Removable Media",
            "10.4": "Configure Automatic Anti-Malware Scanning of Removable Media",
            "10.5": "Enable Anti-Exploitation Features",
            "10.6": "Centrally Manage Anti-Malware Software",
            "10.7": "Use Behavior-Based Anti-Malware Software",
            "11.1": "Establish and Maintain a Data Recovery Process",
            "11.2": "Perform Automated Backups",
            "11.3": "Protect Recovery Data",
            "11.4": "Establish and Maintain an Isolated Instance of Recovery Data",
            "11.5": "Test Data Recovery",
            "12.1": "Ensure Network Infrastructure is Up-to-Date",
            "12.2": "Establish and Maintain a Secure Network Architecture",
            "12.3": "Securely Manage Network Infrastructure",
            "12.4": "Establish and Maintain Architecture Diagram(s)",
            "12.5": "Centralize Network Authentication, Authorization, and Auditing (AAA)",
            "12.6": "Use of Secure Network Management and Communication Protocols",
            "12.7": "Ensure Remote Devices Utilize a VPN and are Connecting to an Enterprise AAA Infrastructure",
            "12.8": "Establish and Maintain Dedicated Computing Resources for All Administrative Work",
            "13.1": "Centralize Security Event Alerting",
            "13.2": "Deploy a Host-Based Intrusion Detection Solution",
            "13.3": "Deploy a Network Intrusion Detection Solution",
            "13.4": "Perform Traffic Filtering Between Network Segments",
            "13.5": "Manage Access Control for Remote Assets",
            "13.6": "Collect Network Traffic Flow Logs",
            "13.7": "Deploy a Host-Based Intrusion Prevention Solution",
            "13.8": "Deploy a Network Intrusion Prevention Solution",
            "13.9": "Deploy Port-Level Access Control",
            "13.10": "Perform Application Layer Filtering",
            "13.11": "Tune Security Event Alerting Thresholds",
            "14.1": "Establish and Maintain a Security Awareness Program",
            "14.2": "Train Workforce Members to Recognize Social Engineering Attacks",
            "14.3": "Train Workforce Members on Authentication Best Practices",
            "14.4": "Train Workforce on Data Handling Best Practices",
            "14.5": "Train Workforce Members on Causes of Unintentional Data Exposure",
            "14.6": "Train Workforce Members on Recognizing and Reporting Security Incidents",
            "14.7": "Train Workforce on How to Identify and Report Missing Security Updates",
            "14.8": "Train Workforce on the Dangers of Connecting to and Transmitting Data Over Insecure Networks",
            "14.9": "Conduct Role-Specific Security Awareness and Skills Training",
            "15.1": "Establish and Maintain an Inventory of Service Providers",
            "15.2": "Establish and Maintain a Service Provider Management Policy",
            "15.3": "Classify Service Providers",
            "15.5": "Assess Service Providers",
            "15.6": "Monitor Service Providers",
            "15.7": "Securely Decommission Service Providers",
            "16.1": "Establish and Maintain a Secure Application Development Process",
            "16.2": "Establish and Maintain a Process to Accept and Address Software Vulnerabilities",
            "16.3": "Perform Root Cause Analysis on Security Vulnerabilities",
            "16.4": "Establish and Manage an Inventory of Third-Party Software Components",
            "16.5": "Use Up-to-Date and Trusted Third-Party Software Components",
            "16.6": "Establish and Maintain a Severity Rating System and Process for Application Vulnerabilities",
            "16.7": "Use Standard Hardening Configuration Templates for Application Infrastructure",
            "16.8": "Separate Production and Non-Production Systems",
            "16.9": "Train Developers in Application Security Concepts and Secure Coding",
            "16.10": "Apply Secure Design Principles in Application Architectures",
            "16.11": "Leverage Vetted Modules or Services for Application Security Components",
            "16.12": "Implement Code-Level Security Checks",
            "16.13": "Conduct Application Penetration Testing",
            "16.14": "Conduct Threat Modeling",
            "17.1": "Designate Personnel to Manage Incident Handling",
            "17.2": "Establish and Maintain Contact Information for Reporting Security Incidents",
            "17.3": "Establish and Maintain an Enterprise Process for Reporting Incidents",
            "17.4": "Establish and Maintain an Incident Response Process",
            "17.5": "Assign Key Roles and Responsibilities",
            "17.6": "Define Mechanisms for Communicating During Incident Response",
            "17.7": "Conduct Routine Incident Response Exercises",
            "17.8": "Conduct Post-Incident Reviews",
            "17.9": "Establish and Maintain Security Incident Thresholds",
            "18.1": "Establish and Maintain a Penetration Testing Program",
            "18.2": "Perform Periodic External Penetration Tests",
            "18.3": "Remediate Penetration Test Findings",
            "18.4": "Validate Security Measures",
            "18.5": "Perform Periodic Internal Penetration Tests",
        }

        seen_controls = {}  # control_id -> dict
        ig_order = ["IG1", "IG2", "IG3"]

        for ig_name in ig_order:
            ig_data = html_data.get("implementation_groups", {}).get(ig_name)
            if not ig_data:
                continue
            for control_id, control_data in ig_data.get("controls", {}).items():
                if control_id in seen_controls:
                    continue

                # Resolve safeguard name: official CIS name first, then YAML title, then fallback
                safeguard_name = cis_safeguard_names.get(control_id) or control_data.get("title") or control_data.get("display_name") or f"CIS Control {control_id}"

                total = control_data.get("total_resources", 0)
                compliant = control_data.get("compliant_resources", 0)
                non_compliant = total - compliant
                pct = control_data.get("compliance_percentage", 0.0)

                # Handle zero total edge case
                if total == 0:
                    pct = 0.0

                # Collect config rule names for display
                rule_names_list = control_data.get("config_rules_evaluated", [])
                if isinstance(rule_names_list, list):
                    rule_names = ", ".join(sorted(set(rule_names_list)))
                else:
                    rule_names = str(rule_names_list) if rule_names_list else ""

                seen_controls[control_id] = {
                    "control_id": control_id,
                    "safeguard_name": safeguard_name,
                    "implementation_group": ig_name,
                    "num_rules": len(rule_names_list) if isinstance(rule_names_list, list) else control_data.get("config_rules_evaluated", 0),
                    "rule_names": rule_names,
                    "compliant_resources": compliant,
                    "non_compliant_resources": non_compliant,
                    "total_resources": total,
                    "compliance_percentage": pct,
                    "status_class": self._get_status_class(pct),
                }

        # Sort by control ID alphanumerically
        result = list(seen_controls.values())
        result.sort(key=lambda c: self._sort_control_id(c["control_id"]))
        return result

    def _generate_controls_overview_section(self, html_data: Dict[str, Any]) -> str:
        """Generate the CIS Controls Overview section with filterable, sortable table.

        Args:
            html_data: Enhanced HTML report data

        Returns:
            Controls Overview HTML section as string
        """
        controls = self._build_controls_overview_data(html_data)

        # Compute summary stats
        total_controls = len(controls)
        fully_compliant = sum(1 for c in controls if c["compliance_percentage"] == 100.0)
        needs_attention = total_controls - fully_compliant
        avg_compliance = (sum(c["compliance_percentage"] for c in controls) / total_controls) if total_controls > 0 else 0.0

        # Build table rows
        table_rows = ""
        import html as html_module
        for c in controls:
            status_color = "#27ae60" if c["compliance_percentage"] > 80 else "#f39c12" if c["compliance_percentage"] >= 50 else "#e74c3c"
            safe_safeguard = html_module.escape(c['safeguard_name'])
            safe_rules = html_module.escape(c['rule_names']) if c['rule_names'] else ""
            rules_display = safe_rules if safe_rules else f"{c['num_rules']} rule(s)"
            rules_tooltip = safe_rules if safe_rules else ""
            table_rows += f"""
                <tr class="controls-overview-row" data-ig="{c['implementation_group']}" data-compliance="{c['compliance_percentage']}" data-rules="{safe_rules}">
                    <td class="co-control-id"><a onclick="onControlRowClick('{c['control_id']}')">{c['control_id']}</a></td>
                    <td class="co-safeguard-name"><span title="{safe_safeguard}">{c['safeguard_name']}</span></td>
                    <td><span class="ig-tag ig-tag-{c['implementation_group'].lower()}">{c['implementation_group']}</span></td>
                    <td class="co-rules-cell"><span title="{rules_tooltip}">{rules_display}</span></td>
                    <td class="co-numeric co-compliant">{c['compliant_resources']}</td>
                    <td class="co-numeric co-non-compliant">{c['non_compliant_resources']}</td>
                    <td class="co-numeric">{c['total_resources']}</td>
                    <td class="co-numeric">
                        <div class="co-compliance-cell">
                            <div class="co-compliance-bar-bg">
                                <div class="co-compliance-bar-fill" style="width: {max(c['compliance_percentage'], 2)}%; background: {status_color};"></div>
                            </div>
                            <span class="co-compliance-pct" style="color: {status_color};">{c['compliance_percentage']:.1f}%</span>
                        </div>
                    </td>
                </tr>"""

        # Build unique sorted list of rule names for dropdown
        all_rule_names = set()
        for c in controls:
            if c['rule_names']:
                for rn in c['rule_names'].split(', '):
                    rn = rn.strip()
                    if rn:
                        all_rule_names.add(rn)
        rule_options = ""
        for rn in sorted(all_rule_names):
            rule_options += f'<option value="{html_module.escape(rn)}">{html_module.escape(rn)}</option>'

        # Build IG compliance cards
        exec_summary = html_data.get("executive_summary", {})
        ig_cards = ""
        for ig_key, ig_label in [("ig1", "IG1"), ("ig2", "IG2"), ("ig3", "IG3")]:
            ig_pct = exec_summary.get(f"{ig_key}_compliance_percentage", 0)
            ig_color = "#27ae60" if ig_pct > 80 else "#f39c12" if ig_pct >= 50 else "#e74c3c"
            ig_cards += f"""
                <div class="co-summary-card" style="border-top: 3px solid {ig_color};">
                    <div class="co-summary-value" style="color: {ig_color};">{ig_pct:.1f}%</div>
                    <div class="co-summary-label">{ig_label} Compliance</div>
                </div>"""

        return f"""
        <section id="controls-overview" class="controls-overview">
            <h2>CIS Controls Overview</h2>
            <p class="section-description">Comprehensive view of all CIS Controls with compliance summaries. Click a Control ID to jump to its resource details.</p>

            <div class="co-summary" id="coSummary">
                {ig_cards}
                <div class="co-summary-card">
                    <div class="co-summary-value" id="coTotalControls">{total_controls}</div>
                    <div class="co-summary-label">Total Controls</div>
                </div>
                <div class="co-summary-card co-card-good">
                    <div class="co-summary-value" id="coFullyCompliant">{fully_compliant}</div>
                    <div class="co-summary-label">Fully Compliant</div>
                </div>
                <div class="co-summary-card co-card-attention">
                    <div class="co-summary-value" id="coNeedsAttention">{needs_attention}</div>
                    <div class="co-summary-label">Needs Attention</div>
                </div>
                <div class="co-summary-card">
                    <div class="co-summary-value" id="coAvgCompliance">{avg_compliance:.1f}%</div>
                    <div class="co-summary-label">Avg Compliance</div>
                </div>
            </div>

            <div class="co-filters">
                <div class="co-ig-filters">
                    <button class="co-ig-btn active" onclick="filterCOByIG(this, '')" data-ig="">All</button>
                    <button class="co-ig-btn" onclick="filterCOByIG(this, 'IG1')" data-ig="IG1">IG1</button>
                    <button class="co-ig-btn" onclick="filterCOByIG(this, 'IG2')" data-ig="IG2">IG2</button>
                    <button class="co-ig-btn" onclick="filterCOByIG(this, 'IG3')" data-ig="IG3">IG3</button>
                </div>
                <select id="coStatusFilter" onchange="filterControlsOverview()" class="co-select">
                    <option value="">All Status</option>
                    <option value="compliant">Fully Compliant</option>
                    <option value="attention">Needs Attention</option>
                </select>
                <select id="coRuleFilter" onchange="filterControlsOverview()" class="co-select">
                    <option value="">All Rules</option>
                    {rule_options}
                </select>
                <input type="text" id="coSearchInput" placeholder="Search by Control ID, Name, or Rule..." onkeyup="filterControlsOverview()" class="co-search">
            </div>

            <div class="co-table-wrapper">
                <table class="co-table" id="controlsOverviewTable">
                    <thead>
                        <tr>
                            <th onclick="sortControlsOverviewTable(0)" class="co-sortable">Control ID &#x25B4;&#x25BE;</th>
                            <th onclick="sortControlsOverviewTable(1)" class="co-sortable">Safeguard Name &#x25B4;&#x25BE;</th>
                            <th onclick="sortControlsOverviewTable(2)" class="co-sortable">IG &#x25B4;&#x25BE;</th>
                            <th onclick="sortControlsOverviewTable(3)" class="co-sortable">Rules &#x25B4;&#x25BE;</th>
                            <th onclick="sortControlsOverviewTable(4)" class="co-sortable">Compliant &#x25B4;&#x25BE;</th>
                            <th onclick="sortControlsOverviewTable(5)" class="co-sortable">Non-Compliant &#x25B4;&#x25BE;</th>
                            <th onclick="sortControlsOverviewTable(6)" class="co-sortable">Total &#x25B4;&#x25BE;</th>
                            <th onclick="sortControlsOverviewTable(7)" class="co-sortable">Compliance &#x25B4;&#x25BE;</th>
                        </tr>
                    </thead>
                    <tbody id="coTableBody">
                        {table_rows}
                    </tbody>
                </table>
            </div>
        </section>
        """


