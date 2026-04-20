"""Accuracy validation against AWS Config rule evaluations."""

import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import boto3
from botocore.exceptions import ClientError

from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Result of accuracy validation."""
    config_rule_name: str
    total_resources: int
    matching_results: int
    accuracy_percentage: float
    discrepancies: List[Dict[str, Any]]
    validation_timestamp: datetime
    
    @property
    def is_accurate(self) -> bool:
        """Check if validation meets accuracy threshold."""
        return self.accuracy_percentage >= 95.0  # 95% accuracy threshold


@dataclass
class ValidationSummary:
    """Summary of all validation results."""
    total_rules_validated: int
    accurate_rules: int
    overall_accuracy: float
    validation_results: List[ValidationResult]
    validation_timestamp: datetime
    
    @property
    def accuracy_percentage(self) -> float:
        """Calculate overall accuracy percentage."""
        if self.total_rules_validated == 0:
            return 0.0
        return (self.accurate_rules / self.total_rules_validated) * 100


class AccuracyValidator:
    """Validates assessment accuracy against AWS Config rule evaluations."""
    
    def __init__(self, aws_factory: AWSClientFactory):
        """Initialize accuracy validator.
        
        Args:
            aws_factory: AWS client factory for API access
        """
        self.aws_factory = aws_factory
        self.config_clients = {}
        self._initialize_config_clients()
    
    def _initialize_config_clients(self):
        """Initialize AWS Config clients for all regions."""
        for region in self.aws_factory.regions:
            try:
                self.config_clients[region] = self.aws_factory.get_client('config', region)
                logger.debug(f"Initialized Config client for region: {region}")
            except Exception as e:
                logger.warning(f"Failed to initialize Config client for {region}: {e}")
    
    def validate_assessment_accuracy(self, 
                                   assessment_results: List[ComplianceResult],
                                   config_rule_names: Optional[List[str]] = None) -> ValidationSummary:
        """Validate assessment accuracy against AWS Config evaluations.
        
        Args:
            assessment_results: Results from our assessment
            config_rule_names: Optional list of specific Config rules to validate
            
        Returns:
            ValidationSummary with accuracy metrics
        """
        logger.info("Starting assessment accuracy validation against AWS Config")
        
        # Group results by Config rule and region
        results_by_rule = self._group_results_by_rule(assessment_results)
        
        # Filter by specific rules if provided
        if config_rule_names:
            results_by_rule = {
                rule: results for rule, results in results_by_rule.items()
                if rule in config_rule_names
            }
        
        validation_results = []
        
        for config_rule_name, rule_results in results_by_rule.items():
            logger.info(f"Validating accuracy for Config rule: {config_rule_name}")
            
            try:
                validation_result = self._validate_single_rule(config_rule_name, rule_results)
                validation_results.append(validation_result)
                
                logger.info(f"  Accuracy: {validation_result.accuracy_percentage:.1f}% "
                          f"({validation_result.matching_results}/{validation_result.total_resources})")
                
            except Exception as e:
                logger.error(f"Failed to validate {config_rule_name}: {e}")
                # Create failed validation result
                validation_results.append(ValidationResult(
                    config_rule_name=config_rule_name,
                    total_resources=len(rule_results),
                    matching_results=0,
                    accuracy_percentage=0.0,
                    discrepancies=[{"error": str(e)}],
                    validation_timestamp=datetime.now()
                ))
        
        # Calculate overall accuracy
        accurate_rules = sum(1 for result in validation_results if result.is_accurate)
        overall_accuracy = (accurate_rules / len(validation_results) * 100) if validation_results else 0.0
        
        summary = ValidationSummary(
            total_rules_validated=len(validation_results),
            accurate_rules=accurate_rules,
            overall_accuracy=overall_accuracy,
            validation_results=validation_results,
            validation_timestamp=datetime.now()
        )
        
        logger.info(f"Validation completed: {summary.accuracy_percentage:.1f}% overall accuracy "
                   f"({accurate_rules}/{len(validation_results)} rules accurate)")
        
        return summary
    
    def _group_results_by_rule(self, results: List[ComplianceResult]) -> Dict[str, List[ComplianceResult]]:
        """Group compliance results by Config rule name.
        
        Args:
            results: List of compliance results
            
        Returns:
            Dictionary mapping rule names to results
        """
        grouped = {}
        for result in results:
            rule_name = result.config_rule_name
            if rule_name not in grouped:
                grouped[rule_name] = []
            grouped[rule_name].append(result)
        
        return grouped
    
    def _validate_single_rule(self, config_rule_name: str, 
                             our_results: List[ComplianceResult]) -> ValidationResult:
        """Validate accuracy for a single Config rule.
        
        Args:
            config_rule_name: Name of the Config rule
            our_results: Our assessment results for this rule
            
        Returns:
            ValidationResult with accuracy metrics
        """
        # Get AWS Config evaluations for this rule
        config_evaluations = self._get_config_evaluations(config_rule_name)
        
        if not config_evaluations:
            logger.warning(f"No Config evaluations found for rule: {config_rule_name}")
            return ValidationResult(
                config_rule_name=config_rule_name,
                total_resources=len(our_results),
                matching_results=0,
                accuracy_percentage=0.0,
                discrepancies=[{"error": "No Config evaluations available"}],
                validation_timestamp=datetime.now()
            )
        
        # Compare our results with Config evaluations
        matching_results = 0
        discrepancies = []
        
        # Create lookup for our results
        our_results_lookup = {
            (result.resource_id, result.region): result 
            for result in our_results
        }
        
        # Create lookup for Config evaluations
        config_lookup = {
            (eval_data['ResourceId'], eval_data['Region']): eval_data
            for eval_data in config_evaluations
        }
        
        # Compare results
        all_resource_keys = set(our_results_lookup.keys()) | set(config_lookup.keys())
        
        for resource_key in all_resource_keys:
            resource_id, region = resource_key
            
            our_result = our_results_lookup.get(resource_key)
            config_result = config_lookup.get(resource_key)
            
            if our_result and config_result:
                # Both have results - compare compliance status
                our_status = self._normalize_compliance_status(our_result.compliance_status)
                config_status = self._normalize_compliance_status(config_result['ComplianceType'])
                
                if our_status == config_status:
                    matching_results += 1
                else:
                    discrepancies.append({
                        'resource_id': resource_id,
                        'region': region,
                        'our_status': our_status.value,
                        'config_status': config_status.value,
                        'our_reason': our_result.evaluation_reason,
                        'config_reason': config_result.get('Annotation', 'No annotation')
                    })
            
            elif our_result and not config_result:
                # We have result but Config doesn't
                discrepancies.append({
                    'resource_id': resource_id,
                    'region': region,
                    'issue': 'Resource found by our assessment but not in Config evaluations',
                    'our_status': our_result.compliance_status.value
                })
            
            elif config_result and not our_result:
                # Config has result but we don't
                discrepancies.append({
                    'resource_id': resource_id,
                    'region': region,
                    'issue': 'Resource found in Config evaluations but not in our assessment',
                    'config_status': config_result['ComplianceType']
                })
        
        total_resources = len(all_resource_keys)
        accuracy_percentage = (matching_results / total_resources * 100) if total_resources > 0 else 0.0
        
        return ValidationResult(
            config_rule_name=config_rule_name,
            total_resources=total_resources,
            matching_results=matching_results,
            accuracy_percentage=accuracy_percentage,
            discrepancies=discrepancies,
            validation_timestamp=datetime.now()
        )
    
    def _get_config_evaluations(self, config_rule_name: str) -> List[Dict[str, Any]]:
        """Get AWS Config evaluations for a specific rule.
        
        Args:
            config_rule_name: Name of the Config rule
            
        Returns:
            List of Config evaluation results
        """
        all_evaluations = []
        
        for region, config_client in self.config_clients.items():
            try:
                # Check if Config rule exists in this region
                try:
                    config_client.describe_config_rules(ConfigRuleNames=[config_rule_name])
                except ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchConfigRuleException':
                        logger.debug(f"Config rule {config_rule_name} not found in region {region}")
                        continue
                    raise
                
                # Get compliance details for the rule
                paginator = config_client.get_paginator('get_compliance_details_by_config_rule')
                
                for page in paginator.paginate(ConfigRuleName=config_rule_name):
                    for evaluation in page.get('EvaluationResults', []):
                        evaluation_data = {
                            'ResourceId': evaluation['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceId'],
                            'ResourceType': evaluation['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceType'],
                            'ComplianceType': evaluation['ComplianceType'],
                            'ConfigRuleInvokedTime': evaluation['ConfigRuleInvokedTime'],
                            'ResultRecordedTime': evaluation['ResultRecordedTime'],
                            'Annotation': evaluation.get('Annotation', ''),
                            'Region': region
                        }
                        all_evaluations.append(evaluation_data)
                
                logger.debug(f"Retrieved {len(all_evaluations)} evaluations for {config_rule_name} in {region}")
                
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', '')
                if error_code in ['ConfigurationNotRecordedException', 'NoSuchConfigurationRecorderException']:
                    logger.warning(f"AWS Config not enabled in region {region}")
                elif error_code == 'AccessDenied':
                    logger.warning(f"Access denied to Config service in region {region}")
                else:
                    logger.error(f"Error getting Config evaluations in {region}: {e}")
            
            except Exception as e:
                logger.error(f"Unexpected error getting Config evaluations in {region}: {e}")
        
        return all_evaluations
    
    def _normalize_compliance_status(self, status: Any) -> ComplianceStatus:
        """Normalize compliance status to our enum.
        
        Args:
            status: Status from either our assessment or AWS Config
            
        Returns:
            Normalized ComplianceStatus
        """
        if isinstance(status, ComplianceStatus):
            return status
        
        # Convert string status to our enum
        status_str = str(status).upper()
        
        if status_str in ['COMPLIANT', 'COMPLIANCE']:
            return ComplianceStatus.COMPLIANT
        elif status_str in ['NON_COMPLIANT', 'NONCOMPLIANT', 'NON-COMPLIANT']:
            return ComplianceStatus.NON_COMPLIANT
        elif status_str in ['NOT_APPLICABLE', 'NOTAPPLICABLE', 'NOT-APPLICABLE']:
            return ComplianceStatus.NOT_APPLICABLE
        elif status_str in ['INSUFFICIENT_DATA', 'INSUFFICIENTDATA', 'INSUFFICIENT-DATA']:
            return ComplianceStatus.INSUFFICIENT_PERMISSIONS
        else:
            return ComplianceStatus.ERROR
    
    def check_config_service_availability(self) -> Dict[str, bool]:
        """Check AWS Config service availability in all regions.
        
        Returns:
            Dictionary mapping regions to availability status
        """
        availability = {}
        
        for region in self.aws_factory.regions:
            try:
                config_client = self.aws_factory.get_client('config', region)
                
                # Try to describe configuration recorders
                response = config_client.describe_configuration_recorders()
                
                # Check if Config is recording
                recorders = response.get('ConfigurationRecorders', [])
                is_recording = any(
                    recorder.get('recordingGroup', {}).get('allSupported', False)
                    for recorder in recorders
                )
                
                availability[region] = is_recording
                
                if is_recording:
                    logger.debug(f"AWS Config is active and recording in region: {region}")
                else:
                    logger.warning(f"AWS Config is not recording in region: {region}")
                
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', '')
                if error_code in ['ConfigurationNotRecordedException', 'NoSuchConfigurationRecorderException']:
                    logger.warning(f"AWS Config not configured in region: {region}")
                    availability[region] = False
                elif error_code == 'AccessDenied':
                    logger.warning(f"Access denied to Config service in region: {region}")
                    availability[region] = False
                else:
                    logger.error(f"Error checking Config availability in {region}: {e}")
                    availability[region] = False
            
            except Exception as e:
                logger.error(f"Unexpected error checking Config in {region}: {e}")
                availability[region] = False
        
        return availability
    
    def generate_validation_report(self, summary: ValidationSummary) -> str:
        """Generate a validation report.
        
        Args:
            summary: ValidationSummary to report on
            
        Returns:
            Validation report as string
        """
        report_lines = []
        report_lines.append("# Assessment Accuracy Validation Report")
        report_lines.append(f"Generated: {summary.validation_timestamp.isoformat()}")
        report_lines.append("")
        
        # Overall summary
        report_lines.append("## Overall Summary")
        report_lines.append(f"- Total rules validated: {summary.total_rules_validated}")
        report_lines.append(f"- Accurate rules: {summary.accurate_rules}")
        report_lines.append(f"- Overall accuracy: {summary.overall_accuracy:.1f}%")
        report_lines.append("")
        
        # Individual rule results
        report_lines.append("## Individual Rule Results")
        
        for result in summary.validation_results:
            status = "✓ ACCURATE" if result.is_accurate else "✗ INACCURATE"
            report_lines.append(f"### {result.config_rule_name} - {status}")
            report_lines.append(f"- Accuracy: {result.accuracy_percentage:.1f}%")
            report_lines.append(f"- Matching results: {result.matching_results}/{result.total_resources}")
            
            if result.discrepancies:
                report_lines.append(f"- Discrepancies: {len(result.discrepancies)}")
                
                # Show first few discrepancies
                for i, discrepancy in enumerate(result.discrepancies[:5]):
                    if 'issue' in discrepancy:
                        report_lines.append(f"  - {discrepancy['resource_id']}: {discrepancy['issue']}")
                    else:
                        report_lines.append(f"  - {discrepancy['resource_id']}: "
                                          f"Our={discrepancy['our_status']}, "
                                          f"Config={discrepancy['config_status']}")
                
                if len(result.discrepancies) > 5:
                    report_lines.append(f"  - ... and {len(result.discrepancies) - 5} more")
            
            report_lines.append("")
        
        return "\n".join(report_lines)