"""Base class for AWS Config rule-based CIS Control assessments."""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
import logging
from botocore.exceptions import ClientError

from aws_cis_assessment.core.models import (
    ComplianceResult, ComplianceStatus, RemediationGuidance, ConfigRule
)
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory
from aws_cis_assessment.core.error_handler import ErrorHandler, ErrorContext, ErrorCategory

logger = logging.getLogger(__name__)


class BaseConfigRuleAssessment(ABC):
    """Abstract base class for all AWS Config rule implementations."""
    
    def __init__(self, rule_name: str, control_id: str, resource_types: List[str], 
                 parameters: Optional[Dict[str, Any]] = None,
                 error_handler: Optional[ErrorHandler] = None):
        """Initialize Config rule assessment with rule specification.
        
        Args:
            rule_name: AWS Config rule name
            control_id: CIS Control ID (e.g., "1.1", "3.3")
            resource_types: List of AWS resource types to evaluate
            parameters: Optional parameters for rule evaluation
            error_handler: Optional error handler for graceful degradation
        """
        self.rule_name = rule_name
        self.control_id = control_id
        self.resource_types = resource_types
        self.parameters = parameters or {}
        self.error_handler = error_handler
        
        # Validate inputs
        if not rule_name:
            raise ValueError("Rule name cannot be empty")
        if not control_id:
            raise ValueError("Control ID cannot be empty")
        if not resource_types:
            raise ValueError("Must specify at least one resource type")
    
    def evaluate_compliance(self, aws_factory: AWSClientFactory, region: str = 'us-east-1') -> List[ComplianceResult]:
        """Evaluate compliance for all applicable resources.
        
        Args:
            aws_factory: AWS client factory for API access
            region: AWS region to evaluate
            
        Returns:
            List of ComplianceResult objects for all evaluated resources
        """
        results = []
        
        try:
            # Evaluate each resource type
            for resource_type in self.resource_types:
                try:
                    # Determine evaluation region (us-east-1 for account-level resources)
                    eval_region = self._get_evaluation_region(resource_type, region)
                    is_account_level = self._is_account_level_resource(resource_type)
                    
                    # Skip account-level resources in non-primary regions to prevent duplication
                    # Account-level resources are only evaluated once in us-east-1
                    if is_account_level and region != 'us-east-1':
                        logger.debug(f"Skipping {resource_type} in {region} (account-level resource, evaluated in us-east-1 only)")
                        continue
                    
                    # Validate that we can access required services in the evaluation region
                    if not self._validate_service_access(aws_factory, eval_region):
                        results.append(self._create_error_result(
                            "SERVICE_UNAVAILABLE",
                            f"Required AWS services not accessible in region {eval_region}",
                            eval_region,
                            resource_type
                        ))
                        continue
                    
                    # Use error handler for resource discovery if available
                    def get_resources():
                        return self._get_resources(aws_factory, resource_type, eval_region)
                    
                    if self.error_handler:
                        context = ErrorContext(
                            service_name=self._get_required_services()[0] if self._get_required_services() else "",
                            region=eval_region,
                            resource_type=resource_type,
                            operation="get_resources",
                            control_id=self.control_id,
                            config_rule_name=self.rule_name
                        )
                        
                        resources = self.error_handler.handle_error(
                            Exception("Resource discovery"), context, get_resources
                        )
                        
                        if resources is None:
                            resources = get_resources()
                    else:
                        resources = get_resources()
                    
                    logger.debug(f"Found {len(resources)} resources of type {resource_type} in {eval_region}")
                    
                    for resource in resources:
                        try:
                            # Safely extract resource_id for error context
                            resource_id = resource.get('id', 'unknown') if isinstance(resource, dict) else str(resource)
                            
                            # Use error handler for resource evaluation if available
                            def evaluate_resource():
                                return self._evaluate_resource_compliance(resource, aws_factory, eval_region)
                            
                            if self.error_handler:
                                context = ErrorContext(
                                    service_name=self._get_required_services()[0] if self._get_required_services() else "",
                                    region=eval_region,
                                    resource_type=resource_type,
                                    resource_id=resource_id,
                                    operation="evaluate_compliance",
                                    control_id=self.control_id,
                                    config_rule_name=self.rule_name
                                )
                                
                                compliance = self.error_handler.handle_error(
                                    Exception("Resource evaluation"), context, evaluate_resource
                                )
                                
                                if compliance is None:
                                    compliance = evaluate_resource()
                            else:
                                compliance = evaluate_resource()
                            
                            results.append(compliance)
                            
                        except Exception as e:
                            error_str = str(e)
                            resource_id = resource.get('id', 'unknown') if isinstance(resource, dict) else str(resource)
                            # Log expected errors at DEBUG level
                            if ("Parameter validation failed" in error_str or 
                                "Missing required parameter" in error_str or
                                "Could not connect to the endpoint URL" in error_str):
                                logger.debug(f"Expected error for resource {resource_id}: {e}")
                            else:
                                logger.error(f"Error evaluating resource {resource_id}: {e}")
                            
                            # Handle error with error handler if available
                            if self.error_handler:
                                context = ErrorContext(
                                    service_name=self._get_required_services()[0] if self._get_required_services() else "",
                                    region=eval_region,
                                    resource_type=resource_type,
                                    resource_id=resource_id,
                                    operation="evaluate_compliance",
                                    control_id=self.control_id,
                                    config_rule_name=self.rule_name
                                )
                                self.error_handler.handle_error(e, context)
                            
                            results.append(self._create_error_result(
                                resource_id,
                                f"Evaluation error: {str(e)}",
                                eval_region,
                                resource_type
                            ))
                
                except ClientError as e:
                    error_code = e.response.get('Error', {}).get('Code', '')
                    error_message = str(e)
                    
                    # Log parameter validation errors at DEBUG level (expected for some resources)
                    if 'Parameter' in error_code or 'parameter' in error_message.lower():
                        logger.debug(f"Parameter validation error for {resource_type} in {eval_region}: {e}")
                    elif error_code in ['AccessDenied', 'UnauthorizedOperation']:
                        logger.debug(f"Access denied for {resource_type} in {eval_region}")
                    else:
                        logger.error(f"AWS API error for {resource_type} in {eval_region}: {e}")
                    
                    # Handle error with error handler if available
                    if self.error_handler:
                        context = ErrorContext(
                            service_name=self._get_required_services()[0] if self._get_required_services() else "",
                            region=eval_region,
                            resource_type=resource_type,
                            operation="get_resources",
                            control_id=self.control_id,
                            config_rule_name=self.rule_name
                        )
                        self.error_handler.handle_error(e, context)
                    
                    if error_code in ['AccessDenied', 'UnauthorizedOperation']:
                        results.append(self._create_error_result(
                            f"{resource_type}_PERMISSION_ERROR",
                            f"Insufficient permissions to evaluate {resource_type}",
                            eval_region,
                            resource_type
                        ))
                    else:
                        results.append(self._create_error_result(
                            f"{resource_type}_API_ERROR",
                            f"AWS API error: {error_message}",
                            eval_region,
                            resource_type
                        ))
                
                except Exception as e:
                    # Log parameter validation errors at DEBUG level (expected for some resources)
                    if "Parameter validation failed" in str(e) or "Missing required parameter" in str(e):
                        logger.debug(f"Parameter validation error for {resource_type} in {eval_region}: {e}")
                    else:
                        logger.error(f"Unexpected error evaluating {resource_type}: {e}")
                    
                    # Handle error with error handler if available
                    if self.error_handler:
                        context = ErrorContext(
                            service_name=self._get_required_services()[0] if self._get_required_services() else "",
                            region=eval_region,
                            resource_type=resource_type,
                            operation="evaluate_resource_type",
                            control_id=self.control_id,
                            config_rule_name=self.rule_name
                        )
                        self.error_handler.handle_error(e, context)
                    
                    results.append(self._create_error_result(
                        f"{resource_type}_UNKNOWN_ERROR",
                        f"Unexpected error: {str(e)}",
                        eval_region,
                        resource_type
                    ))
        
        except Exception as e:
            logger.error(f"Critical error in compliance evaluation: {e}")
            
            # Handle critical error with error handler if available
            if self.error_handler:
                context = ErrorContext(
                    service_name=self._get_required_services()[0] if self._get_required_services() else "",
                    region=region,
                    operation="evaluate_compliance",
                    control_id=self.control_id,
                    config_rule_name=self.rule_name
                )
                self.error_handler.handle_error(e, context)
            
            results.append(self._create_error_result(
                "CRITICAL_ERROR",
                f"Critical evaluation error: {str(e)}",
                region
            ))
        
        return results
    
    @abstractmethod
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate compliance for individual resource.
        
        This method must be implemented by subclasses with specific Config rule logic.
        
        Args:
            resource: Resource data dictionary
            aws_factory: AWS client factory for additional API calls
            region: AWS region
            
        Returns:
            ComplianceResult for the resource
        """
        pass
    
    @abstractmethod
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Discover resources of specified type in region.
        
        This method must be implemented by subclasses based on resource type.
        
        Args:
            aws_factory: AWS client factory for API access
            resource_type: AWS resource type (e.g., "AWS::EC2::Instance")
            region: AWS region
            
        Returns:
            List of resource dictionaries
        """
        pass
    
    def _validate_service_access(self, aws_factory: AWSClientFactory, region: str) -> bool:
        """Validate that required AWS services are accessible.
        
        Args:
            aws_factory: AWS client factory
            region: AWS region
            
        Returns:
            True if all required services are accessible
        """
        required_services = self._get_required_services()
        
        for service in required_services:
            if not aws_factory.test_service_access(service, region):
                logger.debug(f"Service {service} not accessible in region {region}")
                return False
        
        return True
    
    def _get_required_services(self) -> List[str]:
        """Get list of AWS services required for this assessment.
        
        Returns:
            List of AWS service names
        """
        # Map resource types to services
        service_mapping = {
            'AWS::EC2::': 'ec2',
            'AWS::IAM::': 'iam',
            'AWS::S3::': 's3',
            'AWS::RDS::': 'rds',
            'AWS::CloudTrail::': 'cloudtrail',
            'AWS::ElasticLoadBalancing::': 'elbv2',  # Classic ELB uses elbv2 client in boto3
            'AWS::ElasticLoadBalancingV2::': 'elbv2',  # ALB/NLB use elbv2 client
            'AWS::ApiGateway::': 'apigateway',
            'AWS::DynamoDB::': 'dynamodb',
            'AWS::::Account': 'sts'  # Special case for account-level resources
        }
        
        services = set()
        for resource_type in self.resource_types:
            for prefix, service in service_mapping.items():
                if resource_type.startswith(prefix):
                    services.add(service)
                    break
        
        return list(services)
    
    def _is_account_level_resource(self, resource_type: str) -> bool:
        """Check if resource type is account-level (global).
        
        Account-level resources should be evaluated in us-east-1 only once,
        not per region. This prevents duplicate evaluations and region validation errors.
        
        Args:
            resource_type: AWS resource type (e.g., "AWS::::Account", "AWS::IAM::User")
            
        Returns:
            True if resource is account-level/global
        """
        # Explicit account-level marker
        if resource_type == 'AWS::::Account':
            return True
        
        # Global services that should only be evaluated in us-east-1
        global_service_prefixes = [
            'AWS::IAM::',           # IAM is global
            'AWS::CloudFront::',    # CloudFront is global
            'AWS::Route53::',       # Route53 is global
            'AWS::Organizations::', # Organizations is global
        ]
        
        for prefix in global_service_prefixes:
            if resource_type.startswith(prefix):
                return True
        
        # S3 buckets are special - they're global but region-specific
        # We handle them in controls by checking region == 'us-east-1'
        
        return False
    
    def _get_evaluation_region(self, resource_type: str, requested_region: str) -> str:
        """Determine which region to use for resource evaluation.
        
        Account-level and global resources must be evaluated in us-east-1
        to avoid region validation errors and ensure proper API access.
        
        Args:
            resource_type: AWS resource type
            requested_region: Region requested for evaluation
            
        Returns:
            Region to use (us-east-1 for account-level, requested_region otherwise)
        """
        if self._is_account_level_resource(resource_type):
            return 'us-east-1'
        return requested_region
    
    
    def _create_error_result(self, resource_id: str, error_message: str, region: str, resource_type: str = "Unknown") -> ComplianceResult:
        """Create a ComplianceResult for error conditions.
        
        Args:
            resource_id: Resource identifier
            error_message: Error description
            region: AWS region
            resource_type: AWS resource type
            
        Returns:
            ComplianceResult with ERROR status
        """
        return ComplianceResult(
            resource_id=resource_id,
            resource_type=resource_type,
            compliance_status=ComplianceStatus.ERROR,
            evaluation_reason=error_message,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def get_remediation_guidance(self, non_compliant_resources: List[ComplianceResult]) -> RemediationGuidance:
        """Provide remediation guidance based on AWS Config rule documentation.
        
        Args:
            non_compliant_resources: List of non-compliant resources
            
        Returns:
            RemediationGuidance object with specific steps
        """
        return RemediationGuidance(
            config_rule_name=self.rule_name,
            control_id=self.control_id,
            remediation_steps=self._get_rule_remediation_steps(),
            aws_documentation_link=f"https://docs.aws.amazon.com/config/latest/developerguide/{self.rule_name}.html",
            priority=self._determine_priority(non_compliant_resources),
            estimated_effort=self._estimate_remediation_effort(non_compliant_resources)
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for this Config rule.
        
        Override in subclasses for rule-specific guidance.
        
        Returns:
            List of remediation step descriptions
        """
        return [
            f"Review non-compliant resources identified by {self.rule_name}",
            f"Apply remediation actions according to CIS Control {self.control_id}",
            "Verify compliance after remediation",
            "Monitor for future compliance drift"
        ]
    
    def _determine_priority(self, non_compliant_resources: List[ComplianceResult]) -> str:
        """Determine remediation priority based on non-compliant resources.
        
        Args:
            non_compliant_resources: List of non-compliant resources
            
        Returns:
            Priority level: HIGH, MEDIUM, or LOW
        """
        if not non_compliant_resources:
            return "LOW"
        
        # High priority for security-critical controls
        high_priority_controls = ["3.3", "5.2", "6.4", "8.1"]
        if self.control_id in high_priority_controls:
            return "HIGH"
        
        # Medium priority for most controls
        if len(non_compliant_resources) > 5:
            return "HIGH"
        elif len(non_compliant_resources) > 1:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _estimate_remediation_effort(self, non_compliant_resources: List[ComplianceResult]) -> str:
        """Estimate effort required for remediation.
        
        Args:
            non_compliant_resources: List of non-compliant resources
            
        Returns:
            Effort estimate: Low, Medium, High, or Very High
        """
        resource_count = len(non_compliant_resources)
        
        if resource_count == 0:
            return "None"
        elif resource_count <= 5:
            return "Low"
        elif resource_count <= 20:
            return "Medium"
        elif resource_count <= 50:
            return "High"
        else:
            return "Very High"