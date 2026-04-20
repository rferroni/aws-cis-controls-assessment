"""Control 8.2: Collect Audit Logs - Audit logging assessments for Phase 1.

This module implements 7 critical audit logging assessment classes for CIS Control 8
(Audit Log Management). These assessments evaluate AWS resources for comprehensive
audit logging compliance across multiple services:

1. Route53QueryLoggingAssessment - Validates DNS query logging for Route 53 hosted zones
2. ALBAccessLogsEnabledAssessment - Ensures Application Load Balancers have access logging
3. CloudFrontAccessLogsEnabledAssessment - Validates CloudFront distribution access logging
4. CloudWatchLogRetentionCheckAssessment - Ensures CloudWatch log groups have appropriate retention
5. CloudTrailInsightsEnabledAssessment - Validates CloudTrail Insights for anomaly detection
6. ConfigRecordingAllResourcesAssessment - Ensures AWS Config records all resource types
7. WAFLoggingEnabledAssessment - Validates WAF web ACL logging configuration

These rules address the highest priority compliance gap identified in the CIS Controls
Gap Analysis and increase the total rule count from 142 to 149.
"""

from typing import Dict, List, Any
import logging
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


# ============================================================================
# 1. Route 53 Query Logging Assessment
# ============================================================================

class Route53QueryLoggingAssessment(BaseConfigRuleAssessment):
    """Assessment for route53-query-logging-enabled AWS Config rule.
    
    Validates that Route 53 hosted zones have query logging enabled to track
    DNS queries for security investigations and compliance.
    
    This is a global service assessment that only runs in us-east-1.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="route53-query-logging-enabled",
            control_id="8.2",
            resource_types=["AWS::Route53::HostedZone"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get Route 53 hosted zones.
        
        Route 53 is a global service, so we only query in us-east-1.
        
        Args:
            aws_factory: AWS client factory for API access
            resource_type: AWS resource type (should be AWS::Route53::HostedZone)
            region: AWS region (should be us-east-1 for Route 53)
            
        Returns:
            List of hosted zone dictionaries with Id, Name, Config
        """
        if resource_type != "AWS::Route53::HostedZone":
            return []
        
        # Route 53 is a global service - only evaluate in us-east-1
        if region != 'us-east-1':
            logger.debug(f"Skipping Route 53 evaluation in {region} - global service evaluated in us-east-1 only")
            return []
        
        try:
            route53_client = aws_factory.get_client('route53', region)
            
            # List all hosted zones with pagination support
            hosted_zones = []
            marker = None
            
            while True:
                if marker:
                    response = aws_factory.aws_api_call_with_retry(
                        lambda: route53_client.list_hosted_zones(Marker=marker)
                    )
                else:
                    response = aws_factory.aws_api_call_with_retry(
                        lambda: route53_client.list_hosted_zones()
                    )
                
                hosted_zones.extend(response.get('HostedZones', []))
                
                # Check if there are more results
                if response.get('IsTruncated', False):
                    marker = response.get('NextMarker')
                else:
                    break
            
            logger.debug(f"Found {len(hosted_zones)} Route 53 hosted zones")
            return hosted_zones
            
        except ClientError as e:
            logger.error(f"Error retrieving Route 53 hosted zones: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if Route 53 hosted zone has query logging enabled.
        
        Args:
            resource: Hosted zone resource dictionary
            aws_factory: AWS client factory for additional API calls
            region: AWS region
            
        Returns:
            ComplianceResult indicating whether query logging is enabled
        """
        hosted_zone_id = resource.get('Id', 'unknown')
        hosted_zone_name = resource.get('Name', 'unknown')
        
        # Extract just the zone ID (remove /hostedzone/ prefix if present)
        if hosted_zone_id.startswith('/hostedzone/'):
            zone_id = hosted_zone_id.split('/')[-1]
        else:
            zone_id = hosted_zone_id
        
        try:
            route53_client = aws_factory.get_client('route53', region)
            
            # Check if query logging is configured for this hosted zone
            response = aws_factory.aws_api_call_with_retry(
                lambda: route53_client.list_query_logging_configs(HostedZoneId=zone_id)
            )
            
            query_logging_configs = response.get('QueryLoggingConfigs', [])
            
            if query_logging_configs:
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = f"Route 53 hosted zone {hosted_zone_name} ({zone_id}) has query logging enabled"
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = (
                    f"Route 53 hosted zone {hosted_zone_name} ({zone_id}) does not have query logging enabled. "
                    f"Enable Route 53 query logging for this hosted zone. Create a CloudWatch Logs log group "
                    f"and configure query logging using the AWS Console, CLI, or API. Query logging helps track "
                    f"DNS queries for security investigations and compliance."
                )
                
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            
            if error_code == 'AccessDenied':
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Insufficient permissions to check query logging for hosted zone {zone_id}: {str(e)}"
            elif error_code == 'NoSuchHostedZone':
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Hosted zone {zone_id} not found (may have been deleted)"
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Error checking query logging for hosted zone {zone_id}: {str(e)}"
        
        return ComplianceResult(
            resource_id=zone_id,
            resource_type="AWS::Route53::HostedZone",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )


# ============================================================================
# 2. Application Load Balancer Access Logs Assessment
# ============================================================================

class ALBAccessLogsEnabledAssessment(BaseConfigRuleAssessment):
    """Assessment for alb-access-logs-enabled AWS Config rule.
    
    Ensures Application Load Balancers have access logging enabled to analyze
    traffic patterns and investigate security incidents.
    
    This is a regional service assessment that runs in all active regions.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="alb-access-logs-enabled",
            control_id="8.2",
            resource_types=["AWS::ElasticLoadBalancingV2::LoadBalancer"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get Application Load Balancers in the specified region.
        
        Filters for Type='application' to exclude Network Load Balancers and Gateway Load Balancers.
        
        Args:
            aws_factory: AWS client factory for API access
            resource_type: AWS resource type (should be AWS::ElasticLoadBalancingV2::LoadBalancer)
            region: AWS region to query
            
        Returns:
            List of ALB dictionaries with LoadBalancerArn, LoadBalancerName, Type
        """
        if resource_type != "AWS::ElasticLoadBalancingV2::LoadBalancer":
            return []
        
        try:
            elbv2_client = aws_factory.get_client('elbv2', region)
            
            # List all load balancers with pagination support
            load_balancers = []
            marker = None
            
            while True:
                if marker:
                    response = aws_factory.aws_api_call_with_retry(
                        lambda: elbv2_client.describe_load_balancers(Marker=marker)
                    )
                else:
                    response = aws_factory.aws_api_call_with_retry(
                        lambda: elbv2_client.describe_load_balancers()
                    )
                
                # Filter for Application Load Balancers only (exclude NLB and Gateway LB)
                albs = [lb for lb in response.get('LoadBalancers', []) if lb.get('Type') == 'application']
                load_balancers.extend(albs)
                
                # Check if there are more results
                if 'NextMarker' in response:
                    marker = response['NextMarker']
                else:
                    break
            
            logger.debug(f"Found {len(load_balancers)} Application Load Balancers in {region}")
            return load_balancers
            
        except ClientError as e:
            logger.error(f"Error retrieving Application Load Balancers in {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if Application Load Balancer has access logging enabled.
        
        Args:
            resource: Load balancer resource dictionary
            aws_factory: AWS client factory for additional API calls
            region: AWS region
            
        Returns:
            ComplianceResult indicating whether access logging is enabled
        """
        lb_arn = resource.get('LoadBalancerArn', 'unknown')
        lb_name = resource.get('LoadBalancerName', 'unknown')
        
        try:
            elbv2_client = aws_factory.get_client('elbv2', region)
            
            # Get load balancer attributes
            response = aws_factory.aws_api_call_with_retry(
                lambda: elbv2_client.describe_load_balancer_attributes(LoadBalancerArn=lb_arn)
            )
            
            attributes = response.get('Attributes', [])
            
            # Find the access_logs.s3.enabled attribute
            access_logs_enabled = False
            for attr in attributes:
                if attr.get('Key') == 'access_logs.s3.enabled':
                    access_logs_enabled = attr.get('Value', 'false').lower() == 'true'
                    break
            
            if access_logs_enabled:
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = f"Application Load Balancer {lb_name} has access logging enabled"
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = (
                    f"Application Load Balancer {lb_name} does not have access logging enabled. "
                    f"Enable access logging for this Application Load Balancer. Configure an S3 bucket "
                    f"to store access logs using the AWS Console, CLI, or API. Access logs help analyze "
                    f"traffic patterns and investigate security incidents."
                )
                
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            
            if error_code == 'AccessDenied':
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Insufficient permissions to check access logging for ALB {lb_name}: {str(e)}"
            elif error_code == 'LoadBalancerNotFound':
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Load balancer {lb_name} not found (may have been deleted)"
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Error checking access logging for ALB {lb_name}: {str(e)}"
        
        return ComplianceResult(
            resource_id=lb_arn,
            resource_type="AWS::ElasticLoadBalancingV2::LoadBalancer",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )


# ============================================================================
# 3. CloudFront Access Logs Assessment
# ============================================================================

class CloudFrontAccessLogsEnabledAssessment(BaseConfigRuleAssessment):
    """Assessment for cloudfront-access-logs-enabled AWS Config rule.
    
    Validates that CloudFront distributions have access logging enabled to track
    content delivery requests and detect anomalous access patterns.
    
    This is a global service assessment that only runs in us-east-1.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="cloudfront-access-logs-enabled",
            control_id="8.2",
            resource_types=["AWS::CloudFront::Distribution"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get CloudFront distributions.
        
        CloudFront is a global service, so we only query in us-east-1.
        
        Args:
            aws_factory: AWS client factory for API access
            resource_type: AWS resource type (should be AWS::CloudFront::Distribution)
            region: AWS region (should be us-east-1 for CloudFront)
            
        Returns:
            List of distribution dictionaries with Id, ARN, Status, DomainName
        """
        if resource_type != "AWS::CloudFront::Distribution":
            return []
        
        # CloudFront is a global service - only evaluate in us-east-1
        if region != 'us-east-1':
            logger.debug(f"Skipping CloudFront evaluation in {region} - global service evaluated in us-east-1 only")
            return []
        
        try:
            cloudfront_client = aws_factory.get_client('cloudfront', region)
            
            # List all distributions with pagination support
            distributions = []
            marker = None
            
            while True:
                if marker:
                    response = aws_factory.aws_api_call_with_retry(
                        lambda: cloudfront_client.list_distributions(Marker=marker)
                    )
                else:
                    response = aws_factory.aws_api_call_with_retry(
                        lambda: cloudfront_client.list_distributions()
                    )
                
                distribution_list = response.get('DistributionList', {})
                items = distribution_list.get('Items', [])
                distributions.extend(items)
                
                # Check if there are more results
                if distribution_list.get('IsTruncated', False):
                    marker = distribution_list.get('NextMarker')
                else:
                    break
            
            logger.debug(f"Found {len(distributions)} CloudFront distributions")
            return distributions
            
        except ClientError as e:
            logger.error(f"Error retrieving CloudFront distributions: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if CloudFront distribution has access logging enabled.
        
        Args:
            resource: Distribution resource dictionary
            aws_factory: AWS client factory for additional API calls
            region: AWS region
            
        Returns:
            ComplianceResult indicating whether access logging is enabled
        """
        distribution_id = resource.get('Id', 'unknown')
        distribution_domain = resource.get('DomainName', 'unknown')
        
        try:
            cloudfront_client = aws_factory.get_client('cloudfront', region)
            
            # Get distribution configuration
            response = aws_factory.aws_api_call_with_retry(
                lambda: cloudfront_client.get_distribution_config(Id=distribution_id)
            )
            
            distribution_config = response.get('DistributionConfig', {})
            logging_config = distribution_config.get('Logging', {})
            
            # Check if logging is enabled and bucket is configured
            logging_enabled = logging_config.get('Enabled', False)
            logging_bucket = logging_config.get('Bucket', '')
            
            if logging_enabled and logging_bucket:
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = f"CloudFront distribution {distribution_id} ({distribution_domain}) has access logging enabled"
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                if not logging_enabled:
                    evaluation_reason = (
                        f"CloudFront distribution {distribution_id} ({distribution_domain}) does not have access logging enabled. "
                        f"Enable access logging for this CloudFront distribution. Configure an S3 bucket to store access logs "
                        f"using the AWS Console, CLI, or API. Access logs help track content delivery requests and detect "
                        f"anomalous access patterns."
                    )
                else:
                    evaluation_reason = (
                        f"CloudFront distribution {distribution_id} ({distribution_domain}) has logging enabled but no S3 bucket configured. "
                        f"Configure an S3 bucket to store access logs using the AWS Console, CLI, or API."
                    )
                
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            
            if error_code == 'AccessDenied':
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Insufficient permissions to check access logging for CloudFront distribution {distribution_id}: {str(e)}"
            elif error_code == 'NoSuchDistribution':
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"CloudFront distribution {distribution_id} not found (may have been deleted)"
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Error checking access logging for CloudFront distribution {distribution_id}: {str(e)}"
        
        return ComplianceResult(
            resource_id=distribution_id,
            resource_type="AWS::CloudFront::Distribution",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )


# ============================================================================
# 4. CloudWatch Log Retention Assessment
# ============================================================================

class CloudWatchLogRetentionCheckAssessment(BaseConfigRuleAssessment):
    """Assessment for cloudwatch-log-retention-check AWS Config rule.
    
    Ensures CloudWatch log groups have appropriate retention periods so that logs
    are retained long enough for compliance and investigation purposes.
    
    This is a regional service assessment that runs in all active regions.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="cloudwatch-log-retention-check",
            control_id="8.2",
            resource_types=["AWS::Logs::LogGroup"],
            parameters={'minimumRetentionDays': 90}
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get CloudWatch log groups in the specified region.
        
        Uses pagination to handle large numbers of log groups.
        
        Args:
            aws_factory: AWS client factory for API access
            resource_type: AWS resource type (should be AWS::Logs::LogGroup)
            region: AWS region to query
            
        Returns:
            List of log group dictionaries with logGroupName, retentionInDays, creationTime, storedBytes
        """
        if resource_type != "AWS::Logs::LogGroup":
            return []
        
        try:
            logs_client = aws_factory.get_client('logs', region)
            
            # Use paginator for describe_log_groups to handle large result sets
            paginator = logs_client.get_paginator('describe_log_groups')
            
            log_groups = []
            for page in paginator.paginate():
                log_groups.extend(page.get('logGroups', []))
            
            logger.debug(f"Found {len(log_groups)} CloudWatch log groups in {region}")
            return log_groups
            
        except ClientError as e:
            logger.error(f"Error retrieving CloudWatch log groups in {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if CloudWatch log group has appropriate retention period.
        
        Args:
            resource: Log group resource dictionary
            aws_factory: AWS client factory for additional API calls
            region: AWS region
            
        Returns:
            ComplianceResult indicating whether retention period is appropriate
        """
        log_group_name = resource.get('logGroupName', 'unknown')
        retention_in_days = resource.get('retentionInDays')
        
        # Get minimum retention from parameters (default 90 days)
        minimum_retention = self.parameters.get('minimumRetentionDays', 90)
        
        try:
            if retention_in_days is None:
                # Indefinite retention (None) is considered non-compliant
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = (
                    f"CloudWatch log group {log_group_name} has indefinite retention (no retention period set). "
                    f"Set a retention period of at least {minimum_retention} days for this log group using the AWS Console, "
                    f"CLI, or API. Proper retention ensures logs are available for compliance and investigation while "
                    f"managing storage costs."
                )
            elif retention_in_days < minimum_retention:
                # Retention less than minimum is non-compliant
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = (
                    f"CloudWatch log group {log_group_name} has retention period of {retention_in_days} days, "
                    f"which is less than the required {minimum_retention} days. "
                    f"Increase the retention period to at least {minimum_retention} days using the AWS Console, CLI, or API."
                )
            else:
                # Retention meets or exceeds minimum
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = f"CloudWatch log group {log_group_name} has retention period of {retention_in_days} days (>= {minimum_retention} days)"
                
        except Exception as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Error evaluating retention for log group {log_group_name}: {str(e)}"
        
        return ComplianceResult(
            resource_id=log_group_name,
            resource_type="AWS::Logs::LogGroup",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )


# ============================================================================
# 5. CloudTrail Insights Assessment
# ============================================================================

class CloudTrailInsightsEnabledAssessment(BaseConfigRuleAssessment):
    """Assessment for cloudtrail-insights-enabled AWS Config rule.
    
    Validates that CloudTrail Insights is enabled for anomaly detection so that
    anomalous API activity can be automatically detected.
    
    This is an account-level check that verifies at least one trail has Insights enabled.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="cloudtrail-insights-enabled",
            control_id="8.2",
            resource_types=["AWS::CloudTrail::Trail"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get CloudTrail trails in the specified region.
        
        Args:
            aws_factory: AWS client factory for API access
            resource_type: AWS resource type (should be AWS::CloudTrail::Trail)
            region: AWS region to query
            
        Returns:
            List of trail dictionaries with Name, TrailARN, IsMultiRegionTrail, IsLogging
        """
        if resource_type != "AWS::CloudTrail::Trail":
            return []
        
        try:
            cloudtrail_client = aws_factory.get_client('cloudtrail', region)
            
            # Get all trails
            response = aws_factory.aws_api_call_with_retry(
                lambda: cloudtrail_client.describe_trails()
            )
            
            trails = response.get('trailList', [])
            
            # Get status for each trail
            trails_with_status = []
            for trail in trails:
                trail_arn = trail.get('TrailARN', '')
                try:
                    status_response = aws_factory.aws_api_call_with_retry(
                        lambda: cloudtrail_client.get_trail_status(Name=trail_arn)
                    )
                    trail['IsLogging'] = status_response.get('IsLogging', False)
                except ClientError as e:
                    logger.warning(f"Error getting status for trail {trail_arn}: {e}")
                    trail['IsLogging'] = False
                
                trails_with_status.append(trail)
            
            logger.debug(f"Found {len(trails_with_status)} CloudTrail trails in {region}")
            return trails_with_status
            
        except ClientError as e:
            logger.error(f"Error retrieving CloudTrail trails in {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if CloudTrail trail has Insights enabled.
        
        This is an account-level check - we check if at least one active trail has Insights enabled.
        
        Args:
            resource: Trail resource dictionary
            aws_factory: AWS client factory for additional API calls
            region: AWS region
            
        Returns:
            ComplianceResult indicating whether Insights is enabled
        """
        trail_name = resource.get('Name', 'unknown')
        trail_arn = resource.get('TrailARN', 'unknown')
        is_logging = resource.get('IsLogging', False)
        
        try:
            cloudtrail_client = aws_factory.get_client('cloudtrail', region)
            
            # Only check Insights for active trails
            if not is_logging:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = (
                    f"CloudTrail trail {trail_name} is not actively logging. "
                    f"Enable logging for this trail and configure CloudTrail Insights for anomaly detection."
                )
            else:
                # Get insight selectors for the trail
                try:
                    response = aws_factory.aws_api_call_with_retry(
                        lambda: cloudtrail_client.get_insight_selectors(TrailName=trail_arn)
                    )
                    
                    insight_selectors = response.get('InsightSelectors', [])
                    
                    if insight_selectors:
                        compliance_status = ComplianceStatus.COMPLIANT
                        evaluation_reason = f"CloudTrail trail {trail_name} has Insights enabled for anomaly detection"
                    else:
                        compliance_status = ComplianceStatus.NON_COMPLIANT
                        evaluation_reason = (
                            f"CloudTrail trail {trail_name} does not have Insights enabled. "
                            f"Enable CloudTrail Insights for this trail to detect anomalous API activity. "
                            f"Configure Insights using the AWS Console, CLI, or API."
                        )
                        
                except ClientError as e:
                    error_code = e.response.get('Error', {}).get('Code', '')
                    if error_code == 'InsightNotEnabledException':
                        compliance_status = ComplianceStatus.NON_COMPLIANT
                        evaluation_reason = (
                            f"CloudTrail trail {trail_name} does not have Insights enabled. "
                            f"Enable CloudTrail Insights for this trail to detect anomalous API activity."
                        )
                    else:
                        raise
                
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            
            if error_code == 'AccessDenied':
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Insufficient permissions to check Insights for CloudTrail trail {trail_name}: {str(e)}"
            elif error_code == 'TrailNotFoundException':
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"CloudTrail trail {trail_name} not found (may have been deleted)"
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Error checking Insights for CloudTrail trail {trail_name}: {str(e)}"
        
        return ComplianceResult(
            resource_id=trail_arn,
            resource_type="AWS::CloudTrail::Trail",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )


# ============================================================================
# 6. AWS Config Recording Assessment
# ============================================================================

class ConfigRecordingAllResourcesAssessment(BaseConfigRuleAssessment):
    """Assessment for config-recording-all-resources AWS Config rule.
    
    Ensures AWS Config is recording all resource types so that configuration
    changes are tracked for compliance and security analysis.
    
    This is a regional service assessment that runs in all active regions.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="config-recording-all-resources",
            control_id="8.2",
            resource_types=["AWS::Config::ConfigurationRecorder"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get AWS Config configuration recorders in the specified region.
        
        Args:
            aws_factory: AWS client factory for API access
            resource_type: AWS resource type (should be AWS::Config::ConfigurationRecorder)
            region: AWS region to query
            
        Returns:
            List of configuration recorder dictionaries with name, roleARN, recordingGroup, recording status
        """
        if resource_type != "AWS::Config::ConfigurationRecorder":
            return []
        
        try:
            config_client = aws_factory.get_client('config', region)
            
            # Get all configuration recorders
            response = aws_factory.aws_api_call_with_retry(
                lambda: config_client.describe_configuration_recorders()
            )
            
            recorders = response.get('ConfigurationRecorders', [])
            
            # Get status for each recorder
            recorders_with_status = []
            for recorder in recorders:
                recorder_name = recorder.get('name', '')
                try:
                    status_response = aws_factory.aws_api_call_with_retry(
                        lambda: config_client.describe_configuration_recorder_status(
                            ConfigurationRecorderNames=[recorder_name]
                        )
                    )
                    
                    statuses = status_response.get('ConfigurationRecordersStatus', [])
                    if statuses:
                        recorder['recording'] = statuses[0].get('recording', False)
                    else:
                        recorder['recording'] = False
                        
                except ClientError as e:
                    logger.warning(f"Error getting status for recorder {recorder_name}: {e}")
                    recorder['recording'] = False
                
                recorders_with_status.append(recorder)
            
            logger.debug(f"Found {len(recorders_with_status)} AWS Config recorders in {region}")
            return recorders_with_status
            
        except ClientError as e:
            logger.error(f"Error retrieving AWS Config recorders in {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if AWS Config recorder is recording all resource types.
        
        Args:
            resource: Configuration recorder resource dictionary
            aws_factory: AWS client factory for additional API calls
            region: AWS region
            
        Returns:
            ComplianceResult indicating whether recorder is recording all resources
        """
        recorder_name = resource.get('name', 'unknown')
        recording_group = resource.get('recordingGroup', {})
        all_supported = recording_group.get('allSupported', False)
        is_recording = resource.get('recording', False)
        
        try:
            if all_supported and is_recording:
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = f"AWS Config recorder {recorder_name} is recording all resource types and is active"
            elif not all_supported and not is_recording:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = (
                    f"AWS Config recorder {recorder_name} is not recording all resource types and is not active. "
                    f"Configure AWS Config to record all resource types (set allSupported=true) and start the recorder "
                    f"using the AWS Console, CLI, or API. Recording all resources ensures comprehensive configuration tracking."
                )
            elif not all_supported:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = (
                    f"AWS Config recorder {recorder_name} is not recording all resource types (allSupported=false). "
                    f"Configure AWS Config to record all resource types using the AWS Console, CLI, or API."
                )
            else:  # not is_recording
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = (
                    f"AWS Config recorder {recorder_name} is not actively recording (recording=false). "
                    f"Start the configuration recorder using the AWS Console, CLI, or API."
                )
                
        except Exception as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Error evaluating AWS Config recorder {recorder_name}: {str(e)}"
        
        return ComplianceResult(
            resource_id=recorder_name,
            resource_type="AWS::Config::ConfigurationRecorder",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )


# ============================================================================
# 7. WAF Logging Assessment
# ============================================================================

class WAFLoggingEnabledAssessment(BaseConfigRuleAssessment):
    """Assessment for waf-logging-enabled AWS Config rule.
    
    Validates that WAF web ACLs have logging enabled so that web application
    firewall events are captured for security analysis.
    
    This assessment handles both REGIONAL and CLOUDFRONT scopes:
    - REGIONAL scope: Evaluated in all active regions
    - CLOUDFRONT scope: Evaluated in us-east-1 only
    """
    
    def __init__(self):
        super().__init__(
            rule_name="waf-logging-enabled",
            control_id="8.2",
            resource_types=["AWS::WAFv2::WebACL"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get WAF web ACLs in the specified region.
        
        Handles both REGIONAL and CLOUDFRONT scopes. CLOUDFRONT scope is only
        available in us-east-1.
        
        Args:
            aws_factory: AWS client factory for API access
            resource_type: AWS resource type (should be AWS::WAFv2::WebACL)
            region: AWS region to query
            
        Returns:
            List of web ACL dictionaries with Name, Id, ARN, Scope
        """
        if resource_type != "AWS::WAFv2::WebACL":
            return []
        
        try:
            wafv2_client = aws_factory.get_client('wafv2', region)
            
            web_acls = []
            
            # Get REGIONAL web ACLs
            try:
                response = aws_factory.aws_api_call_with_retry(
                    lambda: wafv2_client.list_web_acls(Scope='REGIONAL')
                )
                
                regional_acls = response.get('WebACLs', [])
                for acl in regional_acls:
                    acl['Scope'] = 'REGIONAL'
                web_acls.extend(regional_acls)
                
            except ClientError as e:
                logger.warning(f"Error retrieving REGIONAL WAF web ACLs in {region}: {e}")
            
            # Get CLOUDFRONT web ACLs (only in us-east-1)
            if region == 'us-east-1':
                try:
                    response = aws_factory.aws_api_call_with_retry(
                        lambda: wafv2_client.list_web_acls(Scope='CLOUDFRONT')
                    )
                    
                    cloudfront_acls = response.get('WebACLs', [])
                    for acl in cloudfront_acls:
                        acl['Scope'] = 'CLOUDFRONT'
                    web_acls.extend(cloudfront_acls)
                    
                except ClientError as e:
                    logger.warning(f"Error retrieving CLOUDFRONT WAF web ACLs: {e}")
            
            logger.debug(f"Found {len(web_acls)} WAF web ACLs in {region}")
            return web_acls
            
        except ClientError as e:
            logger.error(f"Error retrieving WAF web ACLs in {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if WAF web ACL has logging enabled.
        
        Args:
            resource: Web ACL resource dictionary
            aws_factory: AWS client factory for additional API calls
            region: AWS region
            
        Returns:
            ComplianceResult indicating whether logging is enabled
        """
        web_acl_name = resource.get('Name', 'unknown')
        web_acl_arn = resource.get('ARN', 'unknown')
        web_acl_scope = resource.get('Scope', 'REGIONAL')
        
        try:
            wafv2_client = aws_factory.get_client('wafv2', region)
            
            # Get logging configuration for the web ACL
            try:
                response = aws_factory.aws_api_call_with_retry(
                    lambda: wafv2_client.get_logging_configuration(ResourceArn=web_acl_arn)
                )
                
                logging_config = response.get('LoggingConfiguration', {})
                log_destinations = logging_config.get('LogDestinationConfigs', [])
                
                if log_destinations:
                    compliance_status = ComplianceStatus.COMPLIANT
                    evaluation_reason = f"WAF web ACL {web_acl_name} ({web_acl_scope}) has logging enabled"
                else:
                    compliance_status = ComplianceStatus.NON_COMPLIANT
                    evaluation_reason = (
                        f"WAF web ACL {web_acl_name} ({web_acl_scope}) has logging configuration but no log destinations. "
                        f"Configure a log destination (Kinesis Data Firehose, S3, or CloudWatch Logs) for this web ACL."
                    )
                    
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', '')
                
                if error_code == 'WAFNonexistentItemException':
                    # No logging configuration exists
                    compliance_status = ComplianceStatus.NON_COMPLIANT
                    evaluation_reason = (
                        f"WAF web ACL {web_acl_name} ({web_acl_scope}) does not have logging enabled. "
                        f"Enable logging for this WAF web ACL. Configure a log destination (Kinesis Data Firehose, "
                        f"S3, or CloudWatch Logs) using the AWS Console, CLI, or API. WAF logs help analyze web "
                        f"application firewall events for security analysis."
                    )
                else:
                    raise
                
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            
            if error_code == 'AccessDenied':
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Insufficient permissions to check logging for WAF web ACL {web_acl_name}: {str(e)}"
            elif error_code == 'WAFNonexistentItemException':
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"WAF web ACL {web_acl_name} not found (may have been deleted)"
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Error checking logging for WAF web ACL {web_acl_name}: {str(e)}"
        
        return ComplianceResult(
            resource_id=web_acl_arn,
            resource_type="AWS::WAFv2::WebACL",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
