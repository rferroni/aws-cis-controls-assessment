"""Control 3.14: Log Sensitive Data Access assessments."""

from typing import Dict, List, Any
import logging
import json
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class APIGatewayExecutionLoggingEnabledAssessment(BaseConfigRuleAssessment):
    """Assessment for api-gw-execution-logging-enabled Config rule."""
    
    def __init__(self):
        """Initialize API Gateway execution logging enabled assessment."""
        super().__init__(
            rule_name="api-gw-execution-logging-enabled",
            control_id="3.14",
            resource_types=["AWS::ApiGateway::Stage"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all API Gateway stages in the region."""
        if resource_type != "AWS::ApiGateway::Stage":
            return []
        
        try:
            apigateway_client = aws_factory.get_client('apigateway', region)
            
            # First get all REST APIs
            apis_response = aws_factory.aws_api_call_with_retry(
                lambda: apigateway_client.get_rest_apis()
            )
            
            stages = []
            for api in apis_response.get('items', []):
                api_id = api.get('id')
                api_name = api.get('name', 'unknown')
                
                try:
                    # Get stages for this API
                    stages_response = aws_factory.aws_api_call_with_retry(
                        lambda: apigateway_client.get_stages(restApiId=api_id)
                    )
                    
                    for stage in stages_response.get('item', []):
                        stages.append({
                            'restApiId': api_id,
                            'apiName': api_name,
                            'stageName': stage.get('stageName'),
                            'deploymentId': stage.get('deploymentId'),
                            'methodSettings': stage.get('methodSettings', {}),
                            'accessLogSettings': stage.get('accessLogSettings', {}),
                            'createdDate': stage.get('createdDate'),
                            'lastUpdatedDate': stage.get('lastUpdatedDate'),
                            'tags': stage.get('tags', {})
                        })
                
                except ClientError as e:
                    logger.warning(f"Could not get stages for API {api_id}: {e}")
                    continue
            
            logger.debug(f"Found {len(stages)} API Gateway stages in region {region}")
            return stages
            
        except ClientError as e:
            logger.error(f"Error retrieving API Gateway stages in region {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving API Gateway stages in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if API Gateway stage has execution logging enabled."""
        api_id = resource.get('restApiId', 'unknown')
        stage_name = resource.get('stageName', 'unknown')
        api_name = resource.get('apiName', 'unknown')
        resource_id = f"{api_id}/{stage_name}"
        
        method_settings = resource.get('methodSettings', {})
        access_log_settings = resource.get('accessLogSettings', {})
        
        # Check if execution logging is enabled
        # Look for logging level in method settings for */* (all methods)
        execution_logging_enabled = False
        logging_level = None
        
        # Check method settings for logging configuration
        for method_key, settings in method_settings.items():
            if method_key == '*/*' or method_key.startswith('*/'):
                logging_level = settings.get('loggingLevel')
                if logging_level and logging_level.upper() in ['INFO', 'ERROR']:
                    execution_logging_enabled = True
                    break
        
        # Also check if access logging is configured (alternative form of logging)
        access_logging_enabled = bool(access_log_settings.get('destinationArn'))
        
        if execution_logging_enabled or access_logging_enabled:
            compliance_status = ComplianceStatus.COMPLIANT
            if execution_logging_enabled:
                evaluation_reason = f"API Gateway stage {stage_name} in API {api_name} has execution logging enabled (level: {logging_level})"
            else:
                evaluation_reason = f"API Gateway stage {stage_name} in API {api_name} has access logging enabled"
        else:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"API Gateway stage {stage_name} in API {api_name} does not have execution or access logging enabled"
        
        return ComplianceResult(
            resource_id=resource_id,
            resource_type="AWS::ApiGateway::Stage",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for API Gateway execution logging."""
        return [
            "Identify API Gateway stages without execution logging enabled",
            "For each non-compliant stage:",
            "  1. Enable execution logging by configuring method settings",
            "  2. Set logging level to INFO or ERROR for comprehensive logging",
            "  3. Ensure CloudWatch Logs permissions are configured",
            "  4. Consider enabling access logging for additional visibility",
            "Use AWS CLI to enable execution logging:",
            "aws apigateway update-stage --rest-api-id <api-id> --stage-name <stage-name> --patch-ops op=replace,path=/*/logging/loglevel,value=INFO",
            "Enable access logging:",
            "aws apigateway update-stage --rest-api-id <api-id> --stage-name <stage-name> --patch-ops op=replace,path=/accessLogSettings/destinationArn,value=<cloudwatch-log-group-arn>",
            "Create CloudWatch Log Group if needed:",
            "aws logs create-log-group --log-group-name /aws/apigateway/<api-name>",
            "Set up log retention policies to manage storage costs",
            "Monitor logs for security events and API usage patterns",
            "Consider implementing log analysis and alerting for suspicious activity"
        ]


class CloudTrailS3DataEventsEnabledAssessment(BaseConfigRuleAssessment):
    """Assessment for cloudtrail-s3-dataevents-enabled Config rule."""
    
    def __init__(self):
        """Initialize CloudTrail S3 data events enabled assessment."""
        super().__init__(
            rule_name="cloudtrail-s3-dataevents-enabled",
            control_id="3.14",
            resource_types=["AWS::CloudTrail::Trail"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all CloudTrail trails in the region."""
        if resource_type != "AWS::CloudTrail::Trail":
            return []
        
        try:
            cloudtrail_client = aws_factory.get_client('cloudtrail', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: cloudtrail_client.describe_trails()
            )
            
            trails = []
            for trail in response.get('trailList', []):
                trail_arn = trail.get('TrailARN')
                trail_name = trail.get('Name')
                
                # Get event selectors for this trail to check for S3 data events
                try:
                    selectors_response = aws_factory.aws_api_call_with_retry(
                        lambda: cloudtrail_client.get_event_selectors(TrailName=trail_arn)
                    )
                    event_selectors = selectors_response.get('EventSelectors', [])
                except ClientError as e:
                    logger.warning(f"Could not get event selectors for trail {trail_name}: {e}")
                    event_selectors = []
                
                trails.append({
                    'TrailARN': trail_arn,
                    'Name': trail_name,
                    'S3BucketName': trail.get('S3BucketName'),
                    'S3KeyPrefix': trail.get('S3KeyPrefix'),
                    'IncludeGlobalServiceEvents': trail.get('IncludeGlobalServiceEvents'),
                    'IsMultiRegionTrail': trail.get('IsMultiRegionTrail'),
                    'IsLogging': trail.get('IsLogging'),
                    'EventSelectors': event_selectors,
                    'HomeRegion': trail.get('HomeRegion')
                })
            
            logger.debug(f"Found {len(trails)} CloudTrail trails in region {region}")
            return trails
            
        except ClientError as e:
            logger.error(f"Error retrieving CloudTrail trails in region {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving CloudTrail trails in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if CloudTrail trail has S3 data events enabled."""
        trail_arn = resource.get('TrailARN', 'unknown')
        trail_name = resource.get('Name', 'unknown')
        event_selectors = resource.get('EventSelectors', [])
        is_logging = resource.get('IsLogging', False)
        
        # Check if trail is actively logging
        if not is_logging:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"CloudTrail trail {trail_name} is not actively logging"
        else:
            # Check if any event selector includes S3 data events
            s3_data_events_enabled = False
            
            for selector in event_selectors:
                read_write_type = selector.get('ReadWriteType', 'All')
                include_management_events = selector.get('IncludeManagementEvents', True)
                data_resources = selector.get('DataResources', [])
                
                # Look for S3 data resources
                for data_resource in data_resources:
                    resource_type = data_resource.get('Type', '')
                    if resource_type == 'AWS::S3::Object':
                        s3_data_events_enabled = True
                        break
                
                if s3_data_events_enabled:
                    break
            
            if s3_data_events_enabled:
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = f"CloudTrail trail {trail_name} has S3 data events logging enabled"
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = f"CloudTrail trail {trail_name} does not have S3 data events logging enabled"
        
        return ComplianceResult(
            resource_id=trail_arn,
            resource_type="AWS::CloudTrail::Trail",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for CloudTrail S3 data events."""
        return [
            "Identify CloudTrail trails without S3 data events logging",
            "For each non-compliant trail:",
            "  1. Configure event selectors to include S3 data events",
            "  2. Specify S3 buckets or use wildcard for all buckets",
            "  3. Choose appropriate read/write event types",
            "  4. Ensure trail is actively logging",
            "Use AWS CLI to enable S3 data events:",
            "aws cloudtrail put-event-selectors --trail-name <trail-name> --event-selectors '[{\"ReadWriteType\":\"All\",\"IncludeManagementEvents\":true,\"DataResources\":[{\"Type\":\"AWS::S3::Object\",\"Values\":[\"arn:aws:s3:::*/*\"]}]}]'",
            "For specific buckets only:",
            "aws cloudtrail put-event-selectors --trail-name <trail-name> --event-selectors '[{\"ReadWriteType\":\"All\",\"IncludeManagementEvents\":true,\"DataResources\":[{\"Type\":\"AWS::S3::Object\",\"Values\":[\"arn:aws:s3:::sensitive-bucket/*\"]}]}]'",
            "Verify trail is logging:",
            "aws cloudtrail get-trail-status --name <trail-name>",
            "Monitor CloudTrail costs as data events can increase charges significantly",
            "Consider using CloudWatch Insights to analyze S3 access patterns",
            "Set up alerts for unusual S3 data access patterns"
        ]


class MultiRegionCloudTrailEnabledAssessment(BaseConfigRuleAssessment):
    """Assessment for multi-region-cloudtrail-enabled Config rule."""
    
    def __init__(self):
        """Initialize multi-region CloudTrail enabled assessment."""
        super().__init__(
            rule_name="multi-region-cloudtrail-enabled",
            control_id="3.14",
            resource_types=["AWS::::Account"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get account-level resource for multi-region CloudTrail assessment."""
        if resource_type != "AWS::::Account":
            return []
        
        # Return a single account resource for this assessment
        account_info = aws_factory.get_account_info()
        return [{
            'accountId': account_info.get('account_id', 'unknown'),
            'region': region
        }]
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if account has multi-region CloudTrail enabled."""
        account_id = resource.get('accountId', 'unknown')
        resource_id = f"account-{account_id}"
        
        try:
            cloudtrail_client = aws_factory.get_client('cloudtrail', region)
            
            # Get all trails (this will include trails from all regions if multi-region)
            response = aws_factory.aws_api_call_with_retry(
                lambda: cloudtrail_client.describe_trails()
            )
            
            trails = response.get('trailList', [])
            
            # Look for at least one multi-region trail that is logging
            multi_region_trails = []
            for trail in trails:
                is_multi_region = trail.get('IsMultiRegionTrail', False)
                is_logging = trail.get('IsLogging', False)
                trail_name = trail.get('Name', 'unknown')
                
                if is_multi_region and is_logging:
                    multi_region_trails.append(trail_name)
            
            if multi_region_trails:
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = f"Account {account_id} has {len(multi_region_trails)} active multi-region CloudTrail trail(s): {', '.join(multi_region_trails)}"
            else:
                # Check if there are any trails at all
                if not trails:
                    compliance_status = ComplianceStatus.NON_COMPLIANT
                    evaluation_reason = f"Account {account_id} has no CloudTrail trails configured"
                else:
                    single_region_trails = [t.get('Name', 'unknown') for t in trails if not t.get('IsMultiRegionTrail', False)]
                    if single_region_trails:
                        compliance_status = ComplianceStatus.NON_COMPLIANT
                        evaluation_reason = f"Account {account_id} has only single-region CloudTrail trails: {', '.join(single_region_trails)}"
                    else:
                        compliance_status = ComplianceStatus.NON_COMPLIANT
                        evaluation_reason = f"Account {account_id} has multi-region trails but they are not actively logging"
        
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code in ['AccessDenied', 'UnauthorizedOperation']:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Insufficient permissions to check CloudTrail configuration for account {account_id}"
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Error checking CloudTrail configuration for account {account_id}: {str(e)}"
        except Exception as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Unexpected error checking CloudTrail configuration for account {account_id}: {str(e)}"
        
        return ComplianceResult(
            resource_id=resource_id,
            resource_type="AWS::::Account",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for multi-region CloudTrail."""
        return [
            "Ensure at least one multi-region CloudTrail trail is configured and active",
            "If no CloudTrail exists:",
            "  1. Create a new CloudTrail trail",
            "  2. Enable multi-region logging",
            "  3. Configure S3 bucket for log storage",
            "  4. Enable log file validation",
            "If single-region trails exist:",
            "  1. Modify existing trail to enable multi-region logging",
            "  2. Or create a new multi-region trail",
            "Use AWS CLI to create multi-region trail:",
            "aws cloudtrail create-trail --name <trail-name> --s3-bucket-name <bucket-name> --is-multi-region-trail",
            "Enable logging:",
            "aws cloudtrail start-logging --name <trail-name>",
            "Enable log file validation:",
            "aws cloudtrail update-trail --name <trail-name> --enable-log-file-validation",
            "Configure CloudWatch Logs integration:",
            "aws cloudtrail update-trail --name <trail-name> --cloud-watch-logs-log-group-arn <log-group-arn> --cloud-watch-logs-role-arn <role-arn>",
            "Set up S3 bucket policy to allow CloudTrail access",
            "Configure SNS notifications for log file delivery",
            "Monitor CloudTrail costs and set up billing alerts",
            "Regularly review CloudTrail logs for security events"
        ]


class CloudTrailCloudWatchLogsEnabledAssessment(BaseConfigRuleAssessment):
    """Assessment for cloud-trail-cloud-watch-logs-enabled Config rule."""
    
    def __init__(self):
        """Initialize CloudTrail CloudWatch Logs enabled assessment."""
        super().__init__(
            rule_name="cloud-trail-cloud-watch-logs-enabled",
            control_id="3.14",
            resource_types=["AWS::CloudTrail::Trail"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all CloudTrail trails in the region."""
        if resource_type != "AWS::CloudTrail::Trail":
            return []
        
        try:
            cloudtrail_client = aws_factory.get_client('cloudtrail', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: cloudtrail_client.describe_trails()
            )
            
            trails = []
            for trail in response.get('trailList', []):
                trails.append({
                    'TrailARN': trail.get('TrailARN'),
                    'Name': trail.get('Name'),
                    'S3BucketName': trail.get('S3BucketName'),
                    'S3KeyPrefix': trail.get('S3KeyPrefix'),
                    'IncludeGlobalServiceEvents': trail.get('IncludeGlobalServiceEvents'),
                    'IsMultiRegionTrail': trail.get('IsMultiRegionTrail'),
                    'IsLogging': trail.get('IsLogging'),
                    'CloudWatchLogsLogGroupArn': trail.get('CloudWatchLogsLogGroupArn'),
                    'CloudWatchLogsRoleArn': trail.get('CloudWatchLogsRoleArn'),
                    'HomeRegion': trail.get('HomeRegion')
                })
            
            logger.debug(f"Found {len(trails)} CloudTrail trails in region {region}")
            return trails
            
        except ClientError as e:
            logger.error(f"Error retrieving CloudTrail trails in region {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving CloudTrail trails in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if CloudTrail trail has CloudWatch Logs integration enabled."""
        trail_arn = resource.get('TrailARN', 'unknown')
        trail_name = resource.get('Name', 'unknown')
        cloudwatch_logs_group_arn = resource.get('CloudWatchLogsLogGroupArn')
        cloudwatch_logs_role_arn = resource.get('CloudWatchLogsRoleArn')
        is_logging = resource.get('IsLogging', False)
        
        # Check if trail is actively logging
        if not is_logging:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"CloudTrail trail {trail_name} is not actively logging"
        else:
            # Check if CloudWatch Logs integration is configured
            if cloudwatch_logs_group_arn and cloudwatch_logs_role_arn:
                # Verify the CloudWatch Logs group exists and is accessible
                try:
                    logs_client = aws_factory.get_client('logs', region)
                    
                    # Extract log group name from ARN
                    # ARN format: arn:aws:logs:region:account:log-group:log-group-name:*
                    log_group_name = cloudwatch_logs_group_arn.split(':')[-2] if ':' in cloudwatch_logs_group_arn else cloudwatch_logs_group_arn
                    
                    # Check if log group exists
                    response = aws_factory.aws_api_call_with_retry(
                        lambda: logs_client.describe_log_groups(
                            logGroupNamePrefix=log_group_name,
                            limit=1
                        )
                    )
                    
                    log_groups = response.get('logGroups', [])
                    log_group_exists = any(lg.get('logGroupName') == log_group_name for lg in log_groups)
                    
                    if log_group_exists:
                        compliance_status = ComplianceStatus.COMPLIANT
                        evaluation_reason = f"CloudTrail trail {trail_name} has CloudWatch Logs integration enabled with log group {log_group_name}"
                    else:
                        compliance_status = ComplianceStatus.NON_COMPLIANT
                        evaluation_reason = f"CloudTrail trail {trail_name} has CloudWatch Logs configured but log group {log_group_name} does not exist"
                
                except ClientError as e:
                    logger.warning(f"Could not verify CloudWatch Logs group for trail {trail_name}: {e}")
                    # Assume compliant if we can't verify but configuration exists
                    compliance_status = ComplianceStatus.COMPLIANT
                    evaluation_reason = f"CloudTrail trail {trail_name} has CloudWatch Logs integration configured (verification limited by permissions)"
                
                except Exception as e:
                    logger.warning(f"Error verifying CloudWatch Logs group for trail {trail_name}: {e}")
                    compliance_status = ComplianceStatus.COMPLIANT
                    evaluation_reason = f"CloudTrail trail {trail_name} has CloudWatch Logs integration configured"
            
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                if not cloudwatch_logs_group_arn and not cloudwatch_logs_role_arn:
                    evaluation_reason = f"CloudTrail trail {trail_name} does not have CloudWatch Logs integration configured"
                elif not cloudwatch_logs_group_arn:
                    evaluation_reason = f"CloudTrail trail {trail_name} is missing CloudWatch Logs group ARN"
                else:
                    evaluation_reason = f"CloudTrail trail {trail_name} is missing CloudWatch Logs role ARN"
        
        return ComplianceResult(
            resource_id=trail_arn,
            resource_type="AWS::CloudTrail::Trail",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for CloudTrail CloudWatch Logs integration."""
        return [
            "Configure CloudWatch Logs integration for CloudTrail trails",
            "For each non-compliant trail:",
            "  1. Create CloudWatch Logs group for CloudTrail",
            "  2. Create IAM role for CloudTrail to write to CloudWatch Logs",
            "  3. Update trail configuration with CloudWatch Logs settings",
            "  4. Verify log delivery is working",
            "Create CloudWatch Logs group:",
            "aws logs create-log-group --log-group-name /aws/cloudtrail/<trail-name>",
            "Create IAM role with trust policy for CloudTrail:",
            "aws iam create-role --role-name CloudTrail_CloudWatchLogs_Role --assume-role-policy-document file://trust-policy.json",
            "Attach policy for CloudWatch Logs access:",
            "aws iam attach-role-policy --role-name CloudTrail_CloudWatchLogs_Role --policy-arn arn:aws:iam::aws:policy/CloudWatchLogsFullAccess",
            "Update CloudTrail with CloudWatch Logs configuration:",
            "aws cloudtrail update-trail --name <trail-name> --cloud-watch-logs-log-group-arn <log-group-arn> --cloud-watch-logs-role-arn <role-arn>",
            "Set up log retention policy to manage costs:",
            "aws logs put-retention-policy --log-group-name /aws/cloudtrail/<trail-name> --retention-in-days 90",
            "Create CloudWatch alarms for security events",
            "Set up log insights queries for security analysis",
            "Monitor CloudWatch Logs costs and usage"
        ]