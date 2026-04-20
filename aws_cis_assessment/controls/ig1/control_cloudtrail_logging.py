"""
CIS Control 8.2 - CloudTrail and Logging Controls
Critical logging and audit trail controls for compliance and security monitoring.
"""

import logging
from typing import List, Dict, Any, Optional
import boto3
import json
from botocore.exceptions import ClientError, NoCredentialsError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class CloudTrailEnabledAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 8.2 - Collect Audit Logs
    AWS Config Rule: cloudtrail-enabled
    
    Ensures CloudTrail is enabled to record AWS Management Console actions and API calls.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="cloudtrail-enabled",
            control_id="8.2",
            resource_types=["AWS::::Account"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get CloudTrail configuration for the account."""
        if resource_type != "AWS::::Account":
            return []
        
        try:
            cloudtrail_client = aws_factory.get_client('cloudtrail', region)
            
            # Get all trails in this region, excluding shadow trails
            # Shadow trails are replications from other regions or organization trails
            response = cloudtrail_client.describe_trails(includeShadowTrails=False)
            trails = response.get('trailList', [])
            
            # Get trail status for each trail
            trail_statuses = []
            for trail in trails:
                trail_name = trail.get('Name', '')
                trail_arn = trail.get('TrailARN', '')
                home_region = trail.get('HomeRegion', '')
                
                # Skip shadow trails (trails from other regions or organization trails)
                # These are indicated by HomeRegion being different from current region
                if home_region and home_region != region:
                    logger.debug(f"Skipping shadow trail {trail_name} (home region: {home_region}, current region: {region})")
                    continue
                
                try:
                    # Get trail status
                    status_response = cloudtrail_client.get_trail_status(Name=trail_name)
                    is_logging = status_response.get('IsLogging', False)
                    
                    # Get event selectors to check what's being logged
                    try:
                        selectors_response = cloudtrail_client.get_event_selectors(TrailName=trail_name)
                        event_selectors = selectors_response.get('EventSelectors', [])
                    except ClientError:
                        event_selectors = []
                    
                    trail_statuses.append({
                        'TrailName': trail_name,
                        'TrailARN': trail_arn,
                        'IsLogging': is_logging,
                        'IsMultiRegionTrail': trail.get('IsMultiRegionTrail', False),
                        'IsOrganizationTrail': trail.get('IsOrganizationTrail', False),
                        'IncludeGlobalServiceEvents': trail.get('IncludeGlobalServiceEvents', False),
                        'S3BucketName': trail.get('S3BucketName', ''),
                        'HomeRegion': home_region,
                        'EventSelectors': event_selectors,
                        'Region': region
                    })
                    
                except ClientError as e:
                    error_code = e.response.get('Error', {}).get('Code', '')
                    
                    # Only log warning for unexpected errors, not for shadow trails
                    if error_code == 'TrailNotFoundException':
                        logger.debug(f"Trail {trail_name} not found in {region} - likely a shadow trail or deleted trail")
                    else:
                        logger.warning(f"Error getting status for trail {trail_name}: {e}")
                    continue
            
            # Return account-level resource with trail information
            return [{
                'AccountId': aws_factory.get_account_info().get('account_id', 'unknown'),
                'Region': region,
                'Trails': trail_statuses,
                'HasActiveTrails': any(trail['IsLogging'] for trail in trail_statuses)
            }]
            
        except ClientError as e:
            logger.error(f"Error retrieving CloudTrail information from {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving CloudTrail information from {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if CloudTrail is enabled and logging."""
        account_id = resource.get('AccountId', 'unknown')
        trails = resource.get('Trails', [])
        has_active_trails = resource.get('HasActiveTrails', False)
        
        if has_active_trails:
            # Check for at least one properly configured trail
            active_trails = [trail for trail in trails if trail['IsLogging']]
            
            # Categorize trails
            org_trails = [t for t in active_trails if t.get('IsOrganizationTrail', False)]
            multi_region_trails = [t for t in active_trails if t.get('IsMultiRegionTrail', False)]
            regional_trails = [t for t in active_trails if not t.get('IsMultiRegionTrail', False)]
            
            # Build detailed reason
            trail_details = []
            for trail in active_trails:
                trail_type = []
                if trail.get('IsOrganizationTrail', False):
                    trail_type.append("organization")
                if trail.get('IsMultiRegionTrail', False):
                    trail_type.append("multi-region")
                else:
                    trail_type.append("regional")
                
                trail_info = f"{trail['TrailName']} ({', '.join(trail_type)})"
                trail_details.append(trail_info)
            
            reason = f"CloudTrail is enabled with {len(active_trails)} active trail(s): {', '.join(trail_details)}"
            
            return ComplianceResult(
                resource_id=account_id,
                resource_type="AWS::::Account",
                compliance_status=ComplianceStatus.COMPLIANT,
                evaluation_reason=reason,
                config_rule_name=self.rule_name,
                region=region
            )
        else:
            return ComplianceResult(
                resource_id=account_id,
                resource_type="AWS::::Account",
                compliance_status=ComplianceStatus.NON_COMPLIANT,
                evaluation_reason="CloudTrail is not enabled or no trails are actively logging in this region",
                config_rule_name=self.rule_name,
                region=region
            )


class CloudWatchLogGroupEncryptedAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 3.11 - Encrypt Sensitive Data at Rest
    AWS Config Rule: cloudwatch-log-group-encrypted
    
    Ensures CloudWatch Log Groups are encrypted with KMS keys.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="cloudwatch-log-group-encrypted",
            control_id="3.11",
            resource_types=["AWS::Logs::LogGroup"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all CloudWatch Log Groups in the region."""
        if resource_type != "AWS::Logs::LogGroup":
            return []
        
        try:
            logs_client = aws_factory.get_client('logs', region)
            
            log_groups = []
            paginator = logs_client.get_paginator('describe_log_groups')
            
            for page in paginator.paginate():
                for log_group in page.get('logGroups', []):
                    log_group_name = log_group.get('logGroupName', '')
                    kms_key_id = log_group.get('kmsKeyId', '')
                    
                    log_groups.append({
                        'LogGroupName': log_group_name,
                        'KmsKeyId': kms_key_id,
                        'IsEncrypted': bool(kms_key_id),
                        'CreationTime': log_group.get('creationTime', 0),
                        'RetentionInDays': log_group.get('retentionInDays'),
                        'StoredBytes': log_group.get('storedBytes', 0)
                    })
            
            logger.debug(f"Found {len(log_groups)} CloudWatch Log Groups in {region}")
            return log_groups
            
        except ClientError as e:
            logger.error(f"Error retrieving CloudWatch Log Groups from {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving CloudWatch Log Groups from {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if CloudWatch Log Group is encrypted."""
        log_group_name = resource.get('LogGroupName', 'unknown')
        is_encrypted = resource.get('IsEncrypted', False)
        kms_key_id = resource.get('KmsKeyId', '')
        
        if is_encrypted:
            return ComplianceResult(
                resource_id=log_group_name,
                resource_type="AWS::Logs::LogGroup",
                compliance_status=ComplianceStatus.COMPLIANT,
                evaluation_reason=f"CloudWatch Log Group is encrypted with KMS key: {kms_key_id}",
                config_rule_name=self.rule_name,
                region=region
            )
        else:
            return ComplianceResult(
                resource_id=log_group_name,
                resource_type="AWS::Logs::LogGroup",
                compliance_status=ComplianceStatus.NON_COMPLIANT,
                evaluation_reason="CloudWatch Log Group is not encrypted with KMS",
                config_rule_name=self.rule_name,
                region=region
            )