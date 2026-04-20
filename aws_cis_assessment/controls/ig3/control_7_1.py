"""Control 7.1: Establish and Maintain a Vulnerability Management Process assessments."""

from typing import Dict, List, Any
import logging
import json
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class ECRPrivateImageScanningEnabledAssessment(BaseConfigRuleAssessment):
    """Assessment for ecr-private-image-scanning-enabled Config rule."""
    
    def __init__(self):
        """Initialize ECR private image scanning enabled assessment."""
        super().__init__(
            rule_name="ecr-private-image-scanning-enabled",
            control_id="7.1",
            resource_types=["AWS::ECR::Repository"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all ECR repositories in the region."""
        if resource_type != "AWS::ECR::Repository":
            return []
        
        try:
            ecr_client = aws_factory.get_client('ecr', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: ecr_client.describe_repositories()
            )
            
            repositories = []
            for repo in response.get('repositories', []):
                repositories.append({
                    'repositoryName': repo.get('repositoryName'),
                    'repositoryArn': repo.get('repositoryArn'),
                    'repositoryUri': repo.get('repositoryUri'),
                    'registryId': repo.get('registryId'),
                    'imageScanningConfiguration': repo.get('imageScanningConfiguration', {}),
                    'createdAt': repo.get('createdAt'),
                    'imageTagMutability': repo.get('imageTagMutability')
                })
            
            logger.debug(f"Found {len(repositories)} ECR repositories in region {region}")
            return repositories
            
        except ClientError as e:
            logger.error(f"Error retrieving ECR repositories in region {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving ECR repositories in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if ECR repository has image scanning enabled."""
        repo_name = resource.get('repositoryName', 'unknown')
        repo_arn = resource.get('repositoryArn', 'unknown')
        scanning_config = resource.get('imageScanningConfiguration', {})
        
        # Check if scan on push is enabled
        scan_on_push = scanning_config.get('scanOnPush', False)
        
        if scan_on_push:
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = f"ECR repository {repo_name} has image scanning enabled (scanOnPush: true)"
        else:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"ECR repository {repo_name} does not have image scanning enabled (scanOnPush: false)"
        
        return ComplianceResult(
            resource_id=repo_arn,
            resource_type="AWS::ECR::Repository",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for ECR image scanning."""
        return [
            "Identify ECR repositories without image scanning enabled",
            "For each non-compliant repository:",
            "  1. Enable scan on push for the repository",
            "  2. Consider enabling enhanced scanning for more comprehensive vulnerability detection",
            "  3. Set up notifications for scan results",
            "Use AWS CLI: aws ecr put-image-scanning-configuration --repository-name <repo-name> --image-scanning-configuration scanOnPush=true",
            "Enable enhanced scanning: aws ecr put-registry-scanning-configuration --scan-type ENHANCED",
            "Set up EventBridge rules to receive scan completion notifications",
            "Review scan results regularly and remediate identified vulnerabilities",
            "Consider implementing automated workflows to block deployment of vulnerable images",
            "Document vulnerability management process for container images"
        ]


class GuardDutyEnabledCentralizedAssessment(BaseConfigRuleAssessment):
    """Assessment for guardduty-enabled-centralized Config rule."""
    
    def __init__(self):
        """Initialize GuardDuty enabled centralized assessment."""
        super().__init__(
            rule_name="guardduty-enabled-centralized",
            control_id="7.1",
            resource_types=["AWS::::Account"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get account-level resource for GuardDuty assessment."""
        if resource_type != "AWS::::Account":
            return []
        
        # Return a single account resource for this region
        account_info = aws_factory.get_account_info()
        return [{
            'accountId': account_info.get('account_id', 'unknown'),
            'region': region
        }]
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if GuardDuty is enabled in the account/region."""
        account_id = resource.get('accountId', 'unknown')
        resource_id = f"account-{account_id}-{region}"
        
        try:
            guardduty_client = aws_factory.get_client('guardduty', region)
            
            # List detectors to see if GuardDuty is enabled
            response = aws_factory.aws_api_call_with_retry(
                lambda: guardduty_client.list_detectors()
            )
            
            detector_ids = response.get('DetectorIds', [])
            
            if not detector_ids:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = f"GuardDuty is not enabled in account {account_id} region {region}"
            else:
                # Check if any detector is enabled
                enabled_detectors = []
                
                for detector_id in detector_ids:
                    try:
                        detector_response = aws_factory.aws_api_call_with_retry(
                            lambda: guardduty_client.get_detector(DetectorId=detector_id)
                        )
                        
                        status = detector_response.get('Status', 'DISABLED')
                        if status == 'ENABLED':
                            enabled_detectors.append(detector_id)
                    
                    except ClientError as e:
                        logger.warning(f"Could not get detector {detector_id} details: {e}")
                        continue
                
                if enabled_detectors:
                    compliance_status = ComplianceStatus.COMPLIANT
                    evaluation_reason = f"GuardDuty is enabled in account {account_id} region {region} with {len(enabled_detectors)} active detector(s)"
                else:
                    compliance_status = ComplianceStatus.NON_COMPLIANT
                    evaluation_reason = f"GuardDuty detectors exist but are disabled in account {account_id} region {region}"
        
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code in ['AccessDenied', 'UnauthorizedOperation']:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Insufficient permissions to check GuardDuty status in account {account_id} region {region}"
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Error checking GuardDuty status in account {account_id} region {region}: {str(e)}"
        except Exception as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Unexpected error checking GuardDuty status in account {account_id} region {region}: {str(e)}"
        
        return ComplianceResult(
            resource_id=resource_id,
            resource_type="AWS::::Account",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for GuardDuty enablement."""
        return [
            "Enable GuardDuty in all AWS regions where resources are deployed",
            "For each region without GuardDuty:",
            "  1. Create a GuardDuty detector",
            "  2. Enable the detector",
            "  3. Configure finding export to S3 or other destinations",
            "  4. Set up notifications for high-severity findings",
            "Use AWS CLI: aws guardduty create-detector --enable --region <region>",
            "Enable S3 protection: aws guardduty update-detector --detector-id <detector-id> --data-sources S3Logs={Enable=true}",
            "Enable Kubernetes protection: aws guardduty update-detector --detector-id <detector-id> --data-sources Kubernetes={AuditLogs={Enable=true}}",
            "Set up centralized logging by configuring finding export",
            "Create EventBridge rules to route findings to security teams",
            "Consider enabling GuardDuty Malware Protection for EC2 instances",
            "Implement automated response workflows for critical findings",
            "Regularly review and tune GuardDuty findings to reduce false positives"
        ]


class EC2ManagedInstancePatchComplianceAssessment(BaseConfigRuleAssessment):
    """Assessment for ec2-managedinstance-patch-compliance-status-check Config rule."""
    
    def __init__(self):
        """Initialize EC2 managed instance patch compliance assessment."""
        super().__init__(
            rule_name="ec2-managedinstance-patch-compliance-status-check",
            control_id="7.1",
            resource_types=["AWS::EC2::Instance"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all EC2 instances that are managed by Systems Manager."""
        if resource_type != "AWS::EC2::Instance":
            return []
        
        try:
            ec2_client = aws_factory.get_client('ec2', region)
            ssm_client = aws_factory.get_client('ssm', region)
            
            # First get all EC2 instances
            response = aws_factory.aws_api_call_with_retry(
                lambda: ec2_client.describe_instances()
            )
            
            all_instances = []
            for reservation in response.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    if instance.get('State', {}).get('Name') == 'running':
                        all_instances.append({
                            'InstanceId': instance.get('InstanceId'),
                            'InstanceType': instance.get('InstanceType'),
                            'Platform': instance.get('Platform', 'Linux'),
                            'LaunchTime': instance.get('LaunchTime'),
                            'Tags': instance.get('Tags', [])
                        })
            
            # Filter to only instances managed by Systems Manager
            managed_instances = []
            if all_instances:
                try:
                    # Get managed instances from Systems Manager
                    ssm_response = aws_factory.aws_api_call_with_retry(
                        lambda: ssm_client.describe_instance_information()
                    )
                    
                    managed_instance_ids = set()
                    for instance_info in ssm_response.get('InstanceInformationList', []):
                        managed_instance_ids.add(instance_info.get('InstanceId'))
                    
                    # Filter EC2 instances to only managed ones
                    for instance in all_instances:
                        if instance['InstanceId'] in managed_instance_ids:
                            managed_instances.append(instance)
                
                except ClientError as e:
                    logger.warning(f"Could not get Systems Manager managed instances: {e}")
                    # If we can't access SSM, we'll evaluate all running instances
                    managed_instances = all_instances
            
            logger.debug(f"Found {len(managed_instances)} managed EC2 instances in region {region}")
            return managed_instances
            
        except ClientError as e:
            logger.error(f"Error retrieving EC2 instances in region {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving EC2 instances in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if EC2 instance has compliant patch status."""
        instance_id = resource.get('InstanceId', 'unknown')
        instance_type = resource.get('InstanceType', 'unknown')
        platform = resource.get('Platform', 'Linux')
        
        try:
            ssm_client = aws_factory.get_client('ssm', region)
            
            # Get patch compliance information for this instance
            response = aws_factory.aws_api_call_with_retry(
                lambda: ssm_client.describe_instance_patch_states(
                    InstanceIds=[instance_id]
                )
            )
            
            patch_states = response.get('InstancePatchStates', [])
            
            if not patch_states:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = f"EC2 instance {instance_id} ({platform}) has no patch compliance information available"
            else:
                patch_state = patch_states[0]
                operation_end_time = patch_state.get('OperationEndTime')
                failed_count = patch_state.get('FailedCount', 0)
                missing_count = patch_state.get('MissingCount', 0)
                installed_count = patch_state.get('InstalledCount', 0)
                not_applicable_count = patch_state.get('NotApplicableCount', 0)
                
                # Consider compliant if no failed or missing patches
                if failed_count == 0 and missing_count == 0:
                    compliance_status = ComplianceStatus.COMPLIANT
                    evaluation_reason = f"EC2 instance {instance_id} ({platform}) is patch compliant - {installed_count} installed, {not_applicable_count} not applicable"
                else:
                    compliance_status = ComplianceStatus.NON_COMPLIANT
                    evaluation_reason = f"EC2 instance {instance_id} ({platform}) is not patch compliant - {missing_count} missing, {failed_count} failed patches"
        
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code in ['AccessDenied', 'UnauthorizedOperation']:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Insufficient permissions to check patch compliance for EC2 instance {instance_id}"
            elif error_code == 'InvalidInstanceId.NotFound':
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"EC2 instance {instance_id} not found in Systems Manager (may not be managed)"
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Error checking patch compliance for EC2 instance {instance_id}: {str(e)}"
        except Exception as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Unexpected error checking patch compliance for EC2 instance {instance_id}: {str(e)}"
        
        return ComplianceResult(
            resource_id=instance_id,
            resource_type="AWS::EC2::Instance",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for EC2 patch compliance."""
        return [
            "Ensure EC2 instances are managed by AWS Systems Manager",
            "For instances not managed by Systems Manager:",
            "  1. Install SSM Agent (pre-installed on Amazon Linux, Windows, Ubuntu)",
            "  2. Attach IAM role with AmazonSSMManagedInstanceCore policy",
            "  3. Verify instance appears in Systems Manager console",
            "For non-compliant patch status:",
            "  1. Create or update patch baselines for your operating systems",
            "  2. Create maintenance windows for patch installation",
            "  3. Run patch scans to identify missing patches",
            "  4. Install missing patches during maintenance windows",
            "Use AWS CLI: aws ssm send-command --document-name 'AWS-RunPatchBaseline' --instance-ids <instance-id> --parameters 'Operation=Scan'",
            "Install patches: aws ssm send-command --document-name 'AWS-RunPatchBaseline' --instance-ids <instance-id> --parameters 'Operation=Install'",
            "Set up automated patching with maintenance windows",
            "Monitor patch compliance using Systems Manager Compliance",
            "Create CloudWatch alarms for patch compliance failures",
            "Implement patch testing procedures before production deployment"
        ]