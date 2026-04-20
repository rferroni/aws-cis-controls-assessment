"""
Critical Security Foundation Controls for CIS Assessment.
Implements the most critical security controls that should be prioritized.
"""

from typing import List, Dict, Any, Optional
import logging
from botocore.exceptions import ClientError, NoCredentialsError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class RootAccountHardwareMFAEnabledAssessment(BaseConfigRuleAssessment):
    """Assessment for root-account-hardware-mfa-enabled AWS Config rule."""
    
    def __init__(self):
        super().__init__(
            rule_name="root-account-hardware-mfa-enabled",
            control_id="1.5",
            resource_types=["AWS::IAM::Root"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get root account MFA configuration."""
        if resource_type != "AWS::IAM::Root":
            return []
            
        try:
            iam_client = aws_factory.get_client('iam', region)
            
            # Get account summary which includes MFA device count for root
            account_summary = iam_client.get_account_summary()
            summary_map = account_summary.get('SummaryMap', {})
            
            # Get virtual MFA devices to check if root has hardware MFA
            # Virtual MFA devices can be listed without specifying a user
            try:
                virtual_mfa_devices = iam_client.list_virtual_mfa_devices()
                virtual_mfa_list = virtual_mfa_devices.get('VirtualMFADevices', [])
            except ClientError as e:
                logger.warning(f"Could not list virtual MFA devices: {e}")
                virtual_mfa_list = []
            
            return [{
                'account_id': aws_factory.account_id,
                'account_summary': summary_map,
                'virtual_mfa_devices': virtual_mfa_list
            }]
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code in ['AccessDenied', 'UnauthorizedOperation']:
                logger.warning(f"Insufficient permissions to check root account MFA: {e}")
            else:
                logger.error(f"Error getting root account MFA configuration: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error in root account MFA check: {e}")
            return []
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate root account hardware MFA compliance."""
        try:
            account_summary = resource.get('account_summary', {})
            virtual_mfa_devices = resource.get('virtual_mfa_devices', [])
            account_id = resource.get('account_id', 'unknown')
            
            # Check if root account has any MFA devices
            account_mfa_enabled = account_summary.get('AccountMFAEnabled', 0)
            
            if account_mfa_enabled == 0:
                return ComplianceResult(
                    resource_id=account_id,
                    resource_type="AWS::IAM::Root",
                    compliance_status=ComplianceStatus.NON_COMPLIANT,
                    evaluation_reason="Root account does not have MFA enabled",
                    config_rule_name=self.rule_name,
                    region=region
                )
            
            # Check if root has a virtual MFA device
            # Virtual MFA devices for root have SerialNumber like: arn:aws:iam::ACCOUNT_ID:mfa/root-account-mfa-device
            root_virtual_mfa = [
                device for device in virtual_mfa_devices 
                if 'root-account-mfa-device' in device.get('SerialNumber', '').lower()
                or device.get('User', {}).get('Arn', '').endswith(':root')
            ]
            
            if root_virtual_mfa:
                return ComplianceResult(
                    resource_id=account_id,
                    resource_type="AWS::IAM::Root",
                    compliance_status=ComplianceStatus.NON_COMPLIANT,
                    evaluation_reason="Root account has virtual MFA enabled, hardware MFA required for enhanced security",
                    config_rule_name=self.rule_name,
                    region=region
                )
            
            # If MFA is enabled but no virtual MFA found, assume hardware MFA
            # Note: We cannot definitively verify hardware MFA without root credentials,
            # but if AccountMFAEnabled=1 and no virtual MFA exists, it's likely hardware
            return ComplianceResult(
                resource_id=account_id,
                resource_type="AWS::IAM::Root",
                compliance_status=ComplianceStatus.COMPLIANT,
                evaluation_reason="Root account has MFA enabled (likely hardware MFA - no virtual MFA detected)",
                config_rule_name=self.rule_name,
                region=region
            )
            
        except Exception as e:
            logger.error(f"Error evaluating root account hardware MFA compliance: {e}")
            return ComplianceResult(
                resource_id=resource.get('account_id', 'unknown'),
                resource_type="AWS::IAM::Root",
                compliance_status=ComplianceStatus.NOT_APPLICABLE,
                evaluation_reason=f"Error evaluating compliance: {str(e)}",
                config_rule_name=self.rule_name,
                region=region
            )


class OpenSearchInVPCOnlyAssessment(BaseConfigRuleAssessment):
    """Assessment for opensearch-in-vpc-only AWS Config rule."""
    
    def __init__(self):
        super().__init__(
            rule_name="opensearch-in-vpc-only",
            control_id="2.2.1",
            resource_types=["AWS::OpenSearch::Domain"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get OpenSearch domains to evaluate."""
        if resource_type != "AWS::OpenSearch::Domain":
            return []
            
        try:
            opensearch_client = aws_factory.get_client('opensearch', region)
            
            # List all OpenSearch domain names
            domain_names_response = opensearch_client.list_domain_names()
            domain_names = [domain['DomainName'] for domain in domain_names_response.get('DomainNames', [])]
            
            if not domain_names:
                return []
            
            # Get detailed information for each domain
            domains_response = opensearch_client.describe_domains(DomainNames=domain_names)
            domains = domains_response.get('DomainStatusList', [])
            
            return domains
            
        except ClientError as e:
            if e.response['Error']['Code'] in ['UnauthorizedOperation', 'AccessDenied']:
                logger.warning("Insufficient permissions to list OpenSearch domains")
                return []
            logger.error(f"Error listing OpenSearch domains: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error listing OpenSearch domains: {e}")
            return []
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate OpenSearch domain VPC compliance."""
        try:
            domain_name = resource.get('DomainName', 'unknown')
            vpc_options = resource.get('VPCOptions', {})
            
            # Check if domain is deployed in VPC
            vpc_id = vpc_options.get('VPCId')
            
            if not vpc_id:
                return ComplianceResult(
                    resource_id=domain_name,
                    resource_type="AWS::OpenSearch::Domain",
                    compliance_status=ComplianceStatus.NON_COMPLIANT,
                    evaluation_reason="OpenSearch domain is not deployed within a VPC",
                    config_rule_name=self.rule_name,
                    region=region
                )
            
            # Additional checks for VPC configuration
            subnet_ids = vpc_options.get('SubnetIds', [])
            security_group_ids = vpc_options.get('SecurityGroupIds', [])
            
            if not subnet_ids:
                return ComplianceResult(
                    resource_id=domain_name,
                    resource_type="AWS::OpenSearch::Domain",
                    compliance_status=ComplianceStatus.NON_COMPLIANT,
                    evaluation_reason="OpenSearch domain VPC configuration is incomplete - no subnets specified",
                    config_rule_name=self.rule_name,
                    region=region
                )
            
            if not security_group_ids:
                return ComplianceResult(
                    resource_id=domain_name,
                    resource_type="AWS::OpenSearch::Domain",
                    compliance_status=ComplianceStatus.NON_COMPLIANT,
                    evaluation_reason="OpenSearch domain VPC configuration is incomplete - no security groups specified",
                    config_rule_name=self.rule_name,
                    region=region
                )
            
            return ComplianceResult(
                resource_id=domain_name,
                resource_type="AWS::OpenSearch::Domain",
                compliance_status=ComplianceStatus.COMPLIANT,
                evaluation_reason=f"OpenSearch domain is properly deployed in VPC {vpc_id} with {len(subnet_ids)} subnets",
                config_rule_name=self.rule_name,
                region=region
            )
            
        except Exception as e:
            logger.error(f"Error evaluating OpenSearch domain VPC compliance: {e}")
            return ComplianceResult(
                resource_id=resource.get('DomainName', 'unknown'),
                resource_type="AWS::OpenSearch::Domain",
                compliance_status=ComplianceStatus.NOT_APPLICABLE,
                evaluation_reason=f"Error evaluating compliance: {str(e)}",
                config_rule_name=self.rule_name,
                region=region
            )


class ECSTaskDefinitionNonRootUserAssessment(BaseConfigRuleAssessment):
    """Assessment for ecs-task-definition-nonroot-user AWS Config rule."""
    
    def __init__(self):
        super().__init__(
            rule_name="ecs-task-definition-nonroot-user",
            control_id="4.1",
            resource_types=["AWS::ECS::TaskDefinition"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get ECS task definitions to evaluate."""
        if resource_type != "AWS::ECS::TaskDefinition":
            return []
            
        try:
            ecs_client = aws_factory.get_client('ecs', region)
            
            # List all task definition families
            families_response = ecs_client.list_task_definition_families(status='ACTIVE')
            families = families_response.get('families', [])
            
            task_definitions = []
            
            for family in families:
                try:
                    # Get the latest active revision for each family
                    task_def_response = ecs_client.describe_task_definition(
                        taskDefinition=family,
                        include=['TAGS']
                    )
                    task_definitions.append(task_def_response.get('taskDefinition', {}))
                except ClientError as e:
                    logger.warning(f"Error describing task definition {family}: {e}")
                    continue
            
            return task_definitions
            
        except ClientError as e:
            if e.response['Error']['Code'] in ['UnauthorizedOperation', 'AccessDenied']:
                logger.warning("Insufficient permissions to list ECS task definitions")
                return []
            logger.error(f"Error listing ECS task definitions: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error listing ECS task definitions: {e}")
            return []
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate ECS task definition non-root user compliance."""
        try:
            task_def_arn = resource.get('taskDefinitionArn', 'unknown')
            family = resource.get('family', 'unknown')
            revision = resource.get('revision', 'unknown')
            container_definitions = resource.get('containerDefinitions', [])
            
            if not container_definitions:
                return ComplianceResult(
                    resource_id=f"{family}:{revision}",
                    resource_type="AWS::ECS::TaskDefinition",
                    compliance_status=ComplianceStatus.NOT_APPLICABLE,
                    evaluation_reason="Task definition has no container definitions",
                    config_rule_name=self.rule_name,
                    region=region
                )
            
            non_compliant_containers = []
            
            for container in container_definitions:
                container_name = container.get('name', 'unknown')
                user = container.get('user')
                
                # Check if user is specified and is not root
                if user is None:
                    # No user specified - defaults to root in most images
                    non_compliant_containers.append(f"{container_name} (no user specified)")
                elif user == 'root' or user == '0':
                    # Explicitly set to root
                    non_compliant_containers.append(f"{container_name} (user: {user})")
                # If user is specified and not root, it's compliant
            
            if non_compliant_containers:
                return ComplianceResult(
                    resource_id=f"{family}:{revision}",
                    resource_type="AWS::ECS::TaskDefinition",
                    compliance_status=ComplianceStatus.NON_COMPLIANT,
                    evaluation_reason=f"Containers running as root: {', '.join(non_compliant_containers)}",
                    config_rule_name=self.rule_name,
                    region=region
                )
            
            return ComplianceResult(
                resource_id=f"{family}:{revision}",
                resource_type="AWS::ECS::TaskDefinition",
                compliance_status=ComplianceStatus.COMPLIANT,
                evaluation_reason=f"All {len(container_definitions)} containers specify non-root users",
                config_rule_name=self.rule_name,
                region=region
            )
            
        except Exception as e:
            logger.error(f"Error evaluating ECS task definition compliance: {e}")
            return ComplianceResult(
                resource_id=resource.get('family', 'unknown'),
                resource_type="AWS::ECS::TaskDefinition",
                compliance_status=ComplianceStatus.NOT_APPLICABLE,
                evaluation_reason=f"Error evaluating compliance: {str(e)}",
                config_rule_name=self.rule_name,
                region=region
            )


class SecurityHubEnabledAssessment(BaseConfigRuleAssessment):
    """Assessment for securityhub-enabled AWS Config rule."""
    
    def __init__(self):
        super().__init__(
            rule_name="securityhub-enabled",
            control_id="8.8",
            resource_types=["AWS::SecurityHub::Hub"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get Security Hub configuration for current region."""
        if resource_type != "AWS::SecurityHub::Hub":
            return []
            
        try:
            securityhub_client = aws_factory.get_client('securityhub', region)
            
            # Check if Security Hub is enabled
            try:
                hub_response = securityhub_client.describe_hub()
                
                # Get enabled standards
                standards_response = securityhub_client.get_enabled_standards()
                
                return [{
                    'region': region,
                    'hub_arn': hub_response.get('HubArn'),
                    'subscribed_at': hub_response.get('SubscribedAt'),
                    'auto_enable_controls': hub_response.get('AutoEnableControls'),
                    'enabled_standards': standards_response.get('StandardsSubscriptions', [])
                }]
                
            except ClientError as e:
                if e.response['Error']['Code'] == 'InvalidAccessException':
                    # Security Hub is not enabled
                    return [{
                        'region': region,
                        'enabled': False,
                        'error': 'Security Hub is not enabled'
                    }]
                else:
                    raise
            
        except ClientError as e:
            if e.response['Error']['Code'] in ['UnauthorizedOperation', 'AccessDenied']:
                logger.warning("Insufficient permissions to check Security Hub status")
                return []
            logger.error(f"Error checking Security Hub status: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error checking Security Hub: {e}")
            return []
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate Security Hub enabled compliance."""
        try:
            resource_region = resource.get('region', region)
            
            # Check if Security Hub is enabled
            if resource.get('enabled') is False:
                return ComplianceResult(
                    resource_id=resource_region,
                    resource_type="AWS::SecurityHub::Hub",
                    compliance_status=ComplianceStatus.NON_COMPLIANT,
                    evaluation_reason="AWS Security Hub is not enabled in this region",
                    config_rule_name=self.rule_name,
                    region=region
                )
            
            hub_arn = resource.get('hub_arn')
            if not hub_arn:
                return ComplianceResult(
                    resource_id=resource_region,
                    resource_type="AWS::SecurityHub::Hub",
                    compliance_status=ComplianceStatus.NON_COMPLIANT,
                    evaluation_reason="Security Hub configuration is incomplete",
                    config_rule_name=self.rule_name,
                    region=region
                )
            
            # Check if any security standards are enabled
            enabled_standards = resource.get('enabled_standards', [])
            active_standards = [std for std in enabled_standards if std.get('StandardsStatus') == 'READY']
            
            if not active_standards:
                return ComplianceResult(
                    resource_id=resource_region,
                    resource_type="AWS::SecurityHub::Hub",
                    compliance_status=ComplianceStatus.NON_COMPLIANT,
                    evaluation_reason="Security Hub is enabled but no security standards are active",
                    config_rule_name=self.rule_name,
                    region=region
                )
            
            return ComplianceResult(
                resource_id=resource_region,
                resource_type="AWS::SecurityHub::Hub",
                compliance_status=ComplianceStatus.COMPLIANT,
                evaluation_reason=f"Security Hub is enabled with {len(active_standards)} active security standards",
                config_rule_name=self.rule_name,
                region=region
            )
            
        except Exception as e:
            logger.error(f"Error evaluating Security Hub compliance: {e}")
            return ComplianceResult(
                resource_id=resource.get('region', region),
                resource_type="AWS::SecurityHub::Hub",
                compliance_status=ComplianceStatus.NOT_APPLICABLE,
                evaluation_reason=f"Error evaluating compliance: {str(e)}",
                config_rule_name=self.rule_name,
                region=region
            )