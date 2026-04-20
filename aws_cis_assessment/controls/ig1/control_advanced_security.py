"""
CIS Control 3.3 - Advanced Security Controls
Advanced security controls for comprehensive security coverage.
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


class EC2ManagedInstanceAssociationComplianceStatusCheckAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 1.1/2.4/4.1 - Systems Management
    AWS Config Rule: ec2-managedinstance-association-compliance-status-check
    
    Ensures EC2 instances have proper Systems Manager associations for compliance tracking.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="ec2-managedinstance-association-compliance-status-check",
            control_id="3.3",
            resource_types=["AWS::EC2::Instance"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all EC2 instances that should be managed by SSM."""
        if resource_type != "AWS::EC2::Instance":
            return []
        
        try:
            ec2_client = aws_factory.get_client('ec2', region)
            ssm_client = aws_factory.get_client('ssm', region)
            
            # Get all running EC2 instances
            paginator = ec2_client.get_paginator('describe_instances')
            instances = []
            
            for page in paginator.paginate(
                Filters=[
                    {'Name': 'instance-state-name', 'Values': ['running']}
                ]
            ):
                for reservation in page['Reservations']:
                    for instance in reservation['Instances']:
                        instance_id = instance['InstanceId']
                        
                        try:
                            # Check if instance is managed by SSM
                            ssm_response = ssm_client.describe_instance_information(
                                Filters=[
                                    {'Key': 'InstanceIds', 'Values': [instance_id]}
                                ]
                            )
                            
                            managed_instances = ssm_response.get('InstanceInformationList', [])
                            is_managed = len(managed_instances) > 0
                            
                            if is_managed:
                                # Get association compliance status
                                try:
                                    compliance_response = ssm_client.list_compliance_items(
                                        ResourceIds=[instance_id],
                                        ResourceTypes=['ManagedInstance']
                                    )
                                    
                                    compliance_items = compliance_response.get('ComplianceItems', [])
                                    association_compliance = []
                                    
                                    for item in compliance_items:
                                        if item.get('ComplianceType') == 'Association':
                                            association_compliance.append({
                                                'Id': item.get('Id', ''),
                                                'Status': item.get('Status', ''),
                                                'Severity': item.get('Severity', ''),
                                                'Title': item.get('Title', '')
                                            })
                                    
                                    instances.append({
                                        'InstanceId': instance_id,
                                        'InstanceType': instance.get('InstanceType', ''),
                                        'Platform': instance.get('Platform', 'Linux'),
                                        'VpcId': instance.get('VpcId', ''),
                                        'IsSSMManaged': True,
                                        'AssociationCompliance': association_compliance,
                                        'HasAssociations': len(association_compliance) > 0
                                    })
                                
                                except ClientError as e:
                                    # Instance is managed but can't get compliance info
                                    instances.append({
                                        'InstanceId': instance_id,
                                        'InstanceType': instance.get('InstanceType', ''),
                                        'Platform': instance.get('Platform', 'Linux'),
                                        'VpcId': instance.get('VpcId', ''),
                                        'IsSSMManaged': True,
                                        'AssociationCompliance': [],
                                        'HasAssociations': None  # Unknown
                                    })
                            else:
                                # Instance is not managed by SSM
                                instances.append({
                                    'InstanceId': instance_id,
                                    'InstanceType': instance.get('InstanceType', ''),
                                    'Platform': instance.get('Platform', 'Linux'),
                                    'VpcId': instance.get('VpcId', ''),
                                    'IsSSMManaged': False,
                                    'AssociationCompliance': [],
                                    'HasAssociations': False
                                })
                        
                        except ClientError as e:
                            logger.warning(f"Error checking SSM status for instance {instance_id}: {e}")
                            continue
            
            logger.debug(f"Found {len(instances)} running EC2 instances in {region}")
            return instances
            
        except ClientError as e:
            logger.error(f"Error retrieving EC2 instances in {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving EC2 instances in {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if EC2 instance has proper SSM association compliance."""
        instance_id = resource.get('InstanceId', 'unknown')
        is_ssm_managed = resource.get('IsSSMManaged', False)
        has_associations = resource.get('HasAssociations', False)
        association_compliance = resource.get('AssociationCompliance', [])
        
        if not is_ssm_managed:
            return ComplianceResult(
                resource_id=instance_id,
                resource_type="AWS::EC2::Instance",
                compliance_status=ComplianceStatus.NON_COMPLIANT,
                evaluation_reason="EC2 instance is not managed by Systems Manager",
                config_rule_name=self.rule_name,
                region=region
            )
        
        if has_associations is None:
            return ComplianceResult(
                resource_id=instance_id,
                resource_type="AWS::EC2::Instance",
                compliance_status=ComplianceStatus.ERROR,
                evaluation_reason="Unable to determine association compliance status",
                config_rule_name=self.rule_name,
                region=region
            )
        
        if not has_associations:
            return ComplianceResult(
                resource_id=instance_id,
                resource_type="AWS::EC2::Instance",
                compliance_status=ComplianceStatus.NON_COMPLIANT,
                evaluation_reason="EC2 instance has no SSM associations configured",
                config_rule_name=self.rule_name,
                region=region
            )
        
        # Check compliance status of associations
        non_compliant_associations = [
            assoc for assoc in association_compliance 
            if assoc.get('Status') != 'COMPLIANT'
        ]
        
        if non_compliant_associations:
            return ComplianceResult(
                resource_id=instance_id,
                resource_type="AWS::EC2::Instance",
                compliance_status=ComplianceStatus.NON_COMPLIANT,
                evaluation_reason=f"EC2 instance has {len(non_compliant_associations)} non-compliant SSM associations",
                config_rule_name=self.rule_name,
                region=region
            )
        else:
            return ComplianceResult(
                resource_id=instance_id,
                resource_type="AWS::EC2::Instance",
                compliance_status=ComplianceStatus.COMPLIANT,
                evaluation_reason=f"EC2 instance has {len(association_compliance)} compliant SSM associations",
                config_rule_name=self.rule_name,
                region=region
            )


class EMRKerberosEnabledAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 3.3 - Configure Data Access Control Lists
    AWS Config Rule: emr-kerberos-enabled
    
    Ensures EMR clusters have Kerberos authentication enabled to prevent unauthorized access.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="emr-kerberos-enabled",
            control_id="3.3",
            resource_types=["AWS::EMR::Cluster"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all EMR clusters in the region."""
        if resource_type != "AWS::EMR::Cluster":
            return []
        
        try:
            emr_client = aws_factory.get_client('emr', region)
            
            # Get all EMR clusters
            paginator = emr_client.get_paginator('list_clusters')
            clusters = []
            
            for page in paginator.paginate():
                for cluster_summary in page['Clusters']:
                    cluster_id = cluster_summary['Id']
                    state = cluster_summary.get('Status', {}).get('State', '')
                    
                    # Skip terminated clusters
                    if state in ['TERMINATED', 'TERMINATED_WITH_ERRORS']:
                        continue
                    
                    try:
                        # Get detailed cluster information
                        cluster_response = emr_client.describe_cluster(ClusterId=cluster_id)
                        cluster = cluster_response['Cluster']
                        
                        # Check for Kerberos configuration
                        kerberos_attributes = cluster.get('KerberosAttributes', {})
                        has_kerberos = bool(kerberos_attributes)
                        
                        clusters.append({
                            'ClusterId': cluster_id,
                            'Name': cluster.get('Name', ''),
                            'State': state,
                            'ReleaseLabel': cluster.get('ReleaseLabel', ''),
                            'Applications': [app['Name'] for app in cluster.get('Applications', [])],
                            'HasKerberos': has_kerberos,
                            'KerberosAttributes': kerberos_attributes
                        })
                    
                    except ClientError as e:
                        logger.warning(f"Error getting details for EMR cluster {cluster_id}: {e}")
                        continue
            
            logger.debug(f"Found {len(clusters)} active EMR clusters in {region}")
            return clusters
            
        except ClientError as e:
            logger.error(f"Error retrieving EMR clusters in {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving EMR clusters in {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if EMR cluster has Kerberos authentication enabled."""
        cluster_id = resource.get('ClusterId', 'unknown')
        state = resource.get('State', '')
        has_kerberos = resource.get('HasKerberos', False)
        
        # Skip clusters that are not running
        if state in ['TERMINATED', 'TERMINATED_WITH_ERRORS', 'TERMINATING']:
            return ComplianceResult(
                resource_id=cluster_id,
                resource_type="AWS::EMR::Cluster",
                compliance_status=ComplianceStatus.NOT_APPLICABLE,
                evaluation_reason=f"EMR cluster is in state '{state}'",
                config_rule_name=self.rule_name,
                region=region
            )
        
        if has_kerberos:
            return ComplianceResult(
                resource_id=cluster_id,
                resource_type="AWS::EMR::Cluster",
                compliance_status=ComplianceStatus.COMPLIANT,
                evaluation_reason="EMR cluster has Kerberos authentication enabled",
                config_rule_name=self.rule_name,
                region=region
            )
        else:
            return ComplianceResult(
                resource_id=cluster_id,
                resource_type="AWS::EMR::Cluster",
                compliance_status=ComplianceStatus.NON_COMPLIANT,
                evaluation_reason="EMR cluster does not have Kerberos authentication enabled",
                config_rule_name=self.rule_name,
                region=region
            )


class LambdaInsideVPCAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 3.3 - Configure Data Access Control Lists
    AWS Config Rule: lambda-inside-vpc
    
    Ensures Lambda functions are deployed within VPC when needed for network isolation.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="lambda-inside-vpc",
            control_id="3.3",
            resource_types=["AWS::Lambda::Function"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all Lambda functions in the region."""
        if resource_type != "AWS::Lambda::Function":
            return []
        
        try:
            lambda_client = aws_factory.get_client('lambda', region)
            
            # Get all Lambda functions
            paginator = lambda_client.get_paginator('list_functions')
            functions = []
            
            for page in paginator.paginate():
                for function in page['Functions']:
                    vpc_config = function.get('VpcConfig', {})
                    
                    functions.append({
                        'FunctionName': function['FunctionName'],
                        'FunctionArn': function['FunctionArn'],
                        'Runtime': function.get('Runtime', ''),
                        'Role': function.get('Role', ''),
                        'VpcConfig': vpc_config,
                        'VpcId': vpc_config.get('VpcId', ''),
                        'SubnetIds': vpc_config.get('SubnetIds', []),
                        'SecurityGroupIds': vpc_config.get('SecurityGroupIds', []),
                        'IsInVPC': bool(vpc_config.get('VpcId'))
                    })
            
            logger.debug(f"Found {len(functions)} Lambda functions in {region}")
            return functions
            
        except ClientError as e:
            logger.error(f"Error retrieving Lambda functions in {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving Lambda functions in {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if Lambda function is deployed within VPC."""
        function_name = resource.get('FunctionName', 'unknown')
        is_in_vpc = resource.get('IsInVPC', False)
        vpc_id = resource.get('VpcId', '')
        
        # Note: This rule is context-dependent. Some Lambda functions may not need VPC access.
        # For this implementation, we'll consider functions that access VPC resources should be in VPC.
        # This is a simplified check - in practice, you might want to check function tags or naming patterns.
        
        if is_in_vpc:
            return ComplianceResult(
                resource_id=function_name,
                resource_type="AWS::Lambda::Function",
                compliance_status=ComplianceStatus.COMPLIANT,
                evaluation_reason=f"Lambda function is deployed within VPC {vpc_id}",
                config_rule_name=self.rule_name,
                region=region
            )
        else:
            # For this assessment, we'll mark as informational rather than non-compliant
            # since not all Lambda functions need VPC access
            return ComplianceResult(
                resource_id=function_name,
                resource_type="AWS::Lambda::Function",
                compliance_status=ComplianceStatus.NOT_APPLICABLE,
                evaluation_reason="Lambda function is not deployed within VPC (may not require VPC access)",
                config_rule_name=self.rule_name,
                region=region
            )


class ECSTaskDefinitionUserForHostModeCheckAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 3.3 - Configure Data Access Control Lists
    AWS Config Rule: ecs-task-definition-user-for-host-mode-check
    
    Ensures ECS tasks in host mode do not run with elevated privileges to prevent container privilege escalation.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="ecs-task-definition-user-for-host-mode-check",
            control_id="3.3",
            resource_types=["AWS::ECS::TaskDefinition"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all ECS task definitions in the region."""
        if resource_type != "AWS::ECS::TaskDefinition":
            return []
        
        try:
            ecs_client = aws_factory.get_client('ecs', region)
            
            # Get all task definition families
            families_response = ecs_client.list_task_definition_families(status='ACTIVE')
            task_definitions = []
            
            for family in families_response.get('families', []):
                try:
                    # Get the latest revision of each family
                    list_response = ecs_client.list_task_definitions(
                        familyPrefix=family,
                        status='ACTIVE',
                        sort='DESC',
                        maxResults=1
                    )
                    
                    if list_response.get('taskDefinitionArns'):
                        task_def_arn = list_response['taskDefinitionArns'][0]
                        
                        # Get detailed task definition
                        describe_response = ecs_client.describe_task_definition(
                            taskDefinition=task_def_arn
                        )
                        
                        task_def = describe_response['taskDefinition']
                        network_mode = task_def.get('networkMode', 'bridge')
                        
                        # Analyze container definitions for host mode issues
                        containers = task_def.get('containerDefinitions', [])
                        host_mode_issues = []
                        
                        if network_mode == 'host':
                            for container in containers:
                                container_name = container.get('name', 'unknown')
                                user = container.get('user', '')
                                privileged = container.get('privileged', False)
                                
                                # Check for privilege escalation risks in host mode
                                if privileged:
                                    host_mode_issues.append(f"Container '{container_name}' runs in privileged mode")
                                elif not user or user == 'root' or user == '0':
                                    host_mode_issues.append(f"Container '{container_name}' runs as root user")
                        
                        task_definitions.append({
                            'TaskDefinitionArn': task_def_arn,
                            'Family': task_def.get('family', ''),
                            'Revision': task_def.get('revision', 0),
                            'NetworkMode': network_mode,
                            'ContainerCount': len(containers),
                            'IsHostMode': network_mode == 'host',
                            'HostModeIssues': host_mode_issues,
                            'HasHostModeIssues': len(host_mode_issues) > 0
                        })
                
                except ClientError as e:
                    logger.warning(f"Error getting task definition details for family {family}: {e}")
                    continue
            
            logger.debug(f"Found {len(task_definitions)} active ECS task definitions in {region}")
            return task_definitions
            
        except ClientError as e:
            logger.error(f"Error retrieving ECS task definitions in {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving ECS task definitions in {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if ECS task definition has proper user configuration for host mode."""
        task_def_arn = resource.get('TaskDefinitionArn', 'unknown')
        family = resource.get('Family', 'unknown')
        is_host_mode = resource.get('IsHostMode', False)
        has_host_mode_issues = resource.get('HasHostModeIssues', False)
        host_mode_issues = resource.get('HostModeIssues', [])
        
        if not is_host_mode:
            return ComplianceResult(
                resource_id=task_def_arn,
                resource_type="AWS::ECS::TaskDefinition",
                compliance_status=ComplianceStatus.NOT_APPLICABLE,
                evaluation_reason="ECS task definition does not use host network mode",
                config_rule_name=self.rule_name,
                region=region
            )
        
        if has_host_mode_issues:
            return ComplianceResult(
                resource_id=task_def_arn,
                resource_type="AWS::ECS::TaskDefinition",
                compliance_status=ComplianceStatus.NON_COMPLIANT,
                evaluation_reason=f"ECS task definition in host mode has privilege escalation risks: {'; '.join(host_mode_issues)}",
                config_rule_name=self.rule_name,
                region=region
            )
        else:
            return ComplianceResult(
                resource_id=task_def_arn,
                resource_type="AWS::ECS::TaskDefinition",
                compliance_status=ComplianceStatus.COMPLIANT,
                evaluation_reason="ECS task definition in host mode has proper user configuration",
                config_rule_name=self.rule_name,
                region=region
            )