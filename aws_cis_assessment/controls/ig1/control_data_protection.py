"""
CIS Control 3.3 - Data Protection Controls
Critical data protection rules to prevent public exposure of sensitive data.
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


class EBSSnapshotPublicRestorableCheckAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 3.3 - Configure Data Access Control Lists
    AWS Config Rule: ebs-snapshot-public-restorable-check
    
    Ensures EBS snapshots are not publicly restorable to prevent data exposure.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="ebs-snapshot-public-restorable-check",
            control_id="3.3",
            resource_types=["AWS::EC2::Snapshot"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all EBS snapshots owned by the account."""
        if resource_type != "AWS::EC2::Snapshot":
            return []
        
        try:
            ec2_client = aws_factory.get_client('ec2', region)
            
            # Get all EBS snapshots owned by the account
            paginator = ec2_client.get_paginator('describe_snapshots')
            page_iterator = paginator.paginate(OwnerIds=['self'])
            
            snapshots = []
            for page in page_iterator:
                for snapshot in page['Snapshots']:
                    snapshots.append({
                        'SnapshotId': snapshot['SnapshotId'],
                        'Description': snapshot.get('Description', ''),
                        'VolumeId': snapshot.get('VolumeId', ''),
                        'VolumeSize': snapshot.get('VolumeSize', 0),
                        'Encrypted': snapshot.get('Encrypted', False),
                        'State': snapshot.get('State', ''),
                        'StartTime': snapshot.get('StartTime')
                    })
            
            logger.debug(f"Found {len(snapshots)} EBS snapshots in {region}")
            return snapshots
            
        except ClientError as e:
            logger.error(f"Error retrieving EBS snapshots in {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving EBS snapshots in {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if EBS snapshot is publicly restorable."""
        snapshot_id = resource.get('SnapshotId', 'unknown')
        
        try:
            ec2_client = aws_factory.get_client('ec2', region)
            
            # Check if snapshot has public restore permissions
            response = ec2_client.describe_snapshot_attribute(
                SnapshotId=snapshot_id,
                Attribute='createVolumePermission'
            )
            
            create_volume_permissions = response.get('CreateVolumePermissions', [])
            is_public = any(
                perm.get('Group') == 'all' 
                for perm in create_volume_permissions
            )
            
            if is_public:
                return ComplianceResult(
                    resource_id=snapshot_id,
                    resource_type="AWS::EC2::Snapshot",
                    compliance_status=ComplianceStatus.NON_COMPLIANT,
                    evaluation_reason="EBS snapshot allows public restore access",
                    config_rule_name=self.rule_name,
                    region=region
                )
            else:
                return ComplianceResult(
                    resource_id=snapshot_id,
                    resource_type="AWS::EC2::Snapshot",
                    compliance_status=ComplianceStatus.COMPLIANT,
                    evaluation_reason="EBS snapshot does not allow public restore access",
                    config_rule_name=self.rule_name,
                    region=region
                )
        
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'InvalidSnapshot.NotFound':
                return ComplianceResult(
                    resource_id=snapshot_id,
                    resource_type="AWS::EC2::Snapshot",
                    compliance_status=ComplianceStatus.NOT_APPLICABLE,
                    evaluation_reason="Snapshot no longer exists",
                    config_rule_name=self.rule_name,
                    region=region
                )
            elif error_code in ['UnauthorizedOperation', 'AccessDenied']:
                return ComplianceResult(
                    resource_id=snapshot_id,
                    resource_type="AWS::EC2::Snapshot",
                    compliance_status=ComplianceStatus.NOT_APPLICABLE,
                    evaluation_reason=f"Insufficient permissions to check snapshot attributes: {error_code}",
                    config_rule_name=self.rule_name,
                    region=region
                )
            else:
                logger.warning(f"Error checking snapshot {snapshot_id} in {region}: {e}")
                return ComplianceResult(
                    resource_id=snapshot_id,
                    resource_type="AWS::EC2::Snapshot",
                    compliance_status=ComplianceStatus.ERROR,
                    evaluation_reason=f"Error checking snapshot attributes: {str(e)}",
                    config_rule_name=self.rule_name,
                    region=region
                )
        
        except Exception as e:
            logger.error(f"Unexpected error checking snapshot {snapshot_id} in {region}: {e}")
            return ComplianceResult(
                resource_id=snapshot_id,
                resource_type="AWS::EC2::Snapshot",
                compliance_status=ComplianceStatus.ERROR,
                evaluation_reason=f"Unexpected error: {str(e)}",
                config_rule_name=self.rule_name,
                region=region
            )


class RDSSnapshotsPublicProhibitedAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 3.3 - Configure Data Access Control Lists
    AWS Config Rule: rds-snapshots-public-prohibited
    
    Ensures RDS snapshots are not publicly accessible to prevent database data exposure.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="rds-snapshots-public-prohibited",
            control_id="3.3",
            resource_types=["AWS::RDS::DBSnapshot", "AWS::RDS::DBClusterSnapshot"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all RDS snapshots (DB and cluster snapshots)."""
        resources = []
        
        try:
            rds_client = aws_factory.get_client('rds', region)
            
            if resource_type == "AWS::RDS::DBSnapshot":
                # Get DB snapshots
                paginator = rds_client.get_paginator('describe_db_snapshots')
                for page in paginator.paginate(SnapshotType='manual'):
                    for snapshot in page['DBSnapshots']:
                        resources.append({
                            'Type': 'DBSnapshot',
                            'SnapshotId': snapshot['DBSnapshotIdentifier'],
                            'DBInstanceIdentifier': snapshot.get('DBInstanceIdentifier', ''),
                            'Engine': snapshot.get('Engine', ''),
                            'Encrypted': snapshot.get('Encrypted', False),
                            'SnapshotType': snapshot.get('SnapshotType', '')
                        })
            
            elif resource_type == "AWS::RDS::DBClusterSnapshot":
                # Get DB cluster snapshots
                paginator = rds_client.get_paginator('describe_db_cluster_snapshots')
                for page in paginator.paginate(SnapshotType='manual'):
                    for snapshot in page['DBClusterSnapshots']:
                        resources.append({
                            'Type': 'DBClusterSnapshot',
                            'SnapshotId': snapshot['DBClusterSnapshotIdentifier'],
                            'DBClusterIdentifier': snapshot.get('DBClusterIdentifier', ''),
                            'Engine': snapshot.get('Engine', ''),
                            'Encrypted': snapshot.get('StorageEncrypted', False)
                        })
            
            logger.debug(f"Found {len(resources)} RDS snapshots of type {resource_type} in {region}")
            return resources
            
        except ClientError as e:
            logger.error(f"Error retrieving RDS snapshots in {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving RDS snapshots in {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if RDS snapshot is publicly accessible."""
        snapshot_id = resource.get('SnapshotId', 'unknown')
        snapshot_type = resource.get('Type', 'Unknown')
        
        try:
            rds_client = aws_factory.get_client('rds', region)
            
            is_public = False
            
            if snapshot_type == 'DBSnapshot':
                # Check DB snapshot attributes
                response = rds_client.describe_db_snapshot_attributes(
                    DBSnapshotIdentifier=snapshot_id
                )
                attributes = response.get('DBSnapshotAttributesResult', {}).get('DBSnapshotAttributes', [])
                
                for attr in attributes:
                    if attr['AttributeName'] == 'restore' and 'all' in attr.get('AttributeValues', []):
                        is_public = True
                        break
                
                resource_type = "AWS::RDS::DBSnapshot"
            
            elif snapshot_type == 'DBClusterSnapshot':
                # Check cluster snapshot attributes
                response = rds_client.describe_db_cluster_snapshot_attributes(
                    DBClusterSnapshotIdentifier=snapshot_id
                )
                attributes = response.get('DBClusterSnapshotAttributesResult', {}).get('DBClusterSnapshotAttributes', [])
                
                for attr in attributes:
                    if attr['AttributeName'] == 'restore' and 'all' in attr.get('AttributeValues', []):
                        is_public = True
                        break
                
                resource_type = "AWS::RDS::DBClusterSnapshot"
            
            else:
                return ComplianceResult(
                    resource_id=snapshot_id,
                    resource_type="AWS::RDS::DBSnapshot",
                    compliance_status=ComplianceStatus.ERROR,
                    evaluation_reason=f"Unknown snapshot type: {snapshot_type}",
                    config_rule_name=self.rule_name,
                    region=region
                )
            
            if is_public:
                return ComplianceResult(
                    resource_id=snapshot_id,
                    resource_type=resource_type,
                    compliance_status=ComplianceStatus.NON_COMPLIANT,
                    evaluation_reason=f"RDS {snapshot_type.lower()} allows public restore access",
                    config_rule_name=self.rule_name,
                    region=region
                )
            else:
                return ComplianceResult(
                    resource_id=snapshot_id,
                    resource_type=resource_type,
                    compliance_status=ComplianceStatus.COMPLIANT,
                    evaluation_reason=f"RDS {snapshot_type.lower()} does not allow public restore access",
                    config_rule_name=self.rule_name,
                    region=region
                )
        
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code in ['DBSnapshotNotFoundFault', 'DBClusterSnapshotNotFoundFault']:
                return ComplianceResult(
                    resource_id=snapshot_id,
                    resource_type=f"AWS::RDS::{snapshot_type}",
                    compliance_status=ComplianceStatus.NOT_APPLICABLE,
                    evaluation_reason="Snapshot no longer exists",
                    config_rule_name=self.rule_name,
                    region=region
                )
            elif error_code in ['UnauthorizedOperation', 'AccessDenied']:
                return ComplianceResult(
                    resource_id=snapshot_id,
                    resource_type=f"AWS::RDS::{snapshot_type}",
                    compliance_status=ComplianceStatus.NOT_APPLICABLE,
                    evaluation_reason=f"Insufficient permissions to check snapshot attributes: {error_code}",
                    config_rule_name=self.rule_name,
                    region=region
                )
            else:
                logger.warning(f"Error checking RDS snapshot {snapshot_id} in {region}: {e}")
                return ComplianceResult(
                    resource_id=snapshot_id,
                    resource_type=f"AWS::RDS::{snapshot_type}",
                    compliance_status=ComplianceStatus.ERROR,
                    evaluation_reason=f"Error checking snapshot attributes: {str(e)}",
                    config_rule_name=self.rule_name,
                    region=region
                )
        
        except Exception as e:
            logger.error(f"Unexpected error checking RDS snapshot {snapshot_id} in {region}: {e}")
            return ComplianceResult(
                resource_id=snapshot_id,
                resource_type=f"AWS::RDS::{snapshot_type}",
                compliance_status=ComplianceStatus.ERROR,
                evaluation_reason=f"Unexpected error: {str(e)}",
                config_rule_name=self.rule_name,
                region=region
            )
        """
        Evaluate RDS snapshot public access compliance.
        
        Args:
            aws_factory: AWS client factory
            region: AWS region to evaluate
            
        Returns:
            List of ComplianceResult objects
        """
        results = []
        
        try:
            rds_client = aws_factory.get_client('rds', region)
            
            # Check DB snapshots
            db_snapshots_paginator = rds_client.get_paginator('describe_db_snapshots')
            db_snapshot_count = 0
            
            for page in db_snapshots_paginator.paginate(SnapshotType='manual'):
                for snapshot in page['DBSnapshots']:
                    db_snapshot_count += 1
                    snapshot_id = snapshot['DBSnapshotIdentifier']
                    
                    try:
                        # Check snapshot attributes for public access
                        response = rds_client.describe_db_snapshot_attributes(
                            DBSnapshotIdentifier=snapshot_id
                        )
                        
                        attributes = response.get('DBSnapshotAttributesResult', {}).get('DBSnapshotAttributes', [])
                        is_public = False
                        
                        for attr in attributes:
                            if attr['AttributeName'] == 'restore' and 'all' in attr.get('AttributeValues', []):
                                is_public = True
                                break
                        
                        if is_public:
                            results.append(ComplianceResult(
                                resource_id=snapshot_id,
                                resource_type="AWS::RDS::DBSnapshot",
                                compliance_status=ComplianceStatus.NON_COMPLIANT,
                                evaluation_reason="RDS DB snapshot allows public restore access",
                                config_rule_name=self.rule_name,
                                region=region,
                                resource_details={
                                    'snapshot_id': snapshot_id,
                                    'db_instance_identifier': snapshot.get('DBInstanceIdentifier', ''),
                                    'engine': snapshot.get('Engine', ''),
                                    'encrypted': snapshot.get('Encrypted', False),
                                    'snapshot_type': snapshot.get('SnapshotType', ''),
                                    'public_attributes': attributes
                                },
                                remediation_guidance={
                                    'description': 'Remove public restore permissions from RDS snapshot',
                                    'cli_command': f'aws rds modify-db-snapshot-attribute --db-snapshot-identifier {snapshot_id} --attribute-name restore --values-to-remove all --region {region}',
                                    'console_url': f'https://{region}.console.aws.amazon.com/rds/home?region={region}#snapshot:id={snapshot_id}',
                                    'additional_info': 'Ensure only specific AWS accounts have restore permissions if sharing is required'
                                }
                            ))
                        else:
                            results.append(ComplianceResult(
                                resource_id=snapshot_id,
                                resource_type="AWS::RDS::DBSnapshot",
                                compliance_status=ComplianceStatus.COMPLIANT,
                                evaluation_reason="RDS DB snapshot does not allow public restore access",
                                config_rule_name=self.rule_name,
                                region=region,
                                resource_details={
                                    'snapshot_id': snapshot_id,
                                    'db_instance_identifier': snapshot.get('DBInstanceIdentifier', ''),
                                    'encrypted': snapshot.get('Encrypted', False)
                                }
                            ))
                    
                    except ClientError as e:
                        error_code = e.response.get('Error', {}).get('Code', '')
                        if error_code == 'DBSnapshotNotFoundFault':
                            continue
                        elif error_code in ['UnauthorizedOperation', 'AccessDenied']:
                            results.append(ComplianceResult(
                                resource_id=snapshot_id,
                                resource_type="AWS::RDS::DBSnapshot",
                                compliance_status=ComplianceStatus.NOT_APPLICABLE,
                                evaluation_reason=f"Insufficient permissions to check snapshot attributes: {error_code}",
                                config_rule_name=self.rule_name,
                                region=region
                            ))
                        else:
                            logger.warning(f"Error checking RDS snapshot {snapshot_id} in {region}: {e}")
            
            # Check DB cluster snapshots
            cluster_snapshots_paginator = rds_client.get_paginator('describe_db_cluster_snapshots')
            cluster_snapshot_count = 0
            
            for page in cluster_snapshots_paginator.paginate(SnapshotType='manual'):
                for snapshot in page['DBClusterSnapshots']:
                    cluster_snapshot_count += 1
                    snapshot_id = snapshot['DBClusterSnapshotIdentifier']
                    
                    try:
                        # Check cluster snapshot attributes for public access
                        response = rds_client.describe_db_cluster_snapshot_attributes(
                            DBClusterSnapshotIdentifier=snapshot_id
                        )
                        
                        attributes = response.get('DBClusterSnapshotAttributesResult', {}).get('DBClusterSnapshotAttributes', [])
                        is_public = False
                        
                        for attr in attributes:
                            if attr['AttributeName'] == 'restore' and 'all' in attr.get('AttributeValues', []):
                                is_public = True
                                break
                        
                        if is_public:
                            results.append(ComplianceResult(
                                resource_id=snapshot_id,
                                resource_type="AWS::RDS::DBClusterSnapshot",
                                compliance_status=ComplianceStatus.NON_COMPLIANT,
                                evaluation_reason="RDS cluster snapshot allows public restore access",
                                config_rule_name=self.rule_name,
                                region=region,
                                resource_details={
                                    'snapshot_id': snapshot_id,
                                    'db_cluster_identifier': snapshot.get('DBClusterIdentifier', ''),
                                    'engine': snapshot.get('Engine', ''),
                                    'encrypted': snapshot.get('StorageEncrypted', False)
                                },
                                remediation_guidance={
                                    'description': 'Remove public restore permissions from RDS cluster snapshot',
                                    'cli_command': f'aws rds modify-db-cluster-snapshot-attribute --db-cluster-snapshot-identifier {snapshot_id} --attribute-name restore --values-to-remove all --region {region}',
                                    'console_url': f'https://{region}.console.aws.amazon.com/rds/home?region={region}#cluster-snapshot:id={snapshot_id}',
                                    'additional_info': 'Ensure only specific AWS accounts have restore permissions if sharing is required'
                                }
                            ))
                        else:
                            results.append(ComplianceResult(
                                resource_id=snapshot_id,
                                resource_type="AWS::RDS::DBClusterSnapshot",
                                compliance_status=ComplianceStatus.COMPLIANT,
                                evaluation_reason="RDS cluster snapshot does not allow public restore access",
                                config_rule_name=self.rule_name,
                                region=region,
                                resource_details={
                                    'snapshot_id': snapshot_id,
                                    'db_cluster_identifier': snapshot.get('DBClusterIdentifier', ''),
                                    'encrypted': snapshot.get('StorageEncrypted', False)
                                }
                            ))
                    
                    except ClientError as e:
                        error_code = e.response.get('Error', {}).get('Code', '')
                        if error_code == 'DBClusterSnapshotNotFoundFault':
                            continue
                        elif error_code in ['UnauthorizedOperation', 'AccessDenied']:
                            results.append(ComplianceResult(
                                resource_id=snapshot_id,
                                resource_type="AWS::RDS::DBClusterSnapshot",
                                compliance_status=ComplianceStatus.NOT_APPLICABLE,
                                evaluation_reason=f"Insufficient permissions to check cluster snapshot attributes: {error_code}",
                                config_rule_name=self.rule_name,
                                region=region
                            ))
                        else:
                            logger.warning(f"Error checking RDS cluster snapshot {snapshot_id} in {region}: {e}")
            
            # If no snapshots found, return informational result
            total_snapshots = db_snapshot_count + cluster_snapshot_count
            if total_snapshots == 0:
                results.append(ComplianceResult(
                    resource_id=f"no-rds-snapshots-{region}",
                    resource_type="AWS::RDS::DBSnapshot",
                    compliance_status=ComplianceStatus.NOT_APPLICABLE,
                    evaluation_reason="No RDS snapshots found in this region",
                    config_rule_name=self.rule_name,
                    region=region
                ))
            
            logger.info(f"Evaluated {total_snapshots} RDS snapshots in {region} ({db_snapshot_count} DB + {cluster_snapshot_count} cluster)")
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code in ['UnauthorizedOperation', 'AccessDenied']:
                results.append(ComplianceResult(
                    resource_id=f"access-denied-{region}",
                    resource_type="AWS::RDS::DBSnapshot",
                    compliance_status=ComplianceStatus.NOT_APPLICABLE,
                    evaluation_reason=f"Insufficient permissions to describe RDS snapshots: {error_code}",
                    config_rule_name=self.rule_name,
                    region=region
                ))
            else:
                logger.error(f"Error evaluating RDS snapshots in {region}: {e}")
                results.append(ComplianceResult(
                    resource_id=f"error-{region}",
                    resource_type="AWS::RDS::DBSnapshot",
                    compliance_status=ComplianceStatus.ERROR,
                    evaluation_reason=f"Error evaluating RDS snapshots: {str(e)}",
                    config_rule_name=self.rule_name,
                    region=region
                ))
        
        except Exception as e:
            logger.error(f"Unexpected error evaluating RDS snapshots in {region}: {e}")
            results.append(ComplianceResult(
                resource_id=f"error-{region}",
                resource_type="AWS::RDS::DBSnapshot",
                compliance_status=ComplianceStatus.ERROR,
                evaluation_reason=f"Unexpected error: {str(e)}",
                config_rule_name=self.rule_name,
                region=region
            ))
        
        return results


class RDSInstancePublicAccessCheckAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 3.3 - Configure Data Access Control Lists
    AWS Config Rule: rds-instance-public-access-check
    
    Ensures RDS instances are not publicly accessible to prevent database exposure.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="rds-instance-public-access-check",
            control_id="3.3",
            resource_types=["AWS::RDS::DBInstance", "AWS::RDS::DBCluster"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all RDS instances and clusters in the region."""
        resources = []
        
        try:
            rds_client = aws_factory.get_client('rds', region)
            
            if resource_type == "AWS::RDS::DBInstance":
                # Get DB instances
                paginator = rds_client.get_paginator('describe_db_instances')
                for page in paginator.paginate():
                    for instance in page['DBInstances']:
                        resources.append({
                            'Type': 'DBInstance',
                            'InstanceId': instance['DBInstanceIdentifier'],
                            'Engine': instance.get('Engine', ''),
                            'InstanceClass': instance.get('DBInstanceClass', ''),
                            'PubliclyAccessible': instance.get('PubliclyAccessible', False),
                            'VpcSecurityGroups': [sg['VpcSecurityGroupId'] for sg in instance.get('VpcSecurityGroups', [])],
                            'DBSubnetGroup': instance.get('DBSubnetGroup', {}).get('DBSubnetGroupName', ''),
                            'Endpoint': instance.get('Endpoint', {}).get('Address', '')
                        })
            
            elif resource_type == "AWS::RDS::DBCluster":
                # Get DB clusters
                paginator = rds_client.get_paginator('describe_db_clusters')
                for page in paginator.paginate():
                    for cluster in page['DBClusters']:
                        # Check if any member instances are publicly accessible
                        public_members = []
                        for member in cluster.get('DBClusterMembers', []):
                            member_id = member['DBInstanceIdentifier']
                            try:
                                member_response = rds_client.describe_db_instances(DBInstanceIdentifier=member_id)
                                member_instance = member_response['DBInstances'][0]
                                if member_instance.get('PubliclyAccessible', False):
                                    public_members.append(member_id)
                            except ClientError:
                                continue
                        
                        resources.append({
                            'Type': 'DBCluster',
                            'ClusterId': cluster['DBClusterIdentifier'],
                            'Engine': cluster.get('Engine', ''),
                            'PublicMembers': public_members,
                            'VpcSecurityGroups': [sg['VpcSecurityGroupId'] for sg in cluster.get('VpcSecurityGroups', [])],
                            'DBSubnetGroup': cluster.get('DBSubnetGroup', ''),
                            'Endpoint': cluster.get('Endpoint', '')
                        })
            
            logger.debug(f"Found {len(resources)} RDS resources of type {resource_type} in {region}")
            return resources
            
        except ClientError as e:
            logger.error(f"Error retrieving RDS resources in {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving RDS resources in {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if RDS instance or cluster is publicly accessible."""
        resource_type = resource.get('Type', 'Unknown')
        
        if resource_type == 'DBInstance':
            instance_id = resource.get('InstanceId', 'unknown')
            is_public = resource.get('PubliclyAccessible', False)
            
            if is_public:
                return ComplianceResult(
                    resource_id=instance_id,
                    resource_type="AWS::RDS::DBInstance",
                    compliance_status=ComplianceStatus.NON_COMPLIANT,
                    evaluation_reason="RDS instance is publicly accessible",
                    config_rule_name=self.rule_name,
                    region=region
                )
            else:
                return ComplianceResult(
                    resource_id=instance_id,
                    resource_type="AWS::RDS::DBInstance",
                    compliance_status=ComplianceStatus.COMPLIANT,
                    evaluation_reason="RDS instance is not publicly accessible",
                    config_rule_name=self.rule_name,
                    region=region
                )
        
        elif resource_type == 'DBCluster':
            cluster_id = resource.get('ClusterId', 'unknown')
            public_members = resource.get('PublicMembers', [])
            
            if public_members:
                return ComplianceResult(
                    resource_id=cluster_id,
                    resource_type="AWS::RDS::DBCluster",
                    compliance_status=ComplianceStatus.NON_COMPLIANT,
                    evaluation_reason=f"RDS cluster has publicly accessible member instances: {', '.join(public_members)}",
                    config_rule_name=self.rule_name,
                    region=region
                )
            else:
                return ComplianceResult(
                    resource_id=cluster_id,
                    resource_type="AWS::RDS::DBCluster",
                    compliance_status=ComplianceStatus.COMPLIANT,
                    evaluation_reason="RDS cluster has no publicly accessible member instances",
                    config_rule_name=self.rule_name,
                    region=region
                )
        
        else:
            return ComplianceResult(
                resource_id="unknown",
                resource_type="AWS::RDS::DBInstance",
                compliance_status=ComplianceStatus.ERROR,
                evaluation_reason=f"Unknown RDS resource type: {resource_type}",
                config_rule_name=self.rule_name,
                region=region
            )


class RedshiftClusterPublicAccessCheckAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 3.3 - Configure Data Access Control Lists
    AWS Config Rule: redshift-cluster-public-access-check
    
    Ensures Redshift clusters are not publicly accessible to prevent data warehouse exposure.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="redshift-cluster-public-access-check",
            control_id="3.3",
            resource_types=["AWS::Redshift::Cluster"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all Redshift clusters in the region."""
        if resource_type != "AWS::Redshift::Cluster":
            return []
        
        try:
            redshift_client = aws_factory.get_client('redshift', region)
            
            # Get all Redshift clusters
            paginator = redshift_client.get_paginator('describe_clusters')
            clusters = []
            
            for page in paginator.paginate():
                for cluster in page['Clusters']:
                    clusters.append({
                        'ClusterId': cluster['ClusterIdentifier'],
                        'NodeType': cluster.get('NodeType', ''),
                        'NumberOfNodes': cluster.get('NumberOfNodes', 0),
                        'PubliclyAccessible': cluster.get('PubliclyAccessible', False),
                        'VpcId': cluster.get('VpcId', ''),
                        'VpcSecurityGroups': [sg['VpcSecurityGroupId'] for sg in cluster.get('VpcSecurityGroups', [])],
                        'ClusterSubnetGroup': cluster.get('ClusterSubnetGroupName', ''),
                        'Endpoint': cluster.get('Endpoint', {}).get('Address', '') if cluster.get('Endpoint') else '',
                        'Encrypted': cluster.get('Encrypted', False)
                    })
            
            logger.debug(f"Found {len(clusters)} Redshift clusters in {region}")
            return clusters
            
        except ClientError as e:
            logger.error(f"Error retrieving Redshift clusters in {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving Redshift clusters in {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if Redshift cluster is publicly accessible."""
        cluster_id = resource.get('ClusterId', 'unknown')
        is_public = resource.get('PubliclyAccessible', False)
        
        if is_public:
            return ComplianceResult(
                resource_id=cluster_id,
                resource_type="AWS::Redshift::Cluster",
                compliance_status=ComplianceStatus.NON_COMPLIANT,
                evaluation_reason="Redshift cluster is publicly accessible",
                config_rule_name=self.rule_name,
                region=region
            )
        else:
            return ComplianceResult(
                resource_id=cluster_id,
                resource_type="AWS::Redshift::Cluster",
                compliance_status=ComplianceStatus.COMPLIANT,
                evaluation_reason="Redshift cluster is not publicly accessible",
                config_rule_name=self.rule_name,
                region=region
            )


class S3BucketLevelPublicAccessProhibitedAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 3.3 - Configure Data Access Control Lists
    AWS Config Rule: s3-bucket-level-public-access-prohibited
    
    Ensures S3 buckets do not allow public access at the bucket level to prevent data exposure.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="s3-bucket-level-public-access-prohibited",
            control_id="3.3",
            resource_types=["AWS::S3::Bucket"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all S3 buckets (only from us-east-1 to avoid duplicates)."""
        if resource_type != "AWS::S3::Bucket":
            return []
        
        # S3 is global, only check from us-east-1 to avoid duplicate checks
        if region != 'us-east-1':
            return []
        
        try:
            s3_client = aws_factory.get_client('s3', region)
            
            response = s3_client.list_buckets()
            buckets = []
            
            for bucket in response.get('Buckets', []):
                bucket_name = bucket['Name']
                
                try:
                    # Get bucket public access block configuration
                    pab_config = {}
                    try:
                        pab_response = s3_client.get_public_access_block(Bucket=bucket_name)
                        pab_config = pab_response.get('PublicAccessBlockConfiguration', {})
                    except ClientError as e:
                        if e.response.get('Error', {}).get('Code') != 'NoSuchPublicAccessBlockConfiguration':
                            raise e
                    
                    # Check bucket ACL for public permissions
                    acl_response = s3_client.get_bucket_acl(Bucket=bucket_name)
                    grants = acl_response.get('Grants', [])
                    
                    public_acl = False
                    for grant in grants:
                        grantee = grant.get('Grantee', {})
                        if grantee.get('Type') == 'Group':
                            uri = grantee.get('URI', '')
                            if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                                public_acl = True
                                break
                    
                    # Check bucket policy for public permissions
                    public_policy = False
                    policy_statements = []
                    try:
                        policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
                        policy_doc = json.loads(policy_response['Policy'])
                        statements = policy_doc.get('Statement', [])
                        
                        for statement in statements:
                            if isinstance(statement, dict):
                                effect = statement.get('Effect', '')
                                principal = statement.get('Principal', {})
                                
                                if effect == 'Allow':
                                    if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                                        public_policy = True
                                        policy_statements.append(statement)
                    
                    except ClientError as e:
                        if e.response.get('Error', {}).get('Code') != 'NoSuchBucketPolicy':
                            raise e
                    
                    buckets.append({
                        'BucketName': bucket_name,
                        'PublicAccessBlock': pab_config,
                        'PublicACL': public_acl,
                        'PublicPolicy': public_policy,
                        'PolicyStatements': policy_statements
                    })
                
                except ClientError as e:
                    error_code = e.response.get('Error', {}).get('Code', '')
                    if error_code in ['NoSuchBucket', 'BucketNotEmpty', 'AccessDenied']:
                        continue
                    else:
                        logger.warning(f"Error checking S3 bucket {bucket_name}: {e}")
                        continue
            
            logger.debug(f"Found {len(buckets)} S3 buckets from {region}")
            return buckets
            
        except ClientError as e:
            logger.error(f"Error retrieving S3 buckets from {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving S3 buckets from {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if S3 bucket allows public access."""
        bucket_name = resource.get('BucketName', 'unknown')
        pab_config = resource.get('PublicAccessBlock', {})
        public_acl = resource.get('PublicACL', False)
        public_policy = resource.get('PublicPolicy', False)
        
        # Check if all public access is blocked
        block_public_acls = pab_config.get('BlockPublicAcls', False)
        ignore_public_acls = pab_config.get('IgnorePublicAcls', False)
        block_public_policy = pab_config.get('BlockPublicPolicy', False)
        restrict_public_buckets = pab_config.get('RestrictPublicBuckets', False)
        
        all_blocked = all([
            block_public_acls,
            ignore_public_acls,
            block_public_policy,
            restrict_public_buckets
        ])
        
        # Determine compliance
        has_public_access = public_acl or public_policy or not all_blocked
        
        if has_public_access:
            issues = []
            if not all_blocked:
                issues.append("Public Access Block not fully configured")
            if public_acl:
                issues.append("Bucket ACL allows public access")
            if public_policy:
                issues.append("Bucket policy allows public access")
            
            return ComplianceResult(
                resource_id=bucket_name,
                resource_type="AWS::S3::Bucket",
                compliance_status=ComplianceStatus.NON_COMPLIANT,
                evaluation_reason=f"S3 bucket allows public access: {', '.join(issues)}",
                config_rule_name=self.rule_name,
                region=region
            )
        else:
            return ComplianceResult(
                resource_id=bucket_name,
                resource_type="AWS::S3::Bucket",
                compliance_status=ComplianceStatus.COMPLIANT,
                evaluation_reason="S3 bucket blocks all public access",
                config_rule_name=self.rule_name,
                region=region
            )