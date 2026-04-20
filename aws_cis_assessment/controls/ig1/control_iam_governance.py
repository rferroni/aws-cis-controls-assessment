"""
CIS Control 3.3 - Identity and Access Management Controls
Critical IAM governance and access control rules to ensure proper access management.
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


class IAMGroupHasUsersCheckAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 3.3 - Configure Data Access Control Lists
    AWS Config Rule: iam-group-has-users-check
    
    Ensures IAM groups have at least one user for proper access management.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="iam-group-has-users-check",
            control_id="3.3",
            resource_types=["AWS::IAM::Group"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all IAM groups."""
        if resource_type != "AWS::IAM::Group":
            return []
        
        try:
            iam_client = aws_factory.get_client('iam', region)
            
            # Get all IAM groups
            paginator = iam_client.get_paginator('list_groups')
            groups = []
            
            for page in paginator.paginate():
                for group in page['Groups']:
                    group_name = group['GroupName']
                    
                    try:
                        # Get users in the group
                        users_response = iam_client.get_group(GroupName=group_name)
                        users = users_response.get('Users', [])
                        
                        groups.append({
                            'GroupName': group_name,
                            'GroupId': group['GroupId'],
                            'Arn': group['Arn'],
                            'Path': group['Path'],
                            'CreateDate': group['CreateDate'],
                            'UserCount': len(users),
                            'Users': [user['UserName'] for user in users]
                        })
                    
                    except ClientError as e:
                        logger.warning(f"Error getting users for IAM group {group_name}: {e}")
                        # Add group with unknown user count
                        groups.append({
                            'GroupName': group_name,
                            'GroupId': group['GroupId'],
                            'Arn': group['Arn'],
                            'Path': group['Path'],
                            'CreateDate': group['CreateDate'],
                            'UserCount': -1,  # Unknown
                            'Users': []
                        })
            
            logger.debug(f"Found {len(groups)} IAM groups")
            return groups
            
        except ClientError as e:
            logger.error(f"Error retrieving IAM groups: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving IAM groups: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if IAM group has at least one user."""
        group_name = resource.get('GroupName', 'unknown')
        user_count = resource.get('UserCount', 0)
        
        if user_count == -1:
            return ComplianceResult(
                resource_id=group_name,
                resource_type="AWS::IAM::Group",
                compliance_status=ComplianceStatus.ERROR,
                evaluation_reason="Unable to determine user count for IAM group",
                config_rule_name=self.rule_name,
                region=region
            )
        elif user_count > 0:
            return ComplianceResult(
                resource_id=group_name,
                resource_type="AWS::IAM::Group",
                compliance_status=ComplianceStatus.COMPLIANT,
                evaluation_reason=f"IAM group has {user_count} user(s)",
                config_rule_name=self.rule_name,
                region=region
            )
        else:
            return ComplianceResult(
                resource_id=group_name,
                resource_type="AWS::IAM::Group",
                compliance_status=ComplianceStatus.NON_COMPLIANT,
                evaluation_reason="IAM group has no users",
                config_rule_name=self.rule_name,
                region=region
            )


class IAMPolicyNoStatementsWithFullAccessAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 3.3 - Configure Data Access Control Lists
    AWS Config Rule: iam-policy-no-statements-with-full-access
    
    Prevents IAM policies with overly broad permissions to prevent privilege escalation.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="iam-policy-no-statements-with-full-access",
            control_id="3.3",
            resource_types=["AWS::IAM::Policy"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all customer-managed IAM policies."""
        if resource_type != "AWS::IAM::Policy":
            return []
        
        try:
            iam_client = aws_factory.get_client('iam', region)
            
            # Get all customer-managed policies (not AWS managed)
            paginator = iam_client.get_paginator('list_policies')
            policies = []
            
            for page in paginator.paginate(Scope='Local'):  # Only customer-managed policies
                for policy in page['Policies']:
                    policy_arn = policy['Arn']
                    
                    try:
                        # Get the policy document
                        policy_response = iam_client.get_policy(PolicyArn=policy_arn)
                        policy_version_response = iam_client.get_policy_version(
                            PolicyArn=policy_arn,
                            VersionId=policy_response['Policy']['DefaultVersionId']
                        )
                        
                        policy_document = policy_version_response['PolicyVersion']['Document']
                        
                        # Analyze policy for full access statements
                        has_full_access = False
                        full_access_statements = []
                        
                        statements = policy_document.get('Statement', [])
                        if not isinstance(statements, list):
                            statements = [statements]
                        
                        for statement in statements:
                            if isinstance(statement, dict):
                                effect = statement.get('Effect', '')
                                action = statement.get('Action', [])
                                resource = statement.get('Resource', [])
                                
                                if effect == 'Allow':
                                    # Check for wildcard actions and resources
                                    if isinstance(action, str):
                                        action = [action]
                                    if isinstance(resource, str):
                                        resource = [resource]
                                    
                                    # Check for full access patterns
                                    has_wildcard_action = '*' in action
                                    has_wildcard_resource = '*' in resource
                                    
                                    if has_wildcard_action and has_wildcard_resource:
                                        has_full_access = True
                                        full_access_statements.append(statement)
                        
                        policies.append({
                            'PolicyName': policy['PolicyName'],
                            'PolicyArn': policy_arn,
                            'Path': policy['Path'],
                            'CreateDate': policy['CreateDate'],
                            'UpdateDate': policy['UpdateDate'],
                            'AttachmentCount': policy['AttachmentCount'],
                            'HasFullAccess': has_full_access,
                            'FullAccessStatements': full_access_statements,
                            'PolicyDocument': policy_document
                        })
                    
                    except ClientError as e:
                        logger.warning(f"Error getting policy document for {policy_arn}: {e}")
                        continue
            
            logger.debug(f"Found {len(policies)} customer-managed IAM policies")
            return policies
            
        except ClientError as e:
            logger.error(f"Error retrieving IAM policies: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving IAM policies: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if IAM policy has statements with full access."""
        policy_name = resource.get('PolicyName', 'unknown')
        policy_arn = resource.get('PolicyArn', 'unknown')
        has_full_access = resource.get('HasFullAccess', False)
        
        if has_full_access:
            return ComplianceResult(
                resource_id=policy_arn,
                resource_type="AWS::IAM::Policy",
                compliance_status=ComplianceStatus.NON_COMPLIANT,
                evaluation_reason="IAM policy contains statements with full access (Action: *, Resource: *)",
                config_rule_name=self.rule_name,
                region=region
            )
        else:
            return ComplianceResult(
                resource_id=policy_arn,
                resource_type="AWS::IAM::Policy",
                compliance_status=ComplianceStatus.COMPLIANT,
                evaluation_reason="IAM policy does not contain statements with full access",
                config_rule_name=self.rule_name,
                region=region
            )


class IAMUserNoPoliciesCheckAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 3.3 - Configure Data Access Control Lists
    AWS Config Rule: iam-user-no-policies-check
    
    Ensures IAM policies are attached to groups/roles, not users directly for proper access management.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="iam-user-no-policies-check",
            control_id="3.3",
            resource_types=["AWS::IAM::User"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all IAM users."""
        if resource_type != "AWS::IAM::User":
            return []
        
        try:
            iam_client = aws_factory.get_client('iam', region)
            
            # Get all IAM users
            paginator = iam_client.get_paginator('list_users')
            users = []
            
            for page in paginator.paginate():
                for user in page['Users']:
                    user_name = user['UserName']
                    
                    try:
                        # Get attached managed policies
                        attached_policies_response = iam_client.list_attached_user_policies(UserName=user_name)
                        attached_policies = attached_policies_response.get('AttachedPolicies', [])
                        
                        # Get inline policies
                        inline_policies_response = iam_client.list_user_policies(UserName=user_name)
                        inline_policies = inline_policies_response.get('PolicyNames', [])
                        
                        users.append({
                            'UserName': user_name,
                            'UserId': user['UserId'],
                            'Arn': user['Arn'],
                            'Path': user['Path'],
                            'CreateDate': user['CreateDate'],
                            'AttachedPolicies': attached_policies,
                            'InlinePolicies': inline_policies,
                            'HasDirectPolicies': len(attached_policies) > 0 or len(inline_policies) > 0
                        })
                    
                    except ClientError as e:
                        logger.warning(f"Error getting policies for IAM user {user_name}: {e}")
                        # Add user with unknown policy status
                        users.append({
                            'UserName': user_name,
                            'UserId': user['UserId'],
                            'Arn': user['Arn'],
                            'Path': user['Path'],
                            'CreateDate': user['CreateDate'],
                            'AttachedPolicies': [],
                            'InlinePolicies': [],
                            'HasDirectPolicies': None  # Unknown
                        })
            
            logger.debug(f"Found {len(users)} IAM users")
            return users
            
        except ClientError as e:
            logger.error(f"Error retrieving IAM users: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving IAM users: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if IAM user has policies attached directly."""
        user_name = resource.get('UserName', 'unknown')
        has_direct_policies = resource.get('HasDirectPolicies', None)
        attached_policies = resource.get('AttachedPolicies', [])
        inline_policies = resource.get('InlinePolicies', [])
        
        if has_direct_policies is None:
            return ComplianceResult(
                resource_id=user_name,
                resource_type="AWS::IAM::User",
                compliance_status=ComplianceStatus.ERROR,
                evaluation_reason="Unable to determine policy attachments for IAM user",
                config_rule_name=self.rule_name,
                region=region
            )
        elif has_direct_policies:
            policy_details = []
            if attached_policies:
                policy_details.append(f"{len(attached_policies)} managed policies")
            if inline_policies:
                policy_details.append(f"{len(inline_policies)} inline policies")
            
            return ComplianceResult(
                resource_id=user_name,
                resource_type="AWS::IAM::User",
                compliance_status=ComplianceStatus.NON_COMPLIANT,
                evaluation_reason=f"IAM user has policies attached directly: {', '.join(policy_details)}",
                config_rule_name=self.rule_name,
                region=region
            )
        else:
            return ComplianceResult(
                resource_id=user_name,
                resource_type="AWS::IAM::User",
                compliance_status=ComplianceStatus.COMPLIANT,
                evaluation_reason="IAM user has no policies attached directly",
                config_rule_name=self.rule_name,
                region=region
            )


class SSMDocumentNotPublicAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 3.3 - Configure Data Access Control Lists
    AWS Config Rule: ssm-document-not-public
    
    Ensures SSM documents are not publicly accessible to prevent exposure of automation scripts.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="ssm-document-not-public",
            control_id="3.3",
            resource_types=["AWS::SSM::Document"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all SSM documents owned by the account."""
        if resource_type != "AWS::SSM::Document":
            return []
        
        try:
            ssm_client = aws_factory.get_client('ssm', region)
            
            # Get all SSM documents owned by the account
            paginator = ssm_client.get_paginator('list_documents')
            documents = []
            
            for page in paginator.paginate(
                Filters=[
                    {
                        'Key': 'Owner',
                        'Values': ['Self']
                    }
                ]
            ):
                for document in page['DocumentIdentifiers']:
                    document_name = document['Name']
                    
                    try:
                        # Get document permissions
                        permissions_response = ssm_client.describe_document_permission(
                            Name=document_name,
                            PermissionType='Share'
                        )
                        
                        account_ids = permissions_response.get('AccountIds', [])
                        is_public = 'all' in account_ids
                        
                        documents.append({
                            'DocumentName': document_name,
                            'DocumentType': document.get('DocumentType', ''),
                            'DocumentFormat': document.get('DocumentFormat', ''),
                            'DocumentVersion': document.get('DocumentVersion', ''),
                            'Owner': document.get('Owner', ''),
                            'CreatedDate': document.get('CreatedDate'),
                            'Status': document.get('Status', ''),
                            'IsPublic': is_public,
                            'SharedAccountIds': account_ids
                        })
                    
                    except ClientError as e:
                        if e.response.get('Error', {}).get('Code') == 'InvalidDocument':
                            # Document might not exist anymore
                            continue
                        else:
                            logger.warning(f"Error getting permissions for SSM document {document_name}: {e}")
                            # Add document with unknown public status
                            documents.append({
                                'DocumentName': document_name,
                                'DocumentType': document.get('DocumentType', ''),
                                'DocumentFormat': document.get('DocumentFormat', ''),
                                'DocumentVersion': document.get('DocumentVersion', ''),
                                'Owner': document.get('Owner', ''),
                                'CreatedDate': document.get('CreatedDate'),
                                'Status': document.get('Status', ''),
                                'IsPublic': None,  # Unknown
                                'SharedAccountIds': []
                            })
            
            logger.debug(f"Found {len(documents)} SSM documents")
            return documents
            
        except ClientError as e:
            logger.error(f"Error retrieving SSM documents in {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving SSM documents in {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if SSM document is publicly accessible."""
        document_name = resource.get('DocumentName', 'unknown')
        is_public = resource.get('IsPublic', None)
        status = resource.get('Status', '')
        
        # Skip documents that are not active
        if status != 'Active':
            return ComplianceResult(
                resource_id=document_name,
                resource_type="AWS::SSM::Document",
                compliance_status=ComplianceStatus.NOT_APPLICABLE,
                evaluation_reason=f"SSM document is in status '{status}'",
                config_rule_name=self.rule_name,
                region=region
            )
        
        if is_public is None:
            return ComplianceResult(
                resource_id=document_name,
                resource_type="AWS::SSM::Document",
                compliance_status=ComplianceStatus.ERROR,
                evaluation_reason="Unable to determine public access status for SSM document",
                config_rule_name=self.rule_name,
                region=region
            )
        elif is_public:
            return ComplianceResult(
                resource_id=document_name,
                resource_type="AWS::SSM::Document",
                compliance_status=ComplianceStatus.NON_COMPLIANT,
                evaluation_reason="SSM document is publicly accessible",
                config_rule_name=self.rule_name,
                region=region
            )
        else:
            return ComplianceResult(
                resource_id=document_name,
                resource_type="AWS::SSM::Document",
                compliance_status=ComplianceStatus.COMPLIANT,
                evaluation_reason="SSM document is not publicly accessible",
                config_rule_name=self.rule_name,
                region=region
            )