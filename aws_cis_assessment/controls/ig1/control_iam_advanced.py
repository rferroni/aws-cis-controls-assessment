"""
CIS Control 3.3 - IAM Advanced Security Controls
Advanced IAM security rules for comprehensive identity and access management.
"""

import logging
from typing import List, Dict, Any, Optional
import boto3
import json
from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError, NoCredentialsError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class IAMRootAccessKeyCheckAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 3.3 - Configure Data Access Control Lists
    AWS Config Rule: iam-root-access-key-check
    
    Ensures the root user does not have access keys attached to prevent unauthorized access.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="iam-root-access-key-check",
            control_id="3.3",
            resource_types=["AWS::::Account"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get account information for root access key check."""
        if resource_type != "AWS::::Account":
            return []
        
        try:
            # Get account ID
            sts_client = aws_factory.get_client('sts', region)
            identity = sts_client.get_caller_identity()
            account_id = identity['Account']
            
            return [{
                'AccountId': account_id,
                'ResourceType': 'Account'
            }]
            
        except ClientError as e:
            logger.error(f"Error retrieving account information: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving account information: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if root user has access keys."""
        account_id = resource.get('AccountId', 'unknown')
        
        try:
            iam_client = aws_factory.get_client('iam', region)
            
            # Get account summary to check for root access keys
            summary = iam_client.get_account_summary()
            
            # Check for root access keys
            root_access_keys = summary.get('SummaryMap', {}).get('AccountAccessKeysPresent', 0)
            
            if root_access_keys > 0:
                return ComplianceResult(
                    resource_id=account_id,
                    resource_type="AWS::::Account",
                    compliance_status=ComplianceStatus.NON_COMPLIANT,
                    evaluation_reason=f"Root user has {root_access_keys} access key(s) attached",
                    config_rule_name=self.rule_name,
                    region=region
                )
            else:
                return ComplianceResult(
                    resource_id=account_id,
                    resource_type="AWS::::Account",
                    compliance_status=ComplianceStatus.COMPLIANT,
                    evaluation_reason="Root user has no access keys attached",
                    config_rule_name=self.rule_name,
                    region=region
                )
        
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code in ['AccessDenied', 'UnauthorizedOperation']:
                return ComplianceResult(
                    resource_id=account_id,
                    resource_type="AWS::::Account",
                    compliance_status=ComplianceStatus.ERROR,
                    evaluation_reason=f"Insufficient permissions to check root access keys: {error_code}",
                    config_rule_name=self.rule_name,
                    region=region
                )
            else:
                return ComplianceResult(
                    resource_id=account_id,
                    resource_type="AWS::::Account",
                    compliance_status=ComplianceStatus.ERROR,
                    evaluation_reason=f"Error checking root access keys: {str(e)}",
                    config_rule_name=self.rule_name,
                    region=region
                )
        
        except Exception as e:
            return ComplianceResult(
                resource_id=account_id,
                resource_type="AWS::::Account",
                compliance_status=ComplianceStatus.ERROR,
                evaluation_reason=f"Unexpected error: {str(e)}",
                config_rule_name=self.rule_name,
                region=region
            )


class IAMUserUnusedCredentialsCheckAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 3.3 - Configure Data Access Control Lists
    AWS Config Rule: iam-user-unused-credentials-check
    
    Ensures IAM users don't have unused credentials that could pose security risks.
    """
    
    def __init__(self, max_credential_usage_age: int = 90):
        super().__init__(
            rule_name="iam-user-unused-credentials-check",
            control_id="3.3",
            resource_types=["AWS::IAM::User"],
            parameters={"maxCredentialUsageAge": max_credential_usage_age}
        )
        self.max_credential_usage_age = max_credential_usage_age
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all IAM users with their credential information."""
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
                        # Get access keys for the user
                        access_keys_response = iam_client.list_access_keys(UserName=user_name)
                        access_keys = access_keys_response.get('AccessKeyMetadata', [])
                        
                        # Get login profile (console password)
                        has_login_profile = False
                        login_profile_last_used = None
                        try:
                            login_profile = iam_client.get_login_profile(UserName=user_name)
                            has_login_profile = True
                            # Get password last used
                            user_detail = iam_client.get_user(UserName=user_name)
                            login_profile_last_used = user_detail['User'].get('PasswordLastUsed')
                        except ClientError as e:
                            if e.response.get('Error', {}).get('Code') != 'NoSuchEntity':
                                logger.warning(f"Error getting login profile for user {user_name}: {e}")
                        
                        users.append({
                            'UserName': user_name,
                            'UserId': user['UserId'],
                            'Arn': user['Arn'],
                            'CreateDate': user['CreateDate'],
                            'PasswordLastUsed': user.get('PasswordLastUsed'),
                            'HasLoginProfile': has_login_profile,
                            'LoginProfileLastUsed': login_profile_last_used,
                            'AccessKeys': access_keys
                        })
                    
                    except ClientError as e:
                        logger.warning(f"Error getting credentials for IAM user {user_name}: {e}")
                        continue
            
            logger.debug(f"Found {len(users)} IAM users")
            return users
            
        except ClientError as e:
            logger.error(f"Error retrieving IAM users: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving IAM users: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if IAM user has unused credentials."""
        user_name = resource.get('UserName', 'unknown')
        password_last_used = resource.get('PasswordLastUsed')
        has_login_profile = resource.get('HasLoginProfile', False)
        access_keys = resource.get('AccessKeys', [])
        
        now = datetime.now(timezone.utc)
        cutoff_date = now - timedelta(days=self.max_credential_usage_age)
        
        unused_credentials = []
        
        # Check password usage
        if has_login_profile:
            if password_last_used is None:
                unused_credentials.append("Console password (never used)")
            elif password_last_used < cutoff_date:
                days_unused = (now - password_last_used).days
                unused_credentials.append(f"Console password (unused for {days_unused} days)")
        
        # Check access keys usage
        try:
            iam_client = aws_factory.get_client('iam', region)
            
            for access_key in access_keys:
                access_key_id = access_key['AccessKeyId']
                
                # Get access key last used
                try:
                    last_used_response = iam_client.get_access_key_last_used(AccessKeyId=access_key_id)
                    last_used_info = last_used_response.get('AccessKeyLastUsed', {})
                    last_used_date = last_used_info.get('LastUsedDate')
                    
                    if last_used_date is None:
                        unused_credentials.append(f"Access key {access_key_id} (never used)")
                    elif last_used_date < cutoff_date:
                        days_unused = (now - last_used_date).days
                        unused_credentials.append(f"Access key {access_key_id} (unused for {days_unused} days)")
                
                except ClientError as e:
                    logger.warning(f"Error getting last used info for access key {access_key_id}: {e}")
        
        except ClientError as e:
            logger.warning(f"Error checking access key usage for user {user_name}: {e}")
        
        if unused_credentials:
            return ComplianceResult(
                resource_id=user_name,
                resource_type="AWS::IAM::User",
                compliance_status=ComplianceStatus.NON_COMPLIANT,
                evaluation_reason=f"IAM user has unused credentials: {'; '.join(unused_credentials)}",
                config_rule_name=self.rule_name,
                region=region
            )
        else:
            return ComplianceResult(
                resource_id=user_name,
                resource_type="AWS::IAM::User",
                compliance_status=ComplianceStatus.COMPLIANT,
                evaluation_reason=f"IAM user has no unused credentials (within {self.max_credential_usage_age} days)",
                config_rule_name=self.rule_name,
                region=region
            )


class IAMCustomerPolicyBlockedKMSActionsAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 3.3 - Configure Data Access Control Lists
    AWS Config Rule: iam-customer-policy-blocked-kms-actions
    
    Ensures customer-managed IAM policies don't contain blocked KMS actions.
    """
    
    def __init__(self, blocked_actions_patterns: List[str] = None):
        super().__init__(
            rule_name="iam-customer-policy-blocked-kms-actions",
            control_id="3.3",
            resource_types=["AWS::IAM::Policy"],
            parameters={"blockedActionsPatterns": blocked_actions_patterns or ["kms:Decrypt", "kms:ReEncryptFrom"]}
        )
        self.blocked_actions_patterns = blocked_actions_patterns or ["kms:Decrypt", "kms:ReEncryptFrom"]
    
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
                        
                        # Analyze policy for blocked KMS actions
                        has_blocked_actions = False
                        blocked_statements = []
                        
                        statements = policy_document.get('Statement', [])
                        if not isinstance(statements, list):
                            statements = [statements]
                        
                        for statement in statements:
                            if isinstance(statement, dict):
                                effect = statement.get('Effect', '')
                                actions = statement.get('Action', [])
                                resources = statement.get('Resource', [])
                                
                                if effect == 'Allow':
                                    if isinstance(actions, str):
                                        actions = [actions]
                                    if isinstance(resources, str):
                                        resources = [resources]
                                    
                                    # Check for blocked KMS actions on all KMS keys
                                    for action in actions:
                                        for blocked_pattern in self.blocked_actions_patterns:
                                            if (action == blocked_pattern or action == 'kms:*' or action == '*') and \
                                               ('*' in resources or any('arn:aws:kms:*' in res for res in resources)):
                                                has_blocked_actions = True
                                                blocked_statements.append({
                                                    'Action': action,
                                                    'Resource': resources,
                                                    'BlockedPattern': blocked_pattern
                                                })
                        
                        policies.append({
                            'PolicyName': policy['PolicyName'],
                            'PolicyArn': policy_arn,
                            'Path': policy['Path'],
                            'CreateDate': policy['CreateDate'],
                            'UpdateDate': policy['UpdateDate'],
                            'AttachmentCount': policy['AttachmentCount'],
                            'HasBlockedActions': has_blocked_actions,
                            'BlockedStatements': blocked_statements,
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
        """Evaluate if IAM policy contains blocked KMS actions."""
        policy_name = resource.get('PolicyName', 'unknown')
        policy_arn = resource.get('PolicyArn', 'unknown')
        has_blocked_actions = resource.get('HasBlockedActions', False)
        blocked_statements = resource.get('BlockedStatements', [])
        
        if has_blocked_actions:
            blocked_details = []
            for stmt in blocked_statements:
                blocked_details.append(f"Action: {stmt['Action']}, Pattern: {stmt['BlockedPattern']}")
            
            return ComplianceResult(
                resource_id=policy_arn,
                resource_type="AWS::IAM::Policy",
                compliance_status=ComplianceStatus.NON_COMPLIANT,
                evaluation_reason=f"IAM policy contains blocked KMS actions: {'; '.join(blocked_details)}",
                config_rule_name=self.rule_name,
                region=region
            )
        else:
            return ComplianceResult(
                resource_id=policy_arn,
                resource_type="AWS::IAM::Policy",
                compliance_status=ComplianceStatus.COMPLIANT,
                evaluation_reason="IAM policy does not contain blocked KMS actions",
                config_rule_name=self.rule_name,
                region=region
            )


class IAMInlinePolicyBlockedKMSActionsAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 3.3 - Configure Data Access Control Lists
    AWS Config Rule: iam-inline-policy-blocked-kms-actions
    
    Ensures inline IAM policies don't contain blocked KMS actions.
    """
    
    def __init__(self, blocked_actions_patterns: List[str] = None):
        super().__init__(
            rule_name="iam-inline-policy-blocked-kms-actions",
            control_id="3.3",
            resource_types=["AWS::IAM::User", "AWS::IAM::Role", "AWS::IAM::Group"],
            parameters={"blockedActionsPatterns": blocked_actions_patterns or ["kms:Decrypt", "kms:ReEncryptFrom"]}
        )
        self.blocked_actions_patterns = blocked_actions_patterns or ["kms:Decrypt", "kms:ReEncryptFrom"]
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all IAM entities with inline policies."""
        resources = []
        
        try:
            iam_client = aws_factory.get_client('iam', region)
            
            if resource_type == "AWS::IAM::User":
                # Get all users with inline policies
                paginator = iam_client.get_paginator('list_users')
                for page in paginator.paginate():
                    for user in page['Users']:
                        user_name = user['UserName']
                        try:
                            inline_policies = iam_client.list_user_policies(UserName=user_name)
                            if inline_policies.get('PolicyNames'):
                                resources.append({
                                    'EntityType': 'User',
                                    'EntityName': user_name,
                                    'EntityArn': user['Arn'],
                                    'InlinePolicyNames': inline_policies['PolicyNames']
                                })
                        except ClientError as e:
                            logger.warning(f"Error getting inline policies for user {user_name}: {e}")
            
            elif resource_type == "AWS::IAM::Role":
                # Get all roles with inline policies
                paginator = iam_client.get_paginator('list_roles')
                for page in paginator.paginate():
                    for role in page['Roles']:
                        role_name = role['RoleName']
                        try:
                            inline_policies = iam_client.list_role_policies(RoleName=role_name)
                            if inline_policies.get('PolicyNames'):
                                resources.append({
                                    'EntityType': 'Role',
                                    'EntityName': role_name,
                                    'EntityArn': role['Arn'],
                                    'InlinePolicyNames': inline_policies['PolicyNames']
                                })
                        except ClientError as e:
                            logger.warning(f"Error getting inline policies for role {role_name}: {e}")
            
            elif resource_type == "AWS::IAM::Group":
                # Get all groups with inline policies
                paginator = iam_client.get_paginator('list_groups')
                for page in paginator.paginate():
                    for group in page['Groups']:
                        group_name = group['GroupName']
                        try:
                            inline_policies = iam_client.list_group_policies(GroupName=group_name)
                            if inline_policies.get('PolicyNames'):
                                resources.append({
                                    'EntityType': 'Group',
                                    'EntityName': group_name,
                                    'EntityArn': group['Arn'],
                                    'InlinePolicyNames': inline_policies['PolicyNames']
                                })
                        except ClientError as e:
                            logger.warning(f"Error getting inline policies for group {group_name}: {e}")
            
            logger.debug(f"Found {len(resources)} IAM entities with inline policies of type {resource_type}")
            return resources
            
        except ClientError as e:
            logger.error(f"Error retrieving IAM entities: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving IAM entities: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if inline policies contain blocked KMS actions."""
        entity_type = resource.get('EntityType', 'unknown')
        entity_name = resource.get('EntityName', 'unknown')
        entity_arn = resource.get('EntityArn', 'unknown')
        inline_policy_names = resource.get('InlinePolicyNames', [])
        
        try:
            iam_client = aws_factory.get_client('iam', region)
            
            blocked_policies = []
            
            for policy_name in inline_policy_names:
                try:
                    # Get the inline policy document
                    if entity_type == 'User':
                        policy_response = iam_client.get_user_policy(UserName=entity_name, PolicyName=policy_name)
                    elif entity_type == 'Role':
                        policy_response = iam_client.get_role_policy(RoleName=entity_name, PolicyName=policy_name)
                    elif entity_type == 'Group':
                        policy_response = iam_client.get_group_policy(GroupName=entity_name, PolicyName=policy_name)
                    else:
                        continue
                    
                    policy_document = policy_response['PolicyDocument']
                    
                    # Check for blocked KMS actions
                    statements = policy_document.get('Statement', [])
                    if not isinstance(statements, list):
                        statements = [statements]
                    
                    for statement in statements:
                        if isinstance(statement, dict):
                            effect = statement.get('Effect', '')
                            actions = statement.get('Action', [])
                            resources_list = statement.get('Resource', [])
                            
                            if effect == 'Allow':
                                if isinstance(actions, str):
                                    actions = [actions]
                                if isinstance(resources_list, str):
                                    resources_list = [resources_list]
                                
                                # Check for blocked KMS actions on all KMS keys
                                for action in actions:
                                    for blocked_pattern in self.blocked_actions_patterns:
                                        if (action == blocked_pattern or action == 'kms:*' or action == '*') and \
                                           ('*' in resources_list or any('arn:aws:kms:*' in res for res in resources_list)):
                                            blocked_policies.append(f"{policy_name} (Action: {action})")
                                            break
                
                except ClientError as e:
                    logger.warning(f"Error getting inline policy {policy_name} for {entity_type} {entity_name}: {e}")
            
            if blocked_policies:
                return ComplianceResult(
                    resource_id=entity_arn,
                    resource_type=f"AWS::IAM::{entity_type}",
                    compliance_status=ComplianceStatus.NON_COMPLIANT,
                    evaluation_reason=f"IAM {entity_type.lower()} has inline policies with blocked KMS actions: {'; '.join(blocked_policies)}",
                    config_rule_name=self.rule_name,
                    region=region
                )
            else:
                return ComplianceResult(
                    resource_id=entity_arn,
                    resource_type=f"AWS::IAM::{entity_type}",
                    compliance_status=ComplianceStatus.COMPLIANT,
                    evaluation_reason=f"IAM {entity_type.lower()} inline policies do not contain blocked KMS actions",
                    config_rule_name=self.rule_name,
                    region=region
                )
        
        except ClientError as e:
            return ComplianceResult(
                resource_id=entity_arn,
                resource_type=f"AWS::IAM::{entity_type}",
                compliance_status=ComplianceStatus.ERROR,
                evaluation_reason=f"Error checking inline policies: {str(e)}",
                config_rule_name=self.rule_name,
                region=region
            )
        except Exception as e:
            return ComplianceResult(
                resource_id=entity_arn,
                resource_type=f"AWS::IAM::{entity_type}",
                compliance_status=ComplianceStatus.ERROR,
                evaluation_reason=f"Unexpected error: {str(e)}",
                config_rule_name=self.rule_name,
                region=region
            )