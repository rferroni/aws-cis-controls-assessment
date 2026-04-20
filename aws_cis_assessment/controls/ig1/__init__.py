"""IG1 Essential Cyber Hygiene Control implementations."""

from .control_1_1 import (
    EIPAttachedAssessment,
    EC2StoppedInstanceAssessment,
    VPCNetworkACLUnusedAssessment,
    EC2InstanceManagedBySSMAssessment,
    EC2SecurityGroupAttachedAssessment
)

from .control_2_2 import (
    ElasticBeanstalkManagedUpdatesEnabledAssessment,
    ECSFargateLatestPlatformVersionAssessment
)

from .control_3_3 import (
    IAMPasswordPolicyAssessment,
    IAMUserMFAEnabledAssessment,
    IAMRootAccessKeyAssessment,
    S3BucketPublicReadProhibitedAssessment,
    EC2InstanceNoPublicIPAssessment
)

from .control_3_4 import (
    S3VersionLifecyclePolicyAssessment,
    CloudWatchLogGroupRetentionAssessment
)

from .control_4_1 import (
    AccountPartOfOrganizationsAssessment,
    EC2VolumeInUseAssessment,
    RedshiftClusterMaintenanceSettingsAssessment,
    SecretsManagerRotationEnabledAssessment
)

from .control_access_keys import (
    AccessKeysRotatedAssessment,
    EC2IMDSv2CheckAssessment,
    EC2InstanceProfileAttachedAssessment
)

from .control_iam_policies import (
    IAMPolicyNoStatementsWithAdminAccessAssessment,
    IAMNoInlinePolicyCheckAssessment,
    IAMUserGroupMembershipCheckAssessment
)

from .control_s3_security import (
    S3BucketSSLRequestsOnlyAssessment,
    S3BucketServerSideEncryptionEnabledAssessment,
    S3BucketLoggingEnabledAssessment,
    S3BucketVersioningEnabledAssessment
)

from .control_data_protection import (
    EBSSnapshotPublicRestorableCheckAssessment,
    RDSSnapshotsPublicProhibitedAssessment,
    RDSInstancePublicAccessCheckAssessment,
    RedshiftClusterPublicAccessCheckAssessment,
    S3BucketLevelPublicAccessProhibitedAssessment
)

from .control_network_security import (
    NetworkFirewallDeployedAssessment,
    Route53ResolverFirewallEnabledAssessment
)

from .control_iam_governance import (
    IAMGroupHasUsersCheckAssessment,
    IAMPolicyNoStatementsWithFullAccessAssessment,
    IAMUserNoPoliciesCheckAssessment,
    SSMDocumentNotPublicAssessment
)

from .control_advanced_security import (
    EC2ManagedInstanceAssociationComplianceStatusCheckAssessment,
    EMRKerberosEnabledAssessment,
    LambdaInsideVPCAssessment,
    ECSTaskDefinitionUserForHostModeCheckAssessment
)

from .control_iam_advanced import (
    IAMRootAccessKeyCheckAssessment,
    IAMUserUnusedCredentialsCheckAssessment,
    IAMCustomerPolicyBlockedKMSActionsAssessment,
    IAMInlinePolicyBlockedKMSActionsAssessment
)

from .control_cloudtrail_logging import (
    CloudTrailEnabledAssessment,
    CloudWatchLogGroupEncryptedAssessment
)

from .control_vpc_security import (
    VPCDefaultSecurityGroupClosedAssessment,
    RestrictedSSHAssessment
)

from .control_critical_security import (
    RootAccountHardwareMFAEnabledAssessment,
    OpenSearchInVPCOnlyAssessment,
    ECSTaskDefinitionNonRootUserAssessment,
    SecurityHubEnabledAssessment
)

from .control_network_enhancements import (
    ElasticsearchNodeToNodeEncryptionCheckAssessment,
    AutoScalingLaunchConfigPublicIPDisabledAssessment,
    EFSAccessPointEnforceRootDirectoryAssessment
)

from .control_backup_recovery import (
    DynamoDBInBackupPlanAssessment,
    EBSInBackupPlanAssessment,
    EFSInBackupPlanAssessment,
    DBInstanceBackupEnabledAssessment,
    RedshiftBackupEnabledAssessment,
    DynamoDBPITREnabledAssessment,
    ElastiCacheRedisClusterAutomaticBackupCheckAssessment,
    S3BucketReplicationEnabledAssessment
)

from .control_aws_backup_service import (
    BackupPlanMinFrequencyAndMinRetentionCheckAssessment,
    BackupVaultAccessPolicyCheckAssessment,
    BackupVaultLockCheckAssessment,
    BackupSelectionResourceCoverageCheckAssessment,
    BackupReportPlanExistsCheckAssessment,
    BackupRestoreTestingPlanExistsCheckAssessment
)

from .control_s3_enhancements import (
    S3AccountLevelPublicAccessBlocksPeriodicAssessment,
    S3BucketPublicWriteProhibitedAssessment
)

from .control_instance_optimization import (
    EBSOptimizedInstanceAssessment
)

# Phase 1-4: CIS Controls v8.1 IG1 Expansion
from .control_guardduty import GuardDutyEnabledAssessment
from .control_inspector import InspectorEnabledAssessment
from .control_macie import MacieEnabledAssessment
from .control_access_analyzer import IAMAccessAnalyzerEnabledAssessment
from .control_vpc_flow_logs import VPCFlowLogsEnabledAssessment
from .control_elb_logging import ELBLoggingEnabledAssessment
from .control_cloudfront_logging import CloudFrontLoggingEnabledAssessment
from .control_waf_logging import WAFLoggingEnabledAssessment
from .control_ebs_encryption import EBSEncryptionByDefaultAssessment
from .control_rds_encryption import RDSStorageEncryptedAssessment
from .control_efs_encryption import EFSEncryptedCheckAssessment
from .control_dynamodb_encryption import DynamoDBTableEncryptedKMSAssessment
from .control_s3_encryption import S3DefaultEncryptionKMSAssessment
from .control_patch_management import (
    SSMPatchManagerEnabledAssessment,
    SSMPatchBaselineConfiguredAssessment,
    EC2PatchComplianceStatusAssessment
)
from .control_access_control import (
    SSOEnabledCheckAssessment,
    IdentityCenterConfiguredAssessment
)
from .control_mfa import (
    IAMAdminMFARequiredAssessment,
    CognitoMFAEnabledAssessment,
    VPNMFAEnabledAssessment
)
from .control_tls_ssl import (
    ALBHTTPToHTTPSRedirectionAssessment,
    ELBTLSHTTPSListenersOnlyAssessment,
    RDSSSLConnectionRequiredAssessment,
    APIGatewaySSLEnabledAssessment,
    RedshiftRequireTLSSSLAssessment
)
from .control_messaging_encryption import (
    SNSEncryptedKMSAssessment,
    SQSQueueEncryptedAssessment,
    CloudTrailS3DataEventsEnabledAssessment
)
from .control_inventory import (
    SSMInventoryEnabledAssessment,
    ConfigEnabledAllRegionsAssessment,
    AMIInventoryTrackingAssessment,
    LambdaRuntimeInventoryAssessment,
    IAMUserInventoryCheckAssessment
)
from .control_configuration_mgmt import (
    ConfigConformancePackDeployedAssessment,
    SecurityHubStandardsEnabledAssessment,
    AssetTaggingComplianceAssessment,
    InspectorAssessmentEnabledAssessment
)
from .control_version_mgmt import (
    EC2OSVersionSupportedAssessment,
    RDSEngineVersionSupportedAssessment,
    LambdaRuntimeSupportedAssessment
)
from .control_access_asset_mgmt import (
    IAMUserLastAccessCheckAssessment,
    SSMSessionManagerEnabledAssessment,
    UnauthorizedAssetDetectionAssessment
)
from .control_data_classification import (
    DataClassificationTaggingAssessment,
    S3BucketClassificationTagsAssessment
)
from .control_network_security import (
    NetworkFirewallDeployedAssessment,
    Route53ResolverFirewallEnabledAssessment
)
from .control_backup_security import (
    BackupVaultEncryptionEnabledAssessment,
    BackupCrossRegionCopyEnabledAssessment,
    BackupVaultLockEnabledAssessment,
    Route53QueryLoggingEnabledAssessment,
    RDSBackupRetentionCheckAssessment
)

__all__ = [
    # Control 1.1 - Asset Inventory
    'EIPAttachedAssessment',
    'EC2StoppedInstanceAssessment',
    'VPCNetworkACLUnusedAssessment',
    'EC2InstanceManagedBySSMAssessment',
    'EC2SecurityGroupAttachedAssessment',
    
    # Control 2.2 - Authorized Software Support
    'ElasticBeanstalkManagedUpdatesEnabledAssessment',
    'ECSFargateLatestPlatformVersionAssessment',
    
    # Control 3.3 - Data Access Control
    'IAMPasswordPolicyAssessment',
    'IAMUserMFAEnabledAssessment',
    'IAMRootAccessKeyAssessment',
    'S3BucketPublicReadProhibitedAssessment',
    'EC2InstanceNoPublicIPAssessment',
    'EC2IMDSv2CheckAssessment',
    'EC2InstanceProfileAttachedAssessment',
    'IAMPolicyNoStatementsWithAdminAccessAssessment',
    'IAMNoInlinePolicyCheckAssessment',
    'IAMUserGroupMembershipCheckAssessment',
    'EBSSnapshotPublicRestorableCheckAssessment',
    'RDSSnapshotsPublicProhibitedAssessment',
    'RDSInstancePublicAccessCheckAssessment',
    'RedshiftClusterPublicAccessCheckAssessment',
    'S3BucketLevelPublicAccessProhibitedAssessment',
    'IAMGroupHasUsersCheckAssessment',
    'IAMPolicyNoStatementsWithFullAccessAssessment',
    'IAMUserNoPoliciesCheckAssessment',
    'SSMDocumentNotPublicAssessment',
    'EC2ManagedInstanceAssociationComplianceStatusCheckAssessment',
    'EMRKerberosEnabledAssessment',
    'LambdaInsideVPCAssessment',
    'ECSTaskDefinitionUserForHostModeCheckAssessment',
    'IAMRootAccessKeyCheckAssessment',
    'IAMUserUnusedCredentialsCheckAssessment',
    'IAMCustomerPolicyBlockedKMSActionsAssessment',
    'IAMInlinePolicyBlockedKMSActionsAssessment',
    
    # Control 3.4 - Data Retention
    'S3VersionLifecyclePolicyAssessment',
    'CloudWatchLogGroupRetentionAssessment',
    
    # Control 4.1 - Secure Configuration Process
    'AccountPartOfOrganizationsAssessment',
    'EC2VolumeInUseAssessment',
    'RedshiftClusterMaintenanceSettingsAssessment',
    'SecretsManagerRotationEnabledAssessment',
    'AccessKeysRotatedAssessment',
    
    # Control 11.2 - Backup Management
    'S3BucketVersioningEnabledAssessment',
    
    # S3 Security Controls (Phase 5)
    'S3BucketSSLRequestsOnlyAssessment',
    'S3BucketServerSideEncryptionEnabledAssessment',
    'S3BucketLoggingEnabledAssessment',
    
    # CloudTrail & Logging Controls (Phase 6)
    'CloudTrailEnabledAssessment',
    'CloudWatchLogGroupEncryptedAssessment',
    
    # VPC Security Controls (Phase 6)
    'VPCDefaultSecurityGroupClosedAssessment',
    'RestrictedSSHAssessment',
    
    # Critical Security Controls
    'RootAccountHardwareMFAEnabledAssessment',
    'OpenSearchInVPCOnlyAssessment', 
    'ECSTaskDefinitionNonRootUserAssessment',
    'SecurityHubEnabledAssessment',
    
    # Network Security Enhancements
    'ElasticsearchNodeToNodeEncryptionCheckAssessment',
    'AutoScalingLaunchConfigPublicIPDisabledAssessment',
    'EFSAccessPointEnforceRootDirectoryAssessment',
    
    # Backup & Recovery Controls
    'DynamoDBInBackupPlanAssessment',
    'EBSInBackupPlanAssessment',
    'EFSInBackupPlanAssessment',
    'DBInstanceBackupEnabledAssessment',
    'RedshiftBackupEnabledAssessment',
    'DynamoDBPITREnabledAssessment',
    'ElastiCacheRedisClusterAutomaticBackupCheckAssessment',
    'S3BucketReplicationEnabledAssessment',
    
    # AWS Backup Service Controls
    'BackupPlanMinFrequencyAndMinRetentionCheckAssessment',
    'BackupVaultAccessPolicyCheckAssessment',
    'BackupVaultLockCheckAssessment',
    'BackupSelectionResourceCoverageCheckAssessment',
    'BackupReportPlanExistsCheckAssessment',
    'BackupRestoreTestingPlanExistsCheckAssessment',
    
    # S3 Security Enhancements
    'S3AccountLevelPublicAccessBlocksPeriodicAssessment',
    'S3BucketPublicWriteProhibitedAssessment',
    
    # Instance Optimization
    'EBSOptimizedInstanceAssessment',
    
    # Phase 1-4: CIS Controls v8.1 IG1 Expansion (50 new rules)
    # Phase 1 - Quick Wins (13 rules)
    'GuardDutyEnabledAssessment',
    'InspectorEnabledAssessment',
    'MacieEnabledAssessment',
    'IAMAccessAnalyzerEnabledAssessment',
    'VPCFlowLogsEnabledAssessment',
    'ELBLoggingEnabledAssessment',
    'CloudFrontLoggingEnabledAssessment',
    'WAFLoggingEnabledAssessment',
    'EBSEncryptionByDefaultAssessment',
    'RDSStorageEncryptedAssessment',
    'EFSEncryptedCheckAssessment',
    'DynamoDBTableEncryptedKMSAssessment',
    'S3DefaultEncryptionKMSAssessment',
    
    # Phase 2 - Core Security (15 rules)
    'SSMPatchManagerEnabledAssessment',
    'SSMPatchBaselineConfiguredAssessment',
    'EC2PatchComplianceStatusAssessment',
    'SSOEnabledCheckAssessment',
    'IdentityCenterConfiguredAssessment',
    'IAMAdminMFARequiredAssessment',
    'CognitoMFAEnabledAssessment',
    'VPNMFAEnabledAssessment',
    'ALBHTTPToHTTPSRedirectionAssessment',
    'ELBTLSHTTPSListenersOnlyAssessment',
    'RDSSSLConnectionRequiredAssessment',
    'APIGatewaySSLEnabledAssessment',
    'RedshiftRequireTLSSSLAssessment',
    'SNSEncryptedKMSAssessment',
    'SQSQueueEncryptedAssessment',
    'CloudTrailS3DataEventsEnabledAssessment',
    
    # Phase 3 - Advanced (15 rules)
    'SSMInventoryEnabledAssessment',
    'ConfigEnabledAllRegionsAssessment',
    'AMIInventoryTrackingAssessment',
    'LambdaRuntimeInventoryAssessment',
    'IAMUserInventoryCheckAssessment',
    'ConfigConformancePackDeployedAssessment',
    'SecurityHubStandardsEnabledAssessment',
    'AssetTaggingComplianceAssessment',
    'InspectorAssessmentEnabledAssessment',
    'EC2OSVersionSupportedAssessment',
    'RDSEngineVersionSupportedAssessment',
    'LambdaRuntimeSupportedAssessment',
    'IAMUserLastAccessCheckAssessment',
    'SSMSessionManagerEnabledAssessment',
    'UnauthorizedAssetDetectionAssessment',
    
    # Phase 4 - Enhanced (7 rules)
    'DataClassificationTaggingAssessment',
    'S3BucketClassificationTagsAssessment',
    'NetworkFirewallDeployedAssessment',
    'Route53ResolverFirewallEnabledAssessment',
    'BackupVaultEncryptionEnabledAssessment',
    'BackupCrossRegionCopyEnabledAssessment',
    'BackupVaultLockEnabledAssessment',
    'Route53QueryLoggingEnabledAssessment',
    'RDSBackupRetentionCheckAssessment'
]