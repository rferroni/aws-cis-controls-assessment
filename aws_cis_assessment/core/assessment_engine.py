"""Assessment Engine for orchestrating CIS Controls compliance assessments."""

import logging
import time
import gc
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass
import weakref
import resource
import sys

from aws_cis_assessment.core.models import (
    AssessmentResult, ControlScore, IGScore, ComplianceResult, 
    ComplianceStatus, ImplementationGroup, CISControl
)
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory
from aws_cis_assessment.core.scoring_engine import ScoringEngine
from aws_cis_assessment.config.config_loader import ConfigRuleLoader
from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.error_handler import ErrorHandler, ErrorContext, ErrorCategory
from aws_cis_assessment.core.audit_trail import AuditTrail, AuditEventType

# Import all control assessments
from aws_cis_assessment.controls.ig1.control_1_1 import (
    EIPAttachedAssessment, EC2StoppedInstanceAssessment, VPCNetworkACLUnusedAssessment,
    EC2InstanceManagedBySSMAssessment, EC2SecurityGroupAttachedAssessment
)
from aws_cis_assessment.controls.ig1.control_2_2 import (
    ElasticBeanstalkManagedUpdatesEnabledAssessment, ECSFargateLatestPlatformVersionAssessment
)
from aws_cis_assessment.controls.ig1.control_3_3 import (
    IAMPasswordPolicyAssessment, IAMUserMFAEnabledAssessment,
    S3BucketPublicReadProhibitedAssessment, EC2InstanceNoPublicIPAssessment
)
from aws_cis_assessment.controls.ig1.control_3_4 import (
    S3VersionLifecyclePolicyAssessment, CloudWatchLogGroupRetentionAssessment
)
from aws_cis_assessment.controls.ig1.control_4_1 import (
    AccountPartOfOrganizationsAssessment, EC2VolumeInUseAssessment,
    RedshiftClusterMaintenanceSettingsAssessment, SecretsManagerRotationEnabledAssessment
)
from aws_cis_assessment.controls.ig1.control_access_keys import (
    AccessKeysRotatedAssessment, EC2IMDSv2CheckAssessment, EC2InstanceProfileAttachedAssessment
)
from aws_cis_assessment.controls.ig1.control_iam_policies import (
    IAMPolicyNoStatementsWithAdminAccessAssessment, IAMNoInlinePolicyCheckAssessment,
    IAMUserGroupMembershipCheckAssessment
)
from aws_cis_assessment.controls.ig1.control_s3_security import (
    S3BucketSSLRequestsOnlyAssessment, S3BucketServerSideEncryptionEnabledAssessment,
    S3BucketLoggingEnabledAssessment, S3BucketVersioningEnabledAssessment
)
from aws_cis_assessment.controls.ig1.control_data_protection import (
    EBSSnapshotPublicRestorableCheckAssessment, RDSSnapshotsPublicProhibitedAssessment,
    RDSInstancePublicAccessCheckAssessment, RedshiftClusterPublicAccessCheckAssessment,
    S3BucketLevelPublicAccessProhibitedAssessment
)
from aws_cis_assessment.controls.ig1.control_network_security import (
    NetworkFirewallDeployedAssessment,
    Route53ResolverFirewallEnabledAssessment
)
from aws_cis_assessment.controls.ig1.control_iam_governance import (
    IAMGroupHasUsersCheckAssessment, IAMPolicyNoStatementsWithFullAccessAssessment,
    IAMUserNoPoliciesCheckAssessment, SSMDocumentNotPublicAssessment
)
from aws_cis_assessment.controls.ig1.control_advanced_security import (
    EC2ManagedInstanceAssociationComplianceStatusCheckAssessment, EMRKerberosEnabledAssessment,
    LambdaInsideVPCAssessment, ECSTaskDefinitionUserForHostModeCheckAssessment
)
from aws_cis_assessment.controls.ig1.control_iam_advanced import (
    IAMRootAccessKeyCheckAssessment, IAMUserUnusedCredentialsCheckAssessment,
    IAMCustomerPolicyBlockedKMSActionsAssessment, IAMInlinePolicyBlockedKMSActionsAssessment
)
from aws_cis_assessment.controls.ig1.control_cloudtrail_logging import (
    CloudTrailEnabledAssessment, CloudWatchLogGroupEncryptedAssessment
)
from aws_cis_assessment.controls.ig1.control_vpc_security import (
    VPCDefaultSecurityGroupClosedAssessment, RestrictedSSHAssessment
)
from aws_cis_assessment.controls.ig1.control_critical_security import (
    RootAccountHardwareMFAEnabledAssessment, OpenSearchInVPCOnlyAssessment,
    ECSTaskDefinitionNonRootUserAssessment, SecurityHubEnabledAssessment
)
from aws_cis_assessment.controls.ig1.control_network_enhancements import (
    ElasticsearchNodeToNodeEncryptionCheckAssessment, AutoScalingLaunchConfigPublicIPDisabledAssessment,
    EFSAccessPointEnforceRootDirectoryAssessment
)
from aws_cis_assessment.controls.ig1.control_backup_recovery import (
    DynamoDBInBackupPlanAssessment, EBSInBackupPlanAssessment, EFSInBackupPlanAssessment,
    DBInstanceBackupEnabledAssessment, RedshiftBackupEnabledAssessment, DynamoDBPITREnabledAssessment,
    ElastiCacheRedisClusterAutomaticBackupCheckAssessment, S3BucketReplicationEnabledAssessment
)
from aws_cis_assessment.controls.ig1.control_aws_backup_service import (
    BackupPlanMinFrequencyAndMinRetentionCheckAssessment,
    BackupVaultAccessPolicyCheckAssessment,
    BackupSelectionResourceCoverageCheckAssessment
)
from aws_cis_assessment.controls.ig1.control_s3_enhancements import (
    S3AccountLevelPublicAccessBlocksPeriodicAssessment, S3BucketPublicWriteProhibitedAssessment
)
from aws_cis_assessment.controls.ig1.control_instance_optimization import (
    EBSOptimizedInstanceAssessment
)

# Phase 1-4: CIS Controls v8.1 IG1 Expansion (50 new rules)
from aws_cis_assessment.controls.ig1.control_guardduty import GuardDutyEnabledAssessment
from aws_cis_assessment.controls.ig1.control_inspector import InspectorEnabledAssessment
from aws_cis_assessment.controls.ig1.control_macie import MacieEnabledAssessment
from aws_cis_assessment.controls.ig1.control_access_analyzer import IAMAccessAnalyzerEnabledAssessment
from aws_cis_assessment.controls.ig1.control_vpc_flow_logs import VPCFlowLogsEnabledAssessment
from aws_cis_assessment.controls.ig1.control_elb_logging import ELBLoggingEnabledAssessment
from aws_cis_assessment.controls.ig1.control_cloudfront_logging import CloudFrontLoggingEnabledAssessment
from aws_cis_assessment.controls.ig1.control_waf_logging import WAFLoggingEnabledAssessment
from aws_cis_assessment.controls.ig1.control_ebs_encryption import EBSEncryptionByDefaultAssessment
from aws_cis_assessment.controls.ig1.control_rds_encryption import RDSStorageEncryptedAssessment as RDSStorageEncryptedIG1Assessment
from aws_cis_assessment.controls.ig1.control_efs_encryption import EFSEncryptedCheckAssessment
from aws_cis_assessment.controls.ig1.control_dynamodb_encryption import DynamoDBTableEncryptedKMSAssessment as DynamoDBTableEncryptedKMSIG1Assessment
from aws_cis_assessment.controls.ig1.control_s3_encryption import S3DefaultEncryptionKMSAssessment as S3DefaultEncryptionKMSIG1Assessment
from aws_cis_assessment.controls.ig1.control_patch_management import (
    SSMPatchManagerEnabledAssessment,
    SSMPatchBaselineConfiguredAssessment,
    EC2PatchComplianceStatusAssessment
)
from aws_cis_assessment.controls.ig1.control_access_control import (
    SSOEnabledCheckAssessment,
    IdentityCenterConfiguredAssessment
)
from aws_cis_assessment.controls.ig1.control_mfa import (
    IAMAdminMFARequiredAssessment,
    CognitoMFAEnabledAssessment,
    VPNMFAEnabledAssessment
)
from aws_cis_assessment.controls.ig1.control_tls_ssl import (
    ALBHTTPToHTTPSRedirectionAssessment as ALBHTTPToHTTPSRedirectionIG1Assessment,
    ELBTLSHTTPSListenersOnlyAssessment as ELBTLSHTTPSListenersOnlyIG1Assessment,
    RDSSSLConnectionRequiredAssessment,
    APIGatewaySSLEnabledAssessment as APIGatewaySSLEnabledIG1Assessment,
    RedshiftRequireTLSSSLAssessment as RedshiftRequireTLSSSLIG1Assessment
)
from aws_cis_assessment.controls.ig1.control_messaging_encryption import (
    SNSEncryptedKMSAssessment,
    SQSQueueEncryptedAssessment,
    CloudTrailS3DataEventsEnabledAssessment
)
from aws_cis_assessment.controls.ig1.control_inventory import (
    SSMInventoryEnabledAssessment,
    ConfigEnabledAllRegionsAssessment,
    AMIInventoryTrackingAssessment,
    LambdaRuntimeInventoryAssessment,
    IAMUserInventoryCheckAssessment
)
from aws_cis_assessment.controls.ig1.control_configuration_mgmt import (
    ConfigConformancePackDeployedAssessment,
    SecurityHubStandardsEnabledAssessment,
    AssetTaggingComplianceAssessment,
    InspectorAssessmentEnabledAssessment
)
from aws_cis_assessment.controls.ig1.control_version_mgmt import (
    EC2OSVersionSupportedAssessment,
    RDSEngineVersionSupportedAssessment,
    LambdaRuntimeSupportedAssessment
)
from aws_cis_assessment.controls.ig1.control_access_asset_mgmt import (
    IAMUserLastAccessCheckAssessment,
    SSMSessionManagerEnabledAssessment,
    UnauthorizedAssetDetectionAssessment
)
from aws_cis_assessment.controls.ig1.control_data_classification import (
    DataClassificationTaggingAssessment,
    S3BucketClassificationTagsAssessment
)
from aws_cis_assessment.controls.ig1.control_backup_security import (
    BackupVaultEncryptionEnabledAssessment,
    BackupCrossRegionCopyEnabledAssessment,
    BackupVaultLockEnabledAssessment,
    Route53QueryLoggingEnabledAssessment,
    RDSBackupRetentionCheckAssessment
)

from aws_cis_assessment.controls.ig2.control_3_10 import (
    APIGatewaySSLEnabledAssessment, ALBHTTPToHTTPSRedirectionAssessment,
    ELBTLSHTTPSListenersOnlyAssessment, S3BucketSSLRequestsOnlyAssessment,
    RedshiftRequireTLSSSLAssessment
)
from aws_cis_assessment.controls.ig2.control_3_11 import (
    EncryptedVolumesAssessment, RDSStorageEncryptedAssessment,
    S3DefaultEncryptionKMSAssessment, DynamoDBTableEncryptedKMSAssessment,
    BackupRecoveryPointEncryptedAssessment
)
from aws_cis_assessment.controls.ig2.control_5_2 import (
    MFAEnabledForIAMConsoleAccessAssessment, RootAccountMFAEnabledAssessment,
    IAMUserUnusedCredentialsAssessment
)
from aws_cis_assessment.controls.ig2.control_encryption_transit import (
    ELBACMCertificateRequiredAssessment, ELBv2ACMCertificateRequiredAssessment,
    OpenSearchHTTPSRequiredAssessment
)
from aws_cis_assessment.controls.ig2.control_encryption_rest import (
    CloudTrailEncryptionEnabledAssessment, EFSEncryptedCheckAssessment as EFSEncryptedCheckIG2Assessment,
    EC2EBSEncryptionByDefaultAssessment, RDSSnapshotEncryptedAssessment
)
from aws_cis_assessment.controls.ig2.control_advanced_encryption import (
    SecretsManagerUsingCMKAssessment, SNSEncryptedKMSAssessment, SQSQueueEncryptedKMSAssessment,
    KinesisStreamEncryptedAssessment, ElasticsearchEncryptedAtRestAssessment
)
from aws_cis_assessment.controls.ig2.control_service_logging import (
    ElasticsearchLogsToCloudWatchAssessment, ELBLoggingEnabledAssessment, RDSLoggingEnabledAssessment,
    WAFv2LoggingEnabledAssessment, CodeBuildProjectLoggingEnabledAssessment, RedshiftClusterConfigurationCheckAssessment
)
from aws_cis_assessment.controls.ig2.control_remaining_encryption import (
    OpenSearchEncryptedAtRestAssessment, OpenSearchNodeToNodeEncryptionCheckAssessment,
    RedshiftClusterKMSEnabledAssessment, SageMakerEndpointConfigurationKMSKeyConfiguredAssessment,
    SageMakerNotebookInstanceKMSKeyConfiguredAssessment, CodeBuildProjectArtifactEncryptionAssessment
)
from aws_cis_assessment.controls.ig2.control_network_ha import (
    ELBCrossZoneLoadBalancingEnabledAssessment, ELBDeletionProtectionEnabledAssessment,
    ELBv2MultipleAZAssessment, RDSClusterMultiAZEnabledAssessment,
    RDSInstanceDeletionProtectionEnabledAssessment, RDSMultiAZSupportAssessment,
    VPCVPNTwoTunnelsUpAssessment
)
from aws_cis_assessment.controls.ig2.control_codebuild_security import (
    CodeBuildProjectEnvironmentPrivilegedCheckAssessment, CodeBuildProjectEnvVarAWSCredCheckAssessment,
    CodeBuildProjectSourceRepoURLCheckAssessment
)
from aws_cis_assessment.controls.ig2.control_remaining_rules import (
    ACMCertificateExpirationCheckAssessment, DynamoDBAutoScalingEnabledAssessment,
    RedshiftEnhancedVPCRoutingEnabledAssessment, RestrictedCommonPortsAssessment,
    AuditLogPolicyExistsAssessment
)
from aws_cis_assessment.controls.ig2.control_aws_backup_ig2 import (
    BackupVaultLockCheckAssessment,
    BackupReportPlanExistsCheckAssessment,
    BackupRestoreTestingPlanExistsCheckAssessment
)
from aws_cis_assessment.controls.ig2.control_8_audit_logging import (
    Route53QueryLoggingAssessment,
    ALBAccessLogsEnabledAssessment,
    CloudFrontAccessLogsEnabledAssessment,
    CloudWatchLogRetentionCheckAssessment,
    CloudTrailInsightsEnabledAssessment,
    ConfigRecordingAllResourcesAssessment,
    WAFLoggingEnabledAssessment
)
from aws_cis_assessment.controls.ig2.control_4_5_6_access_configuration import (
    IAMMaxSessionDurationCheckAssessment,
    SecurityGroupDefaultRulesCheckAssessment,
    VPCDnsResolutionEnabledAssessment,
    RDSDefaultAdminCheckAssessment,
    EC2InstanceProfileLeastPrivilegeAssessment,
    IAMServiceAccountInventoryCheckAssessment,
    IAMAdminPolicyAttachedToRoleCheckAssessment,
    SSOEnabledCheckAssessment,
    IAMUserNoInlinePoliciesAssessment,
    IAMAccessAnalyzerEnabledAssessment,
    IAMPermissionBoundariesCheckAssessment,
    OrganizationsSCPEnabledCheckAssessment,
    CognitoUserPoolMFAEnabledAssessment,
    VPNConnectionMFAEnabledAssessment
)
from aws_cis_assessment.controls.ig3.control_3_14 import (
    APIGatewayExecutionLoggingEnabledAssessment, CloudTrailS3DataEventsEnabledAssessment,
    MultiRegionCloudTrailEnabledAssessment, CloudTrailCloudWatchLogsEnabledAssessment
)
from aws_cis_assessment.controls.ig3.control_7_1 import (
    ECRPrivateImageScanningEnabledAssessment, GuardDutyEnabledCentralizedAssessment,
    EC2ManagedInstancePatchComplianceAssessment
)
from aws_cis_assessment.controls.ig3.control_12_8 import (
    APIGatewayAssociatedWithWAFAssessment, VPCSecurityGroupOpenOnlyToAuthorizedPortsAssessment,
    NoUnrestrictedRouteToIGWAssessment
)
from aws_cis_assessment.controls.ig3.control_13_1 import (
    RestrictedIncomingTrafficAssessment, IncomingSSHDisabledAssessment,
    VPCFlowLogsEnabledAssessment
)

logger = logging.getLogger(__name__)


@dataclass
class AssessmentProgress:
    """Progress tracking for assessment execution."""
    total_controls: int = 0
    completed_controls: int = 0
    total_regions: int = 0
    completed_regions: int = 0
    current_control: str = ""
    current_region: str = ""
    start_time: Optional[datetime] = None
    estimated_completion: Optional[datetime] = None
    errors: List[str] = None
    memory_usage_mb: float = 0.0
    peak_memory_mb: float = 0.0
    active_threads: int = 0
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []
    
    @property
    def progress_percentage(self) -> float:
        """Calculate overall progress percentage."""
        if self.total_controls == 0:
            return 0.0
        return (self.completed_controls / self.total_controls) * 100
    
    @property
    def elapsed_time(self) -> Optional[timedelta]:
        """Calculate elapsed time since start."""
        if self.start_time is None:
            return None
        return datetime.now() - self.start_time


@dataclass
class ResourceUsageStats:
    """Resource usage statistics for performance monitoring."""
    peak_memory_mb: float = 0.0
    current_memory_mb: float = 0.0
    cpu_time_seconds: float = 0.0
    active_connections: int = 0
    total_api_calls: int = 0
    failed_api_calls: int = 0
    avg_response_time_ms: float = 0.0
    
    def update_memory_usage(self):
        """Update current memory usage."""
        try:
            # Try to get memory usage from resource module (Unix-like systems)
            memory_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            if sys.platform == 'darwin':  # macOS reports in bytes
                self.current_memory_mb = memory_kb / 1024 / 1024
            else:  # Linux reports in KB
                self.current_memory_mb = memory_kb / 1024
            
            if self.current_memory_mb > self.peak_memory_mb:
                self.peak_memory_mb = self.current_memory_mb
        except:
            # Fallback - try psutil if available
            try:
                import psutil
                process = psutil.Process()
                memory_info = process.memory_info()
                self.current_memory_mb = memory_info.rss / 1024 / 1024
                if self.current_memory_mb > self.peak_memory_mb:
                    self.peak_memory_mb = self.current_memory_mb
            except ImportError:
                pass


class AssessmentEngine:
    """Orchestrates the entire compliance assessment process."""
    
    def __init__(self, aws_credentials: Optional[Dict[str, str]] = None, 
                 regions: Optional[List[str]] = None, 
                 config_path: Optional[str] = None,
                 max_workers: int = 4,
                 progress_callback: Optional[Callable[[AssessmentProgress], None]] = None,
                 enable_error_recovery: bool = True,
                 enable_audit_trail: bool = True,
                 timeout: int = 3600,
                 memory_limit_mb: Optional[int] = None,
                 enable_resource_monitoring: bool = True):
        """Initialize assessment engine with AWS credentials and configuration.
        
        Args:
            aws_credentials: Optional AWS credentials dict
            regions: List of AWS regions to assess. If None, uses default regions.
            config_path: Path to CIS Controls configuration files
            max_workers: Maximum number of parallel workers for assessment
            progress_callback: Optional callback function for progress updates
            enable_error_recovery: Whether to enable error recovery mechanisms
            enable_audit_trail: Whether to enable audit trail logging
            timeout: Assessment timeout in seconds (default: 3600)
            memory_limit_mb: Optional memory limit in MB for resource management
            enable_resource_monitoring: Whether to enable resource usage monitoring
        """
        self.aws_factory = AWSClientFactory(aws_credentials, regions)
        self.config_loader = ConfigRuleLoader(config_path)
        self.scoring_engine = ScoringEngine()
        self.max_workers = max_workers
        self.timeout = timeout
        self.memory_limit_mb = memory_limit_mb
        self.enable_resource_monitoring = enable_resource_monitoring
        self.progress_callback = progress_callback
        self.progress = AssessmentProgress()
        self.resource_stats = ResourceUsageStats()
        self._progress_lock = threading.Lock()
        self._resource_lock = threading.Lock()
        self._client_cache = weakref.WeakValueDictionary()  # Weak references for memory management
        
        # Initialize error handling and audit trail
        self.error_handler = ErrorHandler() if enable_error_recovery else None
        self.audit_trail = AuditTrail() if enable_audit_trail else None
        
        # Initialize control assessment registry
        self._assessment_registry = self._build_assessment_registry()
        
        # Cache for assessment results shared across IGs
        self._assessment_result_cache = {}
        
        # Start resource monitoring thread if enabled
        self._monitoring_active = False
        self._monitoring_thread = None
        if self.enable_resource_monitoring:
            self._start_resource_monitoring()
        
        logger.info(f"Assessment Engine initialized for regions: {self.aws_factory.regions}")
        logger.info(f"Performance settings: max_workers={max_workers}, memory_limit={memory_limit_mb}MB")
        
        if self.audit_trail:
            self.audit_trail.log_event(
                event_type=AuditEventType.CONFIGURATION_LOAD,
                message="Assessment Engine initialized",
                details={
                    "regions": self.aws_factory.regions,
                    "max_workers": max_workers,
                    "memory_limit_mb": memory_limit_mb,
                    "resource_monitoring": enable_resource_monitoring,
                    "error_recovery_enabled": enable_error_recovery,
                    "audit_trail_enabled": enable_audit_trail
                }
            )
    
    def _build_assessment_registry(self) -> Dict[str, Dict[str, BaseConfigRuleAssessment]]:
        """Build registry of all available control assessments."""
        registry = {
            'IG1': {
                # Control 1.1 - Asset Inventory
                'eip-attached': EIPAttachedAssessment(),
                'ec2-stopped-instance': EC2StoppedInstanceAssessment(),
                'vpc-network-acl-unused-check': VPCNetworkACLUnusedAssessment(),
                'ec2-instance-managed-by-systems-manager': EC2InstanceManagedBySSMAssessment(),
                'ec2-security-group-attached-to-eni': EC2SecurityGroupAttachedAssessment(),
                
                # Control 2.2 - Authorized Software Support
                'elastic-beanstalk-managed-updates-enabled': ElasticBeanstalkManagedUpdatesEnabledAssessment(),
                'ecs-fargate-latest-platform-version': ECSFargateLatestPlatformVersionAssessment(),
                
                # Control 3.3 - Data Access Control
                'iam-password-policy': IAMPasswordPolicyAssessment(),
                'iam-user-mfa-enabled': IAMUserMFAEnabledAssessment(),
                's3-bucket-public-read-prohibited': S3BucketPublicReadProhibitedAssessment(),
                'ec2-instance-no-public-ip': EC2InstanceNoPublicIPAssessment(),
                'ec2-imdsv2-check': EC2IMDSv2CheckAssessment(),
                'ec2-instance-profile-attached': EC2InstanceProfileAttachedAssessment(),
                'iam-policy-no-statements-with-admin-access': IAMPolicyNoStatementsWithAdminAccessAssessment(),
                'iam-no-inline-policy-check': IAMNoInlinePolicyCheckAssessment(),
                'iam-user-group-membership-check': IAMUserGroupMembershipCheckAssessment(),
                'ebs-snapshot-public-restorable-check': EBSSnapshotPublicRestorableCheckAssessment(),
                'rds-snapshots-public-prohibited': RDSSnapshotsPublicProhibitedAssessment(),
                'rds-instance-public-access-check': RDSInstancePublicAccessCheckAssessment(),
                'redshift-cluster-public-access-check': RedshiftClusterPublicAccessCheckAssessment(),
                's3-bucket-level-public-access-prohibited': S3BucketLevelPublicAccessProhibitedAssessment(),
                'iam-group-has-users-check': IAMGroupHasUsersCheckAssessment(),
                'iam-policy-no-statements-with-full-access': IAMPolicyNoStatementsWithFullAccessAssessment(),
                'iam-user-no-policies-check': IAMUserNoPoliciesCheckAssessment(),
                'ssm-document-not-public': SSMDocumentNotPublicAssessment(),
                'ec2-managedinstance-association-compliance-status-check': EC2ManagedInstanceAssociationComplianceStatusCheckAssessment(),
                'emr-kerberos-enabled': EMRKerberosEnabledAssessment(),
                'lambda-inside-vpc': LambdaInsideVPCAssessment(),
                'ecs-task-definition-user-for-host-mode-check': ECSTaskDefinitionUserForHostModeCheckAssessment(),
                'iam-root-access-key-check': IAMRootAccessKeyCheckAssessment(),
                'iam-user-unused-credentials-check': IAMUserUnusedCredentialsCheckAssessment(),
                'iam-customer-policy-blocked-kms-actions': IAMCustomerPolicyBlockedKMSActionsAssessment(),
                'iam-inline-policy-blocked-kms-actions': IAMInlinePolicyBlockedKMSActionsAssessment(),
                
                # Control 3.4 - Data Retention
                's3-version-lifecycle-policy-check': S3VersionLifecyclePolicyAssessment(),
                'cw-loggroup-retention-period-check': CloudWatchLogGroupRetentionAssessment(),
                
                # Control 4.1 - Secure Configuration
                'account-part-of-organizations': AccountPartOfOrganizationsAssessment(),
                'ec2-volume-inuse-check': EC2VolumeInUseAssessment(),
                'redshift-cluster-maintenancesettings-check': RedshiftClusterMaintenanceSettingsAssessment(),
                'secretsmanager-rotation-enabled-check': SecretsManagerRotationEnabledAssessment(),
                'access-keys-rotated': AccessKeysRotatedAssessment(),
                
                # Control 11.2 - Backup Management
                's3-bucket-versioning-enabled': S3BucketVersioningEnabledAssessment(),
                
                # S3 Security Controls (Phase 5)
                's3-bucket-ssl-requests-only': S3BucketSSLRequestsOnlyAssessment(),
                's3-bucket-server-side-encryption-enabled': S3BucketServerSideEncryptionEnabledAssessment(),
                's3-bucket-logging-enabled': S3BucketLoggingEnabledAssessment(),
                
                # CloudTrail & Logging Controls (Phase 6)
                'cloudtrail-enabled': CloudTrailEnabledAssessment(),
                'cloudwatch-log-group-encrypted': CloudWatchLogGroupEncryptedAssessment(),
                
                # VPC Security Controls (Phase 6)
                'vpc-default-security-group-closed': VPCDefaultSecurityGroupClosedAssessment(),
                'restricted-ssh': RestrictedSSHAssessment(),
                
                # Critical Security Controls
                'root-account-hardware-mfa-enabled': RootAccountHardwareMFAEnabledAssessment(),
                'opensearch-in-vpc-only': OpenSearchInVPCOnlyAssessment(),
                'ecs-task-definition-nonroot-user': ECSTaskDefinitionNonRootUserAssessment(),
                'securityhub-enabled': SecurityHubEnabledAssessment(),
                
                # Network Security Enhancements
                'elasticsearch-node-to-node-encryption-check': ElasticsearchNodeToNodeEncryptionCheckAssessment(),
                'autoscaling-launch-config-public-ip-disabled': AutoScalingLaunchConfigPublicIPDisabledAssessment(),
                'efs-access-point-enforce-root-directory': EFSAccessPointEnforceRootDirectoryAssessment(),
                
                # Backup & Recovery Controls
                'dynamodb-in-backup-plan': DynamoDBInBackupPlanAssessment(),
                'ebs-in-backup-plan': EBSInBackupPlanAssessment(),
                'efs-in-backup-plan': EFSInBackupPlanAssessment(),
                'db-instance-backup-enabled': DBInstanceBackupEnabledAssessment(),
                'redshift-backup-enabled': RedshiftBackupEnabledAssessment(),
                'dynamodb-pitr-enabled': DynamoDBPITREnabledAssessment(),
                'elasticache-redis-cluster-automatic-backup-check': ElastiCacheRedisClusterAutomaticBackupCheckAssessment(),
                's3-bucket-replication-enabled': S3BucketReplicationEnabledAssessment(),
                
                # AWS Backup Service Controls (IG1)
                'backup-plan-min-frequency-and-min-retention-check': BackupPlanMinFrequencyAndMinRetentionCheckAssessment(),
                'backup-vault-access-policy-check': BackupVaultAccessPolicyCheckAssessment(),
                'backup-selection-resource-coverage-check': BackupSelectionResourceCoverageCheckAssessment(),
                
                # S3 Security Enhancements
                's3-account-level-public-access-blocks-periodic': S3AccountLevelPublicAccessBlocksPeriodicAssessment(),
                's3-bucket-public-write-prohibited': S3BucketPublicWriteProhibitedAssessment(),
                
                # Instance Optimization
                'ebs-optimized-instance': EBSOptimizedInstanceAssessment(),
                
                # Phase 1-4: CIS Controls v8.1 IG1 Expansion (50 new rules)
                # Phase 1 - Quick Wins: Security Services (4 rules)
                'guardduty-enabled-centralized': GuardDutyEnabledAssessment(),
                'inspector-enabled': InspectorEnabledAssessment(),
                'macie-enabled': MacieEnabledAssessment(),
                'iam-access-analyzer-enabled': IAMAccessAnalyzerEnabledAssessment(),
                
                # Phase 1 - Quick Wins: Logging (4 rules)
                'vpc-flow-logs-enabled': VPCFlowLogsEnabledAssessment(),
                'elb-logging-enabled': ELBLoggingEnabledAssessment(),
                'cloudfront-accesslogs-enabled': CloudFrontLoggingEnabledAssessment(),
                'wafv2-logging-enabled': WAFLoggingEnabledAssessment(),
                
                # Phase 1 - Quick Wins: Encryption (5 rules)
                'ebs-encryption-by-default': EBSEncryptionByDefaultAssessment(),
                'rds-storage-encrypted-ig1': RDSStorageEncryptedIG1Assessment(),
                'efs-encrypted-check-ig1': EFSEncryptedCheckAssessment(),
                'dynamodb-table-encrypted-kms-ig1': DynamoDBTableEncryptedKMSIG1Assessment(),
                's3-default-encryption-kms-ig1': S3DefaultEncryptionKMSIG1Assessment(),
                
                # Phase 2 - Core Security: Patch Management (3 rules)
                'ssm-patch-manager-enabled': SSMPatchManagerEnabledAssessment(),
                'ssm-patch-baseline-configured': SSMPatchBaselineConfiguredAssessment(),
                'ec2-patch-compliance-status': EC2PatchComplianceStatusAssessment(),
                
                # Phase 2 - Core Security: Access Control (5 rules)
                'sso-enabled-check': SSOEnabledCheckAssessment(),
                'identity-center-configured': IdentityCenterConfiguredAssessment(),
                'iam-admin-mfa-required': IAMAdminMFARequiredAssessment(),
                'cognito-mfa-enabled': CognitoMFAEnabledAssessment(),
                'vpn-mfa-enabled': VPNMFAEnabledAssessment(),
                
                # Phase 2 - Core Security: TLS/SSL (5 rules)
                'alb-http-to-https-redirection-check': ALBHTTPToHTTPSRedirectionIG1Assessment(),
                'elb-tls-https-listeners-only-ig1': ELBTLSHTTPSListenersOnlyIG1Assessment(),
                'rds-ssl-connection-required': RDSSSLConnectionRequiredAssessment(),
                'api-gateway-ssl-enabled-ig1': APIGatewaySSLEnabledIG1Assessment(),
                'redshift-require-tls-ssl-ig1': RedshiftRequireTLSSSLIG1Assessment(),
                
                # Phase 2 - Core Security: Additional Encryption (3 rules)
                'sns-encrypted-kms': SNSEncryptedKMSAssessment(),
                'sqs-queue-encrypted': SQSQueueEncryptedAssessment(),
                'cloudtrail-s3-dataevents-enabled': CloudTrailS3DataEventsEnabledAssessment(),
                
                # Phase 3 - Advanced: Inventory (5 rules)
                'ssm-inventory-enabled': SSMInventoryEnabledAssessment(),
                'config-enabled-all-regions': ConfigEnabledAllRegionsAssessment(),
                'ami-inventory-tracking': AMIInventoryTrackingAssessment(),
                'lambda-runtime-inventory': LambdaRuntimeInventoryAssessment(),
                'iam-user-inventory-check': IAMUserInventoryCheckAssessment(),
                
                # Phase 3 - Advanced: Configuration Management (4 rules)
                'config-conformance-pack-deployed': ConfigConformancePackDeployedAssessment(),
                'securityhub-standards-enabled': SecurityHubStandardsEnabledAssessment(),
                'asset-tagging-compliance': AssetTaggingComplianceAssessment(),
                'inspector-assessment-enabled': InspectorAssessmentEnabledAssessment(),
                
                # Phase 3 - Advanced: Version Management (3 rules)
                'ec2-os-version-supported': EC2OSVersionSupportedAssessment(),
                'rds-engine-version-supported': RDSEngineVersionSupportedAssessment(),
                'lambda-runtime-supported': LambdaRuntimeSupportedAssessment(),
                
                # Phase 3 - Advanced: Access/Asset Management (3 rules)
                'iam-user-last-access-check': IAMUserLastAccessCheckAssessment(),
                'ssm-session-manager-enabled': SSMSessionManagerEnabledAssessment(),
                'unauthorized-asset-detection': UnauthorizedAssetDetectionAssessment(),
                
                # Phase 4 - Enhanced: Data Classification (2 rules)
                'data-classification-tagging': DataClassificationTaggingAssessment(),
                's3-bucket-classification-tags': S3BucketClassificationTagsAssessment(),
                
                # Phase 4 - Enhanced: Network Security (2 rules)
                'network-firewall-deployed': NetworkFirewallDeployedAssessment(),
                'route53-resolver-firewall-enabled': Route53ResolverFirewallEnabledAssessment(),
                
                # Phase 4 - Enhanced: Backup Security (5 rules)
                'backup-vault-encryption-enabled': BackupVaultEncryptionEnabledAssessment(),
                'backup-cross-region-copy-enabled': BackupCrossRegionCopyEnabledAssessment(),
                'backup-vault-lock-enabled': BackupVaultLockEnabledAssessment(),
                'route53-query-logging-enabled': Route53QueryLoggingEnabledAssessment(),
                'rds-backup-retention-check': RDSBackupRetentionCheckAssessment(),
            },
            'IG2': {
                # Control 3.10 - Encryption in Transit
                'api-gw-ssl-enabled': APIGatewaySSLEnabledAssessment(),
                'alb-http-to-https-redirection-check': ALBHTTPToHTTPSRedirectionAssessment(),
                'elb-tls-https-listeners-only': ELBTLSHTTPSListenersOnlyAssessment(),
                'redshift-require-tls-ssl': RedshiftRequireTLSSSLAssessment(),
                'elb-acm-certificate-required': ELBACMCertificateRequiredAssessment(),
                'elbv2-acm-certificate-required': ELBv2ACMCertificateRequiredAssessment(),
                'opensearch-https-required': OpenSearchHTTPSRequiredAssessment(),
                
                # Control 3.11 - Encryption at Rest
                'encrypted-volumes': EncryptedVolumesAssessment(),
                'rds-storage-encrypted': RDSStorageEncryptedAssessment(),
                's3-default-encryption-kms': S3DefaultEncryptionKMSAssessment(),
                'dynamodb-table-encrypted-kms': DynamoDBTableEncryptedKMSAssessment(),
                'backup-recovery-point-encrypted': BackupRecoveryPointEncryptedAssessment(),
                'cloud-trail-encryption-enabled': CloudTrailEncryptionEnabledAssessment(),
                'efs-encrypted-check': EFSEncryptedCheckIG2Assessment(),
                'ec2-ebs-encryption-by-default': EC2EBSEncryptionByDefaultAssessment(),
                'rds-snapshot-encrypted': RDSSnapshotEncryptedAssessment(),
                
                # Control 5.2 - Password Management
                'mfa-enabled-for-iam-console-access': MFAEnabledForIAMConsoleAccessAssessment(),
                'root-account-mfa-enabled': RootAccountMFAEnabledAssessment(),
                'iam-user-unused-credentials-check': IAMUserUnusedCredentialsAssessment(),
                
                # Advanced Encryption Controls
                'secretsmanager-using-cmk': SecretsManagerUsingCMKAssessment(),
                'sns-encrypted-kms': SNSEncryptedKMSAssessment(),
                'sqs-queue-encrypted-kms': SQSQueueEncryptedKMSAssessment(),
                'kinesis-stream-encrypted': KinesisStreamEncryptedAssessment(),
                'elasticsearch-encrypted-at-rest': ElasticsearchEncryptedAtRestAssessment(),
                
                # Service Logging Controls
                'elasticsearch-logs-to-cloudwatch': ElasticsearchLogsToCloudWatchAssessment(),
                'elb-logging-enabled': ELBLoggingEnabledAssessment(),
                'rds-logging-enabled': RDSLoggingEnabledAssessment(),
                'wafv2-logging-enabled': WAFv2LoggingEnabledAssessment(),
                'codebuild-project-logging-enabled': CodeBuildProjectLoggingEnabledAssessment(),
                'redshift-cluster-configuration-check': RedshiftClusterConfigurationCheckAssessment(),
                
                # Remaining Encryption Controls
                'opensearch-encrypted-at-rest': OpenSearchEncryptedAtRestAssessment(),
                'opensearch-node-to-node-encryption-check': OpenSearchNodeToNodeEncryptionCheckAssessment(),
                'redshift-cluster-kms-enabled': RedshiftClusterKMSEnabledAssessment(),
                'sagemaker-endpoint-configuration-kms-key-configured': SageMakerEndpointConfigurationKMSKeyConfiguredAssessment(),
                'sagemaker-notebook-instance-kms-key-configured': SageMakerNotebookInstanceKMSKeyConfiguredAssessment(),
                'codebuild-project-artifact-encryption': CodeBuildProjectArtifactEncryptionAssessment(),
                
                # Network/HA Controls
                'elb-cross-zone-load-balancing-enabled': ELBCrossZoneLoadBalancingEnabledAssessment(),
                'elb-deletion-protection-enabled': ELBDeletionProtectionEnabledAssessment(),
                'elbv2-multiple-az': ELBv2MultipleAZAssessment(),
                'rds-cluster-multi-az-enabled': RDSClusterMultiAZEnabledAssessment(),
                'rds-instance-deletion-protection-enabled': RDSInstanceDeletionProtectionEnabledAssessment(),
                'rds-multi-az-support': RDSMultiAZSupportAssessment(),
                'vpc-vpn-2-tunnels-up': VPCVPNTwoTunnelsUpAssessment(),
                
                # CodeBuild Security Controls
                'codebuild-project-environment-privileged-check': CodeBuildProjectEnvironmentPrivilegedCheckAssessment(),
                'codebuild-project-envvar-awscred-check': CodeBuildProjectEnvVarAWSCredCheckAssessment(),
                'codebuild-project-source-repo-url-check': CodeBuildProjectSourceRepoURLCheckAssessment(),
                
                # Remaining Rules
                'acm-certificate-expiration-check': ACMCertificateExpirationCheckAssessment(),
                'dynamodb-autoscaling-enabled': DynamoDBAutoScalingEnabledAssessment(),
                'redshift-enhanced-vpc-routing-enabled': RedshiftEnhancedVPCRoutingEnabledAssessment(),
                'restricted-common-ports': RestrictedCommonPortsAssessment(),
                'audit-log-policy-exists (Process check)': AuditLogPolicyExistsAssessment(),
                
                # AWS Backup Service Controls (IG2)
                'backup-vault-lock-check': BackupVaultLockCheckAssessment(),
                'backup-report-plan-exists-check': BackupReportPlanExistsCheckAssessment(),
                'backup-restore-testing-plan-exists-check': BackupRestoreTestingPlanExistsCheckAssessment(),
                
                # Control 8.2 - Audit Log Management
                'route53-query-logging-enabled': Route53QueryLoggingAssessment(),
                'alb-access-logs-enabled': ALBAccessLogsEnabledAssessment(),
                'cloudfront-access-logs-enabled': CloudFrontAccessLogsEnabledAssessment(),
                'cloudwatch-log-retention-check': CloudWatchLogRetentionCheckAssessment(),
                'cloudtrail-insights-enabled': CloudTrailInsightsEnabledAssessment(),
                'config-recording-all-resources': ConfigRecordingAllResourcesAssessment(),
                'waf-logging-enabled': WAFLoggingEnabledAssessment(),
                
                # Control 4 - Secure Configuration
                'iam-max-session-duration-check': IAMMaxSessionDurationCheckAssessment(),
                'security-group-default-rules-check': SecurityGroupDefaultRulesCheckAssessment(),
                'vpc-dns-resolution-enabled': VPCDnsResolutionEnabledAssessment(),
                'rds-default-admin-check': RDSDefaultAdminCheckAssessment(),
                'ec2-instance-profile-least-privilege': EC2InstanceProfileLeastPrivilegeAssessment(),
                
                # Control 5 - Account Management
                'iam-service-account-inventory-check': IAMServiceAccountInventoryCheckAssessment(),
                'iam-admin-policy-attached-to-role-check': IAMAdminPolicyAttachedToRoleCheckAssessment(),
                'sso-enabled-check': SSOEnabledCheckAssessment(),
                'iam-user-no-inline-policies': IAMUserNoInlinePoliciesAssessment(),
                
                # Control 6 - Access Control Management
                'iam-access-analyzer-enabled': IAMAccessAnalyzerEnabledAssessment(),
                'iam-permission-boundaries-check': IAMPermissionBoundariesCheckAssessment(),
                'organizations-scp-enabled-check': OrganizationsSCPEnabledCheckAssessment(),
                'cognito-user-pool-mfa-enabled': CognitoUserPoolMFAEnabledAssessment(),
                'vpn-connection-mfa-enabled': VPNConnectionMFAEnabledAssessment(),
            },
            'IG3': {
                # Control 3.14 - Sensitive Data Logging
                'api-gw-execution-logging-enabled': APIGatewayExecutionLoggingEnabledAssessment(),
                'cloudtrail-s3-dataevents-enabled': CloudTrailS3DataEventsEnabledAssessment(),
                'multi-region-cloudtrail-enabled': MultiRegionCloudTrailEnabledAssessment(),
                'cloud-trail-cloud-watch-logs-enabled': CloudTrailCloudWatchLogsEnabledAssessment(),
                
                # Control 7.1 - Vulnerability Management
                'ecr-private-image-scanning-enabled': ECRPrivateImageScanningEnabledAssessment(),
                'guardduty-enabled-centralized': GuardDutyEnabledCentralizedAssessment(),
                'ec2-managedinstance-patch-compliance-status-check': EC2ManagedInstancePatchComplianceAssessment(),
                
                # Control 12.8 - Network Segmentation
                'api-gw-associated-with-waf': APIGatewayAssociatedWithWAFAssessment(),
                'vpc-sg-open-only-to-authorized-ports': VPCSecurityGroupOpenOnlyToAuthorizedPortsAssessment(),
                'no-unrestricted-route-to-igw': NoUnrestrictedRouteToIGWAssessment(),
                
                # Control 13.1 - Network Monitoring
                'restricted-incoming-traffic': RestrictedIncomingTrafficAssessment(),
                'incoming-ssh-disabled': IncomingSSHDisabledAssessment(),
                'vpc-flow-logs-enabled': VPCFlowLogsEnabledAssessment(),
            }
        }
        
        # Add IG1 assessments to IG2 and IG3 (inheritance)
        # IG2 includes all IG1 controls plus its own
        registry['IG2'].update(registry['IG1'])
        # IG3 includes all IG2 controls (which already includes IG1) plus its own
        registry['IG3'].update(registry['IG2'])
        
        return registry
    
    def _start_resource_monitoring(self):
        """Start background resource monitoring thread."""
        self._monitoring_active = True
        self._monitoring_thread = threading.Thread(target=self._monitor_resources, daemon=True)
        self._monitoring_thread.start()
        logger.debug("Resource monitoring thread started")
    
    def _stop_resource_monitoring(self):
        """Stop background resource monitoring thread."""
        self._monitoring_active = False
        if self._monitoring_thread and self._monitoring_thread.is_alive():
            self._monitoring_thread.join(timeout=1.0)
        logger.debug("Resource monitoring thread stopped")
    
    def _monitor_resources(self):
        """Background thread to monitor resource usage."""
        while self._monitoring_active:
            try:
                with self._resource_lock:
                    self.resource_stats.update_memory_usage()
                    
                    # Update progress with current memory usage
                    with self._progress_lock:
                        self.progress.memory_usage_mb = self.resource_stats.current_memory_mb
                        self.progress.peak_memory_mb = self.resource_stats.peak_memory_mb
                    
                    # Check memory limit if set
                    if (self.memory_limit_mb and 
                        self.resource_stats.current_memory_mb > self.memory_limit_mb):
                        logger.warning(f"Memory usage ({self.resource_stats.current_memory_mb:.1f}MB) "
                                     f"exceeds limit ({self.memory_limit_mb}MB). Triggering garbage collection.")
                        self._optimize_memory_usage()
                
                time.sleep(1.0)  # Monitor every second
            except Exception as e:
                logger.debug(f"Resource monitoring error: {e}")
                time.sleep(5.0)  # Back off on errors
    
    def _optimize_memory_usage(self):
        """Optimize memory usage by cleaning up resources."""
        try:
            # Force garbage collection
            collected = gc.collect()
            logger.debug(f"Garbage collection freed {collected} objects")
            
            # Clear weak reference cache
            self._client_cache.clear()
            
            # Clear any cached data in AWS factory
            if hasattr(self.aws_factory, '_clients'):
                # Keep only essential clients, clear others
                essential_services = ['sts', 'ec2', 'iam']
                clients_to_remove = []
                for key in self.aws_factory._clients.keys():
                    service_name = key.split('_')[0]
                    if service_name not in essential_services:
                        clients_to_remove.append(key)
                
                for key in clients_to_remove:
                    self.aws_factory._clients.pop(key, None)
                
                logger.debug(f"Cleared {len(clients_to_remove)} cached AWS clients")
            
            # Update memory stats after cleanup
            self.resource_stats.update_memory_usage()
            
        except Exception as e:
            logger.warning(f"Memory optimization failed: {e}")
    
    def get_resource_stats(self) -> ResourceUsageStats:
        """Get current resource usage statistics.
        
        Returns:
            ResourceUsageStats object with current metrics
        """
        with self._resource_lock:
            self.resource_stats.update_memory_usage()
            return ResourceUsageStats(
                peak_memory_mb=self.resource_stats.peak_memory_mb,
                current_memory_mb=self.resource_stats.current_memory_mb,
                cpu_time_seconds=self.resource_stats.cpu_time_seconds,
                active_connections=self.resource_stats.active_connections,
                total_api_calls=self.resource_stats.total_api_calls,
                failed_api_calls=self.resource_stats.failed_api_calls,
                avg_response_time_ms=self.resource_stats.avg_response_time_ms
            )
    
    def run_assessment(self, implementation_groups: Optional[List[str]] = None,
                      controls: Optional[List[str]] = None,
                      exclude_controls: Optional[List[str]] = None) -> AssessmentResult:
        """Execute compliance assessment for specified Implementation Groups.
        
        Args:
            implementation_groups: List of IGs to assess (IG1, IG2, IG3). If None, assesses all.
            controls: List of specific control IDs to assess. If specified, overrides implementation_groups.
            exclude_controls: List of control IDs to exclude from assessment.
            
        Returns:
            AssessmentResult with complete assessment data
        """
        if implementation_groups is None:
            implementation_groups = ['IG1', 'IG2', 'IG3']
        
        # Validate implementation groups
        valid_igs = [ig.value for ig in ImplementationGroup]
        for ig in implementation_groups:
            if ig not in valid_igs:
                raise ValueError(f"Invalid implementation group: {ig}. Valid options: {valid_igs}")
        
        logger.info(f"Starting assessment for Implementation Groups: {implementation_groups}")
        if controls:
            logger.info(f"Specific controls requested: {controls}")
        if exclude_controls:
            logger.info(f"Excluded controls: {exclude_controls}")
        
        # Log assessment start
        if self.audit_trail:
            account_info = self.aws_factory.get_account_info()
            account_id = account_info.get('account_id', 'unknown')
            self.audit_trail.log_assessment_start(
                account_id=account_id,
                regions=self.aws_factory.regions,
                implementation_groups=implementation_groups
            )
        
        # Initialize progress tracking
        with self._progress_lock:
            self.progress = AssessmentProgress(
                start_time=datetime.now(),
                total_regions=len(self.aws_factory.regions)
            )
            
            # Count total controls to assess
            total_controls = 0
            for ig in implementation_groups:
                if ig in self._assessment_registry:
                    ig_controls = self._filter_controls_for_ig(ig, controls, exclude_controls)
                    total_controls += len(ig_controls)
            self.progress.total_controls = total_controls
        
        self._update_progress()
        
        try:
            # Validate AWS credentials with error handling
            credential_validation_start = time.time()
            
            if not self.aws_factory.validate_credentials():
                raise RuntimeError("AWS credential validation failed")
            
            # Log credential validation
            if self.audit_trail:
                validation_duration = int((time.time() - credential_validation_start) * 1000)
                self.audit_trail.log_event(
                    event_type=AuditEventType.CREDENTIAL_VALIDATION,
                    status="SUCCESS",
                    message="AWS credentials validated successfully",
                    duration_ms=validation_duration
                )
            
            account_info = self.aws_factory.get_account_info()
            account_id = account_info.get('account_id', 'unknown')
            
            # Execute assessments for each Implementation Group
            ig_scores = {}
            all_results = []
            
            # Cache assessment results to avoid re-running rules shared across IGs
            # (e.g., rules inherited from IG1 into IG2 and IG3)
            self._assessment_result_cache = {}
            
            for ig in implementation_groups:
                logger.info(f"Assessing Implementation Group: {ig}")
                
                ig_results = self._assess_implementation_group(ig, controls, exclude_controls)
                all_results.extend(ig_results)
                
                # Calculate IG score using scoring engine
                ig_score = self._calculate_ig_score(ig, ig_results)
                ig_scores[ig] = ig_score
                
                logger.info(f"Completed {ig} assessment: {ig_score.compliance_percentage:.1f}% compliant")
            
            # Calculate overall score using scoring engine
            overall_score = self.scoring_engine.calculate_overall_score(ig_scores)
            
            # Calculate AWS Config-style unweighted score
            aws_config_score = self.scoring_engine.calculate_aws_config_style_score(ig_scores)
            
            # Create final assessment result
            assessment_result = AssessmentResult(
                account_id=account_id,
                regions_assessed=self.aws_factory.regions.copy(),
                timestamp=datetime.now(),
                overall_score=overall_score,
                aws_config_score=aws_config_score,  # Add AWS Config score
                ig_scores=ig_scores,
                total_resources_evaluated=len(all_results),
                assessment_duration=self.progress.elapsed_time
            )
            
            # Log assessment completion
            if self.audit_trail:
                self.audit_trail.log_assessment_complete(
                    account_id=account_id,
                    overall_score=overall_score,
                    total_resources=len(all_results),
                    duration=self.progress.elapsed_time or timedelta(0)
                )
            
            logger.info(f"Assessment completed. Overall compliance: {overall_score:.1f}%")
            logger.info(f"Resource usage: Peak memory {self.resource_stats.peak_memory_mb:.1f}MB")
            
            return assessment_result
            
        except Exception as e:
            logger.error(f"Assessment failed: {e}")
            
            # Log assessment error
            if self.audit_trail:
                self.audit_trail.log_event(
                    event_type=AuditEventType.ASSESSMENT_ERROR,
                    status="FAILURE",
                    message=f"Assessment failed: {str(e)}",
                    details={"exception_type": type(e).__name__}
                )
            
            # Handle error with error handler
            if self.error_handler:
                context = ErrorContext(operation="assessment_execution")
                self.error_handler.handle_error(e, context)
            
            with self._progress_lock:
                self.progress.errors.append(f"Assessment failed: {str(e)}")
            self._update_progress()
            raise
        
        finally:
            # Cleanup resources
            self._cleanup_resources()
    
    def _assess_implementation_group(self, implementation_group: str,
                                    controls: Optional[List[str]] = None,
                                    exclude_controls: Optional[List[str]] = None) -> List[ComplianceResult]:
        """Assess all controls for a specific Implementation Group.
        
        Args:
            implementation_group: IG1, IG2, or IG3
            controls: List of specific control IDs to assess
            exclude_controls: List of control IDs to exclude
            
        Returns:
            List of ComplianceResult objects
        """
        if implementation_group not in self._assessment_registry:
            logger.warning(f"No assessments found for Implementation Group: {implementation_group}")
            return []
        
        # Filter assessments based on criteria
        assessments = self._filter_controls_for_ig(implementation_group, controls, exclude_controls)
        all_results = []
        
        # Separate cached vs uncached assessments
        cached_results = []
        uncached_assessments = {}
        cache = getattr(self, '_assessment_result_cache', {})
        
        for rule_name, assessment in assessments.items():
            cache_key = rule_name  # Rule name uniquely identifies the assessment
            if cache_key in cache:
                cached_results.extend(cache[cache_key])
                # Update progress for cached results
                with self._progress_lock:
                    self.progress.completed_controls += len(self.aws_factory.regions)
                self._update_progress()
                logger.debug(f"Using cached results for {rule_name} (shared across IGs)")
            else:
                uncached_assessments[rule_name] = assessment
        
        if cached_results:
            logger.info(f"{implementation_group}: Reusing {len(assessments) - len(uncached_assessments)} "
                       f"cached rule results, running {len(uncached_assessments)} new rules")
        
        all_results.extend(cached_results)
        
        # Calculate optimal batch size based on memory constraints
        batch_size = self._calculate_optimal_batch_size(len(uncached_assessments))
        assessment_items = list(uncached_assessments.items())
        
        # Process assessments in batches to manage memory usage
        for batch_start in range(0, len(assessment_items), batch_size):
            batch_end = min(batch_start + batch_size, len(assessment_items))
            batch_assessments = dict(assessment_items[batch_start:batch_end])
            
            logger.debug(f"Processing batch {batch_start//batch_size + 1}: "
                        f"{len(batch_assessments)} assessments")
            
            # Use ThreadPoolExecutor for parallel assessment execution within batch
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Submit assessment tasks for current batch
                future_to_assessment = {}
                
                for rule_name, assessment in batch_assessments.items():
                    for region in self.aws_factory.regions:
                        future = executor.submit(
                            self._run_single_assessment, assessment, region, rule_name
                        )
                        future_to_assessment[future] = (rule_name, region)
                        
                        # Update active threads count
                        with self._progress_lock:
                            self.progress.active_threads = len(future_to_assessment)
                
                # Collect results as they complete
                batch_results = []
                # Track results per rule for caching
                rule_results = {}
                for future in as_completed(future_to_assessment):
                    rule_name, region = future_to_assessment[future]
                    
                    try:
                        results = future.result()
                        batch_results.extend(results)
                        
                        # Accumulate results per rule for caching
                        if rule_name not in rule_results:
                            rule_results[rule_name] = []
                        rule_results[rule_name].extend(results)
                        
                        with self._progress_lock:
                            self.progress.completed_controls += 1
                            self.progress.current_control = rule_name
                            self.progress.current_region = region
                            self.progress.active_threads = len([f for f in future_to_assessment if not f.done()])
                        
                        self._update_progress()
                        
                        logger.debug(f"Completed assessment: {rule_name} in {region} ({len(results)} results)")
                        
                    except Exception as e:
                        error_msg = f"Assessment failed for {rule_name} in {region}: {str(e)}"
                        logger.error(error_msg)
                        
                        with self._progress_lock:
                            self.progress.errors.append(error_msg)
                            self.progress.completed_controls += 1
                        
                        self._update_progress()
            
            # Add batch results to overall results
            all_results.extend(batch_results)
            
            # Cache results per rule for reuse in subsequent IGs
            cache = getattr(self, '_assessment_result_cache', {})
            for rule_name, results in rule_results.items():
                cache[rule_name] = results
            self._assessment_result_cache = cache
            
            # Optimize memory usage between batches
            if batch_end < len(assessment_items):
                self._optimize_memory_usage()
                logger.debug(f"Completed batch {batch_start//batch_size + 1}, "
                           f"memory usage: {self.resource_stats.current_memory_mb:.1f}MB")
        
        return all_results
    
    def _calculate_optimal_batch_size(self, total_assessments: int) -> int:
        """Calculate optimal batch size based on available resources.
        
        Args:
            total_assessments: Total number of assessments to process
            
        Returns:
            Optimal batch size for memory management
        """
        # Base batch size on memory constraints and worker count
        base_batch_size = max(self.max_workers * 2, 10)  # At least 2x workers, minimum 10
        
        if self.memory_limit_mb:
            # Estimate memory per assessment (rough heuristic)
            estimated_memory_per_assessment = 5  # MB
            max_assessments_for_memory = self.memory_limit_mb // estimated_memory_per_assessment
            base_batch_size = min(base_batch_size, max_assessments_for_memory)
        
        # Don't exceed total assessments
        return min(base_batch_size, total_assessments)
    
    def _run_single_assessment(self, assessment: BaseConfigRuleAssessment, 
                             region: str, rule_name: str) -> List[ComplianceResult]:
        """Run a single assessment in a specific region with error handling.
        
        Args:
            assessment: Assessment instance to run
            region: AWS region
            rule_name: Name of the Config rule
            
        Returns:
            List of ComplianceResult objects
        """
        assessment_start_time = time.time()
        
        try:
            logger.debug(f"Starting assessment: {rule_name} in region {region}")
            
            # Check service availability if error handler is enabled
            if self.error_handler:
                required_services = assessment._get_required_services()
                for service in required_services:
                    if not self.error_handler.is_service_available(service, region):
                        logger.warning(f"Service {service} marked as unavailable in {region}, skipping {rule_name}")
                        return [ComplianceResult(
                            resource_id=f"SKIPPED_{rule_name}_{region}",
                            resource_type="SKIPPED",
                            compliance_status=ComplianceStatus.NOT_APPLICABLE,
                            evaluation_reason=f"Service {service} unavailable in region {region}",
                            config_rule_name=rule_name,
                            region=region
                        )]
            
            # Execute assessment with error handling
            results = assessment.evaluate_compliance(self.aws_factory, region)
            
            assessment_duration = int((time.time() - assessment_start_time) * 1000)
            
            # Log control evaluation
            if self.audit_trail:
                compliant_count = sum(1 for r in results if r.compliance_status == ComplianceStatus.COMPLIANT)
                self.audit_trail.log_control_evaluation(
                    control_id=assessment.control_id,
                    config_rule_name=rule_name,
                    region=region,
                    resource_count=len(results),
                    compliant_count=compliant_count,
                    duration_ms=assessment_duration
                )
            
            logger.debug(f"Assessment {rule_name} in {region} completed with {len(results)} results")
            return results
            
        except Exception as e:
            assessment_duration = int((time.time() - assessment_start_time) * 1000)
            
            logger.error(f"Error in assessment {rule_name} for region {region}: {e}")
            
            # Log assessment error
            if self.audit_trail:
                self.audit_trail.log_event(
                    event_type=AuditEventType.ASSESSMENT_ERROR,
                    region=region,
                    service_name=assessment._get_required_services()[0] if assessment._get_required_services() else "",
                    operation=rule_name,
                    status="FAILURE",
                    message=f"Assessment error: {str(e)}",
                    duration_ms=assessment_duration,
                    details={
                        "control_id": assessment.control_id,
                        "exception_type": type(e).__name__
                    }
                )
            
            # Handle error with error handler
            if self.error_handler:
                context = ErrorContext(
                    service_name=assessment._get_required_services()[0] if assessment._get_required_services() else "",
                    region=region,
                    operation=rule_name,
                    control_id=assessment.control_id,
                    config_rule_name=rule_name
                )
                self.error_handler.handle_error(e, context)
            
            # Return error result instead of failing completely
            return [ComplianceResult(
                resource_id=f"ERROR_{rule_name}_{region}",
                resource_type="ERROR",
                compliance_status=ComplianceStatus.ERROR,
                evaluation_reason=f"Assessment error: {str(e)}",
                config_rule_name=rule_name,
                region=region
            )]
    
    def _calculate_ig_score(self, implementation_group: str, 
                           results: List[ComplianceResult]) -> IGScore:
        """Calculate compliance score for an Implementation Group using ScoringEngine.
        
        Args:
            implementation_group: IG1, IG2, or IG3
            results: List of compliance results
            
        Returns:
            IGScore object
        """
        # Group results by control ID
        results_by_control = {}
        for result in results:
            # Extract control ID from the assessment registry
            control_id = self._get_control_id_for_rule(result.config_rule_name, implementation_group)
            if control_id not in results_by_control:
                results_by_control[control_id] = []
            results_by_control[control_id].append(result)
        
        # Calculate control scores using scoring engine
        control_scores = {}
        for control_id, control_results in results_by_control.items():
            control_score = self.scoring_engine.calculate_control_score(
                control_id=control_id,
                rule_results=control_results,
                control_title=f"CIS Control {control_id}",
                implementation_group=implementation_group
            )
            control_scores[control_id] = control_score
        
        # Calculate IG score using scoring engine
        return self.scoring_engine.calculate_ig_score(implementation_group, control_scores)
    
    def _calculate_control_score(self, control_id: str, 
                               results: List[ComplianceResult]) -> ControlScore:
        """Calculate compliance score for a specific control using ScoringEngine.
        
        Args:
            control_id: CIS Control ID
            results: List of compliance results for the control
            
        Returns:
            ControlScore object
        """
        return self.scoring_engine.calculate_control_score(
            control_id=control_id,
            rule_results=results,
            control_title=f"CIS Control {control_id}"
        )
    
    def generate_compliance_summary(self, assessment_result: AssessmentResult):
        """Generate executive summary using ScoringEngine.
        
        Args:
            assessment_result: Complete assessment result
            
        Returns:
            ComplianceSummary object
        """
        return self.scoring_engine.generate_compliance_summary(assessment_result)
    
    def get_scoring_engine(self) -> ScoringEngine:
        """Get the scoring engine instance.
        
        Returns:
            ScoringEngine instance
        """
        return self.scoring_engine
    
    def _get_control_id_for_rule(self, rule_name: str, implementation_group: str) -> str:
        """Get control ID for a specific Config rule.
        
        Args:
            rule_name: AWS Config rule name
            implementation_group: Implementation Group
            
        Returns:
            Control ID string
        """
        if implementation_group in self._assessment_registry:
            assessment = self._assessment_registry[implementation_group].get(rule_name)
            if assessment:
                return assessment.control_id
        
        # Fallback - try to determine from rule name patterns
        if 'iam' in rule_name or 'password' in rule_name or 'mfa' in rule_name:
            return '3.3'  # Access Control
        elif 'eip' in rule_name or 'instance' in rule_name or 'volume' in rule_name:
            return '1.1'  # Asset Inventory
        elif 'ssl' in rule_name or 'tls' in rule_name or 'encrypt' in rule_name:
            return '3.10'  # Encryption
        elif 'log' in rule_name or 'trail' in rule_name:
            return '3.14'  # Logging
        else:
            return 'unknown'
    
    def _update_progress(self):
        """Update progress and call progress callback if provided."""
        if self.progress_callback:
            try:
                self.progress_callback(self.progress)
            except Exception as e:
                logger.warning(f"Progress callback failed: {e}")
    
    def get_supported_controls(self) -> Dict[str, List[str]]:
        """Return mapping of Implementation Groups to supported CIS Controls.
        
        Returns:
            Dictionary mapping IG names to lists of control IDs
        """
        supported_controls = {}
        
        for ig, assessments in self._assessment_registry.items():
            control_ids = set()
            for assessment in assessments.values():
                control_ids.add(assessment.control_id)
            supported_controls[ig] = sorted(list(control_ids))
        
        return supported_controls
    
    def validate_configuration(self) -> List[str]:
        """Validate assessment configuration and return any errors.
        
        Returns:
            List of validation error messages
        """
        errors = []
        
        # Validate config loader
        try:
            config_errors = self.config_loader.validate_configuration()
            errors.extend(config_errors)
        except Exception as e:
            errors.append(f"Config loader validation failed: {str(e)}")
        
        # Validate AWS credentials
        try:
            if not self.aws_factory.validate_credentials():
                errors.append("AWS credential validation failed")
        except Exception as e:
            errors.append(f"AWS credential validation error: {str(e)}")
        
        # Validate assessment registry
        if not self._assessment_registry:
            errors.append("No assessment implementations found")
        
        for ig, assessments in self._assessment_registry.items():
            if not assessments:
                errors.append(f"No assessments found for Implementation Group: {ig}")
        
        return errors
    
    def get_assessment_summary(self, implementation_groups: Optional[List[str]] = None,
                              controls: Optional[List[str]] = None,
                              exclude_controls: Optional[List[str]] = None) -> Dict[str, Any]:
        """Get summary of available assessments.
        
        Args:
            implementation_groups: List of IGs to include in summary
            controls: List of specific control IDs to include
            exclude_controls: List of control IDs to exclude
        
        Returns:
            Dictionary with assessment summary information
        """
        if implementation_groups is None:
            implementation_groups = list(self._assessment_registry.keys())
        
        summary = {
            'implementation_groups': implementation_groups,
            'total_assessments': 0,
            'regions': self.aws_factory.regions.copy(),
            'supported_services': self.aws_factory.get_supported_services(),
            'assessments_by_ig': {}
        }
        
        # Track unique rules across all IGs to avoid double-counting
        # Since IG2 includes IG1 and IG3 includes IG2, we need to count unique rules
        unique_rules = set()
        
        for ig in implementation_groups:
            if ig in self._assessment_registry:
                ig_controls = self._filter_controls_for_ig(ig, controls, exclude_controls)
                summary['assessments_by_ig'][ig] = {
                    'count': len(ig_controls),
                    'rules': list(ig_controls.keys())
                }
                # Add rules to unique set
                unique_rules.update(ig_controls.keys())
        
        # Total assessments is the count of unique rules across all selected IGs
        summary['total_assessments'] = len(unique_rules)
        return summary
    
    def _filter_controls_for_ig(self, implementation_group: str, 
                               controls: Optional[List[str]] = None,
                               exclude_controls: Optional[List[str]] = None) -> Dict[str, BaseConfigRuleAssessment]:
        """Filter controls for an Implementation Group based on criteria.
        
        Args:
            implementation_group: IG to filter controls for
            controls: List of specific control IDs to include
            exclude_controls: List of control IDs to exclude
            
        Returns:
            Dictionary of filtered control assessments
        """
        if implementation_group not in self._assessment_registry:
            return {}
        
        all_assessments = self._assessment_registry[implementation_group]
        
        # If specific controls are requested, filter by control ID
        if controls:
            filtered_assessments = {}
            for rule_name, assessment in all_assessments.items():
                control_id = self._get_control_id_for_rule(rule_name, implementation_group)
                if control_id in controls:
                    filtered_assessments[rule_name] = assessment
            all_assessments = filtered_assessments
        
        # Exclude specified controls
        if exclude_controls:
            filtered_assessments = {}
            for rule_name, assessment in all_assessments.items():
                control_id = self._get_control_id_for_rule(rule_name, implementation_group)
                if control_id not in exclude_controls:
                    filtered_assessments[rule_name] = assessment
            all_assessments = filtered_assessments
        
        return all_assessments
    
    def get_error_summary(self) -> Optional[Dict[str, Any]]:
        """Get summary of errors encountered during assessment.
        
        Returns:
            Error summary dictionary or None if error handling disabled
        """
        if not self.error_handler:
            return None
        
        return self.error_handler.get_error_summary()
    
    def get_troubleshooting_report(self) -> Optional[List[Dict[str, Any]]]:
        """Get troubleshooting report for critical errors.
        
        Returns:
            List of troubleshooting information or None if error handling disabled
        """
        if not self.error_handler:
            return None
        
        return self.error_handler.get_troubleshooting_report()
    
    def get_audit_summary(self) -> Optional[Dict[str, Any]]:
        """Get audit trail summary for current session.
        
        Returns:
            Audit summary dictionary or None if audit trail disabled
        """
        if not self.audit_trail:
            return None
        
        return self.audit_trail.get_session_summary()
    
    def export_audit_trail(self, output_path: str, format: str = "json") -> bool:
        """Export audit trail to file.
        
        Args:
            output_path: Output file path
            format: Export format ("json" or "csv")
            
        Returns:
            True if export successful, False otherwise
        """
        if not self.audit_trail:
            logger.warning("Audit trail not enabled, cannot export")
            return False
        
        return self.audit_trail.export_session_events(output_path, format)
    
    def _cleanup_resources(self):
        """Clean up resources after assessment completion."""
        try:
            # Stop resource monitoring
            if self.enable_resource_monitoring:
                self._stop_resource_monitoring()
            
            # Clear client cache
            self._client_cache.clear()
            
            # Clean up AWS factory resources
            if hasattr(self.aws_factory, 'cleanup'):
                self.aws_factory.cleanup()
            
            # Force garbage collection
            gc.collect()
            
            logger.debug("Assessment resources cleaned up")
            
        except Exception as e:
            logger.warning(f"Resource cleanup failed: {e}")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with resource cleanup."""
        self._cleanup_resources()
        return False