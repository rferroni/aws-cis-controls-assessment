"""IG3 Advanced Security Controls."""

from .control_7_1 import (
    ECRPrivateImageScanningEnabledAssessment,
    GuardDutyEnabledCentralizedAssessment,
    EC2ManagedInstancePatchComplianceAssessment
)

from .control_3_14 import (
    APIGatewayExecutionLoggingEnabledAssessment,
    CloudTrailS3DataEventsEnabledAssessment,
    MultiRegionCloudTrailEnabledAssessment,
    CloudTrailCloudWatchLogsEnabledAssessment
)

from .control_12_8 import (
    APIGatewayAssociatedWithWAFAssessment,
    VPCSecurityGroupOpenOnlyToAuthorizedPortsAssessment,
    NoUnrestrictedRouteToIGWAssessment
)

from .control_13_1 import (
    RestrictedIncomingTrafficAssessment,
    IncomingSSHDisabledAssessment,
    VPCFlowLogsEnabledAssessment
)

__all__ = [
    # Control 7.1 - Vulnerability Management
    'ECRPrivateImageScanningEnabledAssessment',
    'GuardDutyEnabledCentralizedAssessment',
    'EC2ManagedInstancePatchComplianceAssessment',
    
    # Control 3.14 - Sensitive Data Logging
    'APIGatewayExecutionLoggingEnabledAssessment',
    'CloudTrailS3DataEventsEnabledAssessment',
    'MultiRegionCloudTrailEnabledAssessment',
    'CloudTrailCloudWatchLogsEnabledAssessment',
    
    # Control 12.8 - Network Segmentation
    'APIGatewayAssociatedWithWAFAssessment',
    'VPCSecurityGroupOpenOnlyToAuthorizedPortsAssessment',
    'NoUnrestrictedRouteToIGWAssessment',
    
    # Control 13.1 - Network Monitoring
    'RestrictedIncomingTrafficAssessment',
    'IncomingSSHDisabledAssessment',
    'VPCFlowLogsEnabledAssessment'
]