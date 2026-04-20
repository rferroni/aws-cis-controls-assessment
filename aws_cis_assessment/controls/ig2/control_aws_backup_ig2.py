"""AWS Backup Service Controls for IG2 - Advanced backup infrastructure assessment.

This module implements IG2-level AWS Backup service controls that assess
advanced backup capabilities like vault lock, reporting, and restore testing.

Controls:
- backup-vault-lock-check: Verifies vault lock (ransomware protection)
- backup-report-plan-exists-check: Validates backup compliance reporting
- backup-restore-testing-plan-exists-check: Ensures backups are recoverable
"""

# Import the IG2 controls from the IG1 module since they're all in the same file
from aws_cis_assessment.controls.ig1.control_aws_backup_service import (
    BackupVaultLockCheckAssessment,
    BackupReportPlanExistsCheckAssessment,
    BackupRestoreTestingPlanExistsCheckAssessment
)

__all__ = [
    'BackupVaultLockCheckAssessment',
    'BackupReportPlanExistsCheckAssessment',
    'BackupRestoreTestingPlanExistsCheckAssessment'
]
