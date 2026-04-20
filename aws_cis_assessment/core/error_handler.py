"""Comprehensive error handling system for AWS CIS Assessment tool."""

import logging
import traceback
import time
from typing import Dict, List, Optional, Any, Callable, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from botocore.exceptions import EndpointConnectionError, ConnectTimeoutError, ReadTimeoutError

logger = logging.getLogger(__name__)


class ErrorSeverity(Enum):
    """Error severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ErrorCategory(Enum):
    """Error category classification."""
    CREDENTIAL = "CREDENTIAL"
    PERMISSION = "PERMISSION"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    NETWORK = "NETWORK"
    THROTTLING = "THROTTLING"
    CONFIGURATION = "CONFIGURATION"
    RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND"
    VALIDATION = "VALIDATION"
    UNKNOWN = "UNKNOWN"


@dataclass
class ErrorContext:
    """Context information for error handling."""
    service_name: str = ""
    region: str = ""
    resource_type: str = ""
    resource_id: str = ""
    operation: str = ""
    control_id: str = ""
    config_rule_name: str = ""
    additional_context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ErrorRecord:
    """Detailed error record for tracking and reporting."""
    error_id: str
    timestamp: datetime
    severity: ErrorSeverity
    category: ErrorCategory
    message: str
    context: ErrorContext
    exception_type: str = ""
    stack_trace: str = ""
    recovery_attempted: bool = False
    recovery_successful: bool = False
    retry_count: int = 0
    troubleshooting_guidance: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Generate error ID if not provided."""
        if not self.error_id:
            self.error_id = f"ERR_{int(time.time())}_{hash(self.message) % 10000:04d}"


class ErrorHandler:
    """Comprehensive error handling with graceful degradation and recovery."""
    
    def __init__(self, max_retries: int = 3, base_delay: float = 1.0, 
                 enable_audit_trail: bool = True):
        """Initialize error handler.
        
        Args:
            max_retries: Maximum retry attempts for recoverable errors
            base_delay: Base delay for exponential backoff
            enable_audit_trail: Whether to maintain detailed error audit trail
        """
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.enable_audit_trail = enable_audit_trail
        
        # Error tracking
        self.error_records: List[ErrorRecord] = []
        self.service_availability: Dict[str, Dict[str, bool]] = {}
        self.retry_counts: Dict[str, int] = {}
        
        # Recovery strategies
        self.recovery_strategies: Dict[ErrorCategory, Callable] = {
            ErrorCategory.THROTTLING: self._handle_throttling_error,
            ErrorCategory.NETWORK: self._handle_network_error,
            ErrorCategory.SERVICE_UNAVAILABLE: self._handle_service_unavailable_error,
            ErrorCategory.PERMISSION: self._handle_permission_error,
            ErrorCategory.CREDENTIAL: self._handle_credential_error,
        }
        
        logger.info("ErrorHandler initialized with comprehensive error handling")
    
    def handle_error(self, exception: Exception, context: ErrorContext, 
                    operation: Optional[Callable] = None) -> Optional[Any]:
        """Handle error with appropriate recovery strategy.
        
        Args:
            exception: The exception that occurred
            context: Context information about the error
            operation: Optional operation to retry
            
        Returns:
            Result of successful recovery or None if recovery failed
        """
        # Classify the error
        category = self._classify_error(exception)
        severity = self._determine_severity(exception, category)
        
        # Create error record
        error_record = self._create_error_record(
            exception, context, category, severity
        )
        
        # Log the error
        self._log_error(error_record)
        
        # Store error record if audit trail is enabled
        if self.enable_audit_trail:
            self.error_records.append(error_record)
        
        # Attempt recovery if strategy exists
        if category in self.recovery_strategies and operation:
            try:
                result = self.recovery_strategies[category](
                    exception, context, operation, error_record
                )
                if result is not None:
                    error_record.recovery_attempted = True
                    error_record.recovery_successful = True
                    logger.info(f"Successfully recovered from error: {error_record.error_id}")
                    return result
            except Exception as recovery_error:
                logger.error(f"Recovery failed for error {error_record.error_id}: {recovery_error}")
                error_record.recovery_attempted = True
                error_record.recovery_successful = False
        
        # Update service availability tracking
        self._update_service_availability(context, category)
        
        return None
    
    def _classify_error(self, exception: Exception) -> ErrorCategory:
        """Classify error into appropriate category.
        
        Args:
            exception: The exception to classify
            
        Returns:
            ErrorCategory enum value
        """
        if isinstance(exception, (NoCredentialsError, PartialCredentialsError)):
            return ErrorCategory.CREDENTIAL
        
        if isinstance(exception, ClientError):
            error_code = exception.response.get('Error', {}).get('Code', '')
            
            # Permission errors
            if error_code in ['AccessDenied', 'UnauthorizedOperation', 'Forbidden']:
                return ErrorCategory.PERMISSION
            
            # Throttling errors
            if error_code in ['Throttling', 'RequestLimitExceeded', 'TooManyRequestsException',
                             'ThrottlingException', 'ProvisionedThroughputExceededException']:
                return ErrorCategory.THROTTLING
            
            # Service unavailable errors
            if error_code in ['ServiceUnavailable', 'InternalError', 'InternalFailure']:
                return ErrorCategory.SERVICE_UNAVAILABLE
            
            # Resource not found errors
            if error_code in ['ResourceNotFound', 'NoSuchBucket', 'NoSuchKey', 'InvalidInstanceID.NotFound']:
                return ErrorCategory.RESOURCE_NOT_FOUND
            
            # Validation errors
            if error_code in ['ValidationException', 'InvalidParameterValue', 'MalformedPolicyDocument']:
                return ErrorCategory.VALIDATION
        
        # Network errors
        if isinstance(exception, (EndpointConnectionError, ConnectTimeoutError, ReadTimeoutError)):
            return ErrorCategory.NETWORK
        
        # Configuration errors
        if isinstance(exception, (ValueError, TypeError, KeyError)):
            return ErrorCategory.CONFIGURATION
        
        return ErrorCategory.UNKNOWN
    
    def _determine_severity(self, exception: Exception, category: ErrorCategory) -> ErrorSeverity:
        """Determine error severity based on exception and category.
        
        Args:
            exception: The exception
            category: Error category
            
        Returns:
            ErrorSeverity enum value
        """
        # Critical errors that prevent assessment
        if category in [ErrorCategory.CREDENTIAL, ErrorCategory.CONFIGURATION]:
            return ErrorSeverity.CRITICAL
        
        # High severity for permission and service issues
        if category in [ErrorCategory.PERMISSION, ErrorCategory.SERVICE_UNAVAILABLE]:
            return ErrorSeverity.HIGH
        
        # Medium severity for throttling and network issues
        if category in [ErrorCategory.THROTTLING, ErrorCategory.NETWORK]:
            return ErrorSeverity.MEDIUM
        
        # Low severity for resource not found (expected in some cases)
        if category == ErrorCategory.RESOURCE_NOT_FOUND:
            return ErrorSeverity.LOW
        
        return ErrorSeverity.MEDIUM
    
    def _create_error_record(self, exception: Exception, context: ErrorContext,
                           category: ErrorCategory, severity: ErrorSeverity) -> ErrorRecord:
        """Create detailed error record.
        
        Args:
            exception: The exception
            context: Error context
            category: Error category
            severity: Error severity
            
        Returns:
            ErrorRecord object
        """
        # Generate troubleshooting guidance
        troubleshooting_guidance = self._generate_troubleshooting_guidance(
            exception, category, context
        )
        
        return ErrorRecord(
            error_id="",  # Will be generated in __post_init__
            timestamp=datetime.now(),
            severity=severity,
            category=category,
            message=str(exception),
            context=context,
            exception_type=type(exception).__name__,
            stack_trace=traceback.format_exc(),
            troubleshooting_guidance=troubleshooting_guidance
        )
    
    def _generate_troubleshooting_guidance(self, exception: Exception, 
                                         category: ErrorCategory, 
                                         context: ErrorContext) -> List[str]:
        """Generate specific troubleshooting guidance for the error.
        
        Args:
            exception: The exception
            category: Error category
            context: Error context
            
        Returns:
            List of troubleshooting steps
        """
        guidance = []
        
        if category == ErrorCategory.CREDENTIAL:
            guidance.extend([
                "Verify AWS credentials are properly configured",
                "Check AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables",
                "Ensure IAM user/role has necessary permissions",
                "Verify credentials haven't expired (for temporary credentials)",
                "Try running 'aws sts get-caller-identity' to test credentials"
            ])
        
        elif category == ErrorCategory.PERMISSION:
            guidance.extend([
                f"Grant necessary permissions for {context.service_name} service",
                f"Check IAM policies for {context.operation} operation",
                "Review AWS Config rule required permissions documentation",
                "Consider using AWS managed policies for CIS assessments",
                f"Verify permissions in region {context.region}"
            ])
        
        elif category == ErrorCategory.SERVICE_UNAVAILABLE:
            guidance.extend([
                f"Check AWS service health dashboard for {context.service_name}",
                f"Verify {context.service_name} is available in region {context.region}",
                "Wait and retry the operation",
                "Consider assessing other regions while service recovers",
                "Check for any ongoing AWS maintenance windows"
            ])
        
        elif category == ErrorCategory.THROTTLING:
            guidance.extend([
                "Reduce API call frequency",
                "Implement exponential backoff with jitter",
                "Consider using fewer parallel workers",
                "Request service limit increase if needed",
                "Spread assessment across multiple time periods"
            ])
        
        elif category == ErrorCategory.NETWORK:
            guidance.extend([
                "Check internet connectivity",
                "Verify DNS resolution for AWS endpoints",
                "Check firewall and proxy settings",
                "Try different AWS region endpoints",
                "Verify VPC endpoints if running in private subnet"
            ])
        
        elif category == ErrorCategory.CONFIGURATION:
            guidance.extend([
                "Review configuration file syntax",
                "Validate all required parameters are provided",
                "Check for typos in configuration values",
                "Ensure configuration matches expected schema",
                "Review example configurations in documentation"
            ])
        
        elif category == ErrorCategory.RESOURCE_NOT_FOUND:
            guidance.extend([
                f"Resource {context.resource_id} may not exist in {context.region}",
                "This may be expected if no resources of this type exist",
                "Verify resource ID format is correct",
                "Check if resource exists in different region",
                "Review resource naming conventions"
            ])
        
        else:
            guidance.extend([
                "Review error message for specific details",
                "Check AWS documentation for the affected service",
                "Verify all prerequisites are met",
                "Consider filing AWS support case if issue persists",
                "Check for known issues in AWS forums"
            ])
        
        return guidance
    
    def _handle_throttling_error(self, exception: Exception, context: ErrorContext,
                               operation: Callable, error_record: ErrorRecord) -> Optional[Any]:
        """Handle throttling errors with exponential backoff.
        
        Args:
            exception: The throttling exception
            context: Error context
            operation: Operation to retry
            error_record: Error record for tracking
            
        Returns:
            Result of successful retry or None
        """
        retry_key = f"{context.service_name}_{context.region}_{context.operation}"
        current_retries = self.retry_counts.get(retry_key, 0)
        
        if current_retries >= self.max_retries:
            logger.warning(f"Max retries exceeded for throttling error: {retry_key}")
            return None
        
        # Calculate delay with exponential backoff and jitter
        delay = self.base_delay * (2 ** current_retries) + (time.time() % 1)
        
        logger.info(f"Throttling detected, retrying in {delay:.2f} seconds "
                   f"(attempt {current_retries + 1}/{self.max_retries})")
        
        time.sleep(delay)
        
        # Update retry count before attempting
        self.retry_counts[retry_key] = current_retries + 1
        error_record.retry_count = current_retries + 1
        
        try:
            result = operation()
            
            # Reset retry count on success
            self.retry_counts[retry_key] = 0
            return result
            
        except Exception as retry_exception:
            logger.warning(f"Retry failed for {retry_key}: {retry_exception}")
            # If this was a throttling error, try again (up to max retries)
            if (isinstance(retry_exception, ClientError) and 
                retry_exception.response.get('Error', {}).get('Code') in 
                ['Throttling', 'RequestLimitExceeded', 'TooManyRequestsException']):
                return self._handle_throttling_error(retry_exception, context, operation, error_record)
            return None
    
    def _handle_network_error(self, exception: Exception, context: ErrorContext,
                            operation: Callable, error_record: ErrorRecord) -> Optional[Any]:
        """Handle network errors with retry logic.
        
        Args:
            exception: The network exception
            context: Error context
            operation: Operation to retry
            error_record: Error record for tracking
            
        Returns:
            Result of successful retry or None
        """
        retry_key = f"network_{context.service_name}_{context.region}"
        current_retries = self.retry_counts.get(retry_key, 0)
        
        if current_retries >= self.max_retries:
            logger.warning(f"Max network retries exceeded: {retry_key}")
            return None
        
        # Shorter delay for network errors
        delay = min(self.base_delay * (1.5 ** current_retries), 10.0)
        
        logger.info(f"Network error detected, retrying in {delay:.2f} seconds")
        time.sleep(delay)
        
        try:
            self.retry_counts[retry_key] = current_retries + 1
            error_record.retry_count = current_retries + 1
            result = operation()
            
            self.retry_counts[retry_key] = 0
            return result
            
        except Exception as retry_exception:
            logger.warning(f"Network retry failed: {retry_exception}")
            return None
    
    def _handle_service_unavailable_error(self, exception: Exception, context: ErrorContext,
                                        operation: Callable, error_record: ErrorRecord) -> Optional[Any]:
        """Handle service unavailable errors.
        
        Args:
            exception: The service unavailable exception
            context: Error context
            operation: Operation to retry
            error_record: Error record for tracking
            
        Returns:
            None (graceful degradation)
        """
        # Mark service as unavailable
        if context.service_name not in self.service_availability:
            self.service_availability[context.service_name] = {}
        
        self.service_availability[context.service_name][context.region] = False
        
        logger.warning(f"Service {context.service_name} unavailable in {context.region}, "
                      "continuing with other services")
        
        return None
    
    def _handle_permission_error(self, exception: Exception, context: ErrorContext,
                               operation: Callable, error_record: ErrorRecord) -> Optional[Any]:
        """Handle permission errors with graceful degradation.
        
        Args:
            exception: The permission exception
            context: Error context
            operation: Operation to retry
            error_record: Error record for tracking
            
        Returns:
            None (graceful degradation)
        """
        logger.warning(f"Permission denied for {context.service_name} in {context.region}, "
                      "skipping this assessment")
        
        return None
    
    def _handle_credential_error(self, exception: Exception, context: ErrorContext,
                               operation: Callable, error_record: ErrorRecord) -> Optional[Any]:
        """Handle credential errors (critical - cannot recover).
        
        Args:
            exception: The credential exception
            context: Error context
            operation: Operation to retry
            error_record: Error record for tracking
            
        Returns:
            None (cannot recover from credential errors)
        """
        logger.critical("Credential error detected - assessment cannot continue")
        return None
    
    def _update_service_availability(self, context: ErrorContext, category: ErrorCategory):
        """Update service availability tracking.
        
        Args:
            context: Error context
            category: Error category
        """
        if category in [ErrorCategory.SERVICE_UNAVAILABLE, ErrorCategory.PERMISSION]:
            if context.service_name not in self.service_availability:
                self.service_availability[context.service_name] = {}
            
            self.service_availability[context.service_name][context.region] = False
    
    def _log_error(self, error_record: ErrorRecord):
        """Log error with appropriate level.
        
        Args:
            error_record: Error record to log
        """
        log_message = (f"[{error_record.error_id}] {error_record.category.value}: "
                      f"{error_record.message}")
        
        if error_record.context.service_name:
            log_message += f" (Service: {error_record.context.service_name}"
            if error_record.context.region:
                log_message += f", Region: {error_record.context.region}"
            log_message += ")"
        
        if error_record.severity == ErrorSeverity.CRITICAL:
            logger.critical(log_message)
        elif error_record.severity == ErrorSeverity.HIGH:
            logger.error(log_message)
        elif error_record.severity == ErrorSeverity.MEDIUM:
            logger.warning(log_message)
        else:
            logger.info(log_message)
    
    def is_service_available(self, service_name: str, region: str) -> bool:
        """Check if service is available in region.
        
        Args:
            service_name: AWS service name
            region: AWS region
            
        Returns:
            True if service is available, False otherwise
        """
        return self.service_availability.get(service_name, {}).get(region, True)
    
    def get_error_summary(self) -> Dict[str, Any]:
        """Get summary of errors encountered.
        
        Returns:
            Dictionary with error summary statistics
        """
        summary = {
            "total_errors": len(self.error_records),
            "unavailable_services": dict(self.service_availability)
        }
        
        if not self.error_records:
            return summary
        
        # Count errors by category and severity
        category_counts = {}
        severity_counts = {}
        
        for error in self.error_records:
            category_counts[error.category.value] = category_counts.get(error.category.value, 0) + 1
            severity_counts[error.severity.value] = severity_counts.get(error.severity.value, 0) + 1
        
        # Calculate recovery statistics
        total_recovery_attempts = sum(1 for e in self.error_records if e.recovery_attempted)
        successful_recoveries = sum(1 for e in self.error_records if e.recovery_successful)
        
        summary.update({
            "errors_by_category": category_counts,
            "errors_by_severity": severity_counts,
            "recovery_attempts": total_recovery_attempts,
            "successful_recoveries": successful_recoveries,
            "recovery_rate": (successful_recoveries / total_recovery_attempts * 100) 
                           if total_recovery_attempts > 0 else 0
        })
        
        return summary
    
    def get_troubleshooting_report(self) -> List[Dict[str, Any]]:
        """Generate troubleshooting report for all errors.
        
        Returns:
            List of error details with troubleshooting guidance
        """
        report = []
        
        for error in self.error_records:
            if error.severity in [ErrorSeverity.CRITICAL, ErrorSeverity.HIGH]:
                report.append({
                    "error_id": error.error_id,
                    "timestamp": error.timestamp.isoformat(),
                    "severity": error.severity.value,
                    "category": error.category.value,
                    "message": error.message,
                    "service": error.context.service_name,
                    "region": error.context.region,
                    "troubleshooting_steps": error.troubleshooting_guidance,
                    "recovery_attempted": error.recovery_attempted,
                    "recovery_successful": error.recovery_successful
                })
        
        return report
    
    def clear_error_history(self):
        """Clear error history and reset tracking."""
        self.error_records.clear()
        self.service_availability.clear()
        self.retry_counts.clear()
        logger.info("Error history cleared")