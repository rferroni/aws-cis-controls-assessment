"""Audit trail system for tracking assessment activities and errors."""

import logging
import json
import os
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class AuditEventType(Enum):
    """Types of audit events."""
    ASSESSMENT_START = "ASSESSMENT_START"
    ASSESSMENT_COMPLETE = "ASSESSMENT_COMPLETE"
    ASSESSMENT_ERROR = "ASSESSMENT_ERROR"
    CONTROL_EVALUATION = "CONTROL_EVALUATION"
    SERVICE_ACCESS = "SERVICE_ACCESS"
    CREDENTIAL_VALIDATION = "CREDENTIAL_VALIDATION"
    ERROR_RECOVERY = "ERROR_RECOVERY"
    CONFIGURATION_LOAD = "CONFIGURATION_LOAD"
    REPORT_GENERATION = "REPORT_GENERATION"


@dataclass
class AuditEvent:
    """Individual audit event record."""
    event_id: str
    timestamp: datetime
    event_type: AuditEventType
    user_id: str
    account_id: str
    region: str
    service_name: str
    operation: str
    status: str  # SUCCESS, FAILURE, WARNING
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    duration_ms: Optional[int] = None
    error_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert audit event to dictionary for serialization."""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        data['event_type'] = self.event_type.value
        return data


class AuditTrail:
    """Comprehensive audit trail system for assessment activities."""
    
    def __init__(self, audit_file_path: Optional[str] = None, 
                 max_file_size_mb: int = 100,
                 retention_days: int = 90,
                 enable_console_logging: bool = True):
        """Initialize audit trail system.
        
        Args:
            audit_file_path: Path to audit log file. If None, uses default location.
            max_file_size_mb: Maximum audit file size before rotation
            retention_days: Number of days to retain audit logs
            enable_console_logging: Whether to also log to console
        """
        self.max_file_size_mb = max_file_size_mb
        self.retention_days = retention_days
        self.enable_console_logging = enable_console_logging
        
        # Set up audit file path
        if audit_file_path:
            self.audit_file_path = Path(audit_file_path)
        else:
            # Default to user's home directory
            audit_dir = Path.home() / ".aws_cis_assessment" / "audit"
            audit_dir.mkdir(parents=True, exist_ok=True)
            self.audit_file_path = audit_dir / "assessment_audit.jsonl"
        
        # Ensure audit directory exists
        self.audit_file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # In-memory event buffer for current session
        self.session_events: List[AuditEvent] = []
        self.session_start_time = datetime.now()
        
        # Set up file logging
        self._setup_file_logging()
        
        logger.info(f"Audit trail initialized: {self.audit_file_path}")
    
    def _setup_file_logging(self):
        """Set up file-based audit logging."""
        try:
            # Create audit file if it doesn't exist
            if not self.audit_file_path.exists():
                self.audit_file_path.touch()
            
            # Check file size and rotate if necessary
            self._rotate_audit_file_if_needed()
            
            # Clean up old audit files
            self._cleanup_old_audit_files()
            
        except Exception as e:
            logger.warning(f"Failed to set up audit file logging: {e}")
    
    def log_event(self, event_type: AuditEventType, user_id: str = "unknown",
                  account_id: str = "unknown", region: str = "unknown",
                  service_name: str = "", operation: str = "",
                  status: str = "SUCCESS", message: str = "",
                  details: Optional[Dict[str, Any]] = None,
                  duration_ms: Optional[int] = None,
                  error_id: Optional[str] = None) -> str:
        """Log an audit event.
        
        Args:
            event_type: Type of event
            user_id: User identifier
            account_id: AWS account ID
            region: AWS region
            service_name: AWS service name
            operation: Operation being performed
            status: Operation status (SUCCESS, FAILURE, WARNING)
            message: Human-readable message
            details: Additional event details
            duration_ms: Operation duration in milliseconds
            error_id: Associated error ID if applicable
            
        Returns:
            Event ID for the logged event
        """
        # Generate unique event ID
        event_id = f"AE_{int(datetime.now().timestamp() * 1000)}_{len(self.session_events):04d}"
        
        # Create audit event
        event = AuditEvent(
            event_id=event_id,
            timestamp=datetime.now(),
            event_type=event_type,
            user_id=user_id,
            account_id=account_id,
            region=region,
            service_name=service_name,
            operation=operation,
            status=status,
            message=message,
            details=details or {},
            duration_ms=duration_ms,
            error_id=error_id
        )
        
        # Add to session events
        self.session_events.append(event)
        
        # Write to file
        self._write_event_to_file(event)
        
        # Log to console if enabled
        if self.enable_console_logging:
            self._log_event_to_console(event)
        
        return event_id
    
    def log_assessment_start(self, account_id: str, regions: List[str],
                           implementation_groups: List[str]) -> str:
        """Log assessment start event.
        
        Args:
            account_id: AWS account ID
            regions: List of regions being assessed
            implementation_groups: List of IGs being assessed
            
        Returns:
            Event ID
        """
        return self.log_event(
            event_type=AuditEventType.ASSESSMENT_START,
            account_id=account_id,
            message=f"Assessment started for account {account_id}",
            details={
                "regions": regions,
                "implementation_groups": implementation_groups,
                "session_start": self.session_start_time.isoformat()
            }
        )
    
    def log_assessment_complete(self, account_id: str, overall_score: float,
                              total_resources: int, duration: timedelta) -> str:
        """Log assessment completion event.
        
        Args:
            account_id: AWS account ID
            overall_score: Overall compliance score
            total_resources: Total resources evaluated
            duration: Assessment duration
            
        Returns:
            Event ID
        """
        return self.log_event(
            event_type=AuditEventType.ASSESSMENT_COMPLETE,
            account_id=account_id,
            message=f"Assessment completed for account {account_id}",
            details={
                "overall_score": overall_score,
                "total_resources": total_resources,
                "session_events": len(self.session_events)
            },
            duration_ms=int(duration.total_seconds() * 1000)
        )
    
    def log_control_evaluation(self, control_id: str, config_rule_name: str,
                             region: str, resource_count: int,
                             compliant_count: int, duration_ms: int) -> str:
        """Log control evaluation event.
        
        Args:
            control_id: CIS Control ID
            config_rule_name: AWS Config rule name
            region: AWS region
            resource_count: Total resources evaluated
            compliant_count: Number of compliant resources
            duration_ms: Evaluation duration in milliseconds
            
        Returns:
            Event ID
        """
        compliance_percentage = (compliant_count / resource_count * 100) if resource_count > 0 else 0
        
        return self.log_event(
            event_type=AuditEventType.CONTROL_EVALUATION,
            region=region,
            operation=config_rule_name,
            message=f"Evaluated control {control_id} in {region}",
            details={
                "control_id": control_id,
                "config_rule_name": config_rule_name,
                "resource_count": resource_count,
                "compliant_count": compliant_count,
                "compliance_percentage": compliance_percentage
            },
            duration_ms=duration_ms
        )
    
    def log_service_access(self, service_name: str, region: str,
                          operation: str, status: str, message: str = "") -> str:
        """Log service access event.
        
        Args:
            service_name: AWS service name
            region: AWS region
            operation: Operation attempted
            status: Access status (SUCCESS, FAILURE)
            message: Additional message
            
        Returns:
            Event ID
        """
        return self.log_event(
            event_type=AuditEventType.SERVICE_ACCESS,
            region=region,
            service_name=service_name,
            operation=operation,
            status=status,
            message=message or f"Service access: {service_name} in {region}"
        )
    
    def log_error_recovery(self, error_id: str, recovery_strategy: str,
                          success: bool, details: Dict[str, Any]) -> str:
        """Log error recovery attempt.
        
        Args:
            error_id: Original error ID
            recovery_strategy: Recovery strategy used
            success: Whether recovery was successful
            details: Recovery details
            
        Returns:
            Event ID
        """
        return self.log_event(
            event_type=AuditEventType.ERROR_RECOVERY,
            status="SUCCESS" if success else "FAILURE",
            message=f"Error recovery {'succeeded' if success else 'failed'}: {recovery_strategy}",
            details=details,
            error_id=error_id
        )
    
    def _write_event_to_file(self, event: AuditEvent):
        """Write audit event to file.
        
        Args:
            event: Audit event to write
        """
        try:
            with open(self.audit_file_path, 'a', encoding='utf-8') as f:
                json.dump(event.to_dict(), f, ensure_ascii=False)
                f.write('\n')
        except Exception as e:
            logger.warning(f"Failed to write audit event to file: {e}")
    
    def _log_event_to_console(self, event: AuditEvent):
        """Log audit event to console.
        
        Args:
            event: Audit event to log
        """
        log_message = f"[AUDIT] {event.event_type.value}: {event.message}"
        
        if event.service_name:
            log_message += f" (Service: {event.service_name}"
            if event.region:
                log_message += f", Region: {event.region}"
            log_message += ")"
        
        if event.status == "FAILURE":
            logger.error(log_message)
        elif event.status == "WARNING":
            logger.warning(log_message)
        else:
            logger.info(log_message)
    
    def _rotate_audit_file_if_needed(self):
        """Rotate audit file if it exceeds maximum size."""
        try:
            if not self.audit_file_path.exists():
                return
            
            file_size_mb = self.audit_file_path.stat().st_size / (1024 * 1024)
            
            if file_size_mb > self.max_file_size_mb:
                # Create rotated filename with timestamp
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                rotated_path = self.audit_file_path.with_suffix(f".{timestamp}.jsonl")
                
                # Move current file to rotated name
                self.audit_file_path.rename(rotated_path)
                
                logger.info(f"Rotated audit file: {rotated_path}")
                
        except Exception as e:
            logger.warning(f"Failed to rotate audit file: {e}")
    
    def _cleanup_old_audit_files(self):
        """Clean up audit files older than retention period."""
        try:
            cutoff_date = datetime.now() - timedelta(days=self.retention_days)
            audit_dir = self.audit_file_path.parent
            
            for file_path in audit_dir.glob("*.jsonl"):
                if file_path == self.audit_file_path:
                    continue  # Skip current audit file
                
                try:
                    file_mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
                    if file_mtime < cutoff_date:
                        file_path.unlink()
                        logger.info(f"Deleted old audit file: {file_path}")
                except Exception as e:
                    logger.warning(f"Failed to delete old audit file {file_path}: {e}")
                    
        except Exception as e:
            logger.warning(f"Failed to cleanup old audit files: {e}")
    
    def get_session_summary(self) -> Dict[str, Any]:
        """Get summary of current session events.
        
        Returns:
            Dictionary with session summary
        """
        if not self.session_events:
            return {"total_events": 0}
        
        # Count events by type and status
        event_type_counts = {}
        status_counts = {}
        
        for event in self.session_events:
            event_type_counts[event.event_type.value] = event_type_counts.get(event.event_type.value, 0) + 1
            status_counts[event.status] = status_counts.get(event.status, 0) + 1
        
        # Calculate session duration
        session_duration = datetime.now() - self.session_start_time
        
        return {
            "total_events": len(self.session_events),
            "session_duration_seconds": int(session_duration.total_seconds()),
            "events_by_type": event_type_counts,
            "events_by_status": status_counts,
            "first_event": self.session_events[0].timestamp.isoformat(),
            "last_event": self.session_events[-1].timestamp.isoformat()
        }
    
    def query_events(self, event_type: Optional[AuditEventType] = None,
                    status: Optional[str] = None,
                    service_name: Optional[str] = None,
                    start_time: Optional[datetime] = None,
                    end_time: Optional[datetime] = None,
                    limit: int = 100) -> List[AuditEvent]:
        """Query audit events with filters.
        
        Args:
            event_type: Filter by event type
            status: Filter by status
            service_name: Filter by service name
            start_time: Filter events after this time
            end_time: Filter events before this time
            limit: Maximum number of events to return
            
        Returns:
            List of matching audit events
        """
        filtered_events = []
        
        for event in reversed(self.session_events):  # Most recent first
            # Apply filters
            if event_type and event.event_type != event_type:
                continue
            if status and event.status != status:
                continue
            if service_name and event.service_name != service_name:
                continue
            if start_time and event.timestamp < start_time:
                continue
            if end_time and event.timestamp > end_time:
                continue
            
            filtered_events.append(event)
            
            if len(filtered_events) >= limit:
                break
        
        return filtered_events
    
    def export_session_events(self, output_path: str, format: str = "json") -> bool:
        """Export session events to file.
        
        Args:
            output_path: Output file path
            format: Export format ("json" or "csv")
            
        Returns:
            True if export successful, False otherwise
        """
        try:
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            if format.lower() == "json":
                with open(output_file, 'w', encoding='utf-8') as f:
                    events_data = [event.to_dict() for event in self.session_events]
                    json.dump(events_data, f, indent=2, ensure_ascii=False)
            
            elif format.lower() == "csv":
                import csv
                
                with open(output_file, 'w', newline='', encoding='utf-8') as f:
                    if not self.session_events:
                        return True
                    
                    fieldnames = ['event_id', 'timestamp', 'event_type', 'user_id', 
                                'account_id', 'region', 'service_name', 'operation',
                                'status', 'message', 'duration_ms', 'error_id']
                    
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    
                    for event in self.session_events:
                        row = event.to_dict()
                        # Remove complex details for CSV
                        row.pop('details', None)
                        writer.writerow(row)
            
            else:
                logger.error(f"Unsupported export format: {format}")
                return False
            
            logger.info(f"Exported {len(self.session_events)} events to {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export session events: {e}")
            return False
    
    def clear_session_events(self):
        """Clear current session events from memory."""
        self.session_events.clear()
        self.session_start_time = datetime.now()
        logger.info("Session events cleared")