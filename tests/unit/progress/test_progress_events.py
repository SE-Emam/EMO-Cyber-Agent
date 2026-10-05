"""Test Progress Event functionality for EMO-Cyber-Agent."""

import pytest
from datetime import datetime
from pathlib import Path

# Add the parent directory to the path to import from emo_cyber_agent
import sys
import os

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent.parent / "src"))

from emo_cyber_agent.progress.events import ProgressEvent, ProgressEventType

class TestProgressEvent:
    """Test Progress Event class functionality."""

    def test_progress_event_creation(self):
        """Test basic ProgressEvent creation."""
        event = ProgressEvent(
            run_id="run-123",
            audit_id="audit-456",
            phase="INITIALIZING",
            phase_index=0,
            phase_count=8,
            completed=1,
            total=8,
            percent=12.5,
            status="INITIALIZING",
            message_code="PHASE_STARTED"
        )

        assert event.run_id == "run-123"
        assert event.audit_id == "audit-456"
        assert event.phase == "INITIALIZING"
        assert event.phase_index == 0
        assert event.phase_count == 8
        assert event.completed == 1
        assert event.total == 8
        assert event.percent == 12.5
        assert event.status == "INITIALIZING"
        assert event.message_code == "PHASE_STARTED"
        assert event.event_type == ProgressEventType.PROGRESS
        assert isinstance(event.timestamp, datetime)

    def test_progress_event_minimal(self):
        """Test ProgressEvent creation with minimal required fields."""
        event = ProgressEvent(
            run_id="run-789",
            audit_id="audit-012",
            phase="PLANNING",
            phase_index=0,
            phase_count=6,
            completed=0,
            total=6,
            percent=0.0,
            status="PLANNING",
            message_code="PHASE_STARTED"
        )

        assert event.run_id == "run-789"
        assert event.audit_id == "audit-012"
        assert event.phase == "PLANNING"
        assert event.completed == 0

    def test_progress_event_error_type(self):
        """Test ProgressEvent with error event type."""
        event = ProgressEvent(
            run_id="run-123",
            audit_id="audit-456",
            phase="VERIFYING",
            phase_index=4,
            phase_count=8,
            completed=4,
            total=8,
            percent=50.0,
            status="FAILED",
            message_code="VERIFICATION_FAILED",
            event_type=ProgressEventType.ERROR
        )

        assert event.event_type == ProgressEventType.ERROR
        assert event.status == "FAILED"

    def test_progress_event_to_dict(self):
        """Test ProgressEvent.to_dict() method."""
        event = ProgressEvent(
            run_id="run-123",
            audit_id="audit-456",
            phase="CODE_INTELLIGENCE",
            phase_index=2,
            phase_count=8,
            completed=3,
            total=8,
            percent=37.5,
            status="CODE_INTELLIGENCE",
            message_code="PHASE_STARTED"
        )

        event_dict = event.to_dict()

        assert event_dict["run_id"] == "run-123"
        assert event_dict["audit_id"] == "audit-456"
        assert event_dict["phase"] == "CODE_INTELLIGENCE"
        assert event_dict["phase_index"] == 2
        assert event_dict["phase_count"] == 8
        assert event_dict["completed"] == 3
        assert event_dict["total"] == 8
        assert event_dict["percent"] == 37.5
        assert event_dict["status"] == "CODE_INTELLIGENCE"
        assert event_dict["message_code"] == "PHASE_STARTED"
        assert "timestamp" in event_dict
        assert "event_type" in event_dict

    def test_progress_event_from_dict(self):
        """Test ProgressEvent.from_dict() method."""
        event_dict = {
            "run_id": "run-123",
            "audit_id": "audit-456",
            "phase": "CODE_INTELLIGENCE",
            "phase_index": 2,
            "phase_count": 8,
            "completed": 3,
            "total": 8,
            "percent": 37.5,
            "status": "CODE_INTELLIGENCE",
            "message_code": "PHASE_STARTED",
            "timestamp": "2025-01-01T12:00:00",
            "event_type": "PROGRESS"
        }

        event = ProgressEvent.from_dict(event_dict)

        assert event.run_id == "run-123"
        assert event.audit_id == "audit-456"
        assert event.phase == "CODE_INTELLIGENCE"
        assert event.phase_index == 2
        assert event.phase_count == 8
        assert event.completed == 3
        assert event.total == 8
        assert event.percent == 37.5
        assert event.status == "CODE_INTELLIGENCE"
        assert event.message_code == "PHASE_STARTED"
        assert event.event_type == ProgressEventType.PROGRESS
        assert isinstance(event.timestamp, datetime)

    def test_progress_event_equality(self):
        """Test ProgressEvent equality and inequality."""
        event1 = ProgressEvent(
            run_id="run-123",
            audit_id="audit-456",
            phase="INITIALIZING",
            phase_index=0,
            phase_count=8,
            completed=1,
            total=8,
            percent=12.5,
            status="INITIALIZING",
            message_code="PHASE_STARTED"
        )

        event2 = ProgressEvent(
            run_id="run-123",
            audit_id="audit-456",
            phase="INITIALIZING",
            phase_index=0,
            phase_count=8,
            completed=1,
            total=8,
            percent=12.5,
            status="INITIALIZING",
            message_code="PHASE_STARTED"
        )

        # Same events should be equal
        assert event1 == event2

        event3 = ProgressEvent(
            run_id="run-456",
            audit_id="audit-789",
            phase="PLANNING",
            phase_index=0,
            phase_count=6,
            completed=0,
            total=6,
            percent=0.0,
            status="PLANNING",
            message_code="PHASE_STARTED"
        )

        # Different events should not be equal
        assert event1 != event3

    def test_progress_event_validation(self):
        """Test ProgressEvent validation with invalid data."""
        # Test invalid run_id
        with pytest.raises(ValueError):
            ProgressEvent(
                run_id="",
                audit_id="audit-456",
                phase="INITIALIZING",
                phase_index=0,
                phase_count=8,
                completed=1,
                total=8,
                percent=12.5,
                status="INITIALIZING",
                message_code="PHASE_STARTED"
            )

        # Test invalid phase_count
        with pytest.raises(ValueError):
            ProgressEvent(
                run_id="run-123",
                audit_id="audit-456",
                phase="INITIALIZING",
                phase_index=0,
                phase_count=0,
                completed=1,
                total=8,
                percent=12.5,
                status="INITIALIZING",
                message_code="PHASE_STARTED"
            )

        # Test invalid completed (greater than total)
        with pytest.raises(ValueError):
            ProgressEvent(
                run_id="run-123",
                audit_id="audit-456",
                phase="INITIALIZING",
                phase_index=0,
                phase_count=8,
                completed=10,
                total=8,
                percent=125.0,
                status="INITIALIZING",
                message_code="PHASE_STARTED"
            )

        # Test invalid percent
        with pytest.raises(ValueError):
            ProgressEvent(
                run_id="run-123",
                audit_id="audit-456",
                phase="INITIALIZING",
                phase_index=0,
                phase_count=8,
                completed=1,
                total=8,
                percent=150.0,
                status="INITIALIZING",
                message_code="PHASE_STARTED"
            )

    def test_progress_event_string_representation(self):
        """Test ProgressEvent string representation."""
        event = ProgressEvent(
            run_id="run-123",
            audit_id="audit-456",
            phase="CODE_INTELLIGENCE",
            phase_index=2,
            phase_count=8,
            completed=3,
            total=8,
            percent=37.5,
            status="CODE_INTELLIGENCE",
            message_code="PHASE_STARTED"
        )

        event_str = repr(event)
        assert "ProgressEvent" in event_str
        assert "run-123" in event_str
        assert "CODE_INTELLIGENCE" in event_str

    def test_progress_event_dict_roundtrip(self):
        """Test ProgressEvent roundtrip conversion."""
        original_event = ProgressEvent(
            run_id="run-123",
            audit_id="audit-456",
            phase="CODE_INTELLIGENCE",
            phase_index=2,
            phase_count=8,
            completed=3,
            total=8,
            percent=37.5,
            status="CODE_INTELLIGENCE",
            message_code="PHASE_STARTED"
        )

        # Convert to dict
        event_dict = original_event.to_dict()

        # Convert back to ProgressEvent
        restored_event = ProgressEvent.from_dict(event_dict)

        # Verify equality
        assert original_event == restored_event
        assert original_event.run_id == restored_event.run_id
        assert original_event.audit_id == restored_event.audit_id
        assert original_event.phase == restored_event.phase
        assert original_event.phase_index == restored_event.phase_index

    def test_progress_event_custom_timestamp(self):
        """Test ProgressEvent with custom timestamp."""
        custom_time = datetime(2025, 1, 1, 12, 0, 0)
        event = ProgressEvent(
            run_id="run-123",
            audit_id="audit-456",
            phase="INITIALIZING",
            phase_index=0,
            phase_count=8,
            completed=1,
            total=8,
            percent=12.5,
            status="INITIALIZING",
            message_code="PHASE_STARTED",
            timestamp=custom_time
        )

        assert event.timestamp == custom_time

    def test_progress_event_default_timestamp(self):
        """Test ProgressEvent with default timestamp."""
        event = ProgressEvent(
            run_id="run-123",
            audit_id="audit-456",
            phase="INITIALIZING",
            phase_index=0,
            phase_count=8,
            completed=1,
            total=8,
            percent=12.5,
            status="INITIALIZING",
            message_code="PHASE_STARTED"
        )

        # Timestamp should be set to now
        assert isinstance(event.timestamp, datetime)


class TestProgressEventIntegration:
    """Test ProgressEvent integration scenarios."""

    def test_progress_event_in_cli_simulation(self):
        """Test ProgressEvent in CLI simulation."""
        events = [
            ProgressEvent(
                run_id="run-123",
                audit_id="audit-456",
                phase="INITIALIZING",
                phase_index=0,
                phase_count=8,
                completed=1,
                total=8,
                percent=12.5,
                status="INITIALIZING",
                message_code="PHASE_STARTED"
            ),
            ProgressEvent(
                run_id="run-123",
                audit_id="audit-456",
                phase="PLANNING",
                phase_index=1,
                phase_count=8,
                completed=2,
                total=8,
                percent=25.0,
                status="PLANNING",
                message_code="PHASE_STARTED"
            ),
            ProgressEvent(
                run_id="run-123",
                audit_id="audit-456",
                phase="CODE_INTELLIGENCE",
                phase_index=2,
                phase_count=8,
                completed=4,
                total=8,
                percent=50.0,
                status="CODE_INTELLIGENCE",
                message_code="PHASE_STARTED"
            ),
        ]

        # Verify events can be processed in order
        assert len(events) == 3
        assert events[0].phase == "INITIALIZING"
        assert events[1].phase == "PLANNING"
        assert events[2].phase == "CODE_INTELLIGENCE"

        # Verify progress percentage increases
        assert events[0].percent == 12.5
        assert events[1].percent == 25.0
        assert events[2].percent == 50.0

    def test_progress_event_error_handling(self):
        """Test ProgressEvent error handling."""
        # Create an error event
        error_event = ProgressEvent(
            run_id="run-123",
            audit_id="audit-456",
            phase="VERIFYING",
            phase_index=4,
            phase_count=8,
            completed=4,
            total=8,
            percent=50.0,
            status="FAILED",
            message_code="VERIFICATION_FAILED",
            event_type=ProgressEventType.ERROR
        )

        # Verify error event properties
        assert error_event.event_type == ProgressEventType.ERROR
        assert error_event.status == "FAILED"
        assert error_event.message_code == "VERIFICATION_FAILED"

    def test_progress_event_terminal_states(self):
        """Test ProgressEvent terminal states."""
        terminal_events = [
            ProgressEvent(
                run_id="run-123",
                audit_id="audit-456",
                phase="COMPLETED",
                phase_index=7,
                phase_count=8,
                completed=8,
                total=8,
                percent=100.0,
                status="COMPLETED",
                message_code="OPERATION_COMPLETE"
            ),
            ProgressEvent(
                run_id="run-123",
                audit_id="audit-456",
                phase="FAILED",
                phase_index=4,
                phase_count=8,
                completed=4,
                total=8,
                percent=50.0,
                status="FAILED",
                message_code="OPERATION_FAILED",
                event_type=ProgressEventType.ERROR
            ),
            ProgressEvent(
                run_id="run-123",
                audit_id="audit-456",
                phase="CANCELLED",
                phase_index=3,
                phase_count=8,
                completed=3,
                total=8,
                percent=37.5,
                status="CANCELLED",
                message_code="OPERATION_CANCELLED"
            ),
        ]

        # Verify terminal events
        for event in terminal_events:
            assert event.event_type in [ProgressEventType.PROGRESS, ProgressEventType.ERROR]
            assert event.phase in ["COMPLETED", "FAILED", "CANCELLED"]

    def test_progress_event_serialization_roundtrip_integration(self):
        """Test ProgressEvent serialization in an integration scenario."""
        # Create multiple events
        events = [
            ProgressEvent(
                run_id="run-123",
                audit_id="audit-456",
                phase="INITIALIZING",
                phase_index=0,
                phase_count=8,
                completed=1,
                total=8,
                percent=12.5,
                status="INITIALIZING",
                message_code="PHASE_STARTED"
            ),
            ProgressEvent(
                run_id="run-123",
                audit_id="audit-456",
                phase="CODE_INTELLIGENCE",
                phase_index=2,
                phase_count=8,
                completed=4,
                total=8,
                percent=50.0,
                status="CODE_INTELLIGENCE",
                message_code="PHASE_STARTED"
            ),
            ProgressEvent(
                run_id="run-123",
                audit_id="audit-456",
                phase="COMPLETED",
                phase_index=7,
                phase_count=8,
                completed=8,
                total=8,
                percent=100.0,
                status="COMPLETED",
                message_code="OPERATION_COMPLETE"
            ),
        ]

        # Serialize all events
        event_dicts = [event.to_dict() for event in events]

        # Deserialize all events
        restored_events = [ProgressEvent.from_dict(ed) for ed in event_dicts]

        # Verify roundtrip
        assert len(events) == len(restored_events)

        for original, restored in zip(events, restored_events):
            assert original == restored
            assert original.run_id == restored.run_id
            assert original.audit_id == restored.audit_id
            assert original.phase == restored.phase
            assert original.phase_index == restored.phase_index
            assert original.phase_count == restored.phase_count
            assert original.completed == restored.completed
            assert original.total == restored.total
            assert original.percent == restored.percent
            assert original.status == restored.status
            assert original.message_code == restored.message_code
            assert original.event_type == restored.event_type
            assert original.timestamp == restored.timestamp
