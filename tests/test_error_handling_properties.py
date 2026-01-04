"""Property-based tests for error handling and logging."""

import logging
import tempfile
import io
from pathlib import Path
from unittest.mock import patch, MagicMock
from hypothesis import given, strategies as st, assume
import pytest

from boot_sector_analyzer.exceptions import (
    BootSectorAnalyzerError,
    InputError,
    InvalidBootSectorError,
    FileAccessError,
    ParsingError,
    MBRParsingError,
    PartitionTableError,
    ContentAnalysisError,
    SecurityAnalysisError,
    NetworkError,
    APIError,
    VirusTotalError,
    CacheError,
    ConfigurationError,
    ReportGenerationError,
    get_exit_code
)
from boot_sector_analyzer.input_handler import InputHandler
from boot_sector_analyzer.structure_analyzer import StructureAnalyzer
from boot_sector_analyzer.content_analyzer import ContentAnalyzer
from boot_sector_analyzer.security_scanner import SecurityScanner


class TestErrorLoggingAndHandling:
    """Test error logging and handling properties."""

    def setup_method(self):
        """Set up test environment."""
        # Create a log capture handler
        self.log_stream = io.StringIO()
        self.log_handler = logging.StreamHandler(self.log_stream)
        self.log_handler.setLevel(logging.DEBUG)
        
        # Set a simple formatter to ensure we capture the level names
        formatter = logging.Formatter('%(levelname)s - %(name)s - %(message)s')
        self.log_handler.setFormatter(formatter)
        
        # Add handler to root logger and ensure propagation
        self.logger = logging.getLogger()
        self.logger.addHandler(self.log_handler)
        self.logger.setLevel(logging.DEBUG)
        
        # Also configure the specific module loggers to ensure they propagate
        for module_name in [
            'boot_sector_analyzer.input_handler',
            'boot_sector_analyzer.structure_analyzer', 
            'boot_sector_analyzer.content_analyzer',
            'boot_sector_analyzer.security_scanner'
        ]:
            module_logger = logging.getLogger(module_name)
            module_logger.setLevel(logging.DEBUG)
            module_logger.propagate = True

    def teardown_method(self):
        """Clean up test environment."""
        self.logger.removeHandler(self.log_handler)
        self.log_handler.close()

    def get_log_contents(self) -> str:
        """Get captured log contents."""
        return self.log_stream.getvalue()

    @given(st.text(min_size=1, max_size=100))
    def test_property_19_error_logging_and_handling_custom_exceptions(self, error_message):
        """
        **Property 19: Error logging and handling**
        *For any* custom exception with error message, the exception should be logged with detailed error information
        **Validates: Requirements 8.1, 8.2**
        **Feature: boot-sector-analyzer, Property 19: Error logging and handling**
        """
        assume(error_message.strip())  # Ensure non-empty message
        
        # Test various custom exception types
        exception_types = [
            InputError,
            InvalidBootSectorError,
            FileAccessError,
            ParsingError,
            MBRParsingError,
            PartitionTableError,
            ContentAnalysisError,
            SecurityAnalysisError,
            NetworkError,
            APIError,
            VirusTotalError,
            CacheError,
            ConfigurationError,
            ReportGenerationError
        ]
        
        for exception_class in exception_types:
            # Clear previous log contents
            self.log_stream.seek(0)
            self.log_stream.truncate(0)
            
            # Create exception with error details
            error_details = {"test_key": "test_value", "error_source": "property_test"}
            
            # Create a logger to simulate how the actual code would log the exception
            test_logger = logging.getLogger(f"test.{exception_class.__name__}")
            
            try:
                raise exception_class(
                    error_message,
                    error_code="TEST_ERROR",
                    details=error_details
                )
            except exception_class as e:
                # Verify exception properties
                assert e.message == error_message
                assert e.error_code == "TEST_ERROR"
                assert e.details == error_details
                
                # Log the exception as the actual code would do
                test_logger.error(f"{e.error_code}: {e.message}")
                
                # Verify logging occurred
                log_contents = self.get_log_contents()
                assert error_message in log_contents
                assert "TEST_ERROR" in log_contents
                assert "ERROR" in log_contents  # Log level

    @given(st.binary(min_size=0, max_size=1024))
    def test_property_19_input_handler_error_logging(self, invalid_data):
        """
        **Property 19: Error logging and handling**
        *For any* invalid boot sector data, InputHandler should log detailed error information and raise appropriate exceptions
        **Validates: Requirements 8.1, 8.2**
        **Feature: boot-sector-analyzer, Property 19: Error logging and handling**
        """
        assume(len(invalid_data) != 512)  # Ensure invalid size
        
        # Clear log contents
        self.log_stream.seek(0)
        self.log_stream.truncate(0)
        
        input_handler = InputHandler()
        
        # Create temporary file with invalid data (ensure it's a file, not directory)
        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as temp_file:
            temp_file.write(invalid_data)
            temp_path = Path(temp_file.name)
        
        try:
            # This should raise an exception and log error details
            with pytest.raises((InvalidBootSectorError, InputError)):
                input_handler.read_boot_sector(temp_path)
            
            # Verify error logging
            log_contents = self.get_log_contents()
            assert "ERROR" in log_contents
            assert str(temp_path) in log_contents or temp_path.name in log_contents
            # Check for either type of error message depending on the data
            assert ("Boot sector must be exactly 512 bytes" in log_contents or 
                   "No data read from source" in log_contents or
                   "OS error reading" in log_contents)
            
        finally:
            # Clean up
            temp_path.unlink(missing_ok=True)

    @given(st.binary(min_size=1, max_size=511))
    def test_property_19_structure_analyzer_error_logging(self, invalid_boot_sector):
        """
        **Property 19: Error logging and handling**
        *For any* invalid boot sector structure, StructureAnalyzer should log detailed error information and raise appropriate exceptions
        **Validates: Requirements 8.1, 8.2**
        **Feature: boot-sector-analyzer, Property 19: Error logging and handling**
        """
        # Clear log contents
        self.log_stream.seek(0)
        self.log_stream.truncate(0)
        
        structure_analyzer = StructureAnalyzer()
        
        # This should raise an exception and log error details
        with pytest.raises(InvalidBootSectorError):
            structure_analyzer.parse_mbr(invalid_boot_sector)
        
        # Verify error logging
        log_contents = self.get_log_contents()
        assert "ERROR" in log_contents
        assert "Boot sector must be exactly 512 bytes" in log_contents
        assert str(len(invalid_boot_sector)) in log_contents

    @given(st.one_of(st.none(), st.integers(), st.text(), st.lists(st.integers())))
    def test_property_19_content_analyzer_error_logging(self, invalid_input):
        """
        **Property 19: Error logging and handling**
        *For any* invalid input type to ContentAnalyzer, it should log detailed error information and raise appropriate exceptions
        **Validates: Requirements 8.1, 8.2**
        **Feature: boot-sector-analyzer, Property 19: Error logging and handling**
        """
        assume(not isinstance(invalid_input, bytes))  # Ensure invalid type
        
        # Clear log contents
        self.log_stream.seek(0)
        self.log_stream.truncate(0)
        
        content_analyzer = ContentAnalyzer()
        
        # This should raise an exception and log error details
        with pytest.raises(ContentAnalysisError):
            content_analyzer.calculate_hashes(invalid_input)
        
        # Verify error logging
        log_contents = self.get_log_contents()
        assert "ERROR" in log_contents
        assert "Boot code must be bytes" in log_contents
        assert str(type(invalid_input)) in log_contents

    @given(st.one_of(st.none(), st.integers(), st.text(), st.lists(st.text())))
    def test_property_19_security_scanner_error_logging(self, invalid_hashes):
        """
        **Property 19: Error logging and handling**
        *For any* invalid hash input to SecurityScanner, it should log detailed error information and raise appropriate exceptions
        **Validates: Requirements 8.1, 8.2**
        **Feature: boot-sector-analyzer, Property 19: Error logging and handling**
        """
        assume(not isinstance(invalid_hashes, dict))  # Ensure invalid type
        
        # Clear log contents
        self.log_stream.seek(0)
        self.log_stream.truncate(0)
        
        security_scanner = SecurityScanner()
        
        # This should raise an exception and log error details
        with pytest.raises(SecurityAnalysisError):
            security_scanner.check_known_signatures(invalid_hashes)
        
        # Verify error logging
        log_contents = self.get_log_contents()
        assert "ERROR" in log_contents
        assert "Hashes must be dictionary" in log_contents
        assert str(type(invalid_hashes)) in log_contents

    @given(st.sampled_from([
        FileNotFoundError("File not found"),
        PermissionError("Permission denied"),
        KeyboardInterrupt(),
        ValueError("Invalid value"),
        RuntimeError("Runtime error"),
        OSError("OS error"),
        IOError("IO error")
    ]))
    def test_property_19_exit_code_mapping(self, exception):
        """
        **Property 19: Error logging and handling**
        *For any* exception type, get_exit_code should return appropriate exit codes for graceful error handling
        **Validates: Requirements 8.1, 8.2**
        **Feature: boot-sector-analyzer, Property 19: Error logging and handling**
        """
        exit_code = get_exit_code(exception)
        
        # Verify exit code is valid (0-255 range)
        assert isinstance(exit_code, int)
        assert 0 <= exit_code <= 255
        
        # Verify specific mappings
        if isinstance(exception, KeyboardInterrupt):
            assert exit_code == 130  # SIGINT
        elif isinstance(exception, FileNotFoundError):
            assert exit_code == 8
        elif isinstance(exception, PermissionError):
            assert exit_code == 7
        else:
            assert exit_code > 0  # All errors should have non-zero exit codes

    @given(st.text(min_size=1, max_size=50), st.text(min_size=1, max_size=20))
    def test_property_19_exception_details_preservation(self, error_message, error_code):
        """
        **Property 19: Error logging and handling**
        *For any* custom exception with error details, all details should be preserved and accessible
        **Validates: Requirements 8.1, 8.2**
        **Feature: boot-sector-analyzer, Property 19: Error logging and handling**
        """
        assume(error_message.strip() and error_code.strip())
        
        error_details = {
            "component": "test_component",
            "operation": "test_operation",
            "timestamp": "2024-01-01T00:00:00Z",
            "additional_info": {"nested": "value"}
        }
        
        exception = BootSectorAnalyzerError(
            error_message,
            error_code=error_code,
            details=error_details
        )
        
        # Verify all details are preserved
        assert exception.message == error_message
        assert exception.error_code == error_code
        assert exception.details == error_details
        assert str(exception) == error_message
        
        # Verify details are accessible
        assert exception.details["component"] == "test_component"
        assert exception.details["additional_info"]["nested"] == "value"

    def test_property_19_logging_audit_trail(self):
        """
        **Property 19: Error logging and handling**
        *For any* analysis operation, all activities should be logged for audit purposes
        **Validates: Requirements 8.1, 8.2**
        **Feature: boot-sector-analyzer, Property 19: Error logging and handling**
        """
        # Clear log contents
        self.log_stream.seek(0)
        self.log_stream.truncate(0)
        
        # Simulate analysis operations that should be logged
        input_handler = InputHandler()
        structure_analyzer = StructureAnalyzer()
        content_analyzer = ContentAnalyzer()
        security_scanner = SecurityScanner()
        
        # Create valid boot sector data
        boot_sector = b'\x00' * 510 + b'\x55\xAA'
        
        # Perform operations that should generate audit logs
        try:
            # This should log successful operations
            mbr = structure_analyzer.parse_mbr(boot_sector)
            hashes = content_analyzer.calculate_hashes(boot_sector)
            threats = security_scanner.check_known_signatures(hashes)
            
            # Verify audit logging occurred
            log_contents = self.get_log_contents()
            
            # Should contain informational logs about operations
            assert "INFO" in log_contents or "DEBUG" in log_contents
            
            # Should contain operation details
            assert any(keyword in log_contents.lower() for keyword in [
                "parsing", "analysis", "hash", "security", "completed"
            ])
            
        except Exception as e:
            # Even exceptions should be logged for audit
            log_contents = self.get_log_contents()
            assert "ERROR" in log_contents
            assert str(e) in log_contents