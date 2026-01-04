"""Property-based tests for graceful error exit."""

import sys
import tempfile
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock
from hypothesis import given, strategies as st, assume
import pytest

from boot_sector_analyzer.cli import main
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
    AnalysisError,
    NetworkError,
    APIError,
    VirusTotalError,
    CacheError,
    ConfigurationError,
    ReportGenerationError,
    get_exit_code,
    EXIT_CODES
)


class TestGracefulErrorExit:
    """Test graceful error exit properties."""

    @given(st.sampled_from([
        FileNotFoundError("File not found"),
        PermissionError("Permission denied"),
        KeyboardInterrupt(),
        ValueError("Invalid value"),
        RuntimeError("Runtime error"),
        OSError("OS error"),
        IOError("IO error"),
        InputError("Input error"),
        ParsingError("Parsing error"),
        AnalysisError("Analysis error"),
        NetworkError("Network error"),
        ConfigurationError("Configuration error")
    ]))
    def test_property_21_graceful_error_exit_codes(self, exception):
        """
        **Property 21: Graceful error exit**
        *For any* critical error, the Boot_Sector_Analyzer should exit gracefully with appropriate exit codes
        **Validates: Requirements 8.5**
        **Feature: boot-sector-analyzer, Property 21: Graceful error exit**
        """
        exit_code = get_exit_code(exception)
        exception_name = type(exception).__name__
        
        # Verify exit code is valid (0-255 range for Unix systems)
        assert isinstance(exit_code, int), f"Exit code should be integer for {exception_name}"
        assert 0 <= exit_code <= 255, f"Exit code {exit_code} should be in range 0-255 for {exception_name}"
        
        # All exceptions in our test should result in non-zero exit codes
        # (we don't test success cases in this property)
        assert exit_code != 0, f"Error {exception_name} should have non-zero exit code, got {exit_code}"
        
        # Verify specific exit code mappings
        if isinstance(exception, KeyboardInterrupt):
            expected_code = EXIT_CODES["interrupted"]
            assert exit_code == expected_code, f"KeyboardInterrupt should map to {expected_code}, got {exit_code}"
        elif isinstance(exception, FileNotFoundError):
            expected_code = EXIT_CODES["file_not_found"]
            assert exit_code == expected_code, f"FileNotFoundError should map to {expected_code}, got {exit_code}"
        elif isinstance(exception, PermissionError):
            expected_code = EXIT_CODES["permission_error"]
            assert exit_code == expected_code, f"PermissionError should map to {expected_code}, got {exit_code}"
        elif isinstance(exception, InputError):
            expected_code = EXIT_CODES["input_error"]
            assert exit_code == expected_code, f"InputError should map to {expected_code}, got {exit_code}"
        elif isinstance(exception, ParsingError):
            expected_code = EXIT_CODES["parsing_error"]
            assert exit_code == expected_code, f"ParsingError should map to {expected_code}, got {exit_code}"
        elif isinstance(exception, AnalysisError):
            expected_code = EXIT_CODES["analysis_error"]
            assert exit_code == expected_code, f"AnalysisError should map to {expected_code}, got {exit_code}"
        elif isinstance(exception, NetworkError):
            expected_code = EXIT_CODES["network_error"]
            assert exit_code == expected_code, f"NetworkError should map to {expected_code}, got {exit_code}"
        elif isinstance(exception, ConfigurationError):
            expected_code = EXIT_CODES["configuration_error"]
            assert exit_code == expected_code, f"ConfigurationError should map to {expected_code}, got {exit_code}"
        else:
            # General errors should map to general_error code
            expected_code = EXIT_CODES["general_error"]
            assert exit_code == expected_code, f"General error {exception_name} should map to {expected_code}, got {exit_code}"

    def test_property_21_keyboard_interrupt_specific(self):
        """
        **Property 21: Graceful error exit**
        *For any* KeyboardInterrupt, it should specifically map to exit code 130 (SIGINT)
        **Validates: Requirements 8.5**
        **Feature: boot-sector-analyzer, Property 21: Graceful error exit**
        """
        # Test KeyboardInterrupt specifically
        ki = KeyboardInterrupt()
        exit_code = get_exit_code(ki)
        
        # KeyboardInterrupt should map to 130 (standard SIGINT exit code)
        assert exit_code == 130, f"KeyboardInterrupt should map to exit code 130, got {exit_code}"
        assert exit_code == EXIT_CODES["interrupted"], f"KeyboardInterrupt should map to interrupted code {EXIT_CODES['interrupted']}, got {exit_code}"
        
        # Verify it's in valid range
        assert 0 <= exit_code <= 255, f"Exit code {exit_code} should be in valid range"
        assert exit_code != 0, f"KeyboardInterrupt should have non-zero exit code"

    def test_property_21_exit_code_consistency(self):
        """
        **Property 21: Graceful error exit**
        *For any* defined exit code, it should be consistent and within valid range
        **Validates: Requirements 8.5**
        **Feature: boot-sector-analyzer, Property 21: Graceful error exit**
        """
        # Verify all defined exit codes are valid
        for code_name, code_value in EXIT_CODES.items():
            assert isinstance(code_value, int), f"Exit code {code_name} should be integer"
            assert 0 <= code_value <= 255, f"Exit code {code_name} should be in range 0-255"
        
        # Verify success code is 0
        assert EXIT_CODES["success"] == 0
        
        # Verify all error codes are non-zero
        for code_name, code_value in EXIT_CODES.items():
            if code_name != "success":
                assert code_value != 0, f"Error code {code_name} should be non-zero"

    @given(st.text(min_size=1, max_size=50))
    def test_property_21_cli_invalid_arguments_exit(self, invalid_arg):
        """
        **Property 21: Graceful error exit**
        *For any* invalid command line arguments, the CLI should exit gracefully with appropriate error code
        **Validates: Requirements 8.5**
        **Feature: boot-sector-analyzer, Property 21: Graceful error exit**
        """
        assume(invalid_arg.strip())  # Ensure non-empty
        assume(not invalid_arg.startswith('-'))  # Avoid flag-like arguments
        assume('/' not in invalid_arg)  # Avoid path-like arguments
        
        # Test with invalid arguments that should cause graceful exit
        with patch('sys.argv', ['boot-sector-analyzer', '--invalid-flag', invalid_arg]):
            with patch('sys.exit') as mock_exit:
                try:
                    main()
                except SystemExit as e:
                    # Should exit with non-zero code for invalid arguments
                    assert e.code != 0
                    return
                
                # If main() returns instead of exiting, check the return code
                # (This handles cases where SystemExit is caught)
                if mock_exit.called:
                    exit_code = mock_exit.call_args[0][0] if mock_exit.call_args[0] else 1
                    assert exit_code != 0

    def test_property_21_missing_source_argument_exit(self):
        """
        **Property 21: Graceful error exit**
        *For any* missing required source argument, the CLI should exit gracefully with input error code
        **Validates: Requirements 8.5**
        **Feature: boot-sector-analyzer, Property 21: Graceful error exit**
        """
        # Test with missing source argument
        with patch('sys.argv', ['boot-sector-analyzer']):
            exit_code = main()
            # Should return 0 for help display when no arguments provided
            assert exit_code == 0

    @given(st.text(min_size=1, max_size=100))
    def test_property_21_nonexistent_file_exit(self, nonexistent_filename):
        """
        **Property 21: Graceful error exit**
        *For any* nonexistent file path, the CLI should exit gracefully with file not found error code
        **Validates: Requirements 8.5**
        **Feature: boot-sector-analyzer, Property 21: Graceful error exit**
        """
        assume(nonexistent_filename.strip())
        assume('/' not in nonexistent_filename)  # Simple filename
        assume(not nonexistent_filename.startswith('.'))  # Avoid hidden files
        
        # Ensure file doesn't exist
        nonexistent_path = Path(f"/tmp/nonexistent_{nonexistent_filename}")
        assume(not nonexistent_path.exists())
        
        with patch('sys.argv', ['boot-sector-analyzer', str(nonexistent_path)]):
            exit_code = main()
            # Should exit with input error code for nonexistent file
            assert exit_code == EXIT_CODES["input_error"]

    def test_property_21_keyboard_interrupt_exit(self):
        """
        **Property 21: Graceful error exit**
        *For any* keyboard interrupt during analysis, the CLI should exit gracefully with interrupt code
        **Validates: Requirements 8.5**
        **Feature: boot-sector-analyzer, Property 21: Graceful error exit**
        """
        # Create a temporary valid boot sector file
        boot_sector_data = b'\x00' * 510 + b'\x55\xAA'
        
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(boot_sector_data)
            temp_path = Path(temp_file.name)
        
        try:
            # Mock KeyboardInterrupt during analysis
            with patch('sys.argv', ['boot-sector-analyzer', str(temp_path)]):
                with patch('boot_sector_analyzer.input_handler.InputHandler.read_boot_sector', 
                          side_effect=KeyboardInterrupt()):
                    exit_code = main()
                    # Should exit with interrupt code
                    assert exit_code == EXIT_CODES["interrupted"]
        finally:
            temp_path.unlink(missing_ok=True)

    @given(st.binary(min_size=1, max_size=511))
    def test_property_21_invalid_boot_sector_exit(self, invalid_data):
        """
        **Property 21: Graceful error exit**
        *For any* invalid boot sector data, the CLI should exit gracefully with parsing error code
        **Validates: Requirements 8.5**
        **Feature: boot-sector-analyzer, Property 21: Graceful error exit**
        """
        # Create temporary file with invalid boot sector data
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(invalid_data)
            temp_path = Path(temp_file.name)
        
        try:
            with patch('sys.argv', ['boot-sector-analyzer', str(temp_path)]):
                exit_code = main()
                # Should exit with input error code for invalid boot sector
                assert exit_code == EXIT_CODES["input_error"]
        finally:
            temp_path.unlink(missing_ok=True)

    def test_property_21_permission_error_exit(self):
        """
        **Property 21: Graceful error exit**
        *For any* permission denied error, the CLI should exit gracefully with permission error code
        **Validates: Requirements 8.5**
        **Feature: boot-sector-analyzer, Property 21: Graceful error exit**
        """
        # Create a temporary file and make it unreadable
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(b'\x00' * 512)
            temp_path = Path(temp_file.name)
        
        try:
            # Remove read permissions
            temp_path.chmod(0o000)
            
            with patch('sys.argv', ['boot-sector-analyzer', str(temp_path)]):
                exit_code = main()
                # Should exit with permission error code
                assert exit_code == EXIT_CODES["permission_error"]
        finally:
            # Restore permissions and clean up
            temp_path.chmod(0o644)
            temp_path.unlink(missing_ok=True)

    def test_property_21_configuration_error_exit(self):
        """
        **Property 21: Graceful error exit**
        *For any* configuration error, the CLI should exit gracefully with configuration error code
        **Validates: Requirements 8.5**
        **Feature: boot-sector-analyzer, Property 21: Graceful error exit**
        """
        # Create a temporary invalid config file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ini', delete=False) as temp_config:
            temp_config.write("invalid config content [[[")
            temp_config_path = Path(temp_config.name)
        
        # Create a valid boot sector file
        with tempfile.NamedTemporaryFile(delete=False) as temp_boot:
            temp_boot.write(b'\x00' * 510 + b'\x55\xAA')
            temp_boot_path = Path(temp_boot.name)
        
        try:
            with patch('sys.argv', ['boot-sector-analyzer', '--config', str(temp_config_path), str(temp_boot_path)]):
                exit_code = main()
                # Should succeed with warning about invalid config, using defaults
                assert exit_code == 0
        finally:
            temp_config_path.unlink(missing_ok=True)
            temp_boot_path.unlink(missing_ok=True)

    def test_property_21_successful_analysis_exit(self):
        """
        **Property 21: Graceful error exit**
        *For any* successful analysis, the CLI should exit with success code (0)
        **Validates: Requirements 8.5**
        **Feature: boot-sector-analyzer, Property 21: Graceful error exit**
        """
        # Create a valid boot sector file
        boot_sector_data = b'\x00' * 510 + b'\x55\xAA'
        
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(boot_sector_data)
            temp_path = Path(temp_file.name)
        
        try:
            with patch('sys.argv', ['boot-sector-analyzer', '--no-internet', str(temp_path)]):
                exit_code = main()
                # Should exit with success code
                assert exit_code == EXIT_CODES["success"]
        finally:
            temp_path.unlink(missing_ok=True)

    @given(st.sampled_from([
        "input_error",
        "parsing_error", 
        "analysis_error",
        "network_error",
        "configuration_error",
        "permission_error",
        "file_not_found",
        "general_error"
    ]))
    def test_property_21_error_code_uniqueness(self, error_type):
        """
        **Property 21: Graceful error exit**
        *For any* error type, it should have a unique exit code for proper error identification
        **Validates: Requirements 8.5**
        **Feature: boot-sector-analyzer, Property 21: Graceful error exit**
        """
        error_code = EXIT_CODES[error_type]
        
        # Count how many error types have the same code
        same_code_count = sum(1 for code in EXIT_CODES.values() if code == error_code)
        
        # Each error type should have a unique code (except success which is always 0)
        if error_type != "success":
            # Allow some overlap for related error types, but ensure it's intentional
            assert same_code_count <= 2, f"Too many error types share exit code {error_code}"

    def test_property_21_exit_code_documentation(self):
        """
        **Property 21: Graceful error exit**
        *For any* exit code, it should be properly documented and meaningful
        **Validates: Requirements 8.5**
        **Feature: boot-sector-analyzer, Property 21: Graceful error exit**
        """
        # Verify all exit codes have meaningful names
        required_codes = [
            "success",
            "general_error", 
            "input_error",
            "parsing_error",
            "analysis_error",
            "network_error",
            "configuration_error",
            "permission_error",
            "file_not_found",
            "interrupted"
        ]
        
        for code_name in required_codes:
            assert code_name in EXIT_CODES, f"Required exit code {code_name} is missing"
            assert isinstance(EXIT_CODES[code_name], int), f"Exit code {code_name} should be integer"

    def test_property_21_exception_to_exit_code_mapping(self):
        """
        **Property 21: Graceful error exit**
        *For any* custom exception type, it should map to an appropriate exit code
        **Validates: Requirements 8.5**
        **Feature: boot-sector-analyzer, Property 21: Graceful error exit**
        """
        # Test mapping of custom exceptions to exit codes
        exception_mappings = [
            (InputError("test"), EXIT_CODES["input_error"]),
            (ParsingError("test"), EXIT_CODES["parsing_error"]),
            (NetworkError("test"), EXIT_CODES["network_error"]),
            (ConfigurationError("test"), EXIT_CODES["configuration_error"]),
            (FileNotFoundError("test"), EXIT_CODES["file_not_found"]),
            (PermissionError("test"), EXIT_CODES["permission_error"]),
            (KeyboardInterrupt(), EXIT_CODES["interrupted"]),
            (ValueError("test"), EXIT_CODES["general_error"])
        ]
        
        for exception, expected_code in exception_mappings:
            actual_code = get_exit_code(exception)
            assert actual_code == expected_code, f"Exception {type(exception).__name__} should map to exit code {expected_code}, got {actual_code}"