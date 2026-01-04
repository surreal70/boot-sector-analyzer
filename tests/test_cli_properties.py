"""Property-based tests for CLI argument validation."""

import pytest
from hypothesis import given, strategies as st, assume
from pathlib import Path
import tempfile
import os
import sys
from unittest.mock import patch, MagicMock
import argparse
import logging
import io

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent.parent))

from boot_sector_analyzer.cli import create_parser, validate_arguments, setup_logging


class TestCLIArgumentValidation:
    """Property tests for CLI argument validation."""

    @given(
        source=st.one_of(
            st.text(min_size=1, max_size=100).filter(lambda x: not x.isspace()),
            st.just("/dev/sda"),
            st.just("/dev/sdb1"),
        ),
        format_choice=st.sampled_from(["human", "json"]),
        verbose=st.booleans(),
        quiet=st.booleans(),
        log_level=st.sampled_from(["DEBUG", "INFO", "WARNING", "ERROR"]),
        no_internet=st.booleans(),
    )
    def test_property_16_command_line_argument_validation(
        self, source, format_choice, verbose, quiet, log_level, no_internet
    ):
        """
        Property 16: Command line argument validation
        For any set of command line arguments, the Boot_Sector_Analyzer should validate 
        input parameters and display helpful error messages for invalid arguments.
        
        **Validates: Requirements 7.2, 7.5**
        """
        # Don't test with both verbose and quiet (mutually exclusive)
        assume(not (verbose and quiet))
        
        parser = create_parser()
        
        # Build argument list
        args_list = [source]
        
        if format_choice:
            args_list.extend(["-f", format_choice])
            
        if verbose:
            args_list.append("-v")
        elif quiet:
            args_list.append("-q")
            
        args_list.extend(["--log-level", log_level])
        
        if no_internet:
            args_list.append("--no-internet")
        
        try:
            # Parse arguments
            args = parser.parse_args(args_list)
            
            # Validate that parsed arguments have expected values
            assert args.source == source
            assert args.format == format_choice
            assert args.verbose == verbose
            assert args.quiet == quiet
            assert args.log_level == log_level
            assert args.no_internet == no_internet
            
            # Test validation function
            # For valid device paths or when we can't check existence, validation should work
            if source.startswith("/dev/") or source == "test_file.img":
                # Create a temporary file for testing if it's not a device path
                if not source.startswith("/dev/"):
                    with tempfile.NamedTemporaryFile(delete=False, suffix=".img") as tmp:
                        tmp.write(b"x" * 512)  # Write 512 bytes
                        args.source = tmp.name
                        
                    try:
                        # Should validate successfully for existing files
                        result = validate_arguments(args)
                        assert result == 0
                    finally:
                        # Clean up
                        os.unlink(tmp.name)
                else:
                    # For device paths, validation should handle them appropriately
                    result = validate_arguments(args)
                    assert result == 0
            
        except SystemExit:
            # argparse raises SystemExit on invalid arguments - this is expected behavior
            # The property is that invalid arguments are handled gracefully
            pass

    @given(
        invalid_format=st.text().filter(lambda x: x not in ["human", "json"] and x.strip()),
        invalid_log_level=st.text().filter(
            lambda x: x not in ["DEBUG", "INFO", "WARNING", "ERROR"] and x.strip()
        ),
    )
    def test_property_16_invalid_argument_handling(self, invalid_format, invalid_log_level):
        """
        Property 16: Invalid argument handling
        For any invalid command line arguments, the system should handle them gracefully
        and provide helpful error messages.
        
        **Validates: Requirements 7.2, 7.5**
        """
        parser = create_parser()
        
        # Test invalid format
        with pytest.raises(SystemExit):
            parser.parse_args(["test.img", "-f", invalid_format])
        
        # Test invalid log level
        with pytest.raises(SystemExit):
            parser.parse_args(["test.img", "--log-level", invalid_log_level])

    @given(
        source=st.text(min_size=1, max_size=50).filter(
            lambda x: not x.isspace() 
            and not x.startswith("/dev/") 
            and not x.startswith("-")
            and "/" not in x  # Avoid complex paths that might exist
        )
    )
    def test_property_16_nonexistent_file_validation(self, source):
        """
        Property 16: Nonexistent file validation
        For any nonexistent file path, validation should fail with helpful error message.
        
        **Validates: Requirements 7.2, 7.5**
        """
        # Ensure the file doesn't exist and add a unique suffix to make it very unlikely to exist
        test_source = f"nonexistent_{source}.img"
        assume(not Path(test_source).exists())
        
        parser = create_parser()
        args = parser.parse_args([test_source])
        
        # Validation should fail for nonexistent files
        with patch('sys.stderr'):  # Suppress error output during testing
            result = validate_arguments(args)
            assert result != 0

    def test_property_16_help_display(self):
        """
        Property 16: Help display
        The system should display help information when requested.
        
        **Validates: Requirements 7.1, 7.5**
        """
        parser = create_parser()
        
        # Test that help can be generated without errors
        help_text = parser.format_help()
        assert isinstance(help_text, str)
        assert len(help_text) > 0
        assert "boot-sector-analyzer" in help_text
        assert "Boot sector source" in help_text

    @given(
        config_content=st.text(max_size=1000),
    )
    def test_property_16_config_file_validation(self, config_content):
        """
        Property 16: Configuration file validation
        For any configuration file path, the system should validate it appropriately.
        
        **Validates: Requirements 7.6**
        """
        parser = create_parser()
        
        # Create a temporary config file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ini', delete=False) as tmp:
            tmp.write(config_content)
            config_path = tmp.name
        
        try:
            # Test with existing config file
            args = parser.parse_args(["test.img", "--config", config_path])
            
            # Validation should handle config file appropriately
            # (The actual config parsing is tested elsewhere)
            assert args.config == Path(config_path)
            
        finally:
            # Clean up
            os.unlink(config_path)
        
        # Test with nonexistent config file
        nonexistent_config = "/nonexistent/config.ini"
        args = parser.parse_args(["test.img", "--config", nonexistent_config])
        
        with patch('sys.stderr'):  # Suppress error output during testing
            result = validate_arguments(args)
            # Should fail validation for nonexistent config file
            assert result != 0


class TestCLIOutputModeSupport:
    """Property tests for CLI output mode support."""

    @given(
        log_level=st.sampled_from(["DEBUG", "INFO", "WARNING", "ERROR"]),
        verbose=st.booleans(),
        quiet=st.booleans(),
    )
    def test_property_17_output_mode_support(self, log_level, verbose, quiet):
        """
        Property 17: Output mode support
        For any analysis operation, the Boot_Sector_Analyzer should support both verbose 
        and quiet output modes with appropriate detail levels.
        
        **Validates: Requirements 7.3, 7.4**
        """
        # Don't test with both verbose and quiet (mutually exclusive)
        assume(not (verbose and quiet))
        
        # Capture logging output
        log_stream = io.StringIO()
        
        # Set up logging with the specified parameters
        with patch('logging.StreamHandler') as mock_handler, \
             patch('logging.Formatter') as mock_formatter:
            
            mock_handler_instance = MagicMock()
            mock_handler.return_value = mock_handler_instance
            
            # Set up the level attribute to return the expected level
            expected_level = logging.WARNING if quiet else (
                logging.DEBUG if verbose else getattr(logging, log_level.upper())
            )
            mock_handler_instance.level = expected_level
            
            setup_logging(log_level, quiet, verbose)
            
            # Verify that StreamHandler was created
            assert mock_handler.called
            
            # Check that the correct logging level was set on the handler
            mock_handler_instance.setLevel.assert_called_with(expected_level)
            
            # Check that formatter was created
            assert mock_formatter.called
            formatter_call_args = mock_formatter.call_args[0]
            log_format = formatter_call_args[0]
            
            if verbose:
                # Verbose mode should include filename and line number
                assert 'filename' in log_format
                assert 'lineno' in log_format
            else:
                # Normal mode should have standard format
                assert 'asctime' in log_format
                assert 'name' in log_format
                assert 'levelname' in log_format
                assert 'message' in log_format

    @given(
        verbose_flag=st.booleans(),
        quiet_flag=st.booleans(),
    )
    def test_property_17_mutually_exclusive_modes(self, verbose_flag, quiet_flag):
        """
        Property 17: Mutually exclusive verbose/quiet modes
        For any combination of verbose and quiet flags, they should be mutually exclusive.
        
        **Validates: Requirements 7.3, 7.4**
        """
        parser = create_parser()
        
        if verbose_flag and quiet_flag:
            # Both flags should cause an error (mutually exclusive)
            with pytest.raises(SystemExit):
                parser.parse_args(["test.img", "-v", "-q"])
        else:
            # Single flag or no flags should work
            args_list = ["test.img"]
            if verbose_flag:
                args_list.append("-v")
            elif quiet_flag:
                args_list.append("-q")
            
            args = parser.parse_args(args_list)
            assert args.verbose == verbose_flag
            assert args.quiet == quiet_flag

    @given(
        format_choice=st.sampled_from(["human", "json"]),
        output_specified=st.booleans(),
    )
    def test_property_17_output_format_support(self, format_choice, output_specified):
        """
        Property 17: Output format support
        For any output format choice, the system should handle it appropriately.
        
        **Validates: Requirements 7.3, 7.4**
        """
        parser = create_parser()
        
        args_list = ["test.img", "-f", format_choice]
        
        if output_specified:
            # Add output file specification
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                output_path = tmp.name
            args_list.extend(["-o", output_path])
            
            # Create a temporary source file for validation to pass
            with tempfile.NamedTemporaryFile(delete=False, suffix='.img') as src_tmp:
                src_tmp.write(b'x' * 512)  # Write 512 bytes
                args_list[0] = src_tmp.name  # Replace "test.img" with actual file
            
            try:
                args = parser.parse_args(args_list)
                assert args.format == format_choice
                assert args.output == Path(output_path)
                
                # Test that validation handles output file creation
                result = validate_arguments(args)
                # Should succeed since we can create the output file
                assert result == 0
                
            finally:
                # Clean up
                if Path(output_path).exists():
                    os.unlink(output_path)
                if Path(src_tmp.name).exists():
                    os.unlink(src_tmp.name)
        else:
            args = parser.parse_args(args_list)
            assert args.format == format_choice
            assert args.output is None

    def test_property_17_logging_configuration_consistency(self):
        """
        Property 17: Logging configuration consistency
        The logging configuration should be consistent with the specified output modes.
        
        **Validates: Requirements 7.3, 7.4**
        """
        # Test quiet mode
        with patch('logging.StreamHandler') as mock_handler:
            mock_handler_instance = MagicMock()
            mock_handler_instance.level = logging.WARNING
            mock_handler.return_value = mock_handler_instance
            
            setup_logging("INFO", quiet=True, verbose=False)
            mock_handler_instance.setLevel.assert_called_with(logging.WARNING)
        
        # Test verbose mode
        with patch('logging.StreamHandler') as mock_handler, \
             patch('logging.Formatter') as mock_formatter:
            
            mock_handler_instance = MagicMock()
            mock_handler_instance.level = logging.DEBUG
            mock_handler.return_value = mock_handler_instance
            
            setup_logging("INFO", quiet=False, verbose=True)
            mock_handler_instance.setLevel.assert_called_with(logging.DEBUG)
            
            # Verbose format should include more details
            formatter_call_args = mock_formatter.call_args[0]
            assert 'filename' in formatter_call_args[0]
        
        # Test normal mode
        with patch('logging.StreamHandler') as mock_handler:
            mock_handler_instance = MagicMock()
            mock_handler_instance.level = logging.INFO
            mock_handler.return_value = mock_handler_instance
            
            setup_logging("INFO", quiet=False, verbose=False)
            mock_handler_instance.setLevel.assert_called_with(logging.INFO)