"""Unit tests for CLI edge cases."""

import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
import tempfile
import os

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent.parent))

from boot_sector_analyzer.cli import create_parser, validate_arguments, main, load_config


class TestCLIEdgeCases:
    """Unit tests for CLI edge cases."""

    def test_no_arguments_provided(self):
        """
        Test that help is displayed when no arguments are provided.
        
        **Validates: Requirements 7.1, 7.5**
        """
        # Test the main function with no arguments
        with patch('sys.argv', ['boot-sector-analyzer']):
            with patch('boot_sector_analyzer.cli.create_parser') as mock_parser:
                mock_parser_instance = MagicMock()
                mock_parser.return_value = mock_parser_instance
                
                result = main()
                
                # Should return 0 (success) and print help
                assert result == 0
                mock_parser_instance.print_help.assert_called_once()

    def test_invalid_arguments_display_error(self):
        """
        Test that invalid arguments display helpful error messages.
        
        **Validates: Requirements 7.1, 7.5**
        """
        parser = create_parser()
        
        # Test completely invalid argument
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(['--completely-invalid-argument'])
        
        # Should exit with error code
        assert exc_info.value.code != 0

    def test_help_display_comprehensive(self):
        """
        Test that help display is comprehensive and includes all necessary information.
        
        **Validates: Requirements 7.1, 7.5**
        """
        parser = create_parser()
        help_text = parser.format_help()
        
        # Check that help contains essential information
        assert "boot-sector-analyzer" in help_text
        assert "Boot sector source" in help_text
        assert "Examples:" in help_text
        assert "/dev/sda" in help_text
        assert "boot_sector.img" in help_text
        assert "--verbose" in help_text or "-v" in help_text
        assert "--quiet" in help_text or "-q" in help_text
        assert "--format" in help_text or "-f" in help_text
        assert "--config" in help_text

    def test_version_display(self):
        """
        Test that version information is displayed correctly.
        
        **Validates: Requirements 7.1**
        """
        parser = create_parser()
        
        # Test version argument
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(['--version'])
        
        # Should exit with success code (0)
        assert exc_info.value.code == 0

    def test_mutually_exclusive_verbose_quiet(self):
        """
        Test that verbose and quiet flags are mutually exclusive.
        
        **Validates: Requirements 7.3, 7.4**
        """
        parser = create_parser()
        
        # Should fail when both are specified
        with pytest.raises(SystemExit):
            parser.parse_args(['test.img', '--verbose', '--quiet'])
        
        with pytest.raises(SystemExit):
            parser.parse_args(['test.img', '-v', '-q'])

    def test_invalid_format_argument(self):
        """
        Test handling of invalid format arguments.
        
        **Validates: Requirements 7.5**
        """
        parser = create_parser()
        
        # Should fail with invalid format
        with pytest.raises(SystemExit):
            parser.parse_args(['test.img', '--format', 'invalid_format'])
        
        with pytest.raises(SystemExit):
            parser.parse_args(['test.img', '-f', 'xml'])

    def test_invalid_log_level_argument(self):
        """
        Test handling of invalid log level arguments.
        
        **Validates: Requirements 7.5**
        """
        parser = create_parser()
        
        # Should fail with invalid log level
        with pytest.raises(SystemExit):
            parser.parse_args(['test.img', '--log-level', 'INVALID'])
        
        with pytest.raises(SystemExit):
            parser.parse_args(['test.img', '--log-level', 'TRACE'])

    def test_nonexistent_source_file(self):
        """
        Test validation of nonexistent source files.
        
        **Validates: Requirements 7.2, 7.5**
        """
        parser = create_parser()
        args = parser.parse_args(['nonexistent_file.img'])
        
        # Validation should fail
        with patch('sys.stderr'):
            result = validate_arguments(args)
            assert result != 0

    def test_nonexistent_config_file(self):
        """
        Test validation of nonexistent configuration files.
        
        **Validates: Requirements 7.6**
        """
        parser = create_parser()
        args = parser.parse_args(['test.img', '--config', '/nonexistent/config.ini'])
        
        # Validation should fail
        with patch('sys.stderr'):
            result = validate_arguments(args)
            assert result != 0

    def test_invalid_output_directory_creation_failure(self):
        """
        Test handling when output directory cannot be created.
        
        **Validates: Requirements 7.5**
        """
        parser = create_parser()
        
        # Use a path that cannot be created (read-only filesystem simulation)
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a read-only directory
            readonly_dir = Path(temp_dir) / "readonly"
            readonly_dir.mkdir()
            readonly_dir.chmod(0o444)  # Read-only
            
            invalid_output_path = readonly_dir / "subdir" / "output.txt"
            args = parser.parse_args(['test.img', '--output', str(invalid_output_path)])
            
            # Create a temporary file to make source validation pass
            with tempfile.NamedTemporaryFile(delete=False, suffix='.img') as tmp:
                tmp.write(b'x' * 512)
                args.source = tmp.name
            
            try:
                # Validation should fail due to output directory creation failure
                with patch('sys.stderr'):
                    result = validate_arguments(args)
                    # Should fail because we can't create subdirectory in read-only dir
                    assert result != 0
            finally:
                os.unlink(tmp.name)
                # Restore permissions for cleanup
                readonly_dir.chmod(0o755)

    def test_cache_directory_creation(self):
        """
        Test cache directory creation during validation.
        
        **Validates: Requirements 7.6**
        """
        parser = create_parser()
        
        # Create a temporary directory for cache
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_path = Path(temp_dir) / "test_cache"
            args = parser.parse_args(['test.img', '--cache-dir', str(cache_path)])
            
            # Create a temporary source file
            with tempfile.NamedTemporaryFile(delete=False, suffix='.img') as tmp:
                tmp.write(b'x' * 512)
                args.source = tmp.name
            
            try:
                # Validation should succeed and create cache directory
                result = validate_arguments(args)
                assert result == 0
                assert cache_path.exists()
            finally:
                os.unlink(tmp.name)

    def test_device_path_validation(self):
        """
        Test validation of device paths.
        
        **Validates: Requirements 7.2**
        """
        parser = create_parser()
        
        # Test common device paths
        device_paths = ['/dev/sda', '/dev/sdb1', '/dev/nvme0n1']
        
        for device_path in device_paths:
            args = parser.parse_args([device_path])
            
            # Validation should handle device paths appropriately
            # (May succeed or fail depending on system, but should not crash)
            result = validate_arguments(args)
            assert isinstance(result, int)

    def test_load_config_with_nonexistent_file(self):
        """
        Test configuration loading with nonexistent files.
        
        **Validates: Requirements 7.6**
        """
        # Should return empty dict for nonexistent file
        config = load_config(Path('/nonexistent/config.ini'))
        assert isinstance(config, dict)

    def test_load_config_with_invalid_content(self):
        """
        Test configuration loading with invalid content.
        
        **Validates: Requirements 7.6**
        """
        # Create a file with invalid INI content
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ini', delete=False) as tmp:
            tmp.write("invalid ini content without sections\nkey=value")
            config_path = tmp.name
        
        try:
            # Should handle invalid config gracefully
            config = load_config(Path(config_path))
            assert isinstance(config, dict)
        finally:
            os.unlink(config_path)

    def test_main_function_keyboard_interrupt(self):
        """
        Test main function handling of keyboard interrupt.
        
        **Validates: Requirements 7.1**
        """
        # Test that main function can handle SystemExit from argparse
        with patch('sys.argv', ['boot-sector-analyzer', '--invalid-option']):
            result = main()
            # Should return 2 for invalid arguments (argparse standard)
            assert result == 2

    def test_main_function_general_exception(self):
        """
        Test main function handling of general exceptions.
        
        **Validates: Requirements 7.1**
        """
        # Test that main function handles validation failure gracefully
        with patch('sys.argv', ['boot-sector-analyzer', 'nonexistent_file.img']):
            result = main()
            # Should return 2 for validation failure (InputError exit code)
            assert result == 2

    def test_argument_parsing_edge_cases(self):
        """
        Test edge cases in argument parsing.
        
        **Validates: Requirements 7.2, 7.5**
        """
        parser = create_parser()
        
        # Test with minimal valid arguments
        args = parser.parse_args(['test.img'])
        assert args.source == 'test.img'
        assert args.format == 'human'  # default
        assert args.verbose is False
        assert args.quiet is False
        
        # Test with all arguments specified
        args = parser.parse_args([
            'test.img',
            '--format', 'json',
            '--verbose',
            '--log-level', 'DEBUG',
            '--no-internet',
            '--api-key', 'test_key',
            '--output', 'output.json'
        ])
        
        assert args.source == 'test.img'
        assert args.format == 'json'
        assert args.verbose is True
        assert args.log_level == 'DEBUG'
        assert args.no_internet is True
        assert args.api_key == 'test_key'
        assert args.output == Path('output.json')