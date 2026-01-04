"""Unit tests for input handler error handling scenarios."""

import tempfile
import os
import stat
from pathlib import Path
import pytest

from boot_sector_analyzer.input_handler import InputHandler
from boot_sector_analyzer.exceptions import (
    FileAccessError,
    BSAPermissionError,
    InvalidBootSectorError,
    InputError
)


class TestInputHandlerErrorHandling:
    """Unit tests for error handling scenarios in InputHandler."""
    
    def test_file_not_found_error(self):
        """
        Test that FileNotFoundError is raised for non-existent files.
        Requirements: 1.3
        """
        handler = InputHandler()
        non_existent_path = "/path/that/does/not/exist/boot_sector.img"
        
        with pytest.raises(FileAccessError):
            handler.read_boot_sector(non_existent_path)
    
    def test_permission_denied_error(self):
        """
        Test that PermissionError is handled gracefully.
        Requirements: 1.4
        """
        handler = InputHandler()
        
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            try:
                # Write valid boot sector data
                boot_sector_data = b'\x00' * 512
                temp_file.write(boot_sector_data)
                temp_file.flush()
                temp_file_path = temp_file.name
                
                # Remove read permissions
                os.chmod(temp_file_path, stat.S_IWRITE)
                
                # Should raise BSAPermissionError
                with pytest.raises(BSAPermissionError):
                    handler.read_boot_sector(temp_file_path)
                    
            finally:
                # Restore permissions and clean up
                try:
                    os.chmod(temp_file_path, stat.S_IREAD | stat.S_IWRITE)
                    os.unlink(temp_file_path)
                except (OSError, FileNotFoundError):
                    pass
    
    def test_incorrect_file_size_too_small(self):
        """
        Test that ValueError is raised for files smaller than 512 bytes.
        Requirements: 1.3
        """
        handler = InputHandler()
        
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            try:
                # Write less than 512 bytes
                small_data = b'\x00' * 256
                temp_file.write(small_data)
                temp_file.flush()
                temp_file_path = temp_file.name
                
                with pytest.raises(InvalidBootSectorError, match="Boot sector must be exactly 512 bytes, got 256 bytes"):
                    handler.read_boot_sector(temp_file_path)
                    
            finally:
                os.unlink(temp_file_path)
    
    def test_large_file_reads_first_512_bytes(self):
        """
        Test that files larger than 512 bytes only read the first 512 bytes.
        This is correct behavior for boot sector reading from devices or large files.
        Requirements: 1.1, 1.2
        """
        handler = InputHandler()
        
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            try:
                # Write more than 512 bytes with a pattern
                first_512 = b'\xAA' * 512
                remaining = b'\xBB' * 512
                large_data = first_512 + remaining
                temp_file.write(large_data)
                temp_file.flush()
                temp_file_path = temp_file.name
                
                # Should successfully read only the first 512 bytes
                read_data = handler.read_boot_sector(temp_file_path)
                assert len(read_data) == 512
                assert read_data == first_512
                assert read_data != large_data[:512] or read_data == first_512  # Should be first 512 bytes
                    
            finally:
                os.unlink(temp_file_path)
    
    def test_empty_file_error(self):
        """
        Test that ValueError is raised for empty files.
        Requirements: 1.3
        """
        handler = InputHandler()
        
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            try:
                # Create empty file
                temp_file_path = temp_file.name
                
                with pytest.raises(InvalidBootSectorError, match="No data read from source"):
                    handler.read_boot_sector(temp_file_path)
                    
            finally:
                os.unlink(temp_file_path)
    
    def test_directory_instead_of_file_error(self):
        """
        Test that appropriate error is raised when trying to read a directory.
        Requirements: 1.3, 1.4
        """
        handler = InputHandler()
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Should raise an IOError, PermissionError, IsADirectoryError, or InputError when trying to read a directory
            with pytest.raises((IOError, PermissionError, IsADirectoryError, InputError)):
                handler.read_boot_sector(temp_dir)
    
    def test_validation_with_invalid_data_size(self):
        """
        Test validation method with various invalid data sizes.
        Requirements: 1.5
        """
        handler = InputHandler()
        
        # Test various invalid sizes
        test_cases = [
            b'',  # Empty
            b'\x00' * 100,  # Too small
            b'\x00' * 256,  # Half size
            b'\x00' * 1024,  # Too large
            b'\x00' * 2048,  # Much too large
        ]
        
        for invalid_data in test_cases:
            assert handler.validate_boot_sector(invalid_data) is False
    
    def test_validation_with_valid_size(self):
        """
        Test validation method with valid 512-byte data.
        Requirements: 1.5
        """
        handler = InputHandler()
        
        # Test with exactly 512 bytes
        valid_data = b'\x00' * 512
        assert handler.validate_boot_sector(valid_data) is True
        
        # Test with valid boot signature
        valid_with_signature = b'\x00' * 510 + b'\x55\xAA'
        assert handler.validate_boot_sector(valid_with_signature) is True
        
        # Test with invalid boot signature (should still be considered valid for analysis)
        invalid_signature = b'\x00' * 510 + b'\xFF\xFF'
        assert handler.validate_boot_sector(invalid_signature) is True
    
    def test_path_object_handling(self):
        """
        Test that Path objects are handled correctly.
        Requirements: 1.1, 1.2
        """
        handler = InputHandler()
        
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            try:
                # Write valid boot sector data
                boot_sector_data = b'\x00' * 512
                temp_file.write(boot_sector_data)
                temp_file.flush()
                temp_file_path = Path(temp_file.name)
                
                # Should work with Path object
                read_data = handler.read_boot_sector(temp_file_path)
                assert len(read_data) == 512
                assert read_data == boot_sector_data
                
            finally:
                os.unlink(temp_file.name)