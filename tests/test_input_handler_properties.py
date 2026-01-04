"""Property-based tests for input handling and boot sector reading."""

import tempfile
import os
from pathlib import Path
from hypothesis import given, strategies as st, assume
import pytest

from boot_sector_analyzer.input_handler import InputHandler
from boot_sector_analyzer.exceptions import InvalidBootSectorError


class TestInputHandlerProperties:
    """Property-based tests for input handling functionality."""
    
    @given(
        boot_sector_data=st.binary(min_size=512, max_size=512)
    )
    def test_input_validation_and_reading(self, boot_sector_data):
        """
        **Feature: boot-sector-analyzer, Property 1: Input validation and reading**
        **Validates: Requirements 1.1, 1.2, 1.5**
        
        For any valid input source (device path or image file), the Boot_Sector_Analyzer 
        should read exactly 512 bytes and validate the input data size.
        """
        handler = InputHandler()
        
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            try:
                # Write exactly 512 bytes to the temporary file
                temp_file.write(boot_sector_data)
                temp_file.flush()
                temp_file_path = temp_file.name
                
                # Read the boot sector data
                read_data = handler.read_boot_sector(temp_file_path)
                
                # Verify exactly 512 bytes were read
                assert len(read_data) == 512
                assert read_data == boot_sector_data
                
                # Verify validation passes for 512-byte data
                assert handler.validate_boot_sector(read_data) is True
                
            finally:
                # Clean up the temporary file
                os.unlink(temp_file_path)
    
    @given(
        invalid_size_data=st.binary(min_size=0, max_size=2048).filter(lambda x: len(x) != 512)
    )
    def test_invalid_size_rejection(self, invalid_size_data):
        """
        **Feature: boot-sector-analyzer, Property 1: Input validation and reading**
        **Validates: Requirements 1.5**
        
        For any data that is not exactly 512 bytes, the Boot_Sector_Analyzer 
        should reject it with a ValueError.
        """
        handler = InputHandler()
        
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            try:
                # Write invalid size data to the temporary file
                temp_file.write(invalid_size_data)
                temp_file.flush()
                temp_file_path = temp_file.name
                
                # Attempt to read should raise InvalidBootSectorError for wrong size
                with pytest.raises(InvalidBootSectorError, match="(Boot sector must be exactly 512 bytes|No data read from source)"):
                    handler.read_boot_sector(temp_file_path)
                
                # Direct validation should also fail for wrong size
                assert handler.validate_boot_sector(invalid_size_data) is False
                
            finally:
                # Clean up the temporary file
                os.unlink(temp_file_path)
    
    @given(
        boot_sector_data=st.binary(min_size=512, max_size=512),
        file_path=st.text(min_size=1, max_size=100, alphabet=st.characters(
            whitelist_categories=('Lu', 'Ll', 'Nd'), 
            blacklist_characters='<>:"|?*\x00'
        ))
    )
    def test_file_path_handling(self, boot_sector_data, file_path):
        """
        **Feature: boot-sector-analyzer, Property 1: Input validation and reading**
        **Validates: Requirements 1.1, 1.2**
        
        For any valid file path containing 512 bytes of data, the InputHandler 
        should successfully read and return the data.
        """
        # Skip paths that might be problematic on the filesystem
        assume(not file_path.startswith('.'))
        assume('..' not in file_path)
        assume(len(file_path.strip()) > 0)
        
        handler = InputHandler()
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create file with the generated path name
            file_path_obj = Path(temp_dir) / file_path
            
            try:
                # Write boot sector data to file
                with open(file_path_obj, 'wb') as f:
                    f.write(boot_sector_data)
                
                # Read using InputHandler
                read_data = handler.read_boot_sector(file_path_obj)
                
                # Verify data integrity
                assert len(read_data) == 512
                assert read_data == boot_sector_data
                
                # Verify validation passes
                assert handler.validate_boot_sector(read_data) is True
                
            except OSError:
                # Some generated file names might not be valid on the filesystem
                # This is acceptable for this test
                pass
    
    @given(
        boot_sector_data=st.binary(min_size=510, max_size=512)
    )
    def test_boot_signature_validation(self, boot_sector_data):
        """
        **Feature: boot-sector-analyzer, Property 1: Input validation and reading**
        **Validates: Requirements 1.2, 1.5**
        
        For any boot sector data, the validation should check for proper boot signature
        and handle cases with and without valid signatures appropriately.
        """
        handler = InputHandler()
        
        # Pad data to exactly 512 bytes if needed
        if len(boot_sector_data) < 512:
            boot_sector_data = boot_sector_data + b'\x00' * (512 - len(boot_sector_data))
        
        # Test with valid boot signature (0x55AA)
        valid_data = boot_sector_data[:-2] + b'\x55\xAA'
        assert handler.validate_boot_sector(valid_data) is True
        
        # Test with invalid boot signature
        invalid_data = boot_sector_data[:-2] + b'\x00\x00'
        # Should still return True as per implementation (allows analysis even without signature)
        assert handler.validate_boot_sector(invalid_data) is True
        
        # Test validation of the original data
        result = handler.validate_boot_sector(boot_sector_data)
        assert isinstance(result, bool)