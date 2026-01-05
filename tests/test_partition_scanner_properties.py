"""Property-based tests for partition scanner functionality."""

import pytest
import tempfile
import os
from hypothesis import given, strategies as st, assume
from boot_sector_analyzer.partition_scanner import PartitionScanner
from boot_sector_analyzer.models import MBRStructure, PartitionEntry


def generate_partition_entry():
    """Generate a partition entry strategy."""
    return st.builds(
        PartitionEntry,
        status=st.integers(min_value=0, max_value=255),
        start_chs=st.tuples(
            st.integers(min_value=0, max_value=1023),  # cylinder
            st.integers(min_value=0, max_value=255),   # head
            st.integers(min_value=1, max_value=63)     # sector
        ),
        partition_type=st.integers(min_value=0, max_value=255),
        end_chs=st.tuples(
            st.integers(min_value=0, max_value=1023),  # cylinder
            st.integers(min_value=0, max_value=255),   # head
            st.integers(min_value=1, max_value=63)     # sector
        ),
        start_lba=st.integers(min_value=0, max_value=2**32 - 1),
        size_sectors=st.integers(min_value=0, max_value=2**32 - 1)
    )


def generate_mbr_structure():
    """Generate an MBR structure strategy."""
    return st.builds(
        MBRStructure,
        bootstrap_code=st.binary(min_size=446, max_size=446),
        partition_table=st.lists(generate_partition_entry(), min_size=4, max_size=4),
        boot_signature=st.just(0x55AA),
        disk_signature=st.one_of(st.none(), st.integers(min_value=0, max_value=2**32 - 1))
    )


class TestPartitionScannerProperties:
    """Property-based tests for PartitionScanner class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.scanner = PartitionScanner()

    @given(generate_mbr_structure())
    def test_property_47_valid_partition_identification(self, mbr_structure):
        """
        Property 47: Valid partition identification
        
        For any MBR structure with partition entries, the VBR_Analyzer should 
        identify all valid, non-empty partitions correctly.
        
        **Feature: boot-sector-analyzer, Property 47: Valid partition identification**
        **Validates: Requirements 14.1**
        """
        # Execute partition identification
        valid_partitions = self.scanner.identify_valid_partitions(mbr_structure)
        
        # Property: All returned partitions should be valid and non-empty
        for valid_partition in valid_partitions:
            partition = valid_partition.partition_entry
            
            # Valid partitions must have non-zero partition type
            assert partition.partition_type != 0, \
                f"Valid partition has zero partition type: {partition}"
            
            # Valid partitions must have non-zero start LBA (not MBR)
            assert partition.start_lba > 0, \
                f"Valid partition has zero start LBA: {partition}"
            
            # Valid partitions must have non-zero size
            assert partition.size_sectors > 0, \
                f"Valid partition has zero size: {partition}"
            
            # Partition number should be 1-4
            assert 1 <= valid_partition.partition_number <= 4, \
                f"Invalid partition number: {valid_partition.partition_number}"
            
            # Start byte offset should be calculated correctly
            expected_offset = partition.start_lba * 512
            assert valid_partition.start_byte_offset == expected_offset, \
                f"Incorrect byte offset calculation: expected {expected_offset}, " \
                f"got {valid_partition.start_byte_offset}"

    @given(generate_mbr_structure())
    def test_empty_partitions_not_identified_as_valid(self, mbr_structure):
        """
        Test that empty partitions (all zeros) are not identified as valid.
        
        This is part of Property 47 validation.
        """
        # Create an MBR with at least one empty partition
        empty_partition = PartitionEntry(
            status=0,
            start_chs=(0, 0, 1),
            partition_type=0,
            end_chs=(0, 0, 1),
            start_lba=0,
            size_sectors=0
        )
        
        # Replace first partition with empty one
        mbr_structure.partition_table[0] = empty_partition
        
        valid_partitions = self.scanner.identify_valid_partitions(mbr_structure)
        
        # Property: Empty partitions should not be in valid partitions list
        for valid_partition in valid_partitions:
            assert valid_partition.partition_number != 1, \
                "Empty partition was incorrectly identified as valid"

    @given(st.integers(min_value=1, max_value=2**32 - 1))
    def test_partition_offset_calculation_accuracy(self, start_lba):
        """
        Test that partition offset calculation is accurate.
        
        This supports Property 47 by ensuring offset calculations are correct.
        """
        partition = PartitionEntry(
            status=0x80,
            start_chs=(0, 1, 1),
            partition_type=0x83,  # Linux filesystem
            end_chs=(0, 1, 1),
            start_lba=start_lba,
            size_sectors=1000
        )
        
        calculated_offset = self.scanner.calculate_partition_offset(partition)
        expected_offset = start_lba * 512
        
        assert calculated_offset == expected_offset, \
            f"Offset calculation error: expected {expected_offset}, got {calculated_offset}"

    @given(generate_mbr_structure())
    def test_partition_numbering_consistency(self, mbr_structure):
        """
        Test that partition numbering is consistent with MBR table position.
        
        This supports Property 47 by ensuring correct partition identification.
        """
        valid_partitions = self.scanner.identify_valid_partitions(mbr_structure)
        
        # Property: Partition numbers should correspond to their position in MBR table
        for valid_partition in valid_partitions:
            mbr_index = valid_partition.partition_number - 1  # Convert to 0-based index
            expected_partition = mbr_structure.partition_table[mbr_index]
            
            assert valid_partition.partition_entry == expected_partition, \
                f"Partition number {valid_partition.partition_number} does not match " \
                f"MBR table position {mbr_index + 1}"

    @given(generate_mbr_structure())
    def test_valid_partition_count_bounds(self, mbr_structure):
        """
        Test that the number of valid partitions is within expected bounds.
        
        This supports Property 47 by ensuring reasonable partition identification.
        """
        valid_partitions = self.scanner.identify_valid_partitions(mbr_structure)
        
        # Property: Number of valid partitions should be between 0 and 4
        assert 0 <= len(valid_partitions) <= 4, \
            f"Invalid number of valid partitions: {len(valid_partitions)}"
        
        # Property: Should not exceed the number of non-empty partitions in MBR
        non_empty_count = sum(
            1 for p in mbr_structure.partition_table
            if not (p.partition_type == 0 and p.start_lba == 0 and p.size_sectors == 0)
        )
        
        assert len(valid_partitions) <= non_empty_count, \
            f"More valid partitions ({len(valid_partitions)}) than non-empty " \
            f"partitions ({non_empty_count})"

    @given(st.binary(min_size=512, max_size=512))
    def test_property_48_vbr_extraction_completeness(self, vbr_data):
        """
        Property 48: VBR extraction completeness
        
        For any valid partition detected from MBR analysis, the Partition_Scanner 
        should extract exactly 512 bytes from the partition's starting LBA address.
        
        **Feature: boot-sector-analyzer, Property 48: VBR extraction completeness**
        **Validates: Requirements 14.2, 14.3**
        """
        # Create a temporary file to simulate a disk device
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            try:
                # Write some padding before the VBR data
                padding_size = 1024 * 512  # 1024 sectors of padding
                temp_file.write(b'\x00' * padding_size)
                
                # Write the VBR data
                temp_file.write(vbr_data)
                
                # Write some data after VBR
                temp_file.write(b'\xFF' * 512)
                temp_file.flush()
                
                # Create a partition entry that points to the VBR location
                start_lba = 1024  # Points to where we wrote the VBR data
                partition = PartitionEntry(
                    status=0x80,
                    start_chs=(0, 1, 1),
                    partition_type=0x83,  # Linux filesystem
                    end_chs=(0, 1, 1),
                    start_lba=start_lba,
                    size_sectors=1000
                )
                
                # Extract VBR data
                extracted_data = self.scanner.extract_vbr_data(temp_file.name, partition)
                
                # Property: Should extract exactly 512 bytes
                assert extracted_data is not None, "VBR extraction should not return None"
                assert len(extracted_data) == 512, \
                    f"VBR extraction should return exactly 512 bytes, got {len(extracted_data)}"
                
                # Property: Extracted data should match the original VBR data
                assert extracted_data == vbr_data, \
                    "Extracted VBR data should match the original data"
                
                # Property: Offset calculation should be correct
                expected_offset = start_lba * 512
                calculated_offset = self.scanner.calculate_partition_offset(partition)
                assert calculated_offset == expected_offset, \
                    f"Offset calculation error: expected {expected_offset}, got {calculated_offset}"
                
            finally:
                # Clean up temporary file
                os.unlink(temp_file.name)

    @given(st.integers(min_value=1, max_value=1000))
    def test_vbr_extraction_with_various_lba_positions(self, start_lba):
        """
        Test VBR extraction from various LBA positions.
        
        This supports Property 48 by testing extraction at different disk locations.
        """
        # Create test VBR data
        test_vbr = b'TEST_VBR_DATA' + b'\x00' * (512 - 13)
        
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            try:
                # Write padding to reach the desired LBA position
                padding_size = start_lba * 512
                temp_file.write(b'\x00' * padding_size)
                
                # Write the test VBR data
                temp_file.write(test_vbr)
                temp_file.flush()
                
                # Create partition entry
                partition = PartitionEntry(
                    status=0x80,
                    start_chs=(0, 1, 1),
                    partition_type=0x83,
                    end_chs=(0, 1, 1),
                    start_lba=start_lba,
                    size_sectors=100
                )
                
                # Extract and verify
                extracted_data = self.scanner.extract_vbr_data(temp_file.name, partition)
                
                assert extracted_data is not None, \
                    f"VBR extraction failed for LBA {start_lba}"
                assert len(extracted_data) == 512, \
                    f"Wrong data size for LBA {start_lba}: {len(extracted_data)}"
                assert extracted_data == test_vbr, \
                    f"Data mismatch for LBA {start_lba}"
                
            finally:
                os.unlink(temp_file.name)

    def test_vbr_extraction_error_handling(self):
        """
        Test VBR extraction error handling for non-existent files.
        
        This supports Property 48 by testing error conditions.
        """
        partition = PartitionEntry(
            status=0x80,
            start_chs=(0, 1, 1),
            partition_type=0x83,
            end_chs=(0, 1, 1),
            start_lba=1,
            size_sectors=100
        )
        
        # Try to extract from non-existent file
        result = self.scanner.extract_vbr_data("/non/existent/file", partition)
        
        # Property: Should return None for failed extractions
        assert result is None, "VBR extraction should return None for non-existent files"

    def test_partition_access_validation(self):
        """
        Test partition access validation functionality.
        
        This supports Property 48 by testing accessibility checks.
        """
        partition = PartitionEntry(
            status=0x80,
            start_chs=(0, 1, 1),
            partition_type=0x83,
            end_chs=(0, 1, 1),
            start_lba=1,
            size_sectors=100
        )
        
        # Test with non-existent device
        is_accessible = self.scanner.validate_partition_access("/non/existent/device", partition)
        assert not is_accessible, "Non-existent device should not be accessible"
        
        # Test with valid temporary file
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            try:
                # Write enough data to cover the partition
                temp_file.write(b'\x00' * (partition.start_lba + 1) * 512)
                temp_file.flush()
                
                is_accessible = self.scanner.validate_partition_access(temp_file.name, partition)
                assert is_accessible, "Valid partition should be accessible"
                
            finally:
                os.unlink(temp_file.name)