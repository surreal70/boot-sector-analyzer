"""Property-based tests for VBRAnalyzer orchestrator."""

import os
import tempfile
from unittest.mock import Mock, patch, mock_open
import pytest
from hypothesis import given, strategies as st, assume

from boot_sector_analyzer.vbr_analyzer import VBRAnalyzer
from boot_sector_analyzer.models import (
    MBRStructure, PartitionEntry, ValidPartition, VBRData,
    VBRAnalysisResult, VBRStructure, VBRContentAnalysis,
    FilesystemType, FilesystemMetadata, ThreatLevel
)


class TestVBRAnalyzerProperties:
    """Property-based tests for VBRAnalyzer class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_partition_scanner = Mock()
        self.mock_vbr_structure_parser = Mock()
        self.mock_vbr_content_analyzer = Mock()
        
        self.vbr_analyzer = VBRAnalyzer(
            partition_scanner=self.mock_partition_scanner,
            vbr_structure_parser=self.mock_vbr_structure_parser,
            vbr_content_analyzer=self.mock_vbr_content_analyzer
        )

    def teardown_method(self):
        """Clean up test fixtures."""
        self.mock_partition_scanner.reset_mock()
        self.mock_vbr_structure_parser.reset_mock()
        self.mock_vbr_content_analyzer.reset_mock()

    @given(
        partition_count=st.integers(min_value=1, max_value=4),
        failed_partition_indices=st.lists(
            st.integers(min_value=0, max_value=3), 
            min_size=1, 
            max_size=4,
            unique=True
        )
    )
    def test_vbr_extraction_error_handling_property(self, partition_count, failed_partition_indices):
        """
        Property 49: VBR extraction error handling
        
        For any VBR extraction that fails due to I/O errors, the VBR_Analyzer should 
        log the error and continue processing remaining partitions.
        
        **Validates: Requirements 14.4**
        """
        # Reset mocks for each test run
        self.mock_partition_scanner.reset_mock()
        self.mock_vbr_structure_parser.reset_mock()
        self.mock_vbr_content_analyzer.reset_mock()
        
        # Ensure failed indices are within partition count
        failed_partition_indices = [i for i in failed_partition_indices if i < partition_count]
        assume(len(failed_partition_indices) > 0)
        
        # Create mock MBR structure with partitions
        partition_entries = []
        valid_partitions = []
        
        for i in range(partition_count):
            partition_entry = PartitionEntry(
                status=0x80 if i == 0 else 0x00,
                start_chs=(0, 1, 1),
                partition_type=0x83,  # Linux ext4
                end_chs=(1023, 254, 63),
                start_lba=2048 + (i * 1000000),
                size_sectors=1000000
            )
            partition_entries.append(partition_entry)
            
            valid_partition = ValidPartition(
                partition_entry=partition_entry,
                partition_number=i + 1,
                start_byte_offset=(2048 + (i * 1000000)) * 512,
                is_accessible=True
            )
            valid_partitions.append(valid_partition)
        
        mbr_structure = MBRStructure(
            bootstrap_code=b'\x00' * 446,
            partition_table=partition_entries,
            boot_signature=0x55AA
        )
        
        # Mock partition scanner to return valid partitions
        self.mock_partition_scanner.identify_valid_partitions.return_value = valid_partitions
        
        # Mock VBR extraction - some succeed, some fail
        def mock_extract_vbr_data(device_path, partition_entry):
            partition_index = next(
                i for i, p in enumerate(partition_entries) 
                if p.start_lba == partition_entry.start_lba
            )
            
            if partition_index in failed_partition_indices:
                return None  # Simulate extraction failure
            else:
                return b'\x00' * 512  # Simulate successful extraction
        
        def mock_validate_partition_access(device_path, partition_entry):
            partition_index = next(
                i for i, p in enumerate(partition_entries) 
                if p.start_lba == partition_entry.start_lba
            )
            return partition_index not in failed_partition_indices
        
        self.mock_partition_scanner.extract_vbr_data.side_effect = mock_extract_vbr_data
        self.mock_partition_scanner.validate_partition_access.side_effect = mock_validate_partition_access
        
        # Mock VBR structure parsing and content analysis for successful extractions
        mock_vbr_structure = VBRStructure(
            filesystem_type=FilesystemType.EXT4,
            boot_code=b'\x00' * 400,
            boot_signature=0x55AA,
            filesystem_metadata=FilesystemMetadata(),
            raw_data=b'\x00' * 512
        )
        
        mock_content_analysis = VBRContentAnalysis(
            hashes={'md5': 'test_hash', 'sha256': 'test_hash'},
            boot_code_hashes={'md5': 'boot_hash', 'sha256': 'boot_hash'},
            disassembly_result=None,
            detected_patterns=[],
            anomalies=[],
            threat_level=ThreatLevel.LOW
        )
        
        self.mock_vbr_structure_parser.parse_vbr_structure.return_value = mock_vbr_structure
        self.mock_vbr_content_analyzer.analyze_vbr_content.return_value = mock_content_analysis
        
        # Test VBR analysis with device path
        device_path = "/dev/sda"
        
        with patch.object(self.vbr_analyzer, 'should_extract_vbrs', return_value=True):
            results = self.vbr_analyzer.analyze_vbrs(device_path, mbr_structure)
        
        # Verify that we get results for all partitions
        assert len(results) == partition_count
        
        # Verify that failed extractions have extraction_error set
        failed_count = 0
        successful_count = 0
        
        for i, result in enumerate(results):
            if i in failed_partition_indices:
                assert result.extraction_error is not None
                assert result.vbr_structure is None
                assert result.content_analysis is None
                failed_count += 1
            else:
                assert result.extraction_error is None
                assert result.vbr_structure is not None
                assert result.content_analysis is not None
                successful_count += 1
        
        # Verify counts match expectations
        assert failed_count == len(failed_partition_indices)
        assert successful_count == partition_count - len(failed_partition_indices)
        
        # Verify that analysis continued despite failures
        assert len(results) == partition_count  # All partitions processed
        
        # Verify that partition scanner methods were called appropriately
        assert self.mock_partition_scanner.validate_partition_access.call_count == partition_count
        
        # extract_vbr_data should only be called for accessible partitions
        successful_partition_count = partition_count - len(failed_partition_indices)
        assert self.mock_partition_scanner.extract_vbr_data.call_count == successful_partition_count

    @given(
        source_paths=st.lists(
            st.text(min_size=1, max_size=50).filter(lambda x: not x.startswith('/dev/')),
            min_size=1,
            max_size=5
        )
    )
    def test_image_file_vbr_extraction_handling_property(self, source_paths):
        """
        Property 56: Image file VBR extraction handling
        
        For any analysis of image files (not direct disk access), the VBR_Analyzer should 
        skip VBR extraction and inform the user appropriately.
        
        **Validates: Requirements 14.11**
        """
        # Reset mocks for each test run
        self.mock_partition_scanner.reset_mock()
        self.mock_vbr_structure_parser.reset_mock()
        self.mock_vbr_content_analyzer.reset_mock()
        
        # Create a simple MBR structure with one partition
        partition_entry = PartitionEntry(
            status=0x80,
            start_chs=(0, 1, 1),
            partition_type=0x83,  # Linux ext4
            end_chs=(1023, 254, 63),
            start_lba=2048,
            size_sectors=1000000
        )
        
        mbr_structure = MBRStructure(
            bootstrap_code=b'\x00' * 446,
            partition_table=[partition_entry],
            boot_signature=0x55AA
        )
        
        # Test each source path (should all be treated as image files)
        for source_path in source_paths:
            # Ensure the path doesn't look like a device path
            assume(not source_path.startswith('/dev/'))
            
            # Mock the file existence check to return True (regular file)
            with patch('os.path.exists', return_value=True), \
                 patch('os.stat') as mock_stat:
                
                # Mock stat to return regular file (not block/char device)
                mock_stat_result = Mock()
                mock_stat_result.st_mode = 0o100644  # Regular file mode
                mock_stat.return_value = mock_stat_result
                
                # Test VBR analysis with image file path
                results = self.vbr_analyzer.analyze_vbrs(source_path, mbr_structure)
                
                # Verify that VBR extraction was skipped for image files
                assert len(results) == 0
                
                # Verify that no partition scanner methods were called
                assert self.mock_partition_scanner.identify_valid_partitions.call_count == 0
                assert self.mock_partition_scanner.validate_partition_access.call_count == 0
                assert self.mock_partition_scanner.extract_vbr_data.call_count == 0
                
                # Reset mocks for next iteration
                self.mock_partition_scanner.reset_mock()

    @given(
        partition_count=st.integers(min_value=0, max_value=4)
    )
    def test_empty_partition_table_handling_property(self, partition_count):
        """
        Property 57: Empty partition table handling
        
        For any MBR with no valid partitions, the VBR_Analyzer should report this 
        condition without treating it as an error.
        
        **Validates: Requirements 14.12**
        """
        # Reset mocks for each test run
        self.mock_partition_scanner.reset_mock()
        self.mock_vbr_structure_parser.reset_mock()
        self.mock_vbr_content_analyzer.reset_mock()
        
        # Create partition entries - some may be empty
        partition_entries = []
        for i in range(4):  # Always create 4 partition entries (MBR standard)
            if i < partition_count:
                # Create valid partition
                partition_entry = PartitionEntry(
                    status=0x80 if i == 0 else 0x00,
                    start_chs=(0, 1, 1),
                    partition_type=0x83,  # Linux ext4
                    end_chs=(1023, 254, 63),
                    start_lba=2048 + (i * 1000000),
                    size_sectors=1000000
                )
            else:
                # Create empty partition entry
                partition_entry = PartitionEntry(
                    status=0x00,
                    start_chs=(0, 0, 0),
                    partition_type=0x00,  # Empty
                    end_chs=(0, 0, 0),
                    start_lba=0,
                    size_sectors=0
                )
            partition_entries.append(partition_entry)
        
        mbr_structure = MBRStructure(
            bootstrap_code=b'\x00' * 446,
            partition_table=partition_entries,
            boot_signature=0x55AA
        )
        
        # Mock partition scanner to return appropriate number of valid partitions
        valid_partitions = []
        for i in range(partition_count):
            valid_partition = ValidPartition(
                partition_entry=partition_entries[i],
                partition_number=i + 1,
                start_byte_offset=(2048 + (i * 1000000)) * 512,
                is_accessible=True
            )
            valid_partitions.append(valid_partition)
        
        self.mock_partition_scanner.identify_valid_partitions.return_value = valid_partitions
        
        # Test VBR analysis with device path
        device_path = "/dev/sda"
        
        with patch.object(self.vbr_analyzer, 'should_extract_vbrs', return_value=True):
            results = self.vbr_analyzer.analyze_vbrs(device_path, mbr_structure)
        
        # Verify that the number of results matches the number of valid partitions
        assert len(results) == partition_count
        
        # Verify that identify_valid_partitions was called
        assert self.mock_partition_scanner.identify_valid_partitions.call_count == 1
        
        # If no valid partitions, verify no further processing occurred
        if partition_count == 0:
            assert self.mock_partition_scanner.validate_partition_access.call_count == 0
            assert self.mock_partition_scanner.extract_vbr_data.call_count == 0
        else:
            # If there are valid partitions, verify processing occurred
            assert self.mock_partition_scanner.validate_partition_access.call_count > 0