"""Property-based tests for StructureAnalyzer."""

import struct
from hypothesis import given, strategies as st
import pytest

from boot_sector_analyzer.structure_analyzer import StructureAnalyzer
from boot_sector_analyzer.models import MBRStructure, PartitionEntry
from boot_sector_analyzer.exceptions import InvalidBootSectorError


class TestStructureAnalyzerProperties:
    """Property-based tests for StructureAnalyzer class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.analyzer = StructureAnalyzer()

    @given(
        bootstrap_code_prefix=st.binary(min_size=440, max_size=440),  # First 440 bytes
        bootstrap_code_suffix=st.binary(min_size=2, max_size=2),      # Bytes 444-445
        partition_entries=st.lists(
            st.tuples(
                st.integers(min_value=0, max_value=255),  # status
                st.integers(min_value=0, max_value=255),  # start_head
                st.integers(min_value=0, max_value=255),  # start_sector_cylinder
                st.integers(min_value=0, max_value=255),  # start_cylinder
                st.integers(min_value=0, max_value=255),  # partition_type
                st.integers(min_value=0, max_value=255),  # end_head
                st.integers(min_value=0, max_value=255),  # end_sector_cylinder
                st.integers(min_value=0, max_value=255),  # end_cylinder
                st.integers(min_value=0, max_value=2**32-1),  # start_lba
                st.integers(min_value=0, max_value=2**32-1),  # size_sectors
            ),
            min_size=4,
            max_size=4
        ),
        boot_signature=st.integers(min_value=0, max_value=65535),
        disk_signature=st.integers(min_value=0, max_value=2**32-1)
    )
    def test_mbr_structure_parsing_completeness(self, bootstrap_code_prefix, bootstrap_code_suffix, partition_entries, boot_signature, disk_signature):
        """
        Property 2: MBR structure parsing completeness
        For any valid 512-byte boot sector, the Structure_Analyzer should successfully parse 
        the MBR structure, identify the boot code region (first 446 bytes), and extract all partition table entries.
        **Validates: Requirements 2.1, 2.3, 2.4**
        **Feature: boot-sector-analyzer, Property 2: MBR structure parsing completeness**
        """
        # Construct a valid 512-byte boot sector
        boot_sector = bytearray(512)
        
        # Set bootstrap code prefix (first 440 bytes)
        boot_sector[:440] = bootstrap_code_prefix
        
        # Set disk signature at offset 440 (this will be part of bootstrap code)
        boot_sector[440:444] = struct.pack("<I", disk_signature)
        
        # Set bootstrap code suffix (bytes 444-445)
        boot_sector[444:446] = bootstrap_code_suffix
        
        # Set partition table entries (4 entries, 16 bytes each)
        for i, entry in enumerate(partition_entries):
            offset = 446 + (i * 16)
            boot_sector[offset:offset+16] = struct.pack("<BBBBBBBBII", *entry)
        
        # Set boot signature at the end
        boot_sector[510:512] = struct.pack("<H", boot_signature)
        
        # Parse the MBR structure
        mbr = self.analyzer.parse_mbr(bytes(boot_sector))
        
        # Verify the structure was parsed correctly
        assert isinstance(mbr, MBRStructure)
        assert len(mbr.bootstrap_code) == 446
        
        # Verify bootstrap code structure (accounting for disk signature overlap)
        expected_bootstrap = bootstrap_code_prefix + struct.pack("<I", disk_signature) + bootstrap_code_suffix
        assert mbr.bootstrap_code == expected_bootstrap
        
        assert len(mbr.partition_table) == 4
        assert mbr.boot_signature == boot_signature
        assert mbr.disk_signature == disk_signature
        
        # Verify all partition entries were extracted
        for i, (expected_entry, actual_entry) in enumerate(zip(partition_entries, mbr.partition_table)):
            assert isinstance(actual_entry, PartitionEntry)
            assert actual_entry.status == expected_entry[0]
            assert actual_entry.partition_type == expected_entry[4]
            assert actual_entry.start_lba == expected_entry[8]
            assert actual_entry.size_sectors == expected_entry[9]

    @given(st.binary(min_size=0, max_size=511))
    def test_mbr_parsing_invalid_size(self, invalid_boot_sector):
        """Test that MBR parsing fails gracefully with invalid boot sector sizes."""
        with pytest.raises(InvalidBootSectorError, match="Boot sector must be exactly 512 bytes"):
            self.analyzer.parse_mbr(invalid_boot_sector)

    @given(st.binary(min_size=513, max_size=1024))
    def test_mbr_parsing_oversized(self, oversized_boot_sector):
        """Test that MBR parsing fails gracefully with oversized boot sectors."""
        with pytest.raises(InvalidBootSectorError, match="Boot sector must be exactly 512 bytes"):
            self.analyzer.parse_mbr(oversized_boot_sector)
    @given(
        boot_sector_data=st.binary(min_size=510, max_size=510),
        boot_signature=st.integers(min_value=0, max_value=65535)
    )
    def test_boot_signature_validation(self, boot_sector_data, boot_signature):
        """
        Property 3: Boot signature validation
        For any boot sector, the Structure_Analyzer should correctly validate the boot signature (0x55AA or 0xAA55) 
        and flag missing or incorrect signatures as structural anomalies.
        **Validates: Requirements 2.2, 2.6**
        **Feature: boot-sector-analyzer, Property 3: Boot signature validation**
        """
        # Create a 512-byte boot sector with the given signature
        boot_sector = boot_sector_data + struct.pack("<H", boot_signature)
        
        # Validate the boot signature
        is_valid = self.analyzer.validate_boot_signature(boot_sector)
        
        # The signature should be valid if it equals 0x55AA or 0xAA55
        expected_valid = (boot_signature == 0x55AA or boot_signature == 0xAA55)
        assert is_valid == expected_valid
        
        # Test with MBR parsing to check anomaly detection
        mbr = self.analyzer.parse_mbr(boot_sector)
        anomalies = self.analyzer.detect_anomalies(mbr)
        
        if boot_signature not in [0x55AA, 0xAA55]:
            # Should have an invalid boot signature anomaly
            signature_anomalies = [a for a in anomalies if a.type == "invalid_boot_signature"]
            assert len(signature_anomalies) > 0
            assert signature_anomalies[0].severity == "high"
            assert signature_anomalies[0].location == 510
        else:
            # Should not have any boot signature anomalies
            signature_anomalies = [a for a in anomalies if a.type == "invalid_boot_signature"]
            assert len(signature_anomalies) == 0

    @given(st.binary(min_size=0, max_size=509))
    def test_boot_signature_validation_short_sector(self, short_boot_sector):
        """Test boot signature validation with boot sectors shorter than 512 bytes."""
        is_valid = self.analyzer.validate_boot_signature(short_boot_sector)
        assert is_valid is False
    @given(
        partition_data=st.lists(
            st.tuples(
                st.integers(min_value=0, max_value=255),  # status
                st.integers(min_value=0, max_value=255),  # start_head
                st.integers(min_value=0, max_value=255),  # start_sector_cylinder
                st.integers(min_value=0, max_value=255),  # start_cylinder
                st.integers(min_value=0, max_value=255),  # partition_type
                st.integers(min_value=0, max_value=255),  # end_head
                st.integers(min_value=0, max_value=255),  # end_sector_cylinder
                st.integers(min_value=0, max_value=255),  # end_cylinder
                st.integers(min_value=1, max_value=1000),  # start_lba (non-zero for active partitions)
                st.integers(min_value=1, max_value=1000),  # size_sectors (non-zero for active partitions)
            ),
            min_size=2,
            max_size=4
        )
    )
    def test_partition_table_consistency_validation(self, partition_data):
        """
        Property 4: Partition table consistency validation
        For any partition table, the Structure_Analyzer should detect overlapping partitions 
        and validate entry consistency.
        **Validates: Requirements 2.5**
        **Feature: boot-sector-analyzer, Property 4: Partition table consistency validation**
        """
        # Create overlapping partitions by design
        overlapping_partitions = []
        
        # First partition
        if len(partition_data) >= 1:
            p1 = partition_data[0]
            overlapping_partitions.append(p1)
        
        # Second partition that overlaps with the first
        if len(partition_data) >= 2:
            p1_start_lba = partition_data[0][8]
            p1_size = partition_data[0][9]
            # Create an overlapping partition that starts within the first partition
            overlap_start = p1_start_lba + (p1_size // 2)  # Start in the middle of first partition
            p2_data = list(partition_data[1])
            p2_data[8] = overlap_start  # start_lba
            overlapping_partitions.append(tuple(p2_data))
        
        # Add remaining partitions as non-overlapping
        for i in range(2, len(partition_data)):
            # Place these partitions far away to avoid overlap
            p_data = list(partition_data[i])
            p_data[8] = 10000 + (i * 1000)  # start_lba far away
            overlapping_partitions.append(tuple(p_data))
        
        # Pad to 4 partitions with empty entries
        while len(overlapping_partitions) < 4:
            overlapping_partitions.append((0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        
        # Create a boot sector with these partitions
        boot_sector = bytearray(512)
        
        # Set partition table entries
        for i, entry in enumerate(overlapping_partitions):
            offset = 446 + (i * 16)
            boot_sector[offset:offset+16] = struct.pack("<BBBBBBBBII", *entry)
        
        # Set valid boot signature
        boot_sector[510:512] = struct.pack("<H", 0x55AA)
        
        # Parse and analyze
        mbr = self.analyzer.parse_mbr(bytes(boot_sector))
        anomalies = self.analyzer.detect_anomalies(mbr)
        
        # If we created overlapping partitions, there should be an anomaly
        if len(partition_data) >= 2:
            overlap_anomalies = [a for a in anomalies if a.type == "overlapping_partitions"]
            assert len(overlap_anomalies) > 0
            assert overlap_anomalies[0].severity == "critical"

    @given(
        partition_entries=st.lists(
            st.tuples(
                st.integers(min_value=0, max_value=255),  # status
                st.integers(min_value=0, max_value=255),  # start_head
                st.integers(min_value=0, max_value=255),  # start_sector_cylinder
                st.integers(min_value=0, max_value=255),  # start_cylinder
                st.just(0),  # partition_type = 0 (empty)
                st.integers(min_value=0, max_value=255),  # end_head
                st.integers(min_value=0, max_value=255),  # end_sector_cylinder
                st.integers(min_value=0, max_value=255),  # end_cylinder
                st.integers(min_value=0, max_value=2**32-1),  # start_lba
                st.integers(min_value=1, max_value=1000),  # size_sectors > 0
            ),
            min_size=1,
            max_size=4
        )
    )
    def test_invalid_partition_type_detection(self, partition_entries):
        """Test detection of partitions with size but type 0 (invalid)."""
        # Pad to 4 partitions with empty entries
        while len(partition_entries) < 4:
            partition_entries.append((0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        
        # Create a boot sector with these partitions
        boot_sector = bytearray(512)
        
        # Set partition table entries
        for i, entry in enumerate(partition_entries):
            offset = 446 + (i * 16)
            boot_sector[offset:offset+16] = struct.pack("<BBBBBBBBII", *entry)
        
        # Set valid boot signature
        boot_sector[510:512] = struct.pack("<H", 0x55AA)
        
        # Parse and analyze
        mbr = self.analyzer.parse_mbr(bytes(boot_sector))
        anomalies = self.analyzer.detect_anomalies(mbr)
        
        # Should detect invalid partition type anomalies
        invalid_type_anomalies = [a for a in anomalies if a.type == "invalid_partition_type"]
        
        # Count how many partitions have size > 0 but type 0
        expected_anomalies = sum(1 for entry in partition_entries if entry[9] > 0 and entry[4] == 0)
        
        assert len(invalid_type_anomalies) == expected_anomalies
        for anomaly in invalid_type_anomalies:
            assert anomaly.severity == "medium"