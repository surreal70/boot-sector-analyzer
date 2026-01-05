"""Property-based tests for individual partition color coding functionality."""

import pytest
from hypothesis import given, strategies as st, assume
import struct
from boot_sector_analyzer.mbr_decoder import MBRDecoder, PartitionColors, MBRSection
from boot_sector_analyzer.report_generator import ReportGenerator
from boot_sector_analyzer.html_generator import HTMLGenerator
from boot_sector_analyzer.models import AnalysisResult, HexdumpData, StructureAnalysis, ContentAnalysis, SecurityAnalysis, ThreatLevel, MBRStructure, PartitionEntry
from datetime import datetime
import json


class TestPartitionColorProperties:
    """Property-based tests for individual partition color coding."""

    @given(
        partition_types=st.lists(
            st.integers(min_value=0, max_value=255),
            min_size=4, max_size=4
        ),
        partition_sizes=st.lists(
            st.integers(min_value=0, max_value=1000000),
            min_size=4, max_size=4
        ),
        start_lbas=st.lists(
            st.integers(min_value=0, max_value=1000000),
            min_size=4, max_size=4
        )
    )
    def test_property_39_individual_partition_color_coding(self, partition_types, partition_sizes, start_lbas):
        """
        Property 39: Individual partition color coding
        
        For any MBR with partition entries, each partition should have a distinct color
        and the color assignment should be consistent across all access methods.
        
        **Validates: Requirements 12.1, 12.2, 12.3, 12.4**
        """
        # Create test MBR with specified partitions
        test_mbr = bytearray(512)
        test_mbr[510:512] = struct.pack('<H', 0x55AA)  # Boot signature
        
        # Add partition entries
        for i in range(4):
            offset = 446 + (i * 16)
            if partition_sizes[i] > 0:  # Non-empty partition
                test_mbr[offset] = 0x80 if i == 0 else 0x00  # First partition bootable
                test_mbr[offset + 4] = partition_types[i]  # Partition type
                test_mbr[offset + 8:offset + 12] = struct.pack('<I', start_lbas[i])  # Start LBA
                test_mbr[offset + 12:offset + 16] = struct.pack('<I', partition_sizes[i])  # Size
        
        decoder = MBRDecoder()
        mbr_structure = decoder.parse_mbr(bytes(test_mbr))
        
        # Test that each partition gets a distinct color
        partition_colors = {}
        for i in range(4):
            partition_offset = 446 + (i * 16)
            section, partition_num = decoder.get_partition_section_type(partition_offset)
            
            assert section == MBRSection.PARTITION_TABLE
            assert partition_num == i + 1
            
            html_color, ansi_color, part_num = decoder.get_partition_color_info(
                partition_offset, mbr_structure
            )
            
            # Store colors for uniqueness check
            partition_colors[i + 1] = {
                'html': html_color,
                'ansi': ansi_color,
                'partition_num': part_num,
                'is_empty': mbr_structure.partition_entries[i].is_empty
            }
        
        # Verify color consistency and distinctness
        non_empty_partitions = [p for p in partition_colors.values() if not p['is_empty']]
        if len(non_empty_partitions) > 1:
            # Non-empty partitions should have distinct colors
            html_colors = [p['html'] for p in non_empty_partitions]
            assert len(set(html_colors)) == len(html_colors), "Non-empty partitions should have distinct HTML colors"
        
        # Empty partitions should all use the same empty color
        empty_partitions = [p for p in partition_colors.values() if p['is_empty']]
        if empty_partitions:
            empty_html_colors = [p['html'] for p in empty_partitions]
            assert all(color == PartitionColors.EMPTY_PARTITION for color in empty_html_colors), \
                "Empty partitions should all use the empty partition color"

    @given(
        empty_partition_count=st.integers(min_value=1, max_value=4)
    )
    def test_property_40_empty_partition_color_handling(self, empty_partition_count):
        """
        Property 40: Empty partition color handling
        
        For any MBR with empty partitions, empty partitions should use the designated
        empty partition color consistently.
        
        **Validates: Requirements 12.5**
        """
        # Create test MBR with some empty partitions
        test_mbr = bytearray(512)
        test_mbr[510:512] = struct.pack('<H', 0x55AA)  # Boot signature
        
        # Add some non-empty partitions first, then empty ones
        for i in range(4 - empty_partition_count):
            offset = 446 + (i * 16)
            test_mbr[offset] = 0x80 if i == 0 else 0x00  # First partition bootable
            test_mbr[offset + 4] = 0x83  # Linux partition type
            test_mbr[offset + 8:offset + 12] = struct.pack('<I', 2048 + i * 1000)  # Start LBA
            test_mbr[offset + 12:offset + 16] = struct.pack('<I', 1000)  # Size
        
        # Remaining partitions are empty (all zeros)
        
        decoder = MBRDecoder()
        mbr_structure = decoder.parse_mbr(bytes(test_mbr))
        
        # Check empty partition color handling
        empty_partition_colors = []
        for i in range(4):
            partition = mbr_structure.partition_entries[i]
            if partition.is_empty:
                partition_offset = 446 + (i * 16)
                html_color, ansi_color, part_num = decoder.get_partition_color_info(
                    partition_offset, mbr_structure
                )
                empty_partition_colors.append(html_color)
        
        # All empty partitions should use the same color
        if empty_partition_colors:
            assert all(color == PartitionColors.EMPTY_PARTITION for color in empty_partition_colors), \
                "All empty partitions should use the designated empty partition color"
            assert len(empty_partition_colors) == empty_partition_count, \
                "Should have correct number of empty partitions"

    @given(
        partition_configs=st.lists(
            st.tuples(
                st.integers(min_value=0, max_value=255),  # partition type
                st.integers(min_value=0, max_value=1000000)  # size (0 = empty)
            ),
            min_size=4, max_size=4
        )
    )
    def test_property_41_partition_color_legend_inclusion(self, partition_configs):
        """
        Property 41: Partition color legend inclusion
        
        For any MBR structure, the generated color legend should include entries
        for all partitions with appropriate color indicators and status descriptions.
        
        **Validates: Requirements 12.6**
        """
        # Create test MBR with specified partition configuration
        test_mbr = bytearray(512)
        test_mbr[510:512] = struct.pack('<H', 0x55AA)  # Boot signature
        
        for i, (part_type, size) in enumerate(partition_configs):
            offset = 446 + (i * 16)
            if size > 0:  # Non-empty partition
                test_mbr[offset] = 0x80 if i == 0 else 0x00  # First partition bootable
                test_mbr[offset + 4] = part_type  # Partition type
                test_mbr[offset + 8:offset + 12] = struct.pack('<I', 2048 + i * 1000)  # Start LBA
                test_mbr[offset + 12:offset + 16] = struct.pack('<I', size)  # Size
        
        decoder = MBRDecoder()
        mbr_structure = decoder.parse_mbr(bytes(test_mbr))
        
        # Test human-readable legend
        human_legend = decoder.generate_partition_color_legend(mbr_structure, "human")
        assert "Partition Color Legend:" in human_legend
        
        # Should include all 4 partitions
        for i in range(4):
            assert f"Partition {i + 1}" in human_legend
        
        # Test HTML legend
        html_legend = decoder.generate_partition_color_legend(mbr_structure, "html")
        assert "<ul>" in html_legend and "</ul>" in html_legend
        
        # Should include all 4 partitions with proper HTML structure
        for i in range(4):
            assert f"Partition {i + 1}" in html_legend
            # Should have color indicator span
            assert "background-color:" in html_legend
        
        # Verify legend content matches partition status
        for i, (part_type, size) in enumerate(partition_configs):
            partition_num = i + 1
            if size == 0:
                assert "Empty" in human_legend
                assert "Empty" in html_legend
            else:
                assert f"0x{part_type:02X}" in human_legend
                assert f"0x{part_type:02X}" in html_legend

    @given(
        partition_data=st.lists(
            st.tuples(
                st.integers(min_value=0, max_value=255),  # partition type
                st.integers(min_value=0, max_value=1000000),  # size
                st.integers(min_value=0, max_value=1000000)   # start LBA
            ),
            min_size=4, max_size=4
        )
    )
    def test_property_42_cross_format_partition_color_consistency(self, partition_data):
        """
        Property 42: Cross-format partition color consistency
        
        For any MBR structure, partition colors should be consistent across
        human-readable, JSON, and HTML output formats.
        
        **Validates: Requirements 12.7**
        """
        # Create test MBR
        test_mbr = bytearray(512)
        test_mbr[510:512] = struct.pack('<H', 0x55AA)  # Boot signature
        
        for i, (part_type, size, start_lba) in enumerate(partition_data):
            offset = 446 + (i * 16)
            if size > 0:  # Non-empty partition
                test_mbr[offset] = 0x80 if i == 0 else 0x00  # First partition bootable
                test_mbr[offset + 4] = part_type  # Partition type
                test_mbr[offset + 8:offset + 12] = struct.pack('<I', start_lba)  # Start LBA
                test_mbr[offset + 12:offset + 16] = struct.pack('<I', size)  # Size
        
        # Create minimal analysis result for testing
        hexdump_data = HexdumpData(
            total_bytes=512,
            ascii_representation='test',
            formatted_lines=['test'],
            raw_data=bytes(test_mbr)
        )
        
        mbr_struct = MBRStructure(
            bootstrap_code=bytes(446),
            partition_table=[
                PartitionEntry(
                    status=0x80 if i == 0 and partition_data[i][1] > 0 else 0x00,
                    start_chs=(0, 0, 1),
                    partition_type=partition_data[i][0] if partition_data[i][1] > 0 else 0,
                    end_chs=(0, 0, 1),
                    start_lba=partition_data[i][2] if partition_data[i][1] > 0 else 0,
                    size_sectors=partition_data[i][1]
                ) for i in range(4)
            ],
            boot_signature=0x55AA
        )
        
        structure_analysis = StructureAnalysis(
            is_valid_signature=True,
            partition_count=sum(1 for _, size, _ in partition_data if size > 0),
            mbr_structure=mbr_struct,
            anomalies=[]
        )
        
        content_analysis = ContentAnalysis(
            hashes={'md5': 'test', 'sha256': 'test'},
            entropy=0.5,
            strings=[],
            urls=[],
            suspicious_patterns=[]
        )
        
        security_analysis = SecurityAnalysis(
            threat_level=ThreatLevel.LOW,
            detected_threats=[],
            bootkit_indicators=[],
            suspicious_patterns=[],
            anomalies=[]
        )
        
        result = AnalysisResult(
            source='test.bin',
            timestamp=datetime.now(),
            structure_analysis=structure_analysis,
            content_analysis=content_analysis,
            security_analysis=security_analysis,
            threat_intelligence=None,
            hexdump=hexdump_data,
            disassembly=None
        )
        
        # Generate reports in different formats
        generator = ReportGenerator()
        
        # Get JSON report and extract partition colors
        json_report = generator._generate_json_report(result)
        json_data = json.loads(json_report)
        
        # Get HTML report
        html_report = generator._generate_html_report(result)
        
        # Get MBR decoder for direct color info
        decoder = MBRDecoder()
        mbr_structure = decoder.parse_mbr(bytes(test_mbr))
        
        # Verify color consistency across formats
        if 'partition_colors' in json_data.get('hexdump', {}):
            json_colors = json_data['hexdump']['partition_colors']
            
            for i in range(4):
                partition_key = f'partition_{i + 1}'
                if partition_key in json_colors:
                    json_color = json_colors[partition_key]['html_color']
                    json_empty = json_colors[partition_key]['is_empty']
                    
                    # Get color from decoder
                    partition_offset = 446 + (i * 16)
                    decoder_html_color, _, _ = decoder.get_partition_color_info(
                        partition_offset, mbr_structure
                    )
                    
                    # Colors should match between JSON and decoder
                    assert json_color == decoder_html_color, \
                        f"JSON color {json_color} should match decoder color {decoder_html_color} for partition {i + 1}"
                    
                    # Empty status should match
                    decoder_empty = mbr_structure.partition_entries[i].is_empty
                    assert json_empty == decoder_empty, \
                        f"JSON empty status {json_empty} should match decoder empty status {decoder_empty} for partition {i + 1}"
                    
                    # HTML should contain the appropriate CSS class
                    expected_css_class = f'mbr-partition-{i + 1}' if not json_empty else 'mbr-partition-empty'
                    assert expected_css_class in html_report, \
                        f"HTML report should contain CSS class {expected_css_class} for partition {i + 1}"