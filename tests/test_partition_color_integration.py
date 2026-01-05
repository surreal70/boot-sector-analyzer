"""Integration tests for complete partition color coding workflow."""

import pytest
import tempfile
import struct
from pathlib import Path
from boot_sector_analyzer.analyzer import BootSectorAnalyzer
from boot_sector_analyzer.mbr_decoder import MBRDecoder, PartitionColors, MBRSection
from boot_sector_analyzer.models import AnalysisResult
import json


class TestPartitionColorIntegration:
    """Integration tests for complete partition color coding workflow."""

    def create_test_mbr_with_partitions(self, partition_configs):
        """
        Create a test MBR with specified partition configurations.
        
        Args:
            partition_configs: List of tuples (type, size_sectors, start_lba) for each partition
            
        Returns:
            512-byte MBR data
        """
        mbr_data = bytearray(512)
        
        # Add minimal boot code
        mbr_data[0:10] = b'\x33\xc0\x8e\xd0\x8e\xc0\x8e\xd8\xbc\x00'
        
        # Add disk signature
        mbr_data[440:444] = struct.pack('<I', 0x12345678)
        
        # Add partition entries
        for i, (part_type, size_sectors, start_lba) in enumerate(partition_configs):
            if i >= 4:  # Only 4 partition entries allowed
                break
                
            offset = 446 + (i * 16)
            if size_sectors > 0:  # Non-empty partition
                mbr_data[offset] = 0x80 if i == 0 else 0x00  # First partition bootable
                mbr_data[offset + 1:offset + 4] = b'\x01\x01\x00'  # Start CHS
                mbr_data[offset + 4] = part_type  # Partition type
                mbr_data[offset + 5:offset + 8] = b'\xFE\xFF\xFF'  # End CHS
                mbr_data[offset + 8:offset + 12] = struct.pack('<I', start_lba)  # Start LBA
                mbr_data[offset + 12:offset + 16] = struct.pack('<I', size_sectors)  # Size
        
        # Add boot signature
        mbr_data[510:512] = struct.pack('<H', 0x55AA)
        
        return bytes(mbr_data)

    def test_end_to_end_partition_color_workflow_all_partitions(self):
        """
        Test end-to-end partition color coding with all 4 partition entries populated.
        Verifies color assignments for all partition entries across all output formats.
        """
        # Create MBR with all 4 partitions
        partition_configs = [
            (0x83, 1000000, 2048),      # Linux partition
            (0x0C, 2000000, 1002048),   # FAT32 LBA partition  
            (0x07, 1500000, 3002048),   # NTFS partition
            (0x82, 500000, 4502048)     # Linux swap partition
        ]
        
        mbr_data = self.create_test_mbr_with_partitions(partition_configs)
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.img') as temp_file:
            temp_file.write(mbr_data)
            temp_file_path = temp_file.name
        
        try:
            # Perform complete analysis
            analyzer = BootSectorAnalyzer()
            result = analyzer.analyze(temp_file_path, include_threat_intelligence=False)
            
            # Verify analysis completed successfully
            assert isinstance(result, AnalysisResult)
            assert result.structure_analysis.partition_count == 4
            
            # Generate reports in all formats
            human_report = analyzer.generate_report(result, "human")
            json_report = analyzer.generate_report(result, "json")
            html_report = analyzer.generate_report(result, "html")
            
            # Test MBR decoder directly for color assignments
            decoder = MBRDecoder()
            mbr_structure = decoder.parse_mbr(mbr_data)
            
            # Verify each partition gets distinct colors
            partition_colors = {}
            for i in range(4):
                partition_offset = 446 + (i * 16)
                html_color, ansi_color, part_num = decoder.get_partition_color_info(
                    partition_offset, mbr_structure
                )
                
                partition_colors[i + 1] = {
                    'html': html_color,
                    'ansi': ansi_color,
                    'partition_num': part_num,
                    'is_empty': mbr_structure.partition_entries[i].is_empty
                }
            
            # All partitions should be non-empty and have distinct colors
            html_colors = [info['html'] for info in partition_colors.values()]
            assert len(set(html_colors)) == 4, "All 4 partitions should have distinct HTML colors"
            
            # Verify expected colors are assigned
            expected_colors = [
                PartitionColors.PARTITION_1,
                PartitionColors.PARTITION_2, 
                PartitionColors.PARTITION_3,
                PartitionColors.PARTITION_4
            ]
            
            for i, expected_color in enumerate(expected_colors, 1):
                assert partition_colors[i]['html'] == expected_color, \
                    f"Partition {i} should have color {expected_color}"
                assert not partition_colors[i]['is_empty'], \
                    f"Partition {i} should not be empty"
            
            # Verify color legend is included in human report
            assert "Partition Color Legend:" in human_report
            for i in range(1, 5):
                assert f"Partition {i}" in human_report
            
            # Verify HTML report contains partition-specific CSS classes
            for i in range(1, 5):
                expected_css_class = f'mbr-partition-{i}'
                assert expected_css_class in html_report, \
                    f"HTML report should contain CSS class {expected_css_class}"
            
            # Verify JSON report contains partition color metadata
            json_data = json.loads(json_report)
            if 'partition_colors' in json_data.get('hexdump', {}):
                partition_colors_json = json_data['hexdump']['partition_colors']
                
                for i in range(1, 5):
                    partition_key = f'partition_{i}'
                    assert partition_key in partition_colors_json, \
                        f"JSON should contain {partition_key}"
                    
                    json_color = partition_colors_json[partition_key]['html_color']
                    expected_color = expected_colors[i - 1]
                    assert json_color == expected_color, \
                        f"JSON color for partition {i} should be {expected_color}"
                    
                    assert not partition_colors_json[partition_key]['is_empty'], \
                        f"JSON should show partition {i} as not empty"
            
        finally:
            Path(temp_file_path).unlink(missing_ok=True)

    def test_end_to_end_partition_color_workflow_mixed_partitions(self):
        """
        Test end-to-end partition color coding with mix of empty and non-empty partitions.
        Verifies empty partition handling and color assignment.
        """
        # Create MBR with 2 partitions and 2 empty entries
        partition_configs = [
            (0x83, 1000000, 2048),      # Linux partition
            (0, 0, 0),                  # Empty partition
            (0x07, 1500000, 3002048),   # NTFS partition
            (0, 0, 0)                   # Empty partition
        ]
        
        mbr_data = self.create_test_mbr_with_partitions(partition_configs)
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.img') as temp_file:
            temp_file.write(mbr_data)
            temp_file_path = temp_file.name
        
        try:
            # Perform complete analysis
            analyzer = BootSectorAnalyzer()
            result = analyzer.analyze(temp_file_path, include_threat_intelligence=False)
            
            # Verify analysis completed successfully
            assert isinstance(result, AnalysisResult)
            assert result.structure_analysis.partition_count == 2  # Only non-empty partitions counted
            
            # Generate reports in all formats
            human_report = analyzer.generate_report(result, "human")
            json_report = analyzer.generate_report(result, "json")
            html_report = analyzer.generate_report(result, "html")
            
            # Test MBR decoder for color assignments
            decoder = MBRDecoder()
            mbr_structure = decoder.parse_mbr(mbr_data)
            
            # Verify color assignments
            for i in range(4):
                partition_offset = 446 + (i * 16)
                html_color, ansi_color, part_num = decoder.get_partition_color_info(
                    partition_offset, mbr_structure
                )
                
                partition_entry = mbr_structure.partition_entries[i]
                
                if partition_entry.is_empty:
                    # Empty partitions should use empty color
                    assert html_color == PartitionColors.EMPTY_PARTITION, \
                        f"Empty partition {i + 1} should use empty partition color"
                else:
                    # Non-empty partitions should use distinct colors
                    expected_colors = {
                        1: PartitionColors.PARTITION_1,
                        3: PartitionColors.PARTITION_3
                    }
                    expected_color = expected_colors.get(i + 1)
                    if expected_color:
                        assert html_color == expected_color, \
                            f"Non-empty partition {i + 1} should have color {expected_color}"
            
            # Verify color legend includes both empty and non-empty partitions
            assert "Partition Color Legend:" in human_report
            assert "Empty" in human_report  # Should show empty partitions
            assert "Linux" in human_report or "0x83" in human_report  # Should show Linux partition
            assert "NTFS" in human_report or "0x07" in human_report   # Should show NTFS partition
            
            # Verify HTML contains appropriate CSS classes
            assert 'mbr-partition-1' in html_report  # Non-empty partition 1
            assert 'mbr-partition-3' in html_report  # Non-empty partition 3
            
        finally:
            Path(temp_file_path).unlink(missing_ok=True)

    def test_end_to_end_partition_color_workflow_all_empty(self):
        """
        Test end-to-end partition color coding with all empty partitions.
        Verifies handling of completely empty partition table.
        """
        # Create MBR with all empty partitions
        partition_configs = [
            (0, 0, 0),  # Empty partition 1
            (0, 0, 0),  # Empty partition 2
            (0, 0, 0),  # Empty partition 3
            (0, 0, 0)   # Empty partition 4
        ]
        
        mbr_data = self.create_test_mbr_with_partitions(partition_configs)
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.img') as temp_file:
            temp_file.write(mbr_data)
            temp_file_path = temp_file.name
        
        try:
            # Perform complete analysis
            analyzer = BootSectorAnalyzer()
            result = analyzer.analyze(temp_file_path, include_threat_intelligence=False)
            
            # Verify analysis completed successfully
            assert isinstance(result, AnalysisResult)
            assert result.structure_analysis.partition_count == 0  # No non-empty partitions
            
            # Generate reports in all formats
            human_report = analyzer.generate_report(result, "human")
            json_report = analyzer.generate_report(result, "json")
            html_report = analyzer.generate_report(result, "html")
            
            # Test MBR decoder for color assignments
            decoder = MBRDecoder()
            mbr_structure = decoder.parse_mbr(mbr_data)
            
            # All partitions should be empty and use empty color
            for i in range(4):
                partition_offset = 446 + (i * 16)
                html_color, ansi_color, part_num = decoder.get_partition_color_info(
                    partition_offset, mbr_structure
                )
                
                assert html_color == PartitionColors.EMPTY_PARTITION, \
                    f"Empty partition {i + 1} should use empty partition color"
                assert mbr_structure.partition_entries[i].is_empty, \
                    f"Partition {i + 1} should be empty"
            
            # Verify color legend shows all partitions as empty
            assert "Partition Color Legend:" in human_report
            empty_count = human_report.count("Empty")
            assert empty_count >= 4, "Should show all 4 partitions as empty"
            
            # Verify JSON metadata reflects empty partitions
            json_data = json.loads(json_report)
            if 'partition_colors' in json_data.get('hexdump', {}):
                partition_colors_json = json_data['hexdump']['partition_colors']
                
                for i in range(1, 5):
                    partition_key = f'partition_{i}'
                    if partition_key in partition_colors_json:
                        assert partition_colors_json[partition_key]['is_empty'], \
                            f"JSON should show partition {i} as empty"
                        assert partition_colors_json[partition_key]['html_color'] == PartitionColors.EMPTY_PARTITION, \
                            f"JSON should show partition {i} with empty color"
            
        finally:
            Path(temp_file_path).unlink(missing_ok=True)

    def test_partition_color_hexdump_integration(self):
        """
        Test partition color integration in hexdump display.
        Verifies that partition table bytes are properly colored in hexdump output.
        """
        # Create MBR with specific partition layout for testing
        partition_configs = [
            (0x83, 1000000, 2048),      # Linux partition
            (0x0C, 2000000, 1002048),   # FAT32 LBA partition
            (0, 0, 0),                  # Empty partition
            (0, 0, 0)                   # Empty partition
        ]
        
        mbr_data = self.create_test_mbr_with_partitions(partition_configs)
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.img') as temp_file:
            temp_file.write(mbr_data)
            temp_file_path = temp_file.name
        
        try:
            # Perform analysis
            analyzer = BootSectorAnalyzer()
            result = analyzer.analyze(temp_file_path, include_threat_intelligence=False)
            
            # Generate human report with colors
            human_report = analyzer.generate_report(result, "human")
            
            # Verify hexdump section is present
            assert "0x0000" in human_report  # Hexdump should be present
            # Partition table spans 0x01BE-0x01FD, so we should see offsets in that range
            assert any(offset in human_report for offset in ["0x01B0", "0x01C0", "0x01D0", "0x01E0", "0x01F0"]), \
                "Should contain partition table area offsets"
            
            # Verify partition color legend is present
            assert "Partition Color Legend:" in human_report
            
            # Test direct hexdump generation with colors
            from boot_sector_analyzer.report_generator import ReportGenerator
            generator = ReportGenerator()
            
            # Generate colored hexdump
            colored_hexdump = generator.generate_hexdump(mbr_data, use_colors=True)
            
            # Should contain partition table offsets
            # Partition table spans 0x01BE-0x01FD, so check for offsets in that range
            assert any(offset in colored_hexdump for offset in ["0x01B0", "0x01C0", "0x01D0", "0x01E0", "0x01F0"]), \
                "Should contain partition table area offsets"
            
            # Should contain color legend
            assert "Partition Color Legend:" in colored_hexdump
            
            # Test HTML hexdump contains partition-specific styling
            html_report = analyzer.generate_report(result, "html")
            
            # Should contain partition-specific CSS classes
            assert 'mbr-partition-1' in html_report
            assert 'mbr-partition-2' in html_report
            
            # Should contain hexdump table
            assert 'hexdump' in html_report.lower()
            # Check for partition table area in HTML (hex values, not necessarily exact offsets)
            assert any(hex_val in html_report for hex_val in ["01B", "01C", "01D", "01E", "01F"]), \
                "Should contain partition table area hex values"
            
        finally:
            Path(temp_file_path).unlink(missing_ok=True)

class TestPartitionColorCrossFormatCompatibility:
    """Cross-format compatibility tests for partition color coding."""

    def create_test_mbr_with_partitions(self, partition_configs):
        """
        Create a test MBR with specified partition configurations.
        
        Args:
            partition_configs: List of tuples (type, size_sectors, start_lba) for each partition
            
        Returns:
            512-byte MBR data
        """
        mbr_data = bytearray(512)
        
        # Add minimal boot code
        mbr_data[0:10] = b'\x33\xc0\x8e\xd0\x8e\xc0\x8e\xd8\xbc\x00'
        
        # Add disk signature
        mbr_data[440:444] = struct.pack('<I', 0x12345678)
        
        # Add partition entries
        for i, (part_type, size_sectors, start_lba) in enumerate(partition_configs):
            if i >= 4:  # Only 4 partition entries allowed
                break
                
            offset = 446 + (i * 16)
            if size_sectors > 0:  # Non-empty partition
                mbr_data[offset] = 0x80 if i == 0 else 0x00  # First partition bootable
                mbr_data[offset + 1:offset + 4] = b'\x01\x01\x00'  # Start CHS
                mbr_data[offset + 4] = part_type  # Partition type
                mbr_data[offset + 5:offset + 8] = b'\xFE\xFF\xFF'  # End CHS
                mbr_data[offset + 8:offset + 12] = struct.pack('<I', start_lba)  # Start LBA
                mbr_data[offset + 12:offset + 16] = struct.pack('<I', size_sectors)  # Size
        
        # Add boot signature
        mbr_data[510:512] = struct.pack('<H', 0x55AA)
        
        return bytes(mbr_data)

    def test_partition_color_consistency_across_formats(self):
        """
        Test that partition colors are consistent across human, JSON, and HTML formats.
        Ensures color assignments remain the same regardless of output format.
        """
        # Create MBR with diverse partition types
        partition_configs = [
            (0x83, 1000000, 2048),      # Linux partition
            (0x0C, 2000000, 1002048),   # FAT32 LBA partition
            (0x07, 1500000, 3002048),   # NTFS partition
            (0, 0, 0)                   # Empty partition
        ]
        
        mbr_data = self.create_test_mbr_with_partitions(partition_configs)
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.img') as temp_file:
            temp_file.write(mbr_data)
            temp_file_path = temp_file.name
        
        try:
            # Perform analysis
            analyzer = BootSectorAnalyzer()
            result = analyzer.analyze(temp_file_path, include_threat_intelligence=False)
            
            # Generate reports in all formats
            human_report = analyzer.generate_report(result, "human")
            json_report = analyzer.generate_report(result, "json")
            html_report = analyzer.generate_report(result, "html")
            
            # Parse JSON for structured comparison
            json_data = json.loads(json_report)
            
            # Get reference colors from MBR decoder
            decoder = MBRDecoder()
            mbr_structure = decoder.parse_mbr(mbr_data)
            
            reference_colors = {}
            for i in range(4):
                partition_offset = 446 + (i * 16)
                html_color, ansi_color, part_num = decoder.get_partition_color_info(
                    partition_offset, mbr_structure
                )
                reference_colors[i + 1] = {
                    'html': html_color,
                    'ansi': ansi_color,
                    'is_empty': mbr_structure.partition_entries[i].is_empty,
                    'system_id': mbr_structure.partition_entries[i].system_id
                }
            
            # Test 1: JSON format color consistency
            if 'partition_colors' in json_data.get('hexdump', {}):
                json_colors = json_data['hexdump']['partition_colors']
                
                for i in range(1, 5):
                    partition_key = f'partition_{i}'
                    if partition_key in json_colors:
                        json_color = json_colors[partition_key]['html_color']
                        json_empty = json_colors[partition_key]['is_empty']
                        
                        # Should match reference colors
                        assert json_color == reference_colors[i]['html'], \
                            f"JSON color for partition {i} should match reference color"
                        assert json_empty == reference_colors[i]['is_empty'], \
                            f"JSON empty status for partition {i} should match reference"
            
            # Test 2: HTML format color consistency
            for i in range(1, 5):
                if not reference_colors[i]['is_empty']:
                    # Non-empty partitions should have partition-specific CSS classes
                    expected_css_class = f'mbr-partition-{i}'
                    assert expected_css_class in html_report, \
                        f"HTML should contain CSS class {expected_css_class} for partition {i}"
                
                # HTML should contain color legend with partition info
                assert f"Partition {i}" in html_report, \
                    f"HTML should contain partition {i} in legend"
            
            # Test 3: Human format color consistency
            # Human format should contain partition color legend
            assert "Partition Color Legend:" in human_report
            
            for i in range(1, 5):
                assert f"Partition {i}" in human_report, \
                    f"Human format should contain partition {i} in legend"
                
                if reference_colors[i]['is_empty']:
                    # Empty partitions should be marked as "Empty"
                    partition_line_found = False
                    for line in human_report.split('\n'):
                        if f"Partition {i}" in line and "Empty" in line:
                            partition_line_found = True
                            break
                    assert partition_line_found, f"Human format should show partition {i} as Empty"
                else:
                    # Non-empty partitions should show system ID
                    system_id_hex = f"0x{reference_colors[i]['system_id']:02X}"
                    partition_line_found = False
                    for line in human_report.split('\n'):
                        if f"Partition {i}" in line and system_id_hex in line:
                            partition_line_found = True
                            break
                    assert partition_line_found, \
                        f"Human format should show partition {i} with system ID {system_id_hex}"
            
            # Test 4: Color assignment consistency across all formats
            expected_colors = [
                PartitionColors.PARTITION_1,  # Partition 1: Linux
                PartitionColors.PARTITION_2,  # Partition 2: FAT32
                PartitionColors.PARTITION_3,  # Partition 3: NTFS
                PartitionColors.EMPTY_PARTITION  # Partition 4: Empty
            ]
            
            for i, expected_color in enumerate(expected_colors, 1):
                assert reference_colors[i]['html'] == expected_color, \
                    f"Partition {i} should have expected color {expected_color}"
            
        finally:
            Path(temp_file_path).unlink(missing_ok=True)

    def test_color_legend_generation_all_formats(self):
        """
        Test color legend generation in all supported output formats.
        Verifies that legends are properly formatted and contain correct information.
        """
        # Create MBR with mixed partition types for comprehensive legend testing
        partition_configs = [
            (0x83, 1000000, 2048),      # Linux partition
            (0, 0, 0),                  # Empty partition
            (0x07, 1500000, 3002048),   # NTFS partition
            (0x82, 500000, 4502048)     # Linux swap partition
        ]
        
        mbr_data = self.create_test_mbr_with_partitions(partition_configs)
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.img') as temp_file:
            temp_file.write(mbr_data)
            temp_file_path = temp_file.name
        
        try:
            # Perform analysis
            analyzer = BootSectorAnalyzer()
            result = analyzer.analyze(temp_file_path, include_threat_intelligence=False)
            
            # Generate reports in all formats
            human_report = analyzer.generate_report(result, "human")
            json_report = analyzer.generate_report(result, "json")
            html_report = analyzer.generate_report(result, "html")
            
            # Test MBR decoder legend generation directly
            decoder = MBRDecoder()
            mbr_structure = decoder.parse_mbr(mbr_data)
            
            # Test human format legend
            human_legend = decoder.generate_partition_color_legend(mbr_structure, "human")
            assert "Partition Color Legend:" in human_legend
            assert "Partition 1" in human_legend and "Linux" in human_legend
            assert "Partition 2" in human_legend and "Empty" in human_legend
            assert "Partition 3" in human_legend and "NTFS" in human_legend
            assert "Partition 4" in human_legend and "swap" in human_legend.lower()
            
            # Test HTML format legend
            html_legend = decoder.generate_partition_color_legend(mbr_structure, "html")
            assert "<ul>" in html_legend and "</ul>" in html_legend
            assert "<li>" in html_legend  # Should have list items
            assert "background-color:" in html_legend  # Should have color styling
            
            for i in range(1, 5):
                assert f"Partition {i}" in html_legend
            
            # Verify legends are included in full reports
            assert "Partition Color Legend:" in human_report
            assert "Partition 1" in html_report and "Partition 4" in html_report
            
            # JSON should contain partition color metadata
            json_data = json.loads(json_report)
            if 'partition_colors' in json_data.get('hexdump', {}):
                partition_colors = json_data['hexdump']['partition_colors']
                
                # Should have entries for all partitions
                for i in range(1, 5):
                    partition_key = f'partition_{i}'
                    if partition_key in partition_colors:
                        assert 'html_color' in partition_colors[partition_key]
                        assert 'is_empty' in partition_colors[partition_key]
                        assert 'system_id' in partition_colors[partition_key]
            
        finally:
            Path(temp_file_path).unlink(missing_ok=True)

    def test_color_assignments_various_partition_configurations(self):
        """
        Test color assignments with various partition table configurations.
        Ensures consistent behavior across different partition layouts.
        """
        test_configurations = [
            # Configuration 1: All different partition types
            {
                'name': 'all_different',
                'partitions': [
                    (0x83, 1000000, 2048),      # Linux
                    (0x0C, 2000000, 1002048),   # FAT32 LBA
                    (0x07, 1500000, 3002048),   # NTFS
                    (0x82, 500000, 4502048)     # Linux swap
                ]
            },
            # Configuration 2: Some empty partitions
            {
                'name': 'mixed_empty',
                'partitions': [
                    (0x83, 1000000, 2048),      # Linux
                    (0, 0, 0),                  # Empty
                    (0x07, 1500000, 3002048),   # NTFS
                    (0, 0, 0)                   # Empty
                ]
            },
            # Configuration 3: Only first partition
            {
                'name': 'single_partition',
                'partitions': [
                    (0x83, 1000000, 2048),      # Linux
                    (0, 0, 0),                  # Empty
                    (0, 0, 0),                  # Empty
                    (0, 0, 0)                   # Empty
                ]
            },
            # Configuration 4: All empty
            {
                'name': 'all_empty',
                'partitions': [
                    (0, 0, 0),                  # Empty
                    (0, 0, 0),                  # Empty
                    (0, 0, 0),                  # Empty
                    (0, 0, 0)                   # Empty
                ]
            }
        ]
        
        for config in test_configurations:
            mbr_data = self.create_test_mbr_with_partitions(config['partitions'])
            
            with tempfile.NamedTemporaryFile(delete=False, suffix='.img') as temp_file:
                temp_file.write(mbr_data)
                temp_file_path = temp_file.name
            
            try:
                # Perform analysis
                analyzer = BootSectorAnalyzer()
                result = analyzer.analyze(temp_file_path, include_threat_intelligence=False)
                
                # Generate all format reports
                human_report = analyzer.generate_report(result, "human")
                json_report = analyzer.generate_report(result, "json")
                html_report = analyzer.generate_report(result, "html")
                
                # All reports should be generated successfully
                assert len(human_report) > 0, f"Human report should be generated for {config['name']}"
                assert len(json_report) > 0, f"JSON report should be generated for {config['name']}"
                assert len(html_report) > 0, f"HTML report should be generated for {config['name']}"
                
                # JSON should be valid
                json_data = json.loads(json_report)
                assert 'source' in json_data, f"JSON should have source field for {config['name']}"
                
                # Test color consistency for this configuration
                decoder = MBRDecoder()
                mbr_structure = decoder.parse_mbr(mbr_data)
                
                # Verify color assignments are logical
                for i, (part_type, size_sectors, start_lba) in enumerate(config['partitions']):
                    partition_offset = 446 + (i * 16)
                    html_color, ansi_color, part_num = decoder.get_partition_color_info(
                        partition_offset, mbr_structure
                    )
                    
                    if size_sectors == 0:  # Empty partition
                        assert html_color == PartitionColors.EMPTY_PARTITION, \
                            f"Empty partition {i+1} should use empty color in {config['name']}"
                    else:  # Non-empty partition
                        expected_colors = [
                            PartitionColors.PARTITION_1,
                            PartitionColors.PARTITION_2,
                            PartitionColors.PARTITION_3,
                            PartitionColors.PARTITION_4
                        ]
                        assert html_color == expected_colors[i], \
                            f"Non-empty partition {i+1} should use partition-specific color in {config['name']}"
                
                # Verify legends are present and appropriate
                assert "Partition Color Legend:" in human_report, \
                    f"Human report should have color legend for {config['name']}"
                
                # Count non-empty partitions
                non_empty_count = sum(1 for _, size, _ in config['partitions'] if size > 0)
                empty_count = 4 - non_empty_count
                
                if empty_count > 0:
                    empty_occurrences = human_report.count("Empty")
                    assert empty_occurrences >= empty_count, \
                        f"Should show at least {empty_count} empty partitions for {config['name']}"
                
            finally:
                Path(temp_file_path).unlink(missing_ok=True)

    def test_cross_format_hexdump_color_consistency(self):
        """
        Test that hexdump color coding is consistent across different output formats.
        Verifies that the same partition bytes get the same color treatment.
        """
        # Create MBR with specific partition layout
        partition_configs = [
            (0x83, 1000000, 2048),      # Linux partition
            (0x0C, 2000000, 1002048),   # FAT32 LBA partition
            (0, 0, 0),                  # Empty partition
            (0, 0, 0)                   # Empty partition
        ]
        
        mbr_data = self.create_test_mbr_with_partitions(partition_configs)
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.img') as temp_file:
            temp_file.write(mbr_data)
            temp_file_path = temp_file.name
        
        try:
            # Perform analysis
            analyzer = BootSectorAnalyzer()
            result = analyzer.analyze(temp_file_path, include_threat_intelligence=False)
            
            # Generate reports
            human_report = analyzer.generate_report(result, "human")
            json_report = analyzer.generate_report(result, "json")
            html_report = analyzer.generate_report(result, "html")
            
            # Test direct hexdump generation
            from boot_sector_analyzer.report_generator import ReportGenerator
            generator = ReportGenerator()
            
            # Generate hexdump with colors
            colored_hexdump = generator.generate_hexdump(mbr_data, use_colors=True)
            
            # Verify hexdump contains color information
            assert "Partition Color Legend:" in colored_hexdump
            
            # Test MBR decoder color assignments
            decoder = MBRDecoder()
            mbr_structure = decoder.parse_mbr(mbr_data)
            
            # Check specific partition table byte offsets
            partition_offsets = [
                446,   # Partition 1 start
                462,   # Partition 2 start  
                478,   # Partition 3 start
                494    # Partition 4 start
            ]
            
            for i, offset in enumerate(partition_offsets):
                html_color, ansi_color, part_num = decoder.get_partition_color_info(
                    offset, mbr_structure
                )
                
                # Verify partition number matches expected
                assert part_num == i + 1, f"Partition number should be {i + 1} for offset {offset}"
                
                # Verify color assignment
                if mbr_structure.partition_entries[i].is_empty:
                    assert html_color == PartitionColors.EMPTY_PARTITION, \
                        f"Empty partition {i + 1} should use empty color"
                else:
                    expected_colors = [
                        PartitionColors.PARTITION_1,
                        PartitionColors.PARTITION_2,
                        PartitionColors.PARTITION_3,
                        PartitionColors.PARTITION_4
                    ]
                    assert html_color == expected_colors[i], \
                        f"Non-empty partition {i + 1} should use partition-specific color"
            
            # Verify HTML contains appropriate styling
            assert 'mbr-partition-1' in html_report, "HTML should contain partition 1 CSS class"
            assert 'mbr-partition-2' in html_report, "HTML should contain partition 2 CSS class"
            
            # Verify JSON contains color metadata if present
            json_data = json.loads(json_report)
            if 'partition_colors' in json_data.get('hexdump', {}):
                partition_colors = json_data['hexdump']['partition_colors']
                
                # Check that JSON colors match decoder colors
                for i in range(1, 3):  # First 2 partitions are non-empty
                    partition_key = f'partition_{i}'
                    if partition_key in partition_colors:
                        json_color = partition_colors[partition_key]['html_color']
                        
                        # Get reference color from decoder
                        offset = 446 + (i - 1) * 16
                        ref_color, _, _ = decoder.get_partition_color_info(offset, mbr_structure)
                        
                        assert json_color == ref_color, \
                            f"JSON color for partition {i} should match decoder color"
            
        finally:
            Path(temp_file_path).unlink(missing_ok=True)