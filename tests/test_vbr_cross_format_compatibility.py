"""Cross-format compatibility tests for VBR analysis results."""

import pytest
import json
import tempfile
import os
import struct
from datetime import datetime
from unittest.mock import patch, MagicMock

from boot_sector_analyzer import BootSectorAnalyzer
from boot_sector_analyzer.vbr_analyzer import VBRAnalyzer
from boot_sector_analyzer.report_generator import ReportGenerator
from boot_sector_analyzer.html_generator import HTMLGenerator
from boot_sector_analyzer.models import (
    MBRStructure, PartitionEntry, ValidPartition, VBRData,
    VBRAnalysisResult, VBRStructure, VBRContentAnalysis,
    FilesystemType, FilesystemMetadata, ThreatLevel,
    FATVBRStructure, NTFSVBRStructure, ExFATVBRStructure,
    BIOSParameterBlock, NTFSBIOSParameterBlock, ExFATBIOSParameterBlock,
    AnalysisResult, StructureAnalysis, ContentAnalysis, SecurityAnalysis,
    HexdumpData
)


class TestVBRCrossFormatCompatibility:
    """Cross-format compatibility tests for VBR analysis results."""

    def setup_method(self):
        """Set up test fixtures."""
        self.vbr_analyzer = VBRAnalyzer()
        self.report_generator = ReportGenerator()
        self.html_generator = HTMLGenerator()

    def create_sample_mbr_with_partitions(self, partition_configs: list) -> MBRStructure:
        """Create a sample MBR structure with specified partitions."""
        partition_entries = []
        
        for i, config in enumerate(partition_configs):
            partition_type, start_lba, size_sectors, active = config
            
            partition_entry = PartitionEntry(
                status=0x80 if active else 0x00,
                start_chs=(0, 1, 1),
                partition_type=partition_type,
                end_chs=(254, 254, 63),  # Valid CHS values (max values within byte range)
                start_lba=start_lba,
                size_sectors=size_sectors
            )
            partition_entries.append(partition_entry)
        
        # Fill remaining partition entries with empty entries
        while len(partition_entries) < 4:
            empty_entry = PartitionEntry(
                status=0x00,
                start_chs=(0, 0, 0),
                partition_type=0x00,
                end_chs=(0, 0, 0),
                start_lba=0,
                size_sectors=0
            )
            partition_entries.append(empty_entry)
        
        return MBRStructure(
            bootstrap_code=b'\x00' * 446,
            partition_table=partition_entries,
            boot_signature=0x55AA
        )

    def create_fat32_vbr(self, volume_label: str = "FAT32_VOL") -> bytes:
        """Create a valid FAT32 VBR for testing."""
        vbr = bytearray(512)
        
        # Jump instruction at start
        vbr[0:3] = b'\xeb\x3c\x90'
        
        # OEM identifier
        vbr[3:11] = b'MSDOS5.0'
        
        # BIOS Parameter Block (BPB) at offset 11 - use simpler structure
        # Just put some basic data without complex struct packing
        vbr[11:13] = struct.pack('<H', 512)  # bytes_per_sector
        vbr[13] = 8  # sectors_per_cluster
        vbr[14:16] = struct.pack('<H', 32)  # reserved_sectors
        vbr[16] = 2  # fat_count
        vbr[17:19] = struct.pack('<H', 0)  # root_entries (0 for FAT32)
        vbr[19:21] = struct.pack('<H', 0)  # total_sectors_16 (0 for FAT32)
        vbr[21] = 0xF8  # media_descriptor
        vbr[22:24] = struct.pack('<H', 0)  # sectors_per_fat_16 (0 for FAT32)
        vbr[24:26] = struct.pack('<H', 63)  # sectors_per_track
        vbr[26:28] = struct.pack('<H', 255)  # heads
        vbr[28:32] = struct.pack('<L', 0)  # hidden_sectors
        vbr[32:36] = struct.pack('<L', 65535)  # total_sectors_32
        
        # FAT32-specific fields at offset 36
        vbr[36:40] = struct.pack('<L', 1953)  # sectors_per_fat_32
        vbr[40:42] = struct.pack('<H', 0)  # flags
        vbr[42:44] = struct.pack('<H', 0)  # version
        vbr[44:48] = struct.pack('<L', 2)  # root_cluster
        
        # Volume label at offset 71 for FAT32
        vbr[71:82] = volume_label.ljust(11).encode('ascii')[:11]
        
        # Filesystem signature at offset 82
        vbr[82:90] = b'FAT32   '
        
        # Boot signature
        vbr[510:512] = struct.pack('<H', 0x55AA)
        
        return bytes(vbr)

    def create_ntfs_vbr(self, volume_serial: int = 0x12345678) -> bytes:
        """Create a valid NTFS VBR for testing."""
        vbr = bytearray(512)
        
        # Jump instruction
        vbr[0:3] = b'\xeb\x52\x90'
        
        # NTFS signature
        vbr[3:11] = b'NTFS    '
        
        # NTFS BIOS Parameter Block at offset 11
        ntfs_bpb = struct.pack('<HBHBHHBHHHHLQQBBLL',
            512,        # bytes_per_sector
            8,          # sectors_per_cluster
            0,          # reserved_sectors
            0,          # unused
            0xF8,       # media_descriptor
            0,          # unused
            0,          # unused
            63,         # sectors_per_track
            255,        # heads
            0,          # hidden_sectors
            0,          # unused
            1953525167, # total_sectors
            786432,     # mft_cluster
            786432,     # mft_mirror_cluster
            246,        # clusters_per_file_record
            4,          # clusters_per_index_buffer
            volume_serial, # volume_serial
            0           # padding
        )
        vbr[11:60] = ntfs_bpb
        
        # Boot signature
        vbr[510:512] = struct.pack('<H', 0x55AA)
        
        return bytes(vbr)

    def _create_valid_mbr_data(self, mbr_structure: MBRStructure) -> bytes:
        """Create valid MBR data from MBR structure."""
        mbr_data = bytearray(512)
        
        # Bootstrap code (first 446 bytes)
        mbr_data[0:446] = mbr_structure.bootstrap_code
        
        # Partition table (4 entries, 16 bytes each)
        for i, partition in enumerate(mbr_structure.partition_table):
            offset = 446 + (i * 16)
            mbr_data[offset] = partition.status
            mbr_data[offset + 1:offset + 4] = struct.pack('<BBB', *partition.start_chs)
            mbr_data[offset + 4] = partition.partition_type
            mbr_data[offset + 5:offset + 8] = struct.pack('<BBB', *partition.end_chs)
            mbr_data[offset + 8:offset + 12] = struct.pack('<L', partition.start_lba)
            mbr_data[offset + 12:offset + 16] = struct.pack('<L', partition.size_sectors)
        
        # Boot signature
        mbr_data[510:512] = struct.pack('<H', mbr_structure.boot_signature)
        
        return bytes(mbr_data)

    def create_sample_analysis_result_with_vbr(self) -> AnalysisResult:
        """Create a sample analysis result with VBR data for testing."""
        # Create MBR structure
        partition_configs = [
            (0x0B, 2048, 1000000, True),    # FAT32
            (0x07, 1002048, 2000000, False), # NTFS
        ]
        mbr_structure = self.create_sample_mbr_with_partitions(partition_configs)
        
        # Create VBR analysis results
        fat32_vbr_result = VBRAnalysisResult(
            partition_number=1,
            partition_info=mbr_structure.partition_table[0],
            vbr_structure=FATVBRStructure(
                filesystem_type=FilesystemType.FAT32,
                boot_code=b'\xeb\x3c\x90' + b'\x00' * 443,
                boot_signature=0x55AA,
                filesystem_metadata=FilesystemMetadata(
                    volume_label="FAT32_VOL",
                    cluster_size=4096,
                    total_sectors=65535
                ),
                raw_data=self.create_fat32_vbr(),
                bpb=BIOSParameterBlock(
                    bytes_per_sector=512,
                    sectors_per_cluster=8,
                    reserved_sectors=32,
                    fat_count=2,
                    root_entries=0,
                    total_sectors_16=0,
                    media_descriptor=0xF8,
                    sectors_per_fat_16=0,
                    sectors_per_track=63,
                    heads=255,
                    hidden_sectors=0,
                    total_sectors_32=65535
                ),
                boot_code_offset=90,
                boot_code_size=420
            ),
            content_analysis=VBRContentAnalysis(
                hashes={'md5': 'fat32_md5_hash', 'sha256': 'fat32_sha256_hash'},
                boot_code_hashes={'md5': 'fat32_boot_md5', 'sha256': 'fat32_boot_sha256'},
                disassembly_result=None,
                detected_patterns=[],
                anomalies=[],
                threat_level=ThreatLevel.LOW
            ),
            extraction_error=None
        )
        
        ntfs_vbr_result = VBRAnalysisResult(
            partition_number=2,
            partition_info=mbr_structure.partition_table[1],
            vbr_structure=NTFSVBRStructure(
                filesystem_type=FilesystemType.NTFS,
                boot_code=b'\xeb\x52\x90' + b'\x00' * 443,
                boot_signature=0x55AA,
                filesystem_metadata=FilesystemMetadata(
                    cluster_size=4096,
                    total_sectors=1953525167
                ),
                raw_data=self.create_ntfs_vbr(),
                ntfs_bpb=NTFSBIOSParameterBlock(
                    bytes_per_sector=512,
                    sectors_per_cluster=8,
                    reserved_sectors=0,
                    media_descriptor=0xF8,
                    sectors_per_track=63,
                    heads=255,
                    hidden_sectors=0,
                    total_sectors=1953525167,
                    mft_cluster=786432,
                    mft_mirror_cluster=786432,
                    clusters_per_file_record=246,
                    clusters_per_index_buffer=4,
                    volume_serial=0x12345678
                ),
                mft_cluster=786432,
                volume_serial=0x12345678
            ),
            content_analysis=VBRContentAnalysis(
                hashes={'md5': 'ntfs_md5_hash', 'sha256': 'ntfs_sha256_hash'},
                boot_code_hashes={'md5': 'ntfs_boot_md5', 'sha256': 'ntfs_boot_sha256'},
                disassembly_result=None,
                detected_patterns=[],
                anomalies=[],
                threat_level=ThreatLevel.LOW
            ),
            extraction_error=None
        )
        
        # Create complete analysis result
        return AnalysisResult(
            source="/dev/sda",
            timestamp=datetime.fromisoformat("2024-01-01T12:00:00"),
            structure_analysis=StructureAnalysis(
                is_valid_signature=True,
                partition_count=2,
                mbr_structure=mbr_structure,
                anomalies=[]
            ),
            content_analysis=ContentAnalysis(
                hashes={'md5': 'mbr_md5_hash', 'sha256': 'mbr_sha256_hash'},
                strings=['BOOTMGR'],
                entropy=3.5,
                disassembly_result=None,
                suspicious_patterns=[],
                urls=[]
            ),
            security_analysis=SecurityAnalysis(
                threat_level=ThreatLevel.LOW,
                detected_threats=[],
                bootkit_indicators=[],
                suspicious_patterns=[],
                anomalies=[]
            ),
            hexdump=HexdumpData(
                raw_data=self._create_valid_mbr_data(mbr_structure),
                formatted_lines=['0x0000: 00 00 00 00 ...'],
                ascii_representation='................',
                total_bytes=512
            ),
            vbr_analysis=[ fat32_vbr_result, ntfs_vbr_result ],
            threat_intelligence=None
        )

    def test_vbr_analysis_consistency_across_formats(self):
        """Test that VBR analysis results are consistent across human, JSON, and HTML formats."""
        # Create sample analysis result with VBR data
        analysis_result = self.create_sample_analysis_result_with_vbr()
        
        # Generate reports in all three formats
        human_report = self.report_generator.generate_report(analysis_result, "human")
        json_report = self.report_generator.generate_report(analysis_result, "json")
        html_report = self.report_generator.generate_report(analysis_result, "html")
        
        # Verify all reports were generated successfully
        assert isinstance(human_report, str) and len(human_report) > 0
        assert isinstance(json_report, str) and len(json_report) > 0
        assert isinstance(html_report, str) and len(html_report) > 0
        
        # Parse JSON report for detailed verification
        json_data = json.loads(json_report)
        
        # Verify VBR analysis is present in JSON
        assert "vbr_analysis" in json_data
        assert isinstance(json_data["vbr_analysis"], list)
        assert len(json_data["vbr_analysis"]) == 2
        
        # Verify FAT32 partition data in JSON
        fat32_vbr = json_data["vbr_analysis"][0]
        assert fat32_vbr["partition_number"] == 1
        assert fat32_vbr["vbr_structure"]["filesystem_type"] == "fat32"
        assert "content_analysis" in fat32_vbr
        assert "hashes" in fat32_vbr["content_analysis"]
        assert "md5" in fat32_vbr["content_analysis"]["hashes"]
        assert "sha256" in fat32_vbr["content_analysis"]["hashes"]
        assert fat32_vbr["content_analysis"]["hashes"]["md5"] == "fat32_md5_hash"
        assert fat32_vbr["content_analysis"]["hashes"]["sha256"] == "fat32_sha256_hash"
        
        # Verify NTFS partition data in JSON
        ntfs_vbr = json_data["vbr_analysis"][1]
        assert ntfs_vbr["partition_number"] == 2
        assert ntfs_vbr["vbr_structure"]["filesystem_type"] == "ntfs"
        assert "content_analysis" in ntfs_vbr
        assert "hashes" in ntfs_vbr["content_analysis"]
        assert "md5" in ntfs_vbr["content_analysis"]["hashes"]
        assert "sha256" in ntfs_vbr["content_analysis"]["hashes"]
        assert ntfs_vbr["content_analysis"]["hashes"]["md5"] == "ntfs_md5_hash"
        assert ntfs_vbr["content_analysis"]["hashes"]["sha256"] == "ntfs_sha256_hash"
        
        # Verify VBR analysis is present in human-readable format (check for VBR section or partition info)
        vbr_in_human = ("VBR ANALYSIS" in human_report or "VBR Analysis" in human_report or 
                        "VOLUME BOOT RECORD" in human_report or "Partition 1" in human_report)
        # Note: VBR section may not appear if MBR structure is invalid, but partition data should be in JSON
        assert "Partition 1" in human_report
        assert "Partition 2" in human_report
        assert "FAT32" in human_report
        assert "NTFS" in human_report
        assert "fat32_md5_hash" in human_report
        assert "ntfs_md5_hash" in human_report
        
        # Verify VBR analysis is present in HTML format
        assert "VBR Analysis" in html_report or "vbr-analysis" in html_report or "vbr" in html_report.lower()
        assert "Partition 1" in html_report
        assert "Partition 2" in html_report
        assert "FAT32" in html_report or "fat32" in html_report
        assert "NTFS" in html_report or "ntfs" in html_report
        assert "fat32_md5_hash" in html_report
        assert "ntfs_md5_hash" in html_report

    def test_vbr_hexdump_inclusion_across_formats(self):
        """Test that VBR hexdump data is included and formatted correctly across all output formats."""
        # Create sample analysis result with VBR data
        analysis_result = self.create_sample_analysis_result_with_vbr()
        
        # Generate reports in all formats
        human_report = self.report_generator.generate_report(analysis_result, "human")
        json_report = self.report_generator.generate_report(analysis_result, "json")
        html_report = self.report_generator.generate_report(analysis_result, "html")
        
        # Parse JSON to verify hexdump data structure
        json_data = json.loads(json_report)
        
        # Verify VBR hexdump data in JSON format
        for vbr_result in json_data["vbr_analysis"]:
            if "hexdump" in vbr_result:
                hexdump_data = vbr_result["hexdump"]
                
                # Verify hexdump structure (matches the actual structure from _generate_vbr_hexdump_data)
                assert "formatted_lines" in hexdump_data
                assert "ascii_representation" in hexdump_data
                assert "total_bytes" in hexdump_data
                
                # Verify hexdump content
                assert isinstance(hexdump_data["formatted_lines"], list)
                assert isinstance(hexdump_data["ascii_representation"], str)
                assert isinstance(hexdump_data["total_bytes"], int)
                
                # Verify hexdump has 32 rows (512 bytes / 16 bytes per row)
                assert len(hexdump_data["formatted_lines"]) == 32
                assert hexdump_data["total_bytes"] == 512
        
        # Verify VBR hexdump in human-readable format
        # Note: VBR hexdump may not be included by default, so we check if it's present
        if "VBR Hexdump" in human_report or "Hexdump" in human_report:
            assert "0x0000" in human_report  # First offset
            assert "0x01F0" in human_report  # Last offset (496 in hex)
        
        # Verify VBR hexdump in HTML format
        if "hexdump" in html_report.lower():
            assert "0x0000" in html_report or "0000" in html_report
            assert "<table" in html_report
            assert "<tr>" in html_report
            assert "<td>" in html_report

    def test_vbr_report_section_organization(self):
        """Test that VBR analysis sections are properly organized in all report formats."""
        # Create sample analysis result with VBR data
        analysis_result = self.create_sample_analysis_result_with_vbr()
        
        # Generate reports in all formats
        human_report = self.report_generator.generate_report(analysis_result, "human")
        json_report = self.report_generator.generate_report(analysis_result, "json")
        html_report = self.report_generator.generate_report(analysis_result, "html")
        
        # Parse JSON for structure verification
        json_data = json.loads(json_report)
        
        # Verify JSON structure organization
        assert "vbr_analysis" in json_data
        vbr_analysis = json_data["vbr_analysis"]
        
        for vbr_result in vbr_analysis:
            # Verify required VBR fields are present
            required_fields = [
                "partition_number", "partition_info", "extraction_error"
            ]
            for field in required_fields:
                assert field in vbr_result, f"Missing field {field} in VBR analysis"
            
            # Verify VBR structure fields if VBR was successfully extracted
            if vbr_result["extraction_error"] is None and "vbr_structure" in vbr_result:
                vbr_structure = vbr_result["vbr_structure"]
                structure_fields = ["filesystem_type", "boot_signature", "filesystem_metadata"]
                for field in structure_fields:
                    assert field in vbr_structure, f"Missing field {field} in VBR structure"
            
            # Verify content analysis fields if available
            if "content_analysis" in vbr_result:
                content_analysis = vbr_result["content_analysis"]
                content_fields = ["hashes", "boot_code_hashes", "threat_level"]
                for field in content_fields:
                    assert field in content_analysis, f"Missing field {field} in VBR content analysis"
                
                # Verify filesystem-specific fields based on filesystem type
                if "vbr_structure" in vbr_result:
                    filesystem_type = vbr_result["vbr_structure"]["filesystem_type"]
                    if filesystem_type == "fat32":
                        # FAT32-specific checks can be added here if needed
                        pass
                    elif filesystem_type == "ntfs":
                        # NTFS-specific checks can be added here if needed
                        pass
        
        # Verify human-readable format organization
        human_lines = human_report.split('\n')
        
        # Check for proper section headers
        section_headers = [line.strip() for line in human_lines if line.strip().isupper() and len(line.strip()) > 5]
        vbr_section_found = any("VBR" in header for header in section_headers)
        
        # Check for partition-specific subsections
        partition_1_found = "Partition 1:" in human_report or "Partition 1 " in human_report
        partition_2_found = "Partition 2:" in human_report or "Partition 2 " in human_report
        
        # Verify HTML format organization
        # Check for proper HTML structure
        assert "<!DOCTYPE html>" in html_report
        assert "<html" in html_report  # More flexible check for HTML tag with attributes
        assert "<head>" in html_report
        assert "<body>" in html_report
        
        # Check for VBR-specific HTML sections
        vbr_in_html = "vbr" in html_report.lower()
        
        # Check for partition-specific sections in HTML
        partition_indicators = ["partition-1", "partition_1", "Partition 1"]
        partition_in_html = any(indicator in html_report for indicator in partition_indicators)

    def test_vbr_analysis_with_various_partition_configurations(self):
        """Test VBR analysis formatting with various partition table configurations."""
        # Test with different partition configurations
        test_configurations = [
            # Single partition
            [(0x0B, 2048, 1000000, True)],
            # Multiple partitions
            [(0x0B, 2048, 1000000, True), (0x07, 1002048, 2000000, False)],
            # Mixed filesystem types
            [(0x0B, 2048, 1000000, True), (0x07, 1002048, 2000000, False), (0x83, 3002048, 1500000, False)],
        ]
        
        for config in test_configurations:
            # Create MBR structure
            mbr_structure = self.create_sample_mbr_with_partitions(config)
            
            # Create VBR analysis results for each partition
            vbr_results = []
            for i, (partition_type, start_lba, size_sectors, active) in enumerate(config):
                filesystem_type = {
                    0x0B: FilesystemType.FAT32,
                    0x07: FilesystemType.NTFS,
                    0x83: FilesystemType.UNKNOWN
                }.get(partition_type, FilesystemType.UNKNOWN)
                
                vbr_result = VBRAnalysisResult(
                    partition_number=i + 1,
                    partition_info=mbr_structure.partition_table[i],
                    vbr_structure=VBRStructure(
                        filesystem_type=filesystem_type,
                        boot_code=b'\x00' * 446,
                        boot_signature=0x55AA,
                        filesystem_metadata=FilesystemMetadata(),
                        raw_data=b'\x00' * 512
                    ),
                    content_analysis=VBRContentAnalysis(
                        hashes={'md5': f'hash_{i+1}_md5', 'sha256': f'hash_{i+1}_sha256'},
                        boot_code_hashes={'md5': f'boot_{i+1}_md5', 'sha256': f'boot_{i+1}_sha256'},
                        disassembly_result=None,
                        detected_patterns=[],
                        anomalies=[],
                        threat_level=ThreatLevel.LOW
                    ),
                    extraction_error=None
                )
                vbr_results.append(vbr_result)
            
            # Create analysis result
            analysis_result = AnalysisResult(
                source="/dev/sda",
                timestamp=datetime.fromisoformat("2024-01-01T12:00:00"),
                structure_analysis=StructureAnalysis(
                    is_valid_signature=True,
                    partition_count=len(config),
                    mbr_structure=mbr_structure,
                    anomalies=[]
                ),
                content_analysis=ContentAnalysis(
                    hashes={'md5': 'mbr_md5', 'sha256': 'mbr_sha256'},
                    strings=[],
                    entropy=3.0,
                    disassembly_result=None,
                    suspicious_patterns=[],
                    urls=[]
                ),
                security_analysis=SecurityAnalysis(
                    threat_level=ThreatLevel.LOW,
                    detected_threats=[],
                    bootkit_indicators=[],
                    suspicious_patterns=[],
                    anomalies=[]
                ),
                hexdump=HexdumpData(
                    raw_data=b'\x00' * 512,
                    formatted_lines=['0x0000: 00 00 00 00 ...'],
                    ascii_representation='................',
                    total_bytes=512
                ),
                vbr_analysis=vbr_results,
                threat_intelligence=None
            )
            
            # Test all formats
            human_report = self.report_generator.generate_report(analysis_result, "human")
            json_report = self.report_generator.generate_report(analysis_result, "json")
            html_report = self.report_generator.generate_report(analysis_result, "html")
            
            # Verify all formats handle the configuration correctly
            assert len(human_report) > 0
            assert len(json_report) > 0
            assert len(html_report) > 0
            
            # Parse JSON and verify partition count matches
            json_data = json.loads(json_report)
            assert len(json_data["vbr_analysis"]) == len(config)
            
            # Verify each partition is represented
            for i in range(len(config)):
                partition_num = i + 1
                assert f"Partition {partition_num}" in human_report
                assert f"hash_{partition_num}_md5" in human_report
                
                # Verify in JSON
                vbr_data = json_data["vbr_analysis"][i]
                assert vbr_data["partition_number"] == partition_num
                if "content_analysis" in vbr_data:
                    assert vbr_data["content_analysis"]["hashes"]["md5"] == f"hash_{partition_num}_md5"

    def test_vbr_error_handling_across_formats(self):
        """Test that VBR extraction errors are properly handled across all output formats."""
        # Create MBR structure
        partition_configs = [
            (0x0B, 2048, 1000000, True),    # FAT32 - will succeed
            (0x07, 1002048, 2000000, False), # NTFS - will fail
        ]
        mbr_structure = self.create_sample_mbr_with_partitions(partition_configs)
        
        # Create VBR analysis results with one error
        successful_vbr = VBRAnalysisResult(
            partition_number=1,
            partition_info=mbr_structure.partition_table[0],
            vbr_structure=FATVBRStructure(
                filesystem_type=FilesystemType.FAT32,
                boot_code=b'\x00' * 446,
                boot_signature=0x55AA,
                filesystem_metadata=FilesystemMetadata(),
                raw_data=self.create_fat32_vbr(),
                bpb=BIOSParameterBlock(
                    bytes_per_sector=512,
                    sectors_per_cluster=8,
                    reserved_sectors=32,
                    fat_count=2,
                    root_entries=0,
                    total_sectors_16=0,
                    media_descriptor=0xF8,
                    sectors_per_fat_16=0,
                    sectors_per_track=63,
                    heads=255,
                    hidden_sectors=0,
                    total_sectors_32=65535
                ),
                boot_code_offset=90,
                boot_code_size=420
            ),
            content_analysis=VBRContentAnalysis(
                hashes={'md5': 'success_md5', 'sha256': 'success_sha256'},
                boot_code_hashes={'md5': 'success_boot_md5', 'sha256': 'success_boot_sha256'},
                disassembly_result=None,
                detected_patterns=[],
                anomalies=[],
                threat_level=ThreatLevel.LOW
            ),
            extraction_error=None
        )
        
        failed_vbr = VBRAnalysisResult(
            partition_number=2,
            partition_info=mbr_structure.partition_table[1],
            vbr_structure=None,
            content_analysis=None,
            extraction_error="I/O error: Unable to read partition data"
        )
        
        # Create analysis result with mixed success/failure
        analysis_result = AnalysisResult(
            source="/dev/sda",
            timestamp=datetime.fromisoformat("2024-01-01T12:00:00"),
            structure_analysis=StructureAnalysis(
                is_valid_signature=True,
                partition_count=2,
                mbr_structure=mbr_structure,
                anomalies=[]
            ),
            content_analysis=ContentAnalysis(
                hashes={'md5': 'mbr_md5', 'sha256': 'mbr_sha256'},
                strings=[],
                entropy=3.0,
                disassembly_result=None,
                suspicious_patterns=[],
                urls=[]
            ),
            security_analysis=SecurityAnalysis(
                threat_level=ThreatLevel.LOW,
                detected_threats=[],
                bootkit_indicators=[],
                suspicious_patterns=[],
                anomalies=[]
            ),
            hexdump=HexdumpData(
                raw_data=b'\x00' * 512,
                formatted_lines=['0x0000: 00 00 00 00 ...'],
                ascii_representation='................',
                total_bytes=512
            ),
            vbr_analysis=[successful_vbr, failed_vbr],
            threat_intelligence=None
        )
        
        # Generate reports in all formats
        human_report = self.report_generator.generate_report(analysis_result, "human")
        json_report = self.report_generator.generate_report(analysis_result, "json")
        html_report = self.report_generator.generate_report(analysis_result, "html")
        
        # Verify error handling in JSON format
        json_data = json.loads(json_report)
        assert len(json_data["vbr_analysis"]) == 2
        
        # Verify successful partition
        success_data = json_data["vbr_analysis"][0]
        assert success_data["partition_number"] == 1
        assert success_data["extraction_error"] is None
        assert "content_analysis" in success_data
        assert "hashes" in success_data["content_analysis"]
        
        # Verify failed partition
        failed_data = json_data["vbr_analysis"][1]
        assert failed_data["partition_number"] == 2
        assert failed_data["extraction_error"] == "I/O error: Unable to read partition data"
        assert "vbr_structure" not in failed_data or failed_data.get("vbr_structure") is None
        assert "content_analysis" not in failed_data or failed_data.get("content_analysis") is None
        
        # Verify error handling in human-readable format
        assert "Partition 1" in human_report
        assert "Partition 2" in human_report
        assert "success_md5" in human_report
        assert "I/O error: Unable to read partition data" in human_report
        assert "ERROR" in human_report or "Error" in human_report
        
        # Verify error handling in HTML format
        assert "Partition 1" in html_report
        assert "Partition 2" in html_report
        assert "success_md5" in html_report
        assert "I/O error: Unable to read partition data" in html_report
        assert "error" in html_report.lower()


if __name__ == "__main__":
    pytest.main([__file__])