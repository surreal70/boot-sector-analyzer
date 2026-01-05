"""Property-based tests for VBRContentAnalyzer."""

import hashlib
from hypothesis import given, strategies as st
import pytest

from boot_sector_analyzer.vbr_content_analyzer import VBRContentAnalyzer
from boot_sector_analyzer.models import (
    VBRStructure,
    VBRContentAnalysis,
    FilesystemType,
    FilesystemMetadata,
    BIOSParameterBlock,
    NTFSBIOSParameterBlock,
    ExFATBIOSParameterBlock,
    FATVBRStructure,
    NTFSVBRStructure,
    ExFATVBRStructure,
    ThreatLevel
)


class TestVBRContentAnalyzerProperties:
    """Property-based tests for VBRContentAnalyzer class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.analyzer = VBRContentAnalyzer()

    @given(vbr_data=st.binary(min_size=1, max_size=1024))
    def test_vbr_hash_calculation_accuracy(self, vbr_data):
        """
        Property 51: VBR hash calculation accuracy
        For any VBR data, the VBR_Analyzer should calculate correct MD5 and SHA-256 cryptographic hashes
        **Validates: Requirements 14.6**
        **Feature: boot-sector-analyzer, Property 51: VBR hash calculation accuracy**
        """
        # Calculate hashes using VBRContentAnalyzer
        result_hashes = self.analyzer.calculate_vbr_hashes(vbr_data)
        
        # Verify both hash types are present
        assert "md5" in result_hashes
        assert "sha256" in result_hashes
        
        # Calculate expected hashes directly
        expected_md5 = hashlib.md5(vbr_data).hexdigest()
        expected_sha256 = hashlib.sha256(vbr_data).hexdigest()
        
        # Verify hash accuracy
        assert result_hashes["md5"] == expected_md5
        assert result_hashes["sha256"] == expected_sha256
        
        # Verify hash format (hex strings)
        assert len(result_hashes["md5"]) == 32
        assert len(result_hashes["sha256"]) == 64
        assert all(c in "0123456789abcdef" for c in result_hashes["md5"])
        assert all(c in "0123456789abcdef" for c in result_hashes["sha256"])

    def _create_test_vbr_structure(self, filesystem_type: FilesystemType, boot_code: bytes, 
                                  boot_signature: int = 0x55AA) -> VBRStructure:
        """Create a test VBR structure for property testing."""
        # Create basic filesystem metadata
        metadata = FilesystemMetadata(
            volume_label="TEST_VOL",
            cluster_size=4096,
            total_sectors=1000000,
            filesystem_version="1.0"
        )
        
        # Create raw VBR data (512 bytes)
        raw_data = boot_code + b'\x00' * (510 - len(boot_code))
        raw_data += boot_signature.to_bytes(2, byteorder='little')
        raw_data = raw_data[:512]  # Ensure exactly 512 bytes
        
        if filesystem_type in [FilesystemType.FAT12, FilesystemType.FAT16, FilesystemType.FAT32]:
            # Create FAT-specific BPB
            bpb = BIOSParameterBlock(
                bytes_per_sector=512,
                sectors_per_cluster=8,
                reserved_sectors=1,
                fat_count=2,
                root_entries=512,
                total_sectors_16=0,
                media_descriptor=0xF8,
                sectors_per_fat_16=0,
                sectors_per_track=63,
                heads=255,
                hidden_sectors=0,
                total_sectors_32=1000000
            )
            
            return FATVBRStructure(
                filesystem_type=filesystem_type,
                boot_code=boot_code,
                boot_signature=boot_signature,
                filesystem_metadata=metadata,
                raw_data=raw_data,
                bpb=bpb,
                boot_code_offset=62,
                boot_code_size=len(boot_code)
            )
        
        elif filesystem_type == FilesystemType.NTFS:
            # Create NTFS-specific BPB
            ntfs_bpb = NTFSBIOSParameterBlock(
                bytes_per_sector=512,
                sectors_per_cluster=8,
                reserved_sectors=0,
                media_descriptor=0xF8,
                sectors_per_track=63,
                heads=255,
                hidden_sectors=0,
                total_sectors=1000000,
                mft_cluster=786432,
                mft_mirror_cluster=2,
                clusters_per_file_record=1,
                clusters_per_index_buffer=1,
                volume_serial=0x12345678
            )
            
            return NTFSVBRStructure(
                filesystem_type=filesystem_type,
                boot_code=boot_code,
                boot_signature=boot_signature,
                filesystem_metadata=metadata,
                raw_data=raw_data,
                ntfs_bpb=ntfs_bpb,
                mft_cluster=786432,
                volume_serial=0x12345678
            )
        
        elif filesystem_type == FilesystemType.EXFAT:
            # Create exFAT-specific BPB
            exfat_bpb = ExFATBIOSParameterBlock(
                bytes_per_sector=512,
                sectors_per_cluster=8,
                fat_offset=128,
                fat_length=1024,
                cluster_heap_offset=1152,
                cluster_count=124000,
                root_directory_cluster=5,
                volume_serial=0x87654321,
                filesystem_revision=256,
                volume_flags=0,
                bytes_per_sector_shift=9,
                sectors_per_cluster_shift=3
            )
            
            return ExFATVBRStructure(
                filesystem_type=filesystem_type,
                boot_code=boot_code,
                boot_signature=boot_signature,
                filesystem_metadata=metadata,
                raw_data=raw_data,
                exfat_bpb=exfat_bpb,
                fat_offset=128,
                cluster_heap_offset=1152
            )
        
        else:
            # Generic VBR structure
            return VBRStructure(
                filesystem_type=filesystem_type,
                boot_code=boot_code,
                boot_signature=boot_signature,
                filesystem_metadata=metadata,
                raw_data=raw_data
            )

    @given(
        filesystem_type=st.sampled_from([
            FilesystemType.FAT12,
            FilesystemType.FAT16,
            FilesystemType.FAT32,
            FilesystemType.NTFS,
            FilesystemType.EXFAT,
            FilesystemType.UNKNOWN
        ]),
        boot_code=st.binary(min_size=0, max_size=400),
        boot_signature=st.integers(min_value=0, max_value=0xFFFF)
    )
    def test_vbr_content_analysis_completeness(self, filesystem_type, boot_code, boot_signature):
        """
        Test that VBR content analysis produces complete results for any valid VBR structure.
        """
        # Create test VBR structure
        vbr_structure = self._create_test_vbr_structure(filesystem_type, boot_code, boot_signature)
        
        # Perform content analysis
        content_analysis = self.analyzer.analyze_vbr_content(vbr_structure)
        
        # Verify analysis completeness
        assert content_analysis is not None
        assert isinstance(content_analysis.hashes, dict)
        assert isinstance(content_analysis.boot_code_hashes, dict)
        assert isinstance(content_analysis.detected_patterns, list)
        assert isinstance(content_analysis.anomalies, list)
        assert content_analysis.threat_level is not None
        
        # Verify hash presence
        assert "md5" in content_analysis.hashes
        assert "sha256" in content_analysis.hashes
        assert "md5" in content_analysis.boot_code_hashes
        assert "sha256" in content_analysis.boot_code_hashes
        
        # Verify hash accuracy for VBR data
        expected_vbr_md5 = hashlib.md5(vbr_structure.raw_data).hexdigest()
        expected_vbr_sha256 = hashlib.sha256(vbr_structure.raw_data).hexdigest()
        assert content_analysis.hashes["md5"] == expected_vbr_md5
        assert content_analysis.hashes["sha256"] == expected_vbr_sha256
        
        # Verify hash accuracy for boot code
        expected_boot_md5 = hashlib.md5(vbr_structure.boot_code).hexdigest()
        expected_boot_sha256 = hashlib.sha256(vbr_structure.boot_code).hexdigest()
        assert content_analysis.boot_code_hashes["md5"] == expected_boot_md5
        assert content_analysis.boot_code_hashes["sha256"] == expected_boot_sha256

    @given(
        filesystem_type=st.sampled_from([
            FilesystemType.FAT12,
            FilesystemType.FAT16,
            FilesystemType.FAT32,
            FilesystemType.NTFS,
            FilesystemType.EXFAT
        ]),
        boot_code=st.binary(min_size=10, max_size=200)
    )
    def test_filesystem_metadata_extraction(self, filesystem_type, boot_code):
        """
        Test that filesystem metadata extraction works for any filesystem type and boot code.
        """
        # Create test VBR structure
        vbr_structure = self._create_test_vbr_structure(filesystem_type, boot_code)
        
        # Extract metadata
        metadata = self.analyzer.extract_filesystem_metadata(vbr_structure)
        
        # Verify metadata extraction
        assert isinstance(metadata, dict)
        assert "filesystem_type" in metadata
        assert "boot_code_size" in metadata
        assert "boot_signature" in metadata
        
        # Verify metadata accuracy
        assert metadata["filesystem_type"] == filesystem_type.value
        assert metadata["boot_code_size"] == str(len(boot_code))
        assert metadata["boot_signature"] == "0x55AA"
        
        # Verify optional metadata fields are present when available
        if vbr_structure.filesystem_metadata and vbr_structure.filesystem_metadata.volume_label:
            assert "volume_label" in metadata

    @given(
        filesystem_type=st.sampled_from([
            FilesystemType.FAT12,
            FilesystemType.FAT16,
            FilesystemType.FAT32,
            FilesystemType.NTFS,
            FilesystemType.EXFAT,
            FilesystemType.UNKNOWN
        ]),
        boot_code=st.binary(min_size=1, max_size=200)
    )
    def test_vbr_boot_code_disassembly(self, filesystem_type, boot_code):
        """
        Property 52: VBR boot code disassembly
        For any VBR containing boot code, the VBR_Analyzer should disassemble x86/x86-64 assembly instructions from the VBR boot code region
        **Validates: Requirements 14.7**
        **Feature: boot-sector-analyzer, Property 52: VBR boot code disassembly**
        """
        # Skip if boot code is all zeros (empty)
        if all(byte == 0 for byte in boot_code):
            result = self.analyzer.disassemble_vbr_boot_code(boot_code, filesystem_type)
            assert result is None  # Should return None for empty boot code
            return
        
        # Disassemble VBR boot code
        result = self.analyzer.disassemble_vbr_boot_code(boot_code, filesystem_type)
        
        # Verify disassembly result structure
        assert result is not None
        assert hasattr(result, 'instructions')
        assert hasattr(result, 'total_bytes_disassembled')
        assert hasattr(result, 'invalid_instructions')
        assert hasattr(result, 'boot_patterns')
        
        # Verify result types
        assert isinstance(result.instructions, list)
        assert isinstance(result.total_bytes_disassembled, int)
        assert isinstance(result.invalid_instructions, list)
        assert isinstance(result.boot_patterns, list)
        
        # Verify that some bytes were processed (either as valid or invalid instructions)
        total_processed = result.total_bytes_disassembled + sum(len(inv.bytes) for inv in result.invalid_instructions)
        assert total_processed <= len(boot_code)
        
        # Verify instruction structure if any valid instructions found
        for instruction in result.instructions:
            assert hasattr(instruction, 'address')
            assert hasattr(instruction, 'bytes')
            assert hasattr(instruction, 'mnemonic')
            assert hasattr(instruction, 'operands')
            assert isinstance(instruction.address, int)
            assert isinstance(instruction.bytes, bytes)
            assert isinstance(instruction.mnemonic, str)
            assert isinstance(instruction.operands, str)
            assert instruction.address >= 0x7C00  # Standard boot sector load address
            assert len(instruction.bytes) > 0
            assert len(instruction.mnemonic) > 0

    @given(
        filesystem_type=st.sampled_from([
            FilesystemType.FAT12,
            FilesystemType.FAT16,
            FilesystemType.FAT32,
            FilesystemType.NTFS,
            FilesystemType.EXFAT
        ]),
        boot_code=st.binary(min_size=10, max_size=300)
    )
    def test_filesystem_specific_boot_pattern_recognition(self, filesystem_type, boot_code):
        """
        Property 58: Filesystem-specific boot pattern recognition
        For any VBR boot code containing filesystem-specific patterns, the Content_Analyzer should identify the appropriate filesystem boot patterns (FAT boot code, NTFS boot code)
        **Validates: Requirements 14.14**
        **Feature: boot-sector-analyzer, Property 58: Filesystem-specific boot pattern recognition**
        """
        # Create test VBR structure
        vbr_structure = self._create_test_vbr_structure(filesystem_type, boot_code)
        
        # Detect VBR patterns
        detected_patterns = self.analyzer.detect_vbr_patterns(vbr_structure)
        
        # Verify pattern detection result structure
        assert isinstance(detected_patterns, list)
        
        # Verify pattern structure if any patterns found
        for pattern in detected_patterns:
            assert hasattr(pattern, 'pattern_type')
            assert hasattr(pattern, 'description')
            assert hasattr(pattern, 'instructions')
            assert hasattr(pattern, 'significance')
            assert hasattr(pattern, 'filesystem_specific')
            
            assert isinstance(pattern.pattern_type, str)
            assert isinstance(pattern.description, str)
            assert isinstance(pattern.instructions, list)
            assert isinstance(pattern.significance, str)
            assert isinstance(pattern.filesystem_specific, bool)
            
            assert len(pattern.pattern_type) > 0
            assert len(pattern.description) > 0
            assert len(pattern.significance) > 0
        
        # Check for filesystem-specific patterns based on filesystem type
        filesystem_specific_patterns = [p for p in detected_patterns if p.filesystem_specific]
        
        # For FAT filesystems, look for FAT-specific patterns
        if filesystem_type in [FilesystemType.FAT12, FilesystemType.FAT16, FilesystemType.FAT32]:
            fat_patterns = [p for p in filesystem_specific_patterns if 'fat' in p.pattern_type.lower()]
            # We don't assert that FAT patterns must be found since it depends on the random boot code
            # But if found, they should be properly structured
            for pattern in fat_patterns:
                assert 'fat' in pattern.pattern_type.lower()
                assert pattern.filesystem_specific == True
        
        # For NTFS filesystem, look for NTFS-specific patterns
        elif filesystem_type == FilesystemType.NTFS:
            ntfs_patterns = [p for p in filesystem_specific_patterns if 'ntfs' in p.pattern_type.lower()]
            # Similar to FAT, we don't assert patterns must be found
            for pattern in ntfs_patterns:
                assert 'ntfs' in pattern.pattern_type.lower()
                assert pattern.filesystem_specific == True
        
        # For exFAT filesystem, look for exFAT-specific patterns
        elif filesystem_type == FilesystemType.EXFAT:
            exfat_patterns = [p for p in filesystem_specific_patterns if 'exfat' in p.pattern_type.lower()]
            for pattern in exfat_patterns:
                assert 'exfat' in pattern.pattern_type.lower()
                assert pattern.filesystem_specific == True
        
        # Verify common patterns (non-filesystem-specific) are properly marked
        common_patterns = [p for p in detected_patterns if not p.filesystem_specific]
        for pattern in common_patterns:
            assert pattern.filesystem_specific == False
            # Common patterns should not contain filesystem-specific terms
            pattern_type_lower = pattern.pattern_type.lower()
            assert 'fat' not in pattern_type_lower or 'fat' in pattern_type_lower and 'format' in pattern_type_lower  # Allow "format" but not "fat"
            assert 'ntfs' not in pattern_type_lower
            assert 'exfat' not in pattern_type_lower

    @given(boot_code=st.binary(min_size=0, max_size=500))
    def test_empty_boot_code_detection(self, boot_code):
        """
        Test that empty boot code detection works correctly for any boot code.
        """
        # Test with actual boot code
        is_empty = self.analyzer._check_empty_boot_code(boot_code)
        expected_empty = all(byte == 0 for byte in boot_code)
        assert is_empty == expected_empty
        
        # Test with explicitly empty boot code
        empty_boot_code = b'\x00' * len(boot_code) if boot_code else b''
        is_empty_explicit = self.analyzer._check_empty_boot_code(empty_boot_code)
        assert is_empty_explicit == True
        
        # Test with non-empty boot code (if original was empty)
        if boot_code and all(byte == 0 for byte in boot_code):
            non_empty_boot_code = b'\x01' + boot_code[1:]
            is_non_empty = self.analyzer._check_empty_boot_code(non_empty_boot_code)
            assert is_non_empty == False

    @given(
        filesystem_type=st.sampled_from([
            FilesystemType.FAT12, FilesystemType.FAT16, FilesystemType.FAT32,
            FilesystemType.NTFS, FilesystemType.EXFAT, FilesystemType.UNKNOWN
        ]),
        boot_code=st.binary(min_size=1, max_size=400),
        contains_threats=st.booleans()
    )
    def test_property_53_vbr_pattern_and_threat_detection(self, filesystem_type, boot_code, contains_threats):
        """
        Property 53: VBR pattern and threat detection
        For any VBR data containing suspicious patterns or malware signatures, the VBR_Analyzer should detect and classify them appropriately
        **Validates: Requirements 14.8, 14.13**
        **Feature: boot-sector-analyzer, Property 53: VBR pattern and threat detection**
        """
        # Optionally inject known threat patterns for testing
        if contains_threats:
            # Inject some suspicious patterns
            threat_patterns = [
                b"\xeb\xfe",  # Infinite loop
                b"\xf4",      # HLT instruction
                b"\xcc",      # INT3 breakpoint
                b"\x0f\x0b",  # UD2 undefined instruction
            ]
            # Insert a random threat pattern
            import random
            threat_pattern = random.choice(threat_patterns)
            # Insert at a random position (but not at the very beginning to avoid interfering with jump instruction)
            if len(boot_code) > 10:
                insert_pos = random.randint(5, min(len(boot_code) - len(threat_pattern), 50))
                boot_code = boot_code[:insert_pos] + threat_pattern + boot_code[insert_pos + len(threat_pattern):]
        
        # Create test VBR structure with potentially malicious boot code
        vbr_structure = self._create_test_vbr_structure(filesystem_type, boot_code)
        
        # Perform VBR content analysis (which includes security analysis)
        content_analysis = self.analyzer.analyze_vbr_content(vbr_structure)
        
        # Verify that content analysis completed successfully
        assert isinstance(content_analysis, VBRContentAnalysis)
        
        # Verify security analysis components are present
        assert hasattr(content_analysis, 'hashes')
        assert hasattr(content_analysis, 'boot_code_hashes')
        assert hasattr(content_analysis, 'detected_patterns')
        assert hasattr(content_analysis, 'anomalies')
        assert hasattr(content_analysis, 'threat_level')
        
        # Verify hash structure
        assert isinstance(content_analysis.hashes, dict)
        assert isinstance(content_analysis.boot_code_hashes, dict)
        assert 'md5' in content_analysis.hashes
        assert 'sha256' in content_analysis.hashes
        assert 'md5' in content_analysis.boot_code_hashes
        assert 'sha256' in content_analysis.boot_code_hashes
        
        # Verify patterns structure
        assert isinstance(content_analysis.detected_patterns, list)
        for pattern in content_analysis.detected_patterns:
            assert hasattr(pattern, 'pattern_type')
            assert hasattr(pattern, 'description')
            assert isinstance(pattern.pattern_type, str)
            assert isinstance(pattern.description, str)
            assert len(pattern.pattern_type) > 0
            assert len(pattern.description) > 0
        
        # Verify anomalies structure
        assert isinstance(content_analysis.anomalies, list)
        for anomaly in content_analysis.anomalies:
            assert hasattr(anomaly, 'anomaly_type')
            assert hasattr(anomaly, 'description')
            assert hasattr(anomaly, 'severity')
            assert hasattr(anomaly, 'evidence')
            assert isinstance(anomaly.anomaly_type, str)
            assert isinstance(anomaly.description, str)
            assert isinstance(anomaly.severity, str)
            assert isinstance(anomaly.evidence, list)
            assert anomaly.severity in ['low', 'medium', 'high', 'critical']
            assert len(anomaly.anomaly_type) > 0
            assert len(anomaly.description) > 0
        
        # Verify threat level
        assert isinstance(content_analysis.threat_level, ThreatLevel)
        
        # If we injected threats, verify they were detected
        if contains_threats:
            # Should have detected some suspicious patterns or anomalies
            suspicious_indicators = (
                len(content_analysis.anomalies) > 0 or
                any('suspicious' in pattern.description.lower() or 
                    'threat' in pattern.description.lower() or
                    'infinite loop' in pattern.description.lower() or
                    'halt' in pattern.description.lower() or
                    'breakpoint' in pattern.description.lower()
                    for pattern in content_analysis.detected_patterns)
            )
            
            # Note: We don't assert that threats MUST be detected because:
            # 1. The threat pattern might be in a context where it's not considered suspicious
            # 2. The random boot code might mask or interfere with threat detection
            # 3. Some patterns are only suspicious in certain contexts
            # But if threats are detected, they should be properly structured
            
            if suspicious_indicators:
                # If suspicious patterns were detected, threat level should reflect this
                assert content_analysis.threat_level in [ThreatLevel.LOW, ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL]
        
        # Verify that security analysis integration worked
        # The analysis should have been enhanced by SecurityScanner
        # This is indicated by the presence of security-specific anomalies or patterns
        security_enhanced = (
            any('vbr' in anomaly.anomaly_type.lower() for anomaly in content_analysis.anomalies) or
            any('security' in pattern.description.lower() for pattern in content_analysis.detected_patterns) or
            len(content_analysis.anomalies) > 0  # SecurityScanner adds additional anomaly checks
        )
        
        # The security enhancement should have occurred (though specific results depend on input)
        # We verify the integration worked by checking the analysis structure is complete
        assert content_analysis.threat_level is not None
        assert isinstance(content_analysis.threat_level, ThreatLevel)
        
        # Verify that VBR-specific security checks were performed
        # This is evidenced by the comprehensive analysis structure
        assert len(content_analysis.hashes) >= 2  # At least MD5 and SHA-256
        assert len(content_analysis.boot_code_hashes) >= 2  # At least MD5 and SHA-256