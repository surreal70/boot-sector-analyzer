"""Property-based tests for VBRStructureParser."""

import struct
from hypothesis import given, strategies as st
import pytest

from boot_sector_analyzer.vbr_structure_parser import VBRStructureParser
from boot_sector_analyzer.models import (
    FilesystemType, VBRStructure, FATVBRStructure, NTFSVBRStructure, ExFATVBRStructure
)


class TestVBRStructureParserProperties:
    """Property-based tests for VBRStructureParser class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parser = VBRStructureParser()

    def _create_fat_vbr(self, filesystem_type: FilesystemType, volume_label: str = "TEST_VOL") -> bytes:
        """Create a valid FAT VBR for testing."""
        vbr = bytearray(512)
        
        # Jump instruction at start
        vbr[0:3] = b'\xeb\x3c\x90'
        
        # OEM identifier
        vbr[3:11] = b'MSDOS5.0'
        
        # BIOS Parameter Block (BPB) at offset 11
        bpb_data = struct.pack('<HBHBHHBHHHHHL',
            512,    # bytes_per_sector
            1,      # sectors_per_cluster
            1,      # reserved_sectors
            2,      # fat_count
            224,    # root_entries (FAT12/16)
            2880,   # total_sectors_16 (FAT12/16)
            0xF0,   # media_descriptor
            9,      # sectors_per_fat_16 (FAT12/16)
            18,     # sectors_per_track
            2,      # heads
            0,      # hidden_sectors
            0,      # total_sectors_32
            0       # padding to make it 25 bytes
        )
        vbr[11:36] = bpb_data
        
        if filesystem_type == FilesystemType.FAT32:
            # FAT32-specific fields
            fat32_data = struct.pack('<LHHL',
                9,      # sectors_per_fat_32
                0,      # flags
                0,      # version
                2       # root_cluster
            )
            # Pad to 16 bytes to fit the slice
            fat32_data += b'\x00' * (16 - len(fat32_data))
            vbr[36:52] = fat32_data
            
            # Volume label at offset 71 for FAT32
            vbr[71:82] = volume_label.ljust(11).encode('ascii')[:11]
            
            # Filesystem signature at offset 82
            vbr[82:90] = b'FAT32   '
        else:
            # Volume label at offset 43 for FAT12/16
            vbr[43:54] = volume_label.ljust(11).encode('ascii')[:11]
            
            # Filesystem signature at offset 54
            if filesystem_type == FilesystemType.FAT16:
                vbr[54:62] = b'FAT16   '
            else:
                vbr[54:62] = b'FAT12   '
        
        # Boot signature
        vbr[510:512] = struct.pack('<H', 0x55AA)
        
        return bytes(vbr)

    def _create_ntfs_vbr(self, volume_serial: int = 0x12345678) -> bytes:
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

    def _create_exfat_vbr(self, volume_serial: int = 0x87654321) -> bytes:
        """Create a valid exFAT VBR for testing."""
        vbr = bytearray(512)
        
        # Jump instruction
        vbr[0:3] = b'\xeb\x76\x90'
        
        # exFAT signature
        vbr[3:11] = b'EXFAT   '
        
        # exFAT BIOS Parameter Block at offset 11
        exfat_bpb = struct.pack('<QLLLLLLHHHBB',
            0,          # partition_offset
            128,        # fat_offset
            1024,       # fat_length
            1152,       # cluster_heap_offset
            65536,      # cluster_count
            2,          # root_directory_cluster
            volume_serial,  # volume_serial
            0x0100,     # filesystem_revision
            0x0000,     # volume_flags
            9,          # bytes_per_sector_shift (2^9 = 512)
            3,          # sectors_per_cluster_shift (2^3 = 8)
            0           # padding
        )
        # Pad to 44 bytes to fit the slice
        exfat_bpb += b'\x00' * (44 - len(exfat_bpb))
        vbr[11:55] = exfat_bpb
        
        # Boot signature
        vbr[510:512] = struct.pack('<H', 0x55AA)
        
        return bytes(vbr)

    @given(
        filesystem_type=st.sampled_from([
            FilesystemType.FAT12, FilesystemType.FAT16, FilesystemType.FAT32,
            FilesystemType.NTFS, FilesystemType.EXFAT
        ]),
        partition_type=st.integers(min_value=0, max_value=255),
        volume_label=st.text(alphabet=st.characters(min_codepoint=32, max_codepoint=126), 
                           min_size=1, max_size=11)
    )
    def test_filesystem_specific_vbr_parsing(self, filesystem_type, partition_type, volume_label):
        """
        Property 50: Filesystem-specific VBR parsing
        For any valid VBR data with filesystem-specific structure, the VBRStructureParser should 
        correctly parse the VBR according to the detected filesystem type and return appropriate 
        filesystem-specific VBR structure with accurate metadata extraction
        **Validates: Requirements 14.5**
        **Feature: boot-sector-analyzer, Property 50: Filesystem-specific VBR parsing**
        """
        # Create filesystem-specific VBR data and use appropriate partition type
        if filesystem_type in [FilesystemType.FAT12, FilesystemType.FAT16, FilesystemType.FAT32]:
            vbr_data = self._create_fat_vbr(filesystem_type, volume_label)
            # Use appropriate partition type for the filesystem
            test_partition_type = {
                FilesystemType.FAT12: 0x01,
                FilesystemType.FAT16: 0x06,
                FilesystemType.FAT32: 0x0B
            }[filesystem_type]
        elif filesystem_type == FilesystemType.NTFS:
            vbr_data = self._create_ntfs_vbr()
            test_partition_type = 0x07
        elif filesystem_type == FilesystemType.EXFAT:
            vbr_data = self._create_exfat_vbr()
            test_partition_type = 0x07  # exFAT often uses NTFS partition type
        
        # Test filesystem type detection with appropriate partition type
        detected_type = self.parser.detect_filesystem_type(vbr_data, test_partition_type)
        assert detected_type == filesystem_type, \
            f"Expected filesystem type {filesystem_type}, but detected {detected_type}"
        
        # Test VBR structure parsing
        vbr_structure = self.parser.parse_vbr_structure(vbr_data, test_partition_type)
        
        # Verify basic VBR structure properties
        assert isinstance(vbr_structure, VBRStructure), \
            f"Expected VBRStructure instance, got {type(vbr_structure)}"
        assert vbr_structure.filesystem_type == filesystem_type, \
            f"VBR structure filesystem type should be {filesystem_type}"
        assert vbr_structure.raw_data == vbr_data, \
            "VBR structure should contain original raw data"
        assert vbr_structure.boot_signature == 0x55AA, \
            "VBR structure should have valid boot signature"
        assert len(vbr_structure.boot_code) > 0, \
            "VBR structure should contain boot code"
        
        # Test filesystem-specific structure types
        if filesystem_type in [FilesystemType.FAT12, FilesystemType.FAT16, FilesystemType.FAT32]:
            assert isinstance(vbr_structure, FATVBRStructure), \
                f"FAT VBR should return FATVBRStructure, got {type(vbr_structure)}"
            
            # Verify FAT-specific fields
            assert vbr_structure.bpb is not None, "FAT VBR should have BPB"
            assert vbr_structure.bpb.bytes_per_sector == 512, "BPB should have correct sector size"
            assert vbr_structure.boot_code_offset > 0, "FAT VBR should have boot code offset"
            assert vbr_structure.boot_code_size > 0, "FAT VBR should have boot code size"
            
            # Verify volume label extraction (if provided)
            if volume_label.strip():
                assert vbr_structure.filesystem_metadata.volume_label is not None, \
                    "FAT VBR should extract volume label"
                
        elif filesystem_type == FilesystemType.NTFS:
            assert isinstance(vbr_structure, NTFSVBRStructure), \
                f"NTFS VBR should return NTFSVBRStructure, got {type(vbr_structure)}"
            
            # Verify NTFS-specific fields
            assert vbr_structure.ntfs_bpb is not None, "NTFS VBR should have NTFS BPB"
            assert vbr_structure.ntfs_bpb.bytes_per_sector == 512, "NTFS BPB should have correct sector size"
            assert vbr_structure.mft_cluster > 0, "NTFS VBR should have MFT cluster location"
            assert vbr_structure.volume_serial > 0, "NTFS VBR should have volume serial"
            
        elif filesystem_type == FilesystemType.EXFAT:
            assert isinstance(vbr_structure, ExFATVBRStructure), \
                f"exFAT VBR should return ExFATVBRStructure, got {type(vbr_structure)}"
            
            # Verify exFAT-specific fields
            assert vbr_structure.exfat_bpb is not None, "exFAT VBR should have exFAT BPB"
            assert vbr_structure.exfat_bpb.bytes_per_sector == 512, "exFAT BPB should have correct sector size"
            assert vbr_structure.fat_offset > 0, "exFAT VBR should have FAT offset"
            assert vbr_structure.cluster_heap_offset > 0, "exFAT VBR should have cluster heap offset"
        
        # Test boot code extraction
        extracted_boot_code = self.parser.extract_vbr_boot_code(vbr_structure)
        assert extracted_boot_code == vbr_structure.boot_code, \
            "Extracted boot code should match VBR structure boot code"
        assert len(extracted_boot_code) > 0, \
            "Extracted boot code should not be empty"
        
        # Verify filesystem metadata
        assert vbr_structure.filesystem_metadata is not None, \
            "VBR structure should have filesystem metadata"
        if vbr_structure.filesystem_metadata.cluster_size:
            assert vbr_structure.filesystem_metadata.cluster_size > 0, \
                "Cluster size should be positive if present"

    @given(
        invalid_size=st.integers(min_value=0, max_value=2048).filter(lambda x: x != 512),
        partition_type=st.integers(min_value=0, max_value=255)
    )
    def test_invalid_vbr_size_handling(self, invalid_size, partition_type):
        """
        Test that VBR parser handles invalid VBR sizes correctly.
        VBR data must be exactly 512 bytes.
        """
        # Create VBR data with invalid size
        invalid_vbr_data = b'\x00' * invalid_size
        
        # Test filesystem detection with invalid size
        detected_type = self.parser.detect_filesystem_type(invalid_vbr_data, partition_type)
        assert detected_type == FilesystemType.UNKNOWN, \
            "Invalid size VBR should be detected as UNKNOWN filesystem"
        
        # Test VBR parsing with invalid size should raise ValueError
        with pytest.raises(ValueError, match="VBR data must be exactly 512 bytes"):
            self.parser.parse_vbr_structure(invalid_vbr_data, partition_type)

    @given(
        random_data=st.binary(min_size=512, max_size=512),
        partition_type=st.integers(min_value=0, max_value=255)
    )
    def test_unknown_filesystem_handling(self, random_data, partition_type):
        """
        Test that VBR parser handles unknown/corrupted VBR data gracefully.
        """
        # Ensure the data doesn't accidentally match known signatures
        vbr_data = bytearray(random_data)
        
        # Clear potential signature locations to ensure unknown detection
        vbr_data[3:11] = b'\x00' * 8    # Clear potential NTFS/exFAT signature
        vbr_data[54:62] = b'\x00' * 8   # Clear potential FAT12/16 signature
        vbr_data[82:90] = b'\x00' * 8   # Clear potential FAT32 signature
        
        # Set valid boot signature
        vbr_data[510:512] = struct.pack('<H', 0x55AA)
        
        vbr_data = bytes(vbr_data)
        
        # Test filesystem detection
        detected_type = self.parser.detect_filesystem_type(vbr_data, partition_type)
        
        # Should detect as unknown unless partition type gives a strong hint
        if partition_type not in self.parser.PARTITION_TYPE_MAPPING:
            assert detected_type == FilesystemType.UNKNOWN, \
                "Random data should be detected as UNKNOWN filesystem"
        
        # Test VBR parsing should not raise exceptions
        vbr_structure = self.parser.parse_vbr_structure(vbr_data, partition_type)
        
        # Verify basic structure
        assert isinstance(vbr_structure, VBRStructure), \
            "Should return base VBRStructure for unknown filesystem"
        assert vbr_structure.raw_data == vbr_data, \
            "Should preserve raw data"
        assert vbr_structure.boot_signature == 0x55AA, \
            "Should extract boot signature correctly"
        assert len(vbr_structure.boot_code) > 0, \
            "Should extract some boot code"

    @given(
        partition_type=st.sampled_from([0x01, 0x04, 0x06, 0x0B, 0x0C, 0x07, 0x27, 0x83])
    )
    def test_partition_type_mapping_consistency(self, partition_type):
        """
        Test that partition type mapping is consistent with filesystem detection.
        """
        # Get expected filesystem type from partition type
        expected_fs_type = self.parser.PARTITION_TYPE_MAPPING.get(partition_type, FilesystemType.UNKNOWN)
        
        # Create appropriate VBR data for the filesystem type
        if expected_fs_type in [FilesystemType.FAT12, FilesystemType.FAT16, FilesystemType.FAT32]:
            vbr_data = self._create_fat_vbr(expected_fs_type)
        elif expected_fs_type == FilesystemType.NTFS:
            vbr_data = self._create_ntfs_vbr()
        else:
            # For EXT4 or other types, create generic VBR
            vbr_data = bytearray(512)
            vbr_data[510:512] = struct.pack('<H', 0x55AA)
            vbr_data = bytes(vbr_data)
        
        # Test detection
        detected_type = self.parser.detect_filesystem_type(vbr_data, partition_type)
        
        # For known filesystem types with matching VBR signatures, should detect correctly
        if expected_fs_type in [FilesystemType.FAT12, FilesystemType.FAT16, 
                               FilesystemType.FAT32, FilesystemType.NTFS]:
            assert detected_type == expected_fs_type, \
                f"Partition type 0x{partition_type:02X} should detect as {expected_fs_type}, got {detected_type}"