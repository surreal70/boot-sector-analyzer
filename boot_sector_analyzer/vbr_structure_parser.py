"""VBR structure parsing for filesystem-specific boot record analysis."""

import struct
from typing import Optional, Dict, Any
from .models import (
    VBRStructure, FATVBRStructure, NTFSVBRStructure, ExFATVBRStructure,
    FilesystemType, BIOSParameterBlock, NTFSBIOSParameterBlock, ExFATBIOSParameterBlock,
    FilesystemMetadata
)


class VBRStructureParser:
    """Parser for Volume Boot Record structures with filesystem-specific handling."""

    # Filesystem signature patterns for detection
    FILESYSTEM_SIGNATURES = {
        FilesystemType.FAT12: [b'FAT12   '],
        FilesystemType.FAT16: [b'FAT16   '],
        FilesystemType.FAT32: [b'FAT32   '],
        FilesystemType.NTFS: [b'NTFS    '],
        FilesystemType.EXFAT: [b'EXFAT   '],
    }

    # Partition type codes that indicate specific filesystems
    PARTITION_TYPE_MAPPING = {
        0x01: FilesystemType.FAT12,  # FAT12
        0x04: FilesystemType.FAT16,  # FAT16 <32MB
        0x06: FilesystemType.FAT16,  # FAT16 >=32MB
        0x0B: FilesystemType.FAT32,  # FAT32
        0x0C: FilesystemType.FAT32,  # FAT32 LBA
        0x07: FilesystemType.NTFS,   # NTFS
        0x27: FilesystemType.NTFS,   # Windows Recovery Environment
        0x83: FilesystemType.EXT4,   # Linux ext2/3/4
    }

    def detect_filesystem_type(self, vbr_data: bytes, partition_type: int) -> FilesystemType:
        """
        Detect filesystem type using VBR signatures and partition type codes.
        
        Args:
            vbr_data: 512-byte VBR data
            partition_type: Partition type code from MBR
            
        Returns:
            Detected filesystem type
        """
        if len(vbr_data) != 512:
            return FilesystemType.UNKNOWN

        # First check partition type code for strong hints
        if partition_type in self.PARTITION_TYPE_MAPPING:
            suggested_type = self.PARTITION_TYPE_MAPPING[partition_type]
            
            # Verify with VBR signature if possible
            if self._verify_filesystem_signature(vbr_data, suggested_type):
                return suggested_type

        # Check VBR signatures directly
        for fs_type, signatures in self.FILESYSTEM_SIGNATURES.items():
            if self._verify_filesystem_signature(vbr_data, fs_type):
                return fs_type

        # Special case: exFAT detection (signature at different location)
        if self._detect_exfat_signature(vbr_data):
            return FilesystemType.EXFAT

        return FilesystemType.UNKNOWN

    def _verify_filesystem_signature(self, vbr_data: bytes, fs_type: FilesystemType) -> bool:
        """Verify filesystem signature in VBR data."""
        signatures = self.FILESYSTEM_SIGNATURES.get(fs_type, [])
        
        for signature in signatures:
            # Check common signature locations
            if fs_type in [FilesystemType.FAT12, FilesystemType.FAT16, FilesystemType.FAT32]:
                # FAT signature at offset 54 (FAT12/16) or 82 (FAT32)
                if (len(vbr_data) >= 62 and vbr_data[54:62] == signature) or \
                   (len(vbr_data) >= 90 and vbr_data[82:90] == signature):
                    return True
            elif fs_type == FilesystemType.NTFS:
                # NTFS signature at offset 3
                if len(vbr_data) >= 11 and vbr_data[3:11] == signature:
                    return True
                    
        return False

    def _detect_exfat_signature(self, vbr_data: bytes) -> bool:
        """Detect exFAT filesystem signature."""
        # exFAT has "EXFAT   " at offset 3
        return len(vbr_data) >= 11 and vbr_data[3:11] == b'EXFAT   '

    def parse_vbr_structure(self, vbr_data: bytes, partition_type: int) -> VBRStructure:
        """
        Parse VBR structure with filesystem-specific parsing dispatch.
        
        Args:
            vbr_data: 512-byte VBR data
            partition_type: Partition type code from MBR
            
        Returns:
            Parsed VBR structure (filesystem-specific subclass)
        """
        if len(vbr_data) != 512:
            raise ValueError("VBR data must be exactly 512 bytes")

        filesystem_type = self.detect_filesystem_type(vbr_data, partition_type)
        
        # Extract boot signature (last 2 bytes)
        boot_signature = struct.unpack('<H', vbr_data[510:512])[0]
        
        # Dispatch to filesystem-specific parser
        if filesystem_type in [FilesystemType.FAT12, FilesystemType.FAT16, FilesystemType.FAT32]:
            return self.parse_fat_vbr(vbr_data, filesystem_type)
        elif filesystem_type == FilesystemType.NTFS:
            return self.parse_ntfs_vbr(vbr_data)
        elif filesystem_type == FilesystemType.EXFAT:
            return self.parse_exfat_vbr(vbr_data)
        else:
            # Generic VBR parsing for unknown filesystems
            return self._parse_generic_vbr(vbr_data, filesystem_type, boot_signature)

    def parse_fat_vbr(self, vbr_data: bytes, filesystem_type: FilesystemType) -> FATVBRStructure:
        """
        Parse FAT12/16/32 VBR structure with BPB.
        
        Args:
            vbr_data: 512-byte VBR data
            filesystem_type: Specific FAT type (FAT12/16/32)
            
        Returns:
            FAT-specific VBR structure
        """
        # Parse BIOS Parameter Block (starts at offset 11)
        bpb_data = vbr_data[11:62]  # Standard BPB is 51 bytes
        
        # Unpack standard BPB fields
        bpb_fields = struct.unpack('<HBHBHHBHHHHHL', bpb_data[:25])
        
        bpb = BIOSParameterBlock(
            bytes_per_sector=bpb_fields[0],
            sectors_per_cluster=bpb_fields[1],
            reserved_sectors=bpb_fields[2],
            fat_count=bpb_fields[3],
            root_entries=bpb_fields[4],
            total_sectors_16=bpb_fields[5],
            media_descriptor=bpb_fields[6],
            sectors_per_fat_16=bpb_fields[7],
            sectors_per_track=bpb_fields[8],
            heads=bpb_fields[9],
            hidden_sectors=bpb_fields[10],
            total_sectors_32=bpb_fields[11]
        )

        # Handle FAT32-specific fields
        if filesystem_type == FilesystemType.FAT32:
            fat32_fields = struct.unpack('<LHHL', vbr_data[36:48])  # Only take the first 12 bytes
            bpb.sectors_per_fat_32 = fat32_fields[0]
            bpb.flags = fat32_fields[1]
            bpb.version = fat32_fields[2]
            bpb.root_cluster = fat32_fields[3]
            boot_code_offset = 90  # FAT32 boot code starts after extended BPB
            boot_code_size = 420   # Up to boot signature
        else:
            # FAT12/16
            boot_code_offset = 62  # Boot code starts after standard BPB
            boot_code_size = 448   # Up to boot signature

        # Extract boot code
        boot_code = vbr_data[boot_code_offset:boot_code_offset + boot_code_size]
        
        # Extract boot signature
        boot_signature = struct.unpack('<H', vbr_data[510:512])[0]
        
        # Create filesystem metadata
        volume_label = None
        if filesystem_type == FilesystemType.FAT32:
            # FAT32 volume label at offset 71
            if len(vbr_data) > 82:
                volume_label = vbr_data[71:82].decode('ascii', errors='ignore').strip()
        else:
            # FAT12/16 volume label at offset 43
            if len(vbr_data) > 54:
                volume_label = vbr_data[43:54].decode('ascii', errors='ignore').strip()

        metadata = FilesystemMetadata(
            volume_label=volume_label if volume_label else None,
            cluster_size=bpb.bytes_per_sector * bpb.sectors_per_cluster,
            total_sectors=bpb.total_sectors_32 if bpb.total_sectors_32 > 0 else bpb.total_sectors_16
        )

        return FATVBRStructure(
            filesystem_type=filesystem_type,
            boot_code=boot_code,
            boot_signature=boot_signature,
            filesystem_metadata=metadata,
            raw_data=vbr_data,
            bpb=bpb,
            boot_code_offset=boot_code_offset,
            boot_code_size=boot_code_size
        )

    def parse_ntfs_vbr(self, vbr_data: bytes) -> NTFSVBRStructure:
        """
        Parse NTFS VBR structure with NTFS metadata.
        
        Args:
            vbr_data: 512-byte VBR data
            
        Returns:
            NTFS-specific VBR structure
        """
        # Parse NTFS BIOS Parameter Block (starts at offset 11)
        ntfs_bpb_data = vbr_data[11:60]  # NTFS BPB is 49 bytes
        
        # Unpack NTFS BPB fields
        bpb_fields = struct.unpack('<HBHBHHBHHHHLQQBBLL', ntfs_bpb_data)
        
        ntfs_bpb = NTFSBIOSParameterBlock(
            bytes_per_sector=bpb_fields[0],
            sectors_per_cluster=bpb_fields[1],
            reserved_sectors=bpb_fields[2],
            media_descriptor=bpb_fields[4],
            sectors_per_track=bpb_fields[6],
            heads=bpb_fields[7],
            hidden_sectors=bpb_fields[8],
            total_sectors=bpb_fields[10],
            mft_cluster=bpb_fields[11],
            mft_mirror_cluster=bpb_fields[12],
            clusters_per_file_record=bpb_fields[13],
            clusters_per_index_buffer=bpb_fields[14],
            volume_serial=bpb_fields[15]
        )

        # NTFS boot code starts at offset 84
        boot_code = vbr_data[84:510]
        boot_signature = struct.unpack('<H', vbr_data[510:512])[0]

        # Create filesystem metadata
        metadata = FilesystemMetadata(
            cluster_size=ntfs_bpb.bytes_per_sector * ntfs_bpb.sectors_per_cluster,
            total_sectors=ntfs_bpb.total_sectors
        )

        return NTFSVBRStructure(
            filesystem_type=FilesystemType.NTFS,
            boot_code=boot_code,
            boot_signature=boot_signature,
            filesystem_metadata=metadata,
            raw_data=vbr_data,
            ntfs_bpb=ntfs_bpb,
            mft_cluster=ntfs_bpb.mft_cluster,
            volume_serial=ntfs_bpb.volume_serial
        )

    def parse_exfat_vbr(self, vbr_data: bytes) -> ExFATVBRStructure:
        """
        Parse exFAT VBR structure.
        
        Args:
            vbr_data: 512-byte VBR data
            
        Returns:
            exFAT-specific VBR structure
        """
        # Parse exFAT BIOS Parameter Block (starts at offset 11)
        exfat_bpb_data = vbr_data[11:51]  # exFAT BPB is 40 bytes
        
        # Unpack exFAT BPB fields
        bpb_fields = struct.unpack('<QLLLLLLHHHBB', exfat_bpb_data[:40])
        
        exfat_bpb = ExFATBIOSParameterBlock(
            bytes_per_sector=1 << bpb_fields[9],  # 2^bytes_per_sector_shift
            sectors_per_cluster=1 << bpb_fields[10],  # 2^sectors_per_cluster_shift
            fat_offset=bpb_fields[1],
            fat_length=bpb_fields[2],
            cluster_heap_offset=bpb_fields[3],
            cluster_count=bpb_fields[4],
            root_directory_cluster=bpb_fields[5],
            volume_serial=bpb_fields[6],
            filesystem_revision=bpb_fields[7],
            volume_flags=bpb_fields[8],
            bytes_per_sector_shift=bpb_fields[9],
            sectors_per_cluster_shift=bpb_fields[10]
        )

        # exFAT boot code starts at offset 120
        boot_code = vbr_data[120:510]
        boot_signature = struct.unpack('<H', vbr_data[510:512])[0]

        # Create filesystem metadata
        metadata = FilesystemMetadata(
            cluster_size=exfat_bpb.bytes_per_sector * exfat_bpb.sectors_per_cluster,
            total_sectors=exfat_bpb.cluster_count * exfat_bpb.sectors_per_cluster
        )

        return ExFATVBRStructure(
            filesystem_type=FilesystemType.EXFAT,
            boot_code=boot_code,
            boot_signature=boot_signature,
            filesystem_metadata=metadata,
            raw_data=vbr_data,
            exfat_bpb=exfat_bpb,
            fat_offset=exfat_bpb.fat_offset,
            cluster_heap_offset=exfat_bpb.cluster_heap_offset
        )

    def _parse_generic_vbr(self, vbr_data: bytes, filesystem_type: FilesystemType, 
                          boot_signature: int) -> VBRStructure:
        """
        Parse generic VBR structure for unknown filesystem types.
        
        Args:
            vbr_data: 512-byte VBR data
            filesystem_type: Detected (or unknown) filesystem type
            boot_signature: Boot signature from VBR
            
        Returns:
            Generic VBR structure
        """
        # For unknown filesystems, assume boot code starts after potential BPB area
        boot_code = vbr_data[90:510]  # Conservative approach
        
        metadata = FilesystemMetadata()  # Empty metadata for unknown types
        
        return VBRStructure(
            filesystem_type=filesystem_type,
            boot_code=boot_code,
            boot_signature=boot_signature,
            filesystem_metadata=metadata,
            raw_data=vbr_data
        )

    def extract_vbr_boot_code(self, vbr_structure: VBRStructure) -> bytes:
        """
        Extract boot code region from VBR (varies by filesystem).
        
        Args:
            vbr_structure: Parsed VBR structure
            
        Returns:
            Boot code bytes
        """
        return vbr_structure.boot_code