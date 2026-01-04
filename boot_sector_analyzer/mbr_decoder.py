"""MBR Decoder for interpreting Master Boot Record structure."""

import struct
import logging
from dataclasses import dataclass
from typing import List, Optional, Tuple, Dict, Any
from enum import Enum

logger = logging.getLogger(__name__)


class MBRSection(Enum):
    """MBR section types for color coding."""
    BOOT_CODE = "boot_code"
    DISK_SIGNATURE = "disk_signature"
    PARTITION_TABLE = "partition_table"
    BOOT_SIGNATURE = "boot_signature"


class PartitionColors:
    """Color scheme for individual partition entries."""
    # HTML background colors
    PARTITION_1 = "#FFE6E6"  # Light red
    PARTITION_2 = "#E6F3FF"  # Light blue  
    PARTITION_3 = "#E6FFE6"  # Light green
    PARTITION_4 = "#FFF0E6"  # Light orange
    EMPTY_PARTITION = "#F5F5F5"  # Light gray
    
    # ANSI colors for terminal output (imported from report_generator)
    @staticmethod
    def get_ansi_color(partition_number: int, is_empty: bool = False) -> str:
        """Get ANSI color code for partition number."""
        from .report_generator import ANSIColors
        
        if is_empty:
            return ANSIColors.WHITE
        
        colors = {
            1: ANSIColors.RED,
            2: ANSIColors.BLUE,
            3: ANSIColors.GREEN,
            4: ANSIColors.YELLOW
        }
        return colors.get(partition_number, ANSIColors.WHITE)
    
    @staticmethod
    def get_html_color(partition_number: int, is_empty: bool = False) -> str:
        """Get HTML background color for partition number."""
        if is_empty:
            return PartitionColors.EMPTY_PARTITION
        
        colors = {
            1: PartitionColors.PARTITION_1,
            2: PartitionColors.PARTITION_2,
            3: PartitionColors.PARTITION_3,
            4: PartitionColors.PARTITION_4
        }
        return colors.get(partition_number, PartitionColors.EMPTY_PARTITION)


@dataclass
class PartitionEntry:
    """Represents a single partition table entry."""
    bootable: bool
    start_chs: Tuple[int, int, int]  # (cylinder, head, sector)
    system_id: int
    end_chs: Tuple[int, int, int]    # (cylinder, head, sector)
    start_lba: int
    size_sectors: int
    
    @property
    def is_empty(self) -> bool:
        """Check if partition entry is empty."""
        return (self.system_id == 0 and self.start_lba == 0 and 
                self.size_sectors == 0)
    
    @property
    def is_extended(self) -> bool:
        """Check if partition is extended type."""
        return self.system_id in [0x05, 0x0F, 0x85]
    
    @property
    def size_mb(self) -> float:
        """Get partition size in MB."""
        return (self.size_sectors * 512) / (1024 * 1024)
    
    @property
    def size_gb(self) -> float:
        """Get partition size in GB."""
        return self.size_mb / 1024


@dataclass
class MBRStructure:
    """Complete MBR structure representation."""
    boot_code: bytes
    disk_signature: Optional[int]
    partition_entries: List[PartitionEntry]
    boot_signature: int
    
    @property
    def is_valid_signature(self) -> bool:
        """Check if boot signature is valid (accepts both 0x55AA and 0xAA55)."""
        return self.boot_signature in [0x55AA, 0xAA55]
    
    @property
    def active_partitions(self) -> List[PartitionEntry]:
        """Get list of non-empty partition entries."""
        return [entry for entry in self.partition_entries if not entry.is_empty]
    
    @property
    def bootable_partitions(self) -> List[PartitionEntry]:
        """Get list of bootable partition entries."""
        return [entry for entry in self.partition_entries if entry.bootable]


class PartitionTypeRegistry:
    """Registry of partition type identifiers and their descriptions."""
    
    PARTITION_TYPES = {
        0x00: "Empty",
        0x01: "FAT12",
        0x04: "FAT16 (< 32MB)",
        0x05: "Extended",
        0x06: "FAT16 (>= 32MB)",
        0x07: "NTFS/HPFS/exFAT",
        0x0B: "FAT32",
        0x0C: "FAT32 (LBA)",
        0x0E: "FAT16 (LBA)",
        0x0F: "Extended (LBA)",
        0x11: "Hidden FAT12",
        0x12: "Compaq diagnostics",
        0x14: "Hidden FAT16 (< 32MB)",
        0x16: "Hidden FAT16 (>= 32MB)",
        0x17: "Hidden NTFS/HPFS",
        0x1B: "Hidden FAT32",
        0x1C: "Hidden FAT32 (LBA)",
        0x1E: "Hidden FAT16 (LBA)",
        0x27: "Windows Recovery Environment",
        0x39: "Plan 9",
        0x3C: "PartitionMagic recovery",
        0x42: "Windows Dynamic Disk",
        0x44: "GoBack",
        0x51: "Novell",
        0x52: "CP/M",
        0x63: "Unix System V",
        0x64: "Novell Netware 286",
        0x65: "Novell Netware 386",
        0x82: "Linux swap",
        0x83: "Linux",
        0x84: "OS/2 hidden C: drive",
        0x85: "Linux extended",
        0x86: "NTFS volume set",
        0x87: "NTFS volume set",
        0x8E: "Linux LVM",
        0x93: "Amoeba",
        0x94: "Amoeba BBT",
        0x9F: "BSD/OS",
        0xA0: "IBM Thinkpad hibernation",
        0xA5: "FreeBSD",
        0xA6: "OpenBSD",
        0xA7: "NeXTSTEP",
        0xA8: "Darwin UFS",
        0xA9: "NetBSD",
        0xAB: "Darwin boot",
        0xAF: "HFS / HFS+",
        0xB7: "BSDI",
        0xB8: "BSDI swap",
        0xBB: "Boot Wizard hidden",
        0xBE: "Solaris boot",
        0xBF: "Solaris",
        0xC1: "DRDOS/sec (FAT-12)",
        0xC4: "DRDOS/sec (FAT-16)",
        0xC6: "DRDOS/sec (FAT-16B)",
        0xC7: "Syrinx",
        0xDA: "Non-FS data",
        0xDB: "CP/M / CTOS / ...",
        0xDE: "Dell Utility",
        0xDF: "BootIt",
        0xE1: "DOS access",
        0xE3: "DOS R/O",
        0xE4: "SpeedStor",
        0xEB: "BeOS fs",
        0xEE: "GPT",
        0xEF: "EFI (FAT-12/16/32)",
        0xF0: "Linux/PA-RISC boot",
        0xF1: "SpeedStor",
        0xF4: "SpeedStor",
        0xF2: "DOS secondary",
        0xFB: "VMware VMFS",
        0xFC: "VMware VMKCORE",
        0xFD: "Linux raid autodetect",
        0xFE: "SpeedStor",
        0xFF: "BBT"
    }
    
    @classmethod
    def get_partition_type(cls, system_id: int) -> str:
        """Get partition type description from system ID."""
        if system_id in cls.PARTITION_TYPES:
            return cls.PARTITION_TYPES[system_id]
        else:
            return f"Unknown (0x{system_id:02X})"


class MBRDecoder:
    """Decoder for Master Boot Record structure."""
    
    def __init__(self):
        self.partition_registry = PartitionTypeRegistry()
    
    def parse_mbr(self, mbr_data: bytes) -> MBRStructure:
        """
        Parse complete 512-byte MBR structure.
        
        Args:
            mbr_data: 512-byte MBR data
            
        Returns:
            Parsed MBR structure
            
        Raises:
            ValueError: If MBR data is not exactly 512 bytes
        """
        if len(mbr_data) != 512:
            raise ValueError(f"MBR data must be exactly 512 bytes, got {len(mbr_data)}")
        
        # Extract boot code (bytes 0-445)
        boot_code = mbr_data[0:446]
        
        # Extract disk signature (bytes 440-443) - may be zero
        disk_sig_bytes = mbr_data[440:444]
        disk_signature = struct.unpack('<I', disk_sig_bytes)[0] if any(disk_sig_bytes) else None
        
        # Extract partition table (bytes 446-509)
        partition_entries = []
        for i in range(4):
            entry_offset = 446 + (i * 16)
            entry_data = mbr_data[entry_offset:entry_offset + 16]
            partition_entry = self._parse_partition_entry(entry_data)
            partition_entries.append(partition_entry)
        
        # Extract boot signature (bytes 510-511)
        boot_signature = struct.unpack('<H', mbr_data[510:512])[0]
        
        return MBRStructure(
            boot_code=boot_code,
            disk_signature=disk_signature,
            partition_entries=partition_entries,
            boot_signature=boot_signature
        )
    
    def _parse_partition_entry(self, entry_data: bytes) -> PartitionEntry:
        """Parse a single 16-byte partition entry."""
        if len(entry_data) != 16:
            raise ValueError(f"Partition entry must be 16 bytes, got {len(entry_data)}")
        
        # Unpack the partition entry structure
        values = struct.unpack('<BBBBBBBBII', entry_data)
        
        bootable_flag = values[0]
        start_head = values[1]
        start_sector_cyl = values[2]
        start_cylinder = values[3]
        system_id = values[4]
        end_head = values[5]
        end_sector_cyl = values[6]
        end_cylinder = values[7]
        start_lba = values[8]
        size_sectors = values[9]
        
        # Parse CHS values
        start_sector = start_sector_cyl & 0x3F
        start_cyl_high = (start_sector_cyl & 0xC0) << 2
        start_cyl = start_cylinder | start_cyl_high
        
        end_sector = end_sector_cyl & 0x3F
        end_cyl_high = (end_sector_cyl & 0xC0) << 2
        end_cyl = end_cylinder | end_cyl_high
        
        return PartitionEntry(
            bootable=(bootable_flag == 0x80),
            start_chs=(start_cyl, start_head, start_sector),
            system_id=system_id,
            end_chs=(end_cyl, end_head, end_sector),
            start_lba=start_lba,
            size_sectors=size_sectors
        )
    
    def validate_mbr(self, mbr_structure: MBRStructure) -> List[str]:
        """
        Validate MBR structure integrity.
        
        Args:
            mbr_structure: Parsed MBR structure
            
        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []
        
        # Check boot signature
        if not mbr_structure.is_valid_signature:
            errors.append(f"Invalid boot signature: 0x{mbr_structure.boot_signature:04X} "
                         f"(expected 0x55AA or 0xAA55)")
        
        # Check bootable partitions
        bootable_count = len(mbr_structure.bootable_partitions)
        if bootable_count > 1:
            errors.append(f"Multiple bootable partitions found: {bootable_count} "
                         f"(should be at most 1)")
        
        # Check partition overlaps
        active_partitions = mbr_structure.active_partitions
        for i, part1 in enumerate(active_partitions):
            for j, part2 in enumerate(active_partitions[i+1:], i+1):
                if self._partitions_overlap(part1, part2):
                    errors.append(f"Partition overlap detected between partition {i+1} "
                                f"and partition {j+1}")
        
        # Check LBA consistency
        for i, partition in enumerate(mbr_structure.partition_entries):
            if not partition.is_empty:
                if partition.start_lba == 0 and partition.size_sectors > 0:
                    errors.append(f"Partition {i+1}: Invalid LBA start (0) with non-zero size")
                
                # Check for 32-bit LBA overflow
                if partition.start_lba + partition.size_sectors > 0xFFFFFFFF:
                    errors.append(f"Partition {i+1}: LBA values exceed 32-bit range")
        
        return errors
    
    def _partitions_overlap(self, part1: PartitionEntry, part2: PartitionEntry) -> bool:
        """Check if two partitions overlap in LBA space."""
        if part1.is_empty or part2.is_empty:
            return False
        
        part1_end = part1.start_lba + part1.size_sectors - 1
        part2_end = part2.start_lba + part2.size_sectors - 1
        
        return not (part1_end < part2.start_lba or part2_end < part1.start_lba)
    
    def convert_chs_to_lba(self, cylinder: int, head: int, sector: int, 
                          heads_per_cylinder: int = 255, 
                          sectors_per_track: int = 63) -> int:
        """
        Convert CHS address to LBA.
        
        Args:
            cylinder: Cylinder number
            head: Head number  
            sector: Sector number (1-based)
            heads_per_cylinder: Number of heads per cylinder
            sectors_per_track: Number of sectors per track
            
        Returns:
            LBA address
        """
        if sector == 0:
            return 0  # Invalid sector
        
        return (cylinder * heads_per_cylinder + head) * sectors_per_track + sector - 1
    
    def convert_lba_to_chs(self, lba: int, 
                          heads_per_cylinder: int = 255,
                          sectors_per_track: int = 63) -> Tuple[int, int, int]:
        """
        Convert LBA address to CHS.
        
        Args:
            lba: LBA address
            heads_per_cylinder: Number of heads per cylinder
            sectors_per_track: Number of sectors per track
            
        Returns:
            Tuple of (cylinder, head, sector)
        """
        if lba == 0:
            return (0, 0, 0)
        
        cylinder = lba // (heads_per_cylinder * sectors_per_track)
        remainder = lba % (heads_per_cylinder * sectors_per_track)
        head = remainder // sectors_per_track
        sector = remainder % sectors_per_track + 1
        
        return (cylinder, head, sector)
    
    def get_section_type(self, offset: int) -> MBRSection:
        """
        Determine which MBR section a byte offset belongs to.
        
        Args:
            offset: Byte offset within the 512-byte MBR
            
        Returns:
            MBR section type
        """
        if 0 <= offset <= 439:
            return MBRSection.BOOT_CODE
        elif 440 <= offset <= 443:
            return MBRSection.DISK_SIGNATURE
        elif 446 <= offset <= 509:
            return MBRSection.PARTITION_TABLE
        elif 510 <= offset <= 511:
            return MBRSection.BOOT_SIGNATURE
        else:
            raise ValueError(f"Invalid MBR offset: {offset}")
    
    def get_partition_section_type(self, offset: int) -> Tuple[MBRSection, int]:
        """
        Determine which partition entry a byte offset belongs to.
        
        Args:
            offset: Byte offset within the 512-byte MBR
            
        Returns:
            Tuple of (MBR section type, partition number 1-4, or 0 for non-partition sections)
        """
        if 0 <= offset <= 439:
            return (MBRSection.BOOT_CODE, 0)
        elif 440 <= offset <= 443:
            return (MBRSection.DISK_SIGNATURE, 0)
        elif 446 <= offset <= 509:
            # Calculate which partition entry (0-3, return as 1-4)
            partition_offset = offset - 446
            partition_number = (partition_offset // 16) + 1
            return (MBRSection.PARTITION_TABLE, partition_number)
        elif 510 <= offset <= 511:
            return (MBRSection.BOOT_SIGNATURE, 0)
        else:
            raise ValueError(f"Invalid MBR offset: {offset}")
    
    def get_partition_color_info(self, offset: int, mbr_structure: Optional[MBRStructure] = None) -> Tuple[str, str, int]:
        """
        Get color information for a specific byte offset.
        
        Args:
            offset: Byte offset within the 512-byte MBR
            mbr_structure: Optional MBR structure to check if partition is empty
            
        Returns:
            Tuple of (HTML color, ANSI color, partition number)
        """
        section, partition_num = self.get_partition_section_type(offset)
        
        if section == MBRSection.PARTITION_TABLE and partition_num > 0:
            # Check if partition is empty if MBR structure is provided
            is_empty = False
            if mbr_structure and partition_num <= len(mbr_structure.partition_entries):
                partition_entry = mbr_structure.partition_entries[partition_num - 1]
                is_empty = partition_entry.is_empty
            
            html_color = PartitionColors.get_html_color(partition_num, is_empty)
            ansi_color = PartitionColors.get_ansi_color(partition_num, is_empty)
            return (html_color, ansi_color, partition_num)
        else:
            # Non-partition sections use default colors
            return ("", "", 0)
    
    def generate_partition_report(self, mbr_structure: MBRStructure) -> str:
        """
        Generate human-readable partition table report.
        
        Args:
            mbr_structure: Parsed MBR structure
            
        Returns:
            Formatted partition table report
        """
        lines = []
        
        # Header
        lines.append("MBR PARTITION TABLE")
        lines.append("=" * 80)
        
        # Disk signature
        if mbr_structure.disk_signature:
            lines.append(f"Disk Signature: 0x{mbr_structure.disk_signature:08X}")
        else:
            lines.append("Disk Signature: Not set (0x00000000)")
        
        # Boot signature status
        if mbr_structure.is_valid_signature:
            lines.append(f"Boot Signature: Valid (0x{mbr_structure.boot_signature:04X})")
        else:
            lines.append(f"Boot Signature: INVALID (0x{mbr_structure.boot_signature:04X})")
        
        lines.append("")
        
        # Partition table header
        lines.append("Partition Table:")
        lines.append("-" * 80)
        header = f"{'#':<2} {'Boot':<4} {'Type':<20} {'Start LBA':<10} {'Size (MB)':<12} {'CHS Start':<12} {'CHS End':<12}"
        lines.append(header)
        lines.append("-" * 80)
        
        # Partition entries
        for i, partition in enumerate(mbr_structure.partition_entries, 1):
            if partition.is_empty:
                lines.append(f"{i:<2} {'No':<4} {'Empty':<20} {'-':<10} {'-':<12} {'-':<12} {'-':<12}")
            else:
                boot_flag = "Yes" if partition.bootable else "No"
                part_type = self.partition_registry.get_partition_type(partition.system_id)
                size_mb = f"{partition.size_mb:.1f}"
                start_chs = f"{partition.start_chs[0]}/{partition.start_chs[1]}/{partition.start_chs[2]}"
                end_chs = f"{partition.end_chs[0]}/{partition.end_chs[1]}/{partition.end_chs[2]}"
                
                lines.append(f"{i:<2} {boot_flag:<4} {part_type:<20} {partition.start_lba:<10} "
                           f"{size_mb:<12} {start_chs:<12} {end_chs:<12}")
        
        lines.append("-" * 80)
        
        # Validation results
        validation_errors = self.validate_mbr(mbr_structure)
        if validation_errors:
            lines.append("")
            lines.append("VALIDATION ERRORS:")
            for error in validation_errors:
                lines.append(f"  ⚠️  {error}")
        else:
            lines.append("")
            lines.append("✅ MBR structure validation passed")
        
        return "\n".join(lines)
    
    def generate_partition_color_legend(self, mbr_structure: MBRStructure, format_type: str = "human") -> str:
        """
        Generate color legend for partition table entries.
        
        Args:
            mbr_structure: Parsed MBR structure
            format_type: Output format ("human", "html")
            
        Returns:
            Formatted color legend string
        """
        if format_type == "html":
            return self._generate_html_partition_legend(mbr_structure)
        else:
            return self._generate_human_partition_legend(mbr_structure)
    
    def _generate_human_partition_legend(self, mbr_structure: MBRStructure) -> str:
        """Generate human-readable partition color legend."""
        lines = []
        lines.append("Partition Color Legend:")
        
        for i, partition in enumerate(mbr_structure.partition_entries, 1):
            if partition.is_empty:
                status = "Empty"
                color = PartitionColors.get_ansi_color(i, is_empty=True)
            else:
                part_type = self.partition_registry.get_partition_type(partition.system_id)
                status = f"Type 0x{partition.system_id:02X} ({part_type})"
                color = PartitionColors.get_ansi_color(i, is_empty=False)
            
            lines.append(f"  {color}Partition {i}{self._get_ansi_reset()}: {status}")
        
        return "\n".join(lines)
    
    def _generate_html_partition_legend(self, mbr_structure: MBRStructure) -> str:
        """Generate HTML partition color legend."""
        legend_items = []
        
        for i, partition in enumerate(mbr_structure.partition_entries, 1):
            if partition.is_empty:
                status = "Empty"
                color = PartitionColors.get_html_color(i, is_empty=True)
            else:
                part_type = self.partition_registry.get_partition_type(partition.system_id)
                status = f"Type 0x{partition.system_id:02X} ({part_type})"
                color = PartitionColors.get_html_color(i, is_empty=False)
            
            legend_items.append(
                f'<li><span style="background-color: {color}; padding: 2px 8px; margin-right: 10px;">■</span> '
                f'Partition {i}: {status}</li>'
            )
        
        return f'<ul>{"".join(legend_items)}</ul>'
    
    def _get_ansi_reset(self) -> str:
        """Get ANSI reset code."""
        from .report_generator import ANSIColors
        return ANSIColors.RESET