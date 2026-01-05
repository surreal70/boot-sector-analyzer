"""Data models for boot sector analysis."""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Tuple, Any


class ThreatLevel(Enum):
    """Threat level classification."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FilesystemType(Enum):
    """Filesystem type classification for VBR analysis."""

    FAT12 = "fat12"
    FAT16 = "fat16"
    FAT32 = "fat32"
    NTFS = "ntfs"
    EXFAT = "exfat"
    EXT2 = "ext2"
    EXT3 = "ext3"
    EXT4 = "ext4"
    UNKNOWN = "unknown"


@dataclass
class PartitionEntry:
    """Represents a single partition table entry."""

    status: int  # Boot indicator (0x80 = bootable, 0x00 = inactive)
    start_chs: Tuple[int, int, int]  # Start CHS address (cylinder, head, sector)
    partition_type: int  # Partition type code
    end_chs: Tuple[int, int, int]  # End CHS address (cylinder, head, sector)
    start_lba: int  # Start LBA address
    size_sectors: int  # Size in sectors


@dataclass
class MBRStructure:
    """Represents the Master Boot Record structure."""

    bootstrap_code: bytes  # First 446 bytes
    partition_table: List[PartitionEntry]  # 4 partition entries
    boot_signature: int  # Should be 0x55AA
    disk_signature: Optional[int] = None  # Optional 4-byte signature at offset 440


@dataclass
class Anomaly:
    """Represents a structural anomaly found in the boot sector."""

    type: str
    description: str
    severity: str
    location: Optional[int] = None


@dataclass
class Pattern:
    """Represents a suspicious pattern found in boot code."""

    type: str
    description: str
    location: int
    data: bytes


@dataclass
class ThreatMatch:
    """Represents a match against known threat signatures."""

    threat_name: str
    threat_type: str
    confidence: float
    source: str
    hash_match: Optional[str] = None


@dataclass
class BootkitIndicator:
    """Represents indicators of bootkit presence."""

    indicator_type: str
    description: str
    confidence: float
    location: Optional[int] = None


@dataclass
class StructureAnalysis:
    """Results of boot sector structure analysis."""

    mbr_structure: MBRStructure
    is_valid_signature: bool
    anomalies: List[Anomaly]
    partition_count: int


@dataclass
class ContentAnalysis:
    """Results of boot sector content analysis."""

    hashes: Dict[str, str]  # Hash type -> hash value
    strings: List[str]
    suspicious_patterns: List[Pattern]
    entropy: float
    urls: List[str]
    disassembly_result: Optional['DisassemblyResult'] = None


@dataclass
class SecurityAnalysis:
    """Results of security threat analysis."""

    threat_level: ThreatLevel
    detected_threats: List[ThreatMatch]
    bootkit_indicators: List[BootkitIndicator]
    suspicious_patterns: List[Pattern]
    anomalies: List[Anomaly]


@dataclass
class VirusTotalResult:
    """Results from VirusTotal API query."""

    hash_value: str
    detection_count: int
    total_engines: int
    scan_date: Optional[datetime]
    permalink: Optional[str]
    detections: Dict[str, Any]


@dataclass
class ThreatIntelligence:
    """Aggregated threat intelligence results."""

    virustotal_result: Optional[VirusTotalResult]
    cached: bool
    query_timestamp: datetime


@dataclass
class HexdumpData:
    """Hexdump representation of boot sector data."""

    raw_data: bytes  # Complete 512-byte boot sector
    formatted_lines: List[str]  # Pre-formatted hexdump lines
    ascii_representation: str  # ASCII view of the data
    total_bytes: int  # Should always be 512 for boot sectors


@dataclass
class Instruction:
    """Represents a disassembled instruction."""

    address: int  # Memory address (typically starting at 0x7C00)
    bytes: bytes  # Raw instruction bytes
    mnemonic: str  # Assembly mnemonic (e.g., "mov", "jmp")
    operands: str  # Instruction operands
    comment: Optional[str] = None  # Explanatory comment for boot sector operations


@dataclass
class InvalidInstruction:
    """Represents an invalid instruction that couldn't be disassembled."""

    address: int
    bytes: bytes
    reason: str  # Why disassembly failed


@dataclass
class BootPattern:
    """Represents a recognized boot sector pattern."""

    pattern_type: str  # "disk_read", "interrupt_call", "jump", etc.
    description: str
    instructions: List[Instruction]
    significance: str  # Explanation of what this pattern does


@dataclass
class DisassemblyResult:
    """Results of boot code disassembly."""

    instructions: List[Instruction]
    total_bytes_disassembled: int
    invalid_instructions: List[InvalidInstruction]
    boot_patterns: List[BootPattern]


@dataclass
class AnalysisResult:
    """Complete analysis results for a boot sector."""

    source: str
    timestamp: datetime
    structure_analysis: StructureAnalysis
    content_analysis: ContentAnalysis
    security_analysis: SecurityAnalysis
    hexdump: HexdumpData
    disassembly: Optional[DisassemblyResult] = None
    threat_intelligence: Optional[ThreatIntelligence] = None
    vbr_analysis: List['VBRAnalysisResult'] = None

    def __post_init__(self):
        """Initialize vbr_analysis as empty list if None."""
        if self.vbr_analysis is None:
            self.vbr_analysis = []


@dataclass
class ValidPartition:
    """Represents a valid partition identified for VBR extraction."""

    partition_entry: PartitionEntry
    partition_number: int  # 1-4
    start_byte_offset: int  # Calculated byte offset for VBR extraction
    is_accessible: bool  # Whether partition can be accessed for VBR extraction


@dataclass
class VBRData:
    """Raw VBR data extracted from a partition."""

    partition_number: int
    raw_vbr: bytes  # 512-byte VBR data
    extraction_successful: bool
    error_message: Optional[str] = None


@dataclass
class FilesystemMetadata:
    """Filesystem-specific metadata extracted from VBR."""

    volume_label: Optional[str] = None
    cluster_size: Optional[int] = None
    total_sectors: Optional[int] = None
    filesystem_version: Optional[str] = None
    creation_timestamp: Optional[datetime] = None


@dataclass
class BIOSParameterBlock:
    """FAT filesystem BIOS Parameter Block."""

    bytes_per_sector: int
    sectors_per_cluster: int
    reserved_sectors: int
    fat_count: int
    root_entries: int  # FAT12/16 only
    total_sectors_16: int  # FAT12/16 only
    media_descriptor: int
    sectors_per_fat_16: int  # FAT12/16 only
    sectors_per_track: int
    heads: int
    hidden_sectors: int
    total_sectors_32: int  # FAT32 only
    sectors_per_fat_32: Optional[int] = None  # FAT32 only
    flags: Optional[int] = None  # FAT32 only
    version: Optional[int] = None  # FAT32 only
    root_cluster: Optional[int] = None  # FAT32 only


@dataclass
class NTFSBIOSParameterBlock:
    """NTFS filesystem BIOS Parameter Block."""

    bytes_per_sector: int
    sectors_per_cluster: int
    reserved_sectors: int
    media_descriptor: int
    sectors_per_track: int
    heads: int
    hidden_sectors: int
    total_sectors: int
    mft_cluster: int
    mft_mirror_cluster: int
    clusters_per_file_record: int
    clusters_per_index_buffer: int
    volume_serial: int


@dataclass
class ExFATBIOSParameterBlock:
    """exFAT filesystem BIOS Parameter Block."""

    bytes_per_sector: int
    sectors_per_cluster: int
    fat_offset: int
    fat_length: int
    cluster_heap_offset: int
    cluster_count: int
    root_directory_cluster: int
    volume_serial: int
    filesystem_revision: int
    volume_flags: int
    bytes_per_sector_shift: int
    sectors_per_cluster_shift: int


@dataclass
class VBRStructure:
    """Base VBR structure for all filesystem types."""

    filesystem_type: FilesystemType
    boot_code: bytes  # Boot code region (varies by filesystem)
    boot_signature: int  # Boot signature (usually 0x55AA)
    filesystem_metadata: FilesystemMetadata
    raw_data: bytes  # Complete 512-byte VBR


@dataclass
class FATVBRStructure(VBRStructure):
    """FAT-specific VBR structure."""

    bpb: BIOSParameterBlock  # FAT-specific BIOS Parameter Block
    boot_code_offset: int  # Offset where boot code starts
    boot_code_size: int  # Size of boot code region


@dataclass
class NTFSVBRStructure(VBRStructure):
    """NTFS-specific VBR structure."""

    ntfs_bpb: NTFSBIOSParameterBlock  # NTFS-specific BPB
    mft_cluster: int  # Master File Table cluster location
    volume_serial: int  # NTFS volume serial number


@dataclass
class ExFATVBRStructure(VBRStructure):
    """exFAT-specific VBR structure."""

    exfat_bpb: ExFATBIOSParameterBlock  # exFAT-specific BPB
    fat_offset: int  # File Allocation Table offset
    cluster_heap_offset: int  # Cluster heap offset


@dataclass
class VBRPattern:
    """Represents a filesystem-specific boot pattern found in VBR."""

    pattern_type: str  # "fat_boot_code", "ntfs_boot_code", "filesystem_check", etc.
    description: str
    instructions: List[Instruction]  # Associated assembly instructions
    significance: str  # What this pattern indicates
    filesystem_specific: bool  # Whether pattern is filesystem-specific


@dataclass
class VBRAnomalyy:
    """Represents an anomaly detected in VBR analysis."""

    anomaly_type: str  # "modified_boot_code", "suspicious_metadata", etc.
    description: str
    severity: str  # "low", "medium", "high", "critical"
    evidence: List[str]  # Supporting evidence for the anomaly


@dataclass
class VBRContentAnalysis:
    """Results of VBR content analysis."""

    hashes: Dict[str, str]  # MD5, SHA-256 hashes of VBR
    boot_code_hashes: Dict[str, str]  # Hashes of boot code region only
    disassembly_result: Optional[DisassemblyResult]  # Disassembled boot code
    detected_patterns: List[VBRPattern]  # Filesystem-specific patterns
    anomalies: List[VBRAnomalyy]  # Detected anomalies
    threat_level: ThreatLevel  # VBR-specific threat assessment


@dataclass
class VBRAnalysisResult:
    """Complete VBR analysis results for a single partition."""

    partition_number: int  # 1-4 based on MBR partition table position
    partition_info: PartitionEntry  # Original partition entry from MBR
    vbr_structure: Optional[VBRStructure]  # Parsed VBR structure
    content_analysis: Optional[VBRContentAnalysis]  # VBR content analysis
    extraction_error: Optional[str] = None  # Error message if VBR extraction failed
