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
