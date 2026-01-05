"""VBR content analysis for filesystem-specific boot record analysis."""

import hashlib
import logging
from typing import Dict, List, Optional

from .models import (
    VBRStructure,
    VBRContentAnalysis,
    VBRPattern,
    VBRAnomalyy,
    ThreatLevel,
    FilesystemType,
    DisassemblyResult,
    Instruction
)
from .disassembly_engine import DisassemblyEngine
from .exceptions import ContentAnalysisError

logger = logging.getLogger(__name__)


class VBRContentAnalyzer:
    """Analyzes VBR content for filesystem-specific patterns and security threats."""

    def __init__(self):
        """Initialize VBRContentAnalyzer with disassembly engine."""
        self.disassembly_engine = DisassemblyEngine()

    def analyze_vbr_content(self, vbr_structure: VBRStructure) -> VBRContentAnalysis:
        """
        Perform comprehensive VBR content analysis.
        
        Args:
            vbr_structure: Parsed VBR structure to analyze
            
        Returns:
            Complete VBR content analysis results
            
        Raises:
            ContentAnalysisError: If VBR content analysis fails
        """
        logger.debug(f"Starting VBR content analysis for {vbr_structure.filesystem_type}")
        
        try:
            # Calculate hashes for complete VBR and boot code region
            vbr_hashes = self.calculate_vbr_hashes(vbr_structure.raw_data)
            boot_code_hashes = self.calculate_vbr_hashes(vbr_structure.boot_code)
            
            # Disassemble VBR boot code
            disassembly_result = self.disassemble_vbr_boot_code(
                vbr_structure.boot_code, 
                vbr_structure.filesystem_type
            )
            
            # Detect filesystem-specific patterns
            detected_patterns = self.detect_vbr_patterns(vbr_structure)
            
            # Identify anomalies
            anomalies = self.identify_vbr_anomalies(vbr_structure)
            
            # Assess threat level
            threat_level = self._assess_vbr_threat_level(anomalies, detected_patterns)
            
            # Create initial VBR content analysis
            initial_analysis = VBRContentAnalysis(
                hashes=vbr_hashes,
                boot_code_hashes=boot_code_hashes,
                disassembly_result=disassembly_result,
                detected_patterns=detected_patterns,
                anomalies=anomalies,
                threat_level=threat_level
            )
            
            # Enhance with security analysis using SecurityScanner
            from .security_scanner import SecurityScanner
            security_scanner = SecurityScanner()
            
            enhanced_analysis = security_scanner.analyze_vbr_security(
                initial_analysis, vbr_structure
            )
            
            logger.info(f"VBR content analysis completed: {len(enhanced_analysis.detected_patterns)} patterns, "
                       f"{len(enhanced_analysis.anomalies)} anomalies, threat level: {enhanced_analysis.threat_level}")
            
            return enhanced_analysis
            
        except Exception as e:
            error_msg = f"Failed to analyze VBR content: {e}"
            logger.error(error_msg, exc_info=True)
            raise ContentAnalysisError(
                error_msg,
                error_code="VBR_CONTENT_ANALYSIS_ERROR",
                details={"filesystem_type": str(vbr_structure.filesystem_type), "error": str(e)}
            )

    def calculate_vbr_hashes(self, vbr_data: bytes) -> Dict[str, str]:
        """
        Calculate MD5 and SHA-256 hashes of VBR data.
        
        Args:
            vbr_data: VBR data bytes to hash
            
        Returns:
            Dictionary mapping hash algorithm to hex digest
            
        Raises:
            ContentAnalysisError: If hash calculation fails
        """
        logger.debug("Calculating VBR cryptographic hashes")
        
        if not isinstance(vbr_data, bytes):
            error_msg = f"VBR data must be bytes, got {type(vbr_data)}"
            logger.error(error_msg)
            raise ContentAnalysisError(
                error_msg,
                error_code="INVALID_DATA_TYPE",
                details={"data_type": str(type(vbr_data))}
            )
        
        hashes = {}

        try:
            # Calculate MD5
            md5_hash = hashlib.md5(vbr_data)
            hashes["md5"] = md5_hash.hexdigest()

            # Calculate SHA-256
            sha256_hash = hashlib.sha256(vbr_data)
            hashes["sha256"] = sha256_hash.hexdigest()

            logger.debug(f"Calculated VBR hashes - MD5: {hashes['md5']}, SHA-256: {hashes['sha256']}")
            return hashes
            
        except Exception as e:
            error_msg = f"Failed to calculate VBR hashes: {e}"
            logger.error(error_msg, exc_info=True)
            raise ContentAnalysisError(
                error_msg,
                error_code="VBR_HASH_CALCULATION_ERROR",
                details={"exception_type": type(e).__name__, "error": str(e)}
            )

    def disassemble_vbr_boot_code(self, boot_code: bytes, filesystem_type: FilesystemType) -> Optional[DisassemblyResult]:
        """
        Disassemble VBR boot code with filesystem-specific context.
        
        Args:
            boot_code: VBR boot code bytes to disassemble
            filesystem_type: Type of filesystem for context
            
        Returns:
            DisassemblyResult with instructions and patterns, or None if boot code is empty
            
        Raises:
            ContentAnalysisError: If disassembly fails
        """
        logger.debug(f"Starting VBR boot code disassembly for {filesystem_type}")
        
        if not isinstance(boot_code, bytes):
            error_msg = f"Boot code must be bytes, got {type(boot_code)}"
            logger.error(error_msg)
            raise ContentAnalysisError(
                error_msg,
                error_code="INVALID_DATA_TYPE",
                details={"data_type": str(type(boot_code))}
            )
        
        # Check if boot code is empty (all zeros)
        if self._check_empty_boot_code(boot_code):
            logger.info("VBR boot code region contains only zeros, skipping disassembly")
            return None
        
        try:
            # Use disassembly engine with error handling
            # VBR boot code typically uses 16-bit mode like MBR
            disassembly_result = self.disassembly_engine.disassemble_with_error_handling(
                boot_code, 
                base_address=0x7C00,  # Standard boot sector load address
                prefer_16bit=True
            )
            
            logger.info(f"VBR disassembly completed: {len(disassembly_result.instructions)} instructions, "
                       f"{len(disassembly_result.invalid_instructions)} invalid, "
                       f"{len(disassembly_result.boot_patterns)} patterns")
            
            return disassembly_result
            
        except Exception as e:
            error_msg = f"Failed to disassemble VBR boot code: {e}"
            logger.error(error_msg, exc_info=True)
            raise ContentAnalysisError(
                error_msg,
                error_code="VBR_DISASSEMBLY_ERROR",
                details={"filesystem_type": str(filesystem_type), "error": str(e)}
            )

    def detect_vbr_patterns(self, vbr_structure: VBRStructure) -> List[VBRPattern]:
        """
        Detect filesystem-specific boot patterns.
        
        Args:
            vbr_structure: VBR structure to analyze for patterns
            
        Returns:
            List of detected VBR patterns
            
        Raises:
            ContentAnalysisError: If pattern detection fails
        """
        logger.debug(f"Detecting VBR patterns for {vbr_structure.filesystem_type}")
        
        patterns = []
        
        try:
            # Get disassembly if available
            disassembly_result = self.disassemble_vbr_boot_code(
                vbr_structure.boot_code, 
                vbr_structure.filesystem_type
            )
            
            if disassembly_result and disassembly_result.instructions:
                # Detect filesystem-specific patterns based on filesystem type
                if vbr_structure.filesystem_type in [FilesystemType.FAT12, FilesystemType.FAT16, FilesystemType.FAT32]:
                    patterns.extend(self._detect_fat_boot_patterns(disassembly_result.instructions))
                elif vbr_structure.filesystem_type == FilesystemType.NTFS:
                    patterns.extend(self._detect_ntfs_boot_patterns(disassembly_result.instructions))
                elif vbr_structure.filesystem_type == FilesystemType.EXFAT:
                    patterns.extend(self._detect_exfat_boot_patterns(disassembly_result.instructions))
                
                # Detect common VBR patterns regardless of filesystem
                patterns.extend(self._detect_common_vbr_patterns(disassembly_result.instructions))
            
            logger.debug(f"VBR pattern detection completed: {len(patterns)} patterns found")
            return patterns
            
        except Exception as e:
            error_msg = f"Failed to detect VBR patterns: {e}"
            logger.error(error_msg, exc_info=True)
            raise ContentAnalysisError(
                error_msg,
                error_code="VBR_PATTERN_DETECTION_ERROR",
                details={"filesystem_type": str(vbr_structure.filesystem_type), "error": str(e)}
            )

    def identify_vbr_anomalies(self, vbr_structure: VBRStructure) -> List[VBRAnomalyy]:
        """
        Identify suspicious VBR modifications or anomalies.
        
        Args:
            vbr_structure: VBR structure to analyze for anomalies
            
        Returns:
            List of detected VBR anomalies
            
        Raises:
            ContentAnalysisError: If anomaly detection fails
        """
        logger.debug(f"Identifying VBR anomalies for {vbr_structure.filesystem_type}")
        
        anomalies = []
        
        try:
            # Check boot signature
            if vbr_structure.boot_signature != 0x55AA:
                anomalies.append(VBRAnomalyy(
                    anomaly_type="invalid_boot_signature",
                    description=f"Invalid boot signature: 0x{vbr_structure.boot_signature:04X} (expected 0x55AA)",
                    severity="high",
                    evidence=[f"Boot signature: 0x{vbr_structure.boot_signature:04X}"]
                ))
            
            # Check for suspicious boot code modifications
            boot_code_anomalies = self._detect_boot_code_anomalies(vbr_structure)
            anomalies.extend(boot_code_anomalies)
            
            # Check filesystem metadata for anomalies
            metadata_anomalies = self._detect_metadata_anomalies(vbr_structure)
            anomalies.extend(metadata_anomalies)
            
            logger.debug(f"VBR anomaly detection completed: {len(anomalies)} anomalies found")
            return anomalies
            
        except Exception as e:
            error_msg = f"Failed to identify VBR anomalies: {e}"
            logger.error(error_msg, exc_info=True)
            raise ContentAnalysisError(
                error_msg,
                error_code="VBR_ANOMALY_DETECTION_ERROR",
                details={"filesystem_type": str(vbr_structure.filesystem_type), "error": str(e)}
            )

    def extract_filesystem_metadata(self, vbr_structure: VBRStructure) -> Dict[str, str]:
        """
        Extract filesystem-specific metadata for analysis.
        
        Args:
            vbr_structure: VBR structure to extract metadata from
            
        Returns:
            Dictionary of extracted metadata
            
        Raises:
            ContentAnalysisError: If metadata extraction fails
        """
        logger.debug(f"Extracting filesystem metadata for {vbr_structure.filesystem_type}")
        
        metadata = {}
        
        try:
            # Extract common metadata
            if vbr_structure.filesystem_metadata:
                if vbr_structure.filesystem_metadata.volume_label:
                    metadata["volume_label"] = vbr_structure.filesystem_metadata.volume_label
                if vbr_structure.filesystem_metadata.cluster_size:
                    metadata["cluster_size"] = str(vbr_structure.filesystem_metadata.cluster_size)
                if vbr_structure.filesystem_metadata.total_sectors:
                    metadata["total_sectors"] = str(vbr_structure.filesystem_metadata.total_sectors)
                if vbr_structure.filesystem_metadata.filesystem_version:
                    metadata["filesystem_version"] = vbr_structure.filesystem_metadata.filesystem_version
            
            # Extract filesystem-specific metadata
            metadata["filesystem_type"] = vbr_structure.filesystem_type.value
            metadata["boot_code_size"] = str(len(vbr_structure.boot_code))
            metadata["boot_signature"] = f"0x{vbr_structure.boot_signature:04X}"
            
            logger.debug(f"Filesystem metadata extraction completed: {len(metadata)} fields")
            return metadata
            
        except Exception as e:
            error_msg = f"Failed to extract filesystem metadata: {e}"
            logger.error(error_msg, exc_info=True)
            raise ContentAnalysisError(
                error_msg,
                error_code="METADATA_EXTRACTION_ERROR",
                details={"filesystem_type": str(vbr_structure.filesystem_type), "error": str(e)}
            )

    def _check_empty_boot_code(self, boot_code: bytes) -> bool:
        """
        Check if boot code region contains only zero bytes.
        
        Args:
            boot_code: Boot code bytes to check
            
        Returns:
            True if boot code contains only zeros, False otherwise
        """
        if not isinstance(boot_code, bytes):
            return False
        
        return all(byte == 0 for byte in boot_code)

    def _assess_vbr_threat_level(self, anomalies: List[VBRAnomalyy], patterns: List[VBRPattern]) -> ThreatLevel:
        """
        Assess VBR-specific threat level based on anomalies and patterns.
        
        Args:
            anomalies: List of detected anomalies
            patterns: List of detected patterns
            
        Returns:
            Assessed threat level
        """
        # Count anomalies by severity
        critical_count = sum(1 for a in anomalies if a.severity == "critical")
        high_count = sum(1 for a in anomalies if a.severity == "high")
        medium_count = sum(1 for a in anomalies if a.severity == "medium")
        
        # Assess based on anomaly severity
        if critical_count > 0:
            return ThreatLevel.CRITICAL
        elif high_count > 0:
            return ThreatLevel.HIGH
        elif medium_count > 1:
            return ThreatLevel.MEDIUM
        elif medium_count > 0 or len(anomalies) > 0:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.LOW

    def _detect_fat_boot_patterns(self, instructions: List[Instruction]) -> List[VBRPattern]:
        """Detect FAT-specific boot patterns."""
        patterns = []
        
        # Look for FAT-specific patterns like BPB access, FAT loading, etc.
        for i, insn in enumerate(instructions):
            # Look for BPB field access patterns
            if insn.mnemonic.lower() == "mov" and "0x" in insn.operands:
                # Check if accessing common BPB offsets
                if any(offset in insn.operands for offset in ["0xb", "0xd", "0xe", "0x10"]):
                    patterns.append(VBRPattern(
                        pattern_type="fat_bpb_access",
                        description="FAT BIOS Parameter Block access",
                        instructions=[insn],
                        significance="Accesses FAT filesystem parameters",
                        filesystem_specific=True
                    ))
        
        return patterns

    def _detect_ntfs_boot_patterns(self, instructions: List[Instruction]) -> List[VBRPattern]:
        """Detect NTFS-specific boot patterns."""
        patterns = []
        
        # Look for NTFS-specific patterns like MFT access, NTFS signature checks
        for i, insn in enumerate(instructions):
            # Look for NTFS signature checks
            if insn.mnemonic.lower() == "cmp" and "ntfs" in insn.operands.lower():
                patterns.append(VBRPattern(
                    pattern_type="ntfs_signature_check",
                    description="NTFS filesystem signature verification",
                    instructions=[insn],
                    significance="Verifies NTFS filesystem signature",
                    filesystem_specific=True
                ))
        
        return patterns

    def _detect_exfat_boot_patterns(self, instructions: List[Instruction]) -> List[VBRPattern]:
        """Detect exFAT-specific boot patterns."""
        patterns = []
        
        # Look for exFAT-specific patterns
        for i, insn in enumerate(instructions):
            # Look for exFAT signature checks
            if insn.mnemonic.lower() == "cmp" and "exfat" in insn.operands.lower():
                patterns.append(VBRPattern(
                    pattern_type="exfat_signature_check",
                    description="exFAT filesystem signature verification",
                    instructions=[insn],
                    significance="Verifies exFAT filesystem signature",
                    filesystem_specific=True
                ))
        
        return patterns

    def _detect_common_vbr_patterns(self, instructions: List[Instruction]) -> List[VBRPattern]:
        """Detect common VBR patterns regardless of filesystem."""
        patterns = []
        
        # Look for common boot patterns
        for i, insn in enumerate(instructions):
            # Look for error message display patterns
            if insn.mnemonic.lower() == "int" and "0x10" in insn.operands:
                patterns.append(VBRPattern(
                    pattern_type="error_message_display",
                    description="Error message display via BIOS video services",
                    instructions=[insn],
                    significance="Displays error messages to user",
                    filesystem_specific=False
                ))
            
            # Look for system halt patterns
            elif insn.mnemonic.lower() == "hlt":
                patterns.append(VBRPattern(
                    pattern_type="system_halt",
                    description="System halt instruction",
                    instructions=[insn],
                    significance="Halts system execution",
                    filesystem_specific=False
                ))
        
        return patterns

    def _detect_boot_code_anomalies(self, vbr_structure: VBRStructure) -> List[VBRAnomalyy]:
        """Detect anomalies in VBR boot code."""
        anomalies = []
        
        # Check for suspicious boot code size
        boot_code_size = len(vbr_structure.boot_code)
        if boot_code_size == 0:
            anomalies.append(VBRAnomalyy(
                anomaly_type="empty_boot_code",
                description="VBR contains no boot code",
                severity="medium",
                evidence=["Boot code size: 0 bytes"]
            ))
        elif boot_code_size > 400:  # Unusually large for VBR
            anomalies.append(VBRAnomalyy(
                anomaly_type="oversized_boot_code",
                description=f"Unusually large boot code: {boot_code_size} bytes",
                severity="medium",
                evidence=[f"Boot code size: {boot_code_size} bytes"]
            ))
        
        # Check for suspicious patterns in boot code
        if self._contains_suspicious_bytes(vbr_structure.boot_code):
            anomalies.append(VBRAnomalyy(
                anomaly_type="suspicious_boot_code",
                description="Boot code contains suspicious byte patterns",
                severity="high",
                evidence=["Suspicious byte patterns detected"]
            ))
        
        return anomalies

    def _detect_metadata_anomalies(self, vbr_structure: VBRStructure) -> List[VBRAnomalyy]:
        """Detect anomalies in filesystem metadata."""
        anomalies = []
        
        # Check for suspicious metadata values
        if vbr_structure.filesystem_metadata:
            metadata = vbr_structure.filesystem_metadata
            
            # Check cluster size
            if metadata.cluster_size and metadata.cluster_size > 65536:
                anomalies.append(VBRAnomalyy(
                    anomaly_type="suspicious_cluster_size",
                    description=f"Unusually large cluster size: {metadata.cluster_size}",
                    severity="medium",
                    evidence=[f"Cluster size: {metadata.cluster_size} bytes"]
                ))
            
            # Check volume label for suspicious content
            if metadata.volume_label and len(metadata.volume_label) > 11:
                anomalies.append(VBRAnomalyy(
                    anomaly_type="invalid_volume_label",
                    description=f"Volume label exceeds maximum length: {len(metadata.volume_label)}",
                    severity="low",
                    evidence=[f"Volume label: '{metadata.volume_label}'"]
                ))
        
        return anomalies

    def _contains_suspicious_bytes(self, boot_code: bytes) -> bool:
        """Check if boot code contains suspicious byte patterns."""
        # Look for common shellcode patterns
        suspicious_patterns = [
            b"\x90\x90\x90\x90",  # NOP sled
            b"\xcc\xcc\xcc\xcc",  # INT3 debug breaks
            b"\x31\xc0",          # XOR EAX, EAX
        ]
        
        for pattern in suspicious_patterns:
            if pattern in boot_code:
                return True
        
        return False