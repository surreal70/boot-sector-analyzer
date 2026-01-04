"""Security scanning and threat detection."""

import logging
from typing import Dict, List

from .models import ThreatLevel, ThreatMatch, BootkitIndicator, Pattern, SecurityAnalysis
from .exceptions import (
    SecurityAnalysisError,
    AnalysisError
)

logger = logging.getLogger(__name__)


class SecurityScanner:
    """Scans boot sectors for security threats and malicious patterns."""

    def __init__(self):
        """Initialize security scanner with known threat signatures."""
        logger.debug("Initializing SecurityScanner")
        
        # Known malware hashes (example signatures)
        self.known_malware_hashes = {
            "md5": {
                # Example malware hashes - in real implementation, load from database
                "a1b2c3d4e5f6789012345678901234567": "Generic.Bootkit.A",
                "b2c3d4e5f6789012345678901234567a1": "MBR.Hijacker.B",
            },
            "sha256": {
                "a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890": "Advanced.Rootkit.C",
            },
        }

        # Bootkit signatures (byte patterns)
        self.bootkit_signatures = [
            (b"\x31\xc0\x8e\xd8\x8e\xc0", "Common bootkit initialization"),
            (b"\xfa\xfc\x31\xc0", "CLI/CLD bootkit pattern"),
            (b"\x0f\x01\x16", "LGDT instruction (bootkit loader)"),
        ]
        
        logger.debug(f"Loaded {sum(len(hashes) for hashes in self.known_malware_hashes.values())} malware signatures")
        logger.debug(f"Loaded {len(self.bootkit_signatures)} bootkit signatures")

    def scan_for_threats(self, boot_sector: bytes, hashes: Dict[str, str]) -> SecurityAnalysis:
        """
        Perform complete security analysis of boot sector.
        
        Args:
            boot_sector: Boot sector data to analyze
            hashes: Calculated hashes of the boot sector
            
        Returns:
            Complete security analysis results
            
        Raises:
            SecurityAnalysisError: If security analysis fails
        """
        logger.debug("Starting security threat analysis")
        
        try:
            # Check known signatures
            detected_threats = self.check_known_signatures(hashes)
            
            # Detect bootkit patterns
            bootkit_indicators = self.detect_bootkit_patterns(boot_sector)
            
            # Detect MBR hijacking (requires MBR structure)
            from .structure_analyzer import StructureAnalyzer
            structure_analyzer = StructureAnalyzer()
            mbr_structure = structure_analyzer.parse_mbr(boot_sector)
            mbr_hijacking_indicators = self.detect_mbr_hijacking(mbr_structure, boot_sector)
            bootkit_indicators.extend(mbr_hijacking_indicators)
            
            # Detect rootkit indicators
            rootkit_indicators = self.detect_rootkit_indicators(boot_sector)
            bootkit_indicators.extend(rootkit_indicators)
            
            # Detect encryption/obfuscation
            from .content_analyzer import ContentAnalyzer
            content_analyzer = ContentAnalyzer()
            entropy = content_analyzer.analyze_entropy(boot_sector)
            encryption_indicators = self.detect_encryption_obfuscation(boot_sector, entropy)
            bootkit_indicators.extend(encryption_indicators)
            
            # Detect suspicious patterns
            suspicious_patterns = content_analyzer.detect_suspicious_patterns(boot_sector)
            
            # Get anomalies from structure analysis
            anomalies = structure_analyzer.detect_anomalies(mbr_structure)
            
            # Assess overall threat level
            threat_level = self.assess_threat_level(
                detected_threats, bootkit_indicators, suspicious_patterns, anomalies
            )
            
            logger.info(f"Security analysis completed: threat_level={threat_level.value}, {len(detected_threats)} threats, {len(bootkit_indicators)} indicators")
            
            return SecurityAnalysis(
                threat_level=threat_level,
                detected_threats=detected_threats,
                bootkit_indicators=bootkit_indicators,
                suspicious_patterns=suspicious_patterns,
                anomalies=anomalies
            )
            
        except Exception as e:
            error_msg = f"Failed to perform security analysis: {e}"
            logger.error(error_msg, exc_info=True)
            raise SecurityAnalysisError(
                error_msg,
                error_code="SECURITY_ANALYSIS_ERROR",
                details={"exception_type": type(e).__name__, "error": str(e)}
            )

    def check_known_signatures(self, hashes: Dict[str, str]) -> List[ThreatMatch]:
        """
        Check hashes against known malware signatures.

        Args:
            hashes: Dictionary of hash type -> hash value

        Returns:
            List of threat matches found
            
        Raises:
            SecurityAnalysisError: If signature checking fails
        """
        logger.debug("Checking against known malware signatures")
        
        if not isinstance(hashes, dict):
            error_msg = f"Hashes must be dictionary, got {type(hashes)}"
            logger.error(error_msg)
            raise SecurityAnalysisError(
                error_msg,
                error_code="INVALID_HASHES_TYPE",
                details={"hashes_type": str(type(hashes))}
            )
        
        matches = []

        try:
            for hash_type, hash_value in hashes.items():
                if not isinstance(hash_value, str):
                    logger.warning(f"Invalid hash value type for {hash_type}: {type(hash_value)}")
                    continue
                    
                if hash_type in self.known_malware_hashes:
                    threat_db = self.known_malware_hashes[hash_type]
                    if hash_value in threat_db:
                        threat_name = threat_db[hash_value]
                        match = ThreatMatch(
                            threat_name=threat_name,
                            threat_type="malware",
                            confidence=1.0,
                            source="local_database",
                            hash_match=hash_value,
                        )
                        matches.append(match)
                        logger.warning(
                            f"Known malware detected: {threat_name} ({hash_type}: {hash_value})"
                        )

            logger.debug(f"Signature check completed: {len(matches)} matches found")
            return matches
            
        except Exception as e:
            error_msg = f"Failed to check known signatures: {e}"
            logger.error(error_msg, exc_info=True)
            raise SecurityAnalysisError(
                error_msg,
                error_code="SIGNATURE_CHECK_ERROR",
                details={"exception_type": type(e).__name__, "error": str(e)}
            )

    def detect_bootkit_patterns(self, boot_code: bytes) -> List[BootkitIndicator]:
        """
        Identify common bootkit signatures.

        Args:
            boot_code: Boot code bytes to analyze

        Returns:
            List of bootkit indicators found
        """
        indicators = []

        for signature, description in self.bootkit_signatures:
            offset = 0
            while True:
                pos = boot_code.find(signature, offset)
                if pos == -1:
                    break

                indicators.append(
                    BootkitIndicator(
                        indicator_type="signature_match",
                        description=description,
                        confidence=0.8,
                        location=pos,
                    )
                )
                logger.warning(
                    f"Bootkit signature detected at offset {pos}: {description}"
                )
                offset = pos + 1

        # Check for suspicious instruction patterns
        if len(boot_code) >= 10:
            # Look for privilege escalation patterns
            if b"\x0f\x20\xc0" in boot_code:  # MOV EAX, CR0
                indicators.append(
                    BootkitIndicator(
                        indicator_type="privilege_escalation",
                        description="Control register access (MOV EAX, CR0)",
                        confidence=0.7,
                        location=boot_code.find(b"\x0f\x20\xc0"),
                    )
                )

            # Look for interrupt hooking
            if b"\x0f\x01\x1d" in boot_code:  # LIDT
                indicators.append(
                    BootkitIndicator(
                        indicator_type="interrupt_hooking",
                        description="Interrupt descriptor table modification (LIDT)",
                        confidence=0.8,
                        location=boot_code.find(b"\x0f\x01\x1d"),
                    )
                )

        return indicators

    def detect_mbr_hijacking(self, mbr_structure, boot_code: bytes) -> List[BootkitIndicator]:
        """
        Detect signs of MBR hijacking and partition table manipulation.

        Args:
            mbr_structure: Parsed MBR structure
            boot_code: Boot code bytes to analyze

        Returns:
            List of MBR hijacking indicators
        """
        indicators = []

        # Check for suspicious partition table modifications
        active_partitions = [p for p in mbr_structure.partition_table if p.status == 0x80]
        if len(active_partitions) > 1:
            indicators.append(
                BootkitIndicator(
                    indicator_type="partition_manipulation",
                    description="Multiple active partitions detected",
                    confidence=0.7,
                    location=None,
                )
            )

        # Check for overlapping partitions
        for i, partition1 in enumerate(mbr_structure.partition_table):
            if partition1.size_sectors == 0:
                continue
            for j, partition2 in enumerate(mbr_structure.partition_table[i + 1:], i + 1):
                if partition2.size_sectors == 0:
                    continue
                
                # Check for overlap
                p1_end = partition1.start_lba + partition1.size_sectors
                p2_end = partition2.start_lba + partition2.size_sectors
                
                if (partition1.start_lba < p2_end and p1_end > partition2.start_lba):
                    indicators.append(
                        BootkitIndicator(
                            indicator_type="partition_overlap",
                            description=f"Overlapping partitions detected (entries {i} and {j})",
                            confidence=0.8,
                            location=None,
                        )
                    )

        # Check for suspicious partition types
        suspicious_types = [0x00, 0xFF]  # Empty or invalid types in active partitions
        for i, partition in enumerate(mbr_structure.partition_table):
            if partition.status == 0x80 and partition.partition_type in suspicious_types:
                indicators.append(
                    BootkitIndicator(
                        indicator_type="suspicious_partition_type",
                        description=f"Active partition with suspicious type: 0x{partition.partition_type:02X}",
                        confidence=0.6,
                        location=None,
                    )
                )

        # Check for hidden partitions (type 0x17, 0x27, etc.)
        hidden_types = [0x17, 0x27, 0x77]
        for i, partition in enumerate(mbr_structure.partition_table):
            if partition.partition_type in hidden_types:
                indicators.append(
                    BootkitIndicator(
                        indicator_type="hidden_partition",
                        description=f"Hidden partition detected (type 0x{partition.partition_type:02X})",
                        confidence=0.5,
                        location=None,
                    )
                )

        return indicators

    def detect_rootkit_indicators(self, boot_code: bytes) -> List[BootkitIndicator]:
        """
        Detect rootkit indicators in boot code.

        Args:
            boot_code: Boot code bytes to analyze

        Returns:
            List of rootkit indicators
        """
        indicators = []

        # Check for system call hooking patterns
        syscall_patterns = [
            (b"\x0f\x05", "SYSCALL instruction"),
            (b"\xcd\x80", "INT 0x80 (Linux system call)"),
            (b"\xcd\x2e", "INT 0x2E (Windows system call)"),
        ]

        for pattern, description in syscall_patterns:
            if pattern in boot_code:
                pos = boot_code.find(pattern)
                indicators.append(
                    BootkitIndicator(
                        indicator_type="syscall_hooking",
                        description=f"System call pattern detected: {description}",
                        confidence=0.6,
                        location=pos,
                    )
                )

        # Check for memory manipulation patterns
        memory_patterns = [
            (b"\x0f\x22\xc0", "MOV CR0, EAX (disable memory protection)"),
            (b"\x0f\x22\xd8", "MOV CR3, EAX (page directory manipulation)"),
            (b"\x0f\x01\x15", "LGDT (global descriptor table load)"),
        ]

        for pattern, description in memory_patterns:
            if pattern in boot_code:
                pos = boot_code.find(pattern)
                indicators.append(
                    BootkitIndicator(
                        indicator_type="memory_manipulation",
                        description=description,
                        confidence=0.8,
                        location=pos,
                    )
                )

        # Check for anti-debugging techniques
        antidebug_patterns = [
            (b"\x0f\x31", "RDTSC (timing check)"),
            (b"\x64\x8b", "FS segment access (TEB/PEB access)"),
        ]

        for pattern, description in antidebug_patterns:
            if pattern in boot_code:
                pos = boot_code.find(pattern)
                indicators.append(
                    BootkitIndicator(
                        indicator_type="anti_debugging",
                        description=description,
                        confidence=0.5,
                        location=pos,
                    )
                )

        return indicators

    def detect_encryption_obfuscation(self, boot_code: bytes, entropy: float) -> List[BootkitIndicator]:
        """
        Detect signs of encryption or obfuscation in boot code.

        Args:
            boot_code: Boot code bytes to analyze
            entropy: Calculated entropy of the boot code

        Returns:
            List of encryption/obfuscation indicators
        """
        indicators = []

        # High entropy suggests encryption/packing
        if entropy > 7.5:
            indicators.append(
                BootkitIndicator(
                    indicator_type="high_entropy",
                    description=f"High entropy detected ({entropy:.2f}) - possible encryption/packing",
                    confidence=0.8,
                    location=None,
                )
            )
        elif entropy > 6.5:
            indicators.append(
                BootkitIndicator(
                    indicator_type="medium_entropy",
                    description=f"Medium-high entropy detected ({entropy:.2f}) - possible obfuscation",
                    confidence=0.6,
                    location=None,
                )
            )

        # Check for common packing/encryption signatures
        packer_signatures = [
            (b"UPX!", "UPX packer signature"),
            (b"\x60\xE8\x00\x00\x00\x00", "Common packer entry point"),
            (b"\xEB\x10\x5A\x4A", "Polymorphic decryption loop"),
        ]

        for signature, description in packer_signatures:
            if signature in boot_code:
                pos = boot_code.find(signature)
                indicators.append(
                    BootkitIndicator(
                        indicator_type="packer_signature",
                        description=description,
                        confidence=0.9,
                        location=pos,
                    )
                )

        # Check for XOR decryption loops (common obfuscation)
        xor_patterns = [
            b"\x30",  # XOR byte
            b"\x31",  # XOR dword
            b"\x80\xf0",  # XOR immediate byte
        ]

        xor_count = sum(boot_code.count(pattern) for pattern in xor_patterns)
        if xor_count > 5:
            indicators.append(
                BootkitIndicator(
                    indicator_type="xor_obfuscation",
                    description=f"Multiple XOR operations detected ({xor_count}) - possible obfuscation",
                    confidence=0.7,
                    location=None,
                )
            )

        # Check for self-modifying code patterns
        if b"\xc6\x06" in boot_code or b"\xc7\x06" in boot_code:  # MOV byte/word ptr
            indicators.append(
                BootkitIndicator(
                    indicator_type="self_modifying_code",
                    description="Self-modifying code patterns detected",
                    confidence=0.6,
                    location=boot_code.find(b"\xc6\x06") if b"\xc6\x06" in boot_code else boot_code.find(b"\xc7\x06"),
                )
            )

        return indicators

    def assess_threat_level(
        self,
        threat_matches: List[ThreatMatch],
        bootkit_indicators: List[BootkitIndicator],
        suspicious_patterns: List[Pattern],
        anomalies: List,
    ) -> ThreatLevel:
        """
        Classify overall threat level based on findings.

        Args:
            threat_matches: Known threat matches
            bootkit_indicators: Bootkit indicators found
            suspicious_patterns: Suspicious patterns detected
            anomalies: Structural anomalies

        Returns:
            Overall threat level assessment
        """
        score = 0

        # Known malware = critical
        if threat_matches:
            return ThreatLevel.CRITICAL

        # Bootkit indicators
        for indicator in bootkit_indicators:
            if indicator.confidence >= 0.8:
                score += 3
            elif indicator.confidence >= 0.6:
                score += 2
            else:
                score += 1

        # Suspicious patterns
        for pattern in suspicious_patterns:
            if pattern.type == "shellcode_pattern":
                score += 2
            else:
                score += 1

        # Structural anomalies
        for anomaly in anomalies:
            if anomaly.severity == "critical":
                score += 3
            elif anomaly.severity == "high":
                score += 2
            else:
                score += 1

        # Determine threat level based on score
        if score >= 8:
            return ThreatLevel.CRITICAL
        elif score >= 5:
            return ThreatLevel.HIGH
        elif score >= 2:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW
