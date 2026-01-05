"""Security scanning and threat detection."""

import logging
from typing import Dict, List, Optional

from .models import (
    ThreatLevel, ThreatMatch, BootkitIndicator, Pattern, SecurityAnalysis,
    VBRContentAnalysis, VBRStructure, VBRPattern, VBRAnomalyy, FilesystemType
)
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

        # VBR-specific malware hashes
        self.known_vbr_malware_hashes = {
            "md5": {
                # Example VBR malware hashes
                "c1d2e3f4a5b6789012345678901234567": "VBR.Rootkit.A",
                "d2e3f4a5b6789012345678901234567c1": "FAT.Bootkit.B",
            },
            "sha256": {
                "c1d2e3f4a5b6789012345678901234567890123456789012345678901234567890": "NTFS.Hijacker.C",
                "d2e3f4a5b6789012345678901234567890123456789012345678901234567c10": "ExFAT.Malware.D",
            },
        }

        # Bootkit signatures (byte patterns)
        self.bootkit_signatures = [
            (b"\x31\xc0\x8e\xd8\x8e\xc0", "Common bootkit initialization"),
            (b"\xfa\xfc\x31\xc0", "CLI/CLD bootkit pattern"),
            (b"\x0f\x01\x16", "LGDT instruction (bootkit loader)"),
        ]

        # VBR-specific threat patterns
        self.vbr_threat_patterns = {
            FilesystemType.FAT12: [
                (b"\xeb\x3c\x90", "Standard FAT12 boot signature"),
                (b"\xeb\xfe", "Infinite loop (suspicious)"),
                (b"\x0e\x1f\xbe", "Standard FAT boot code start"),
            ],
            FilesystemType.FAT16: [
                (b"\xeb\x3c\x90", "Standard FAT16 boot signature"),
                (b"\xeb\xfe", "Infinite loop (suspicious)"),
                (b"\x0e\x1f\xbe", "Standard FAT boot code start"),
            ],
            FilesystemType.FAT32: [
                (b"\xeb\x58\x90", "Standard FAT32 boot signature"),
                (b"\xeb\xfe", "Infinite loop (suspicious)"),
                (b"\x0e\x1f\xbe", "Standard FAT boot code start"),
            ],
            FilesystemType.NTFS: [
                (b"\xeb\x52\x90", "Standard NTFS boot signature"),
                (b"\xeb\xfe", "Infinite loop (suspicious)"),
                (b"\xfa\xfc", "CLI/CLD NTFS boot start"),
            ],
            FilesystemType.EXFAT: [
                (b"\xeb\x76\x90", "Standard exFAT boot signature"),
                (b"\xeb\xfe", "Infinite loop (suspicious)"),
            ],
        }
        
        logger.debug(f"Loaded {sum(len(hashes) for hashes in self.known_malware_hashes.values())} MBR malware signatures")
        logger.debug(f"Loaded {sum(len(hashes) for hashes in self.known_vbr_malware_hashes.values())} VBR malware signatures")
        logger.debug(f"Loaded {len(self.bootkit_signatures)} bootkit signatures")
        logger.debug(f"Loaded {sum(len(patterns) for patterns in self.vbr_threat_patterns.values())} VBR threat patterns")

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

    def check_known_signatures(self, hashes: Dict[str, str], is_vbr: bool = False) -> List[ThreatMatch]:
        """
        Check hashes against known malware signatures.

        Args:
            hashes: Dictionary of hash type -> hash value
            is_vbr: Whether these are VBR hashes (default: False for MBR)

        Returns:
            List of threat matches found
            
        Raises:
            SecurityAnalysisError: If signature checking fails
        """
        logger.debug(f"Checking against known {'VBR' if is_vbr else 'MBR'} malware signatures")
        
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
            # Choose the appropriate hash database
            hash_database = self.known_vbr_malware_hashes if is_vbr else self.known_malware_hashes
            source_type = "vbr_database" if is_vbr else "local_database"
            
            for hash_type, hash_value in hashes.items():
                if not isinstance(hash_value, str):
                    logger.warning(f"Invalid hash value type for {hash_type}: {type(hash_value)}")
                    continue
                    
                if hash_type in hash_database:
                    threat_db = hash_database[hash_type]
                    if hash_value in threat_db:
                        threat_name = threat_db[hash_value]
                        match = ThreatMatch(
                            threat_name=threat_name,
                            threat_type="vbr_malware" if is_vbr else "malware",
                            confidence=1.0,
                            source=source_type,
                            hash_match=hash_value,
                        )
                        matches.append(match)
                        logger.warning(
                            f"Known {'VBR' if is_vbr else 'MBR'} malware detected: {threat_name} ({hash_type}: {hash_value})"
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

    def analyze_vbr_security(self, vbr_content_analysis: VBRContentAnalysis, 
                           vbr_structure: VBRStructure) -> VBRContentAnalysis:
        """
        Perform comprehensive VBR security analysis.
        
        Args:
            vbr_content_analysis: Existing VBR content analysis to enhance
            vbr_structure: Parsed VBR structure
            
        Returns:
            Enhanced VBR content analysis with security findings
            
        Raises:
            SecurityAnalysisError: If VBR security analysis fails
        """
        logger.debug("Starting VBR security analysis")
        
        try:
            # Check VBR hashes against known malware signatures
            vbr_threat_matches = self.check_known_signatures(vbr_content_analysis.hashes, is_vbr=True)
            boot_code_threat_matches = self.check_known_signatures(vbr_content_analysis.boot_code_hashes, is_vbr=True)
            
            # Detect VBR-specific suspicious patterns
            vbr_suspicious_patterns = self.detect_vbr_suspicious_patterns(
                vbr_structure.raw_data, vbr_structure.filesystem_type
            )
            
            # Detect VBR anomalies and classify threats
            vbr_anomalies = self.detect_vbr_anomalies(vbr_structure, vbr_content_analysis.detected_patterns)
            
            # Assess VBR-specific threat level
            vbr_threat_level = self.assess_vbr_threat_level(
                vbr_threat_matches + boot_code_threat_matches,
                vbr_suspicious_patterns,
                vbr_anomalies
            )
            
            # Combine existing anomalies with new security findings
            all_anomalies = list(vbr_content_analysis.anomalies)
            all_anomalies.extend(vbr_anomalies)
            
            # Update threat level to the higher of existing or new assessment
            final_threat_level = max(vbr_content_analysis.threat_level, vbr_threat_level, key=lambda x: x.value)
            
            logger.info(f"VBR security analysis completed: threat_level={final_threat_level.value}, "
                       f"{len(vbr_threat_matches + boot_code_threat_matches)} threats, "
                       f"{len(vbr_suspicious_patterns)} suspicious patterns, "
                       f"{len(vbr_anomalies)} security anomalies")
            
            # Return enhanced analysis with security findings
            return VBRContentAnalysis(
                hashes=vbr_content_analysis.hashes,
                boot_code_hashes=vbr_content_analysis.boot_code_hashes,
                disassembly_result=vbr_content_analysis.disassembly_result,
                detected_patterns=vbr_content_analysis.detected_patterns,
                anomalies=all_anomalies,
                threat_level=final_threat_level
            )
            
        except Exception as e:
            error_msg = f"Failed to perform VBR security analysis: {e}"
            logger.error(error_msg, exc_info=True)
            raise SecurityAnalysisError(
                error_msg,
                error_code="VBR_SECURITY_ANALYSIS_ERROR",
                details={"exception_type": type(e).__name__, "error": str(e)}
            )

    def detect_vbr_suspicious_patterns(self, vbr_data: bytes, filesystem_type: FilesystemType) -> List[Pattern]:
        """
        Detect suspicious patterns in VBR data specific to filesystem type.
        
        Args:
            vbr_data: Raw VBR data (512 bytes)
            filesystem_type: Type of filesystem for context-aware detection
            
        Returns:
            List of suspicious patterns found
        """
        logger.debug(f"Detecting suspicious patterns in {filesystem_type.value} VBR")
        
        patterns = []
        
        try:
            # Check for filesystem-specific threat patterns
            if filesystem_type in self.vbr_threat_patterns:
                threat_patterns = self.vbr_threat_patterns[filesystem_type]
                
                for pattern_bytes, description in threat_patterns:
                    if pattern_bytes in vbr_data:
                        pos = vbr_data.find(pattern_bytes)
                        
                        # Determine if this is suspicious based on context
                        is_suspicious = self._is_vbr_pattern_suspicious(
                            pattern_bytes, description, pos, filesystem_type
                        )
                        
                        if is_suspicious:
                            patterns.append(Pattern(
                                type="vbr_suspicious_pattern",
                                description=f"{filesystem_type.value.upper()} VBR: {description}",
                                location=pos,
                                data=pattern_bytes
                            ))
                            logger.warning(f"Suspicious VBR pattern detected at offset {pos}: {description}")
            
            # Check for generic VBR threats
            generic_threats = [
                (b"\xeb\xfe", "Infinite loop - possible VBR hijacking"),
                (b"\xf4", "HLT instruction - system halt"),
                (b"\xcc", "INT3 breakpoint - debugging artifact"),
                (b"\x0f\x0b", "UD2 undefined instruction"),
                (b"\xcd\x13", "INT 13h disk service - potential disk manipulation"),
            ]
            
            for pattern_bytes, description in generic_threats:
                offset = 0
                while True:
                    pos = vbr_data.find(pattern_bytes, offset)
                    if pos == -1:
                        break
                    
                    patterns.append(Pattern(
                        type="vbr_threat_pattern",
                        description=f"VBR threat: {description}",
                        location=pos,
                        data=pattern_bytes
                    ))
                    logger.warning(f"VBR threat pattern detected at offset {pos}: {description}")
                    offset = pos + 1
            
            # Check for unusual VBR modifications
            patterns.extend(self._detect_vbr_modifications(vbr_data, filesystem_type))
            
            logger.debug(f"VBR pattern detection completed: {len(patterns)} suspicious patterns found")
            return patterns
            
        except Exception as e:
            logger.error(f"Error detecting VBR suspicious patterns: {e}", exc_info=True)
            return patterns  # Return partial results

    def detect_vbr_anomalies(self, vbr_structure: VBRStructure, 
                           detected_patterns: List[VBRPattern]) -> List[VBRAnomalyy]:
        """
        Detect and classify VBR anomalies for threat assessment.
        
        Args:
            vbr_structure: Parsed VBR structure
            detected_patterns: Previously detected VBR patterns
            
        Returns:
            List of VBR anomalies with security implications
        """
        logger.debug(f"Detecting VBR anomalies for {vbr_structure.filesystem_type.value}")
        
        anomalies = []
        
        try:
            # Check for modified boot code
            boot_code_anomalies = self._detect_boot_code_anomalies(vbr_structure)
            anomalies.extend(boot_code_anomalies)
            
            # Check for suspicious metadata
            metadata_anomalies = self._detect_metadata_anomalies(vbr_structure)
            anomalies.extend(metadata_anomalies)
            
            # Check for filesystem-specific anomalies
            fs_anomalies = self._detect_filesystem_specific_anomalies(vbr_structure)
            anomalies.extend(fs_anomalies)
            
            # Check for pattern-based anomalies
            pattern_anomalies = self._detect_pattern_based_anomalies(detected_patterns)
            anomalies.extend(pattern_anomalies)
            
            logger.debug(f"VBR anomaly detection completed: {len(anomalies)} anomalies found")
            return anomalies
            
        except Exception as e:
            logger.error(f"Error detecting VBR anomalies: {e}", exc_info=True)
            return anomalies  # Return partial results

    def assess_vbr_threat_level(self, threat_matches: List[ThreatMatch],
                              suspicious_patterns: List[Pattern],
                              anomalies: List[VBRAnomalyy]) -> ThreatLevel:
        """
        Assess VBR-specific threat level based on security findings.
        
        Args:
            threat_matches: Known VBR threat matches
            suspicious_patterns: Suspicious patterns in VBR
            anomalies: VBR anomalies detected
            
        Returns:
            VBR threat level assessment
        """
        logger.debug("Assessing VBR threat level")
        
        score = 0
        
        # Known VBR malware = critical
        if threat_matches:
            logger.warning(f"Known VBR malware detected: {len(threat_matches)} matches")
            return ThreatLevel.CRITICAL
        
        # VBR-specific suspicious patterns
        for pattern in suspicious_patterns:
            if pattern.type == "vbr_threat_pattern":
                score += 3
            elif pattern.type == "vbr_suspicious_pattern":
                score += 2
            else:
                score += 1
        
        # VBR anomalies
        for anomaly in anomalies:
            if anomaly.severity == "critical":
                score += 4
            elif anomaly.severity == "high":
                score += 3
            elif anomaly.severity == "medium":
                score += 2
            else:
                score += 1
        
        # Determine VBR threat level
        if score >= 10:
            threat_level = ThreatLevel.CRITICAL
        elif score >= 6:
            threat_level = ThreatLevel.HIGH
        elif score >= 3:
            threat_level = ThreatLevel.MEDIUM
        else:
            threat_level = ThreatLevel.LOW
        
        logger.debug(f"VBR threat assessment: score={score}, level={threat_level.value}")
        return threat_level

    def _is_vbr_pattern_suspicious(self, pattern_bytes: bytes, description: str, 
                                 position: int, filesystem_type: FilesystemType) -> bool:
        """
        Determine if a VBR pattern is suspicious based on context.
        
        Args:
            pattern_bytes: The pattern bytes found
            description: Pattern description
            position: Position where pattern was found
            filesystem_type: Filesystem type for context
            
        Returns:
            True if pattern is suspicious in this context
        """
        # Infinite loop is always suspicious
        if pattern_bytes == b"\xeb\xfe":
            return True
        
        # Standard boot signatures are not suspicious at expected positions
        if "Standard" in description and position < 10:
            return False
        
        # Boot code patterns outside expected regions are suspicious
        if "boot code start" in description and position > 100:
            return True
        
        # Default to not suspicious for standard patterns
        return "suspicious" in description.lower()

    def _detect_vbr_modifications(self, vbr_data: bytes, filesystem_type: FilesystemType) -> List[Pattern]:
        """Detect unusual modifications to VBR structure."""
        patterns = []
        
        # Check for unusual jump instructions at the beginning
        if len(vbr_data) >= 3:
            first_bytes = vbr_data[:3]
            # Standard VBR should start with EB xx 90 (JMP + NOP)
            if first_bytes[0] == 0xEB and first_bytes[2] != 0x90:
                patterns.append(Pattern(
                    type="vbr_modification",
                    description="Non-standard VBR jump instruction format",
                    location=0,
                    data=first_bytes
                ))
        
        # Check for suspicious code in boot code region
        boot_code_start = 90  # Typical start of boot code after BPB
        boot_code_end = 510   # End before boot signature
        
        if len(vbr_data) >= boot_code_end:
            boot_code = vbr_data[boot_code_start:boot_code_end]
            
            # Check for high concentration of unusual opcodes
            unusual_opcodes = [0xCC, 0xF4, 0x0F]  # INT3, HLT, two-byte opcodes
            unusual_count = sum(boot_code.count(opcode) for opcode in unusual_opcodes)
            
            if unusual_count > 5:
                patterns.append(Pattern(
                    type="vbr_modification",
                    description=f"High concentration of unusual opcodes in boot code ({unusual_count})",
                    location=boot_code_start,
                    data=boot_code[:20]  # First 20 bytes as evidence
                ))
        
        return patterns

    def _detect_boot_code_anomalies(self, vbr_structure: VBRStructure) -> List[VBRAnomalyy]:
        """Detect anomalies in VBR boot code."""
        anomalies = []
        
        # Check if boot code region is entirely empty (all zeros)
        boot_code = vbr_structure.boot_code
        if boot_code and len(boot_code) > 0:
            if all(byte == 0 for byte in boot_code):
                anomalies.append(VBRAnomalyy(
                    anomaly_type="empty_boot_code",
                    description="VBR boot code region is entirely empty",
                    severity="medium",
                    evidence=["All boot code bytes are zero"]
                ))
            
            # Check for boot code that's too short
            elif len(boot_code) < 50:
                anomalies.append(VBRAnomalyy(
                    anomaly_type="short_boot_code",
                    description=f"VBR boot code is unusually short ({len(boot_code)} bytes)",
                    severity="low",
                    evidence=[f"Boot code length: {len(boot_code)} bytes"]
                ))
        
        return anomalies

    def _detect_metadata_anomalies(self, vbr_structure: VBRStructure) -> List[VBRAnomalyy]:
        """Detect anomalies in VBR metadata."""
        anomalies = []
        
        # Check for suspicious filesystem metadata based on type
        if hasattr(vbr_structure, 'metadata') and vbr_structure.metadata:
            metadata = vbr_structure.metadata
            
            # Check for unusual sector sizes
            if hasattr(metadata, 'bytes_per_sector'):
                sector_size = metadata.bytes_per_sector
                if sector_size != 512 and sector_size not in [1024, 2048, 4096]:
                    anomalies.append(VBRAnomalyy(
                        anomaly_type="unusual_sector_size",
                        description=f"Unusual sector size: {sector_size} bytes",
                        severity="medium",
                        evidence=[f"Sector size: {sector_size}"]
                    ))
            
            # Check for suspicious cluster sizes
            if hasattr(metadata, 'sectors_per_cluster'):
                cluster_size = metadata.sectors_per_cluster
                if cluster_size > 128:  # Very large cluster size
                    anomalies.append(VBRAnomalyy(
                        anomaly_type="large_cluster_size",
                        description=f"Unusually large cluster size: {cluster_size} sectors",
                        severity="low",
                        evidence=[f"Sectors per cluster: {cluster_size}"]
                    ))
        
        return anomalies

    def _detect_filesystem_specific_anomalies(self, vbr_structure: VBRStructure) -> List[VBRAnomalyy]:
        """Detect filesystem-specific anomalies."""
        anomalies = []
        
        # FAT-specific checks
        if vbr_structure.filesystem_type in [FilesystemType.FAT12, FilesystemType.FAT16, FilesystemType.FAT32]:
            anomalies.extend(self._detect_fat_anomalies(vbr_structure))
        
        # NTFS-specific checks
        elif vbr_structure.filesystem_type == FilesystemType.NTFS:
            anomalies.extend(self._detect_ntfs_anomalies(vbr_structure))
        
        # exFAT-specific checks
        elif vbr_structure.filesystem_type == FilesystemType.EXFAT:
            anomalies.extend(self._detect_exfat_anomalies(vbr_structure))
        
        return anomalies

    def _detect_fat_anomalies(self, vbr_structure: VBRStructure) -> List[VBRAnomalyy]:
        """Detect FAT-specific anomalies."""
        anomalies = []
        
        # Check for missing or invalid FAT signature
        if hasattr(vbr_structure, 'metadata') and vbr_structure.metadata:
            # Check for valid FAT boot signature at expected location
            vbr_data = vbr_structure.raw_data
            if len(vbr_data) >= 512:
                boot_sig = vbr_data[510:512]
                if boot_sig != b'\x55\xaa':
                    anomalies.append(VBRAnomalyy(
                        anomaly_type="invalid_boot_signature",
                        description="Invalid or missing boot signature in FAT VBR",
                        severity="high",
                        evidence=[f"Boot signature: {boot_sig.hex()}"]
                    ))
        
        return anomalies

    def _detect_ntfs_anomalies(self, vbr_structure: VBRStructure) -> List[VBRAnomalyy]:
        """Detect NTFS-specific anomalies."""
        anomalies = []
        
        # Check for NTFS signature
        if hasattr(vbr_structure, 'raw_data'):
            vbr_data = vbr_structure.raw_data
            if len(vbr_data) >= 8:
                # NTFS should have "NTFS    " at offset 3
                ntfs_sig = vbr_data[3:11]
                if ntfs_sig != b'NTFS    ':
                    anomalies.append(VBRAnomalyy(
                        anomaly_type="invalid_ntfs_signature",
                        description="Invalid or missing NTFS signature",
                        severity="high",
                        evidence=[f"NTFS signature: {ntfs_sig}"]
                    ))
        
        return anomalies

    def _detect_exfat_anomalies(self, vbr_structure: VBRStructure) -> List[VBRAnomalyy]:
        """Detect exFAT-specific anomalies."""
        anomalies = []
        
        # Check for exFAT signature
        if hasattr(vbr_structure, 'raw_data'):
            vbr_data = vbr_structure.raw_data
            if len(vbr_data) >= 11:
                # exFAT should have "EXFAT   " at offset 3
                exfat_sig = vbr_data[3:11]
                if exfat_sig != b'EXFAT   ':
                    anomalies.append(VBRAnomalyy(
                        anomaly_type="invalid_exfat_signature",
                        description="Invalid or missing exFAT signature",
                        severity="high",
                        evidence=[f"exFAT signature: {exfat_sig}"]
                    ))
        
        return anomalies

    def _detect_pattern_based_anomalies(self, detected_patterns: List[VBRPattern]) -> List[VBRAnomalyy]:
        """Detect anomalies based on VBR patterns."""
        anomalies = []
        
        # Check for missing expected patterns
        expected_pattern_types = ["filesystem_signature", "boot_code_pattern"]
        found_types = {pattern.pattern_type for pattern in detected_patterns}
        
        for expected_type in expected_pattern_types:
            if expected_type not in found_types:
                anomalies.append(VBRAnomalyy(
                    anomaly_type="missing_pattern",
                    description=f"Missing expected VBR pattern: {expected_type}",
                    severity="medium",
                    evidence=[f"Expected pattern type: {expected_type}"]
                ))
        
        # Check for too many suspicious patterns
        suspicious_patterns = [p for p in detected_patterns if "suspicious" in p.description.lower()]
        if len(suspicious_patterns) > 3:
            anomalies.append(VBRAnomalyy(
                anomaly_type="multiple_suspicious_patterns",
                description=f"Multiple suspicious patterns detected ({len(suspicious_patterns)})",
                severity="high",
                evidence=[f"Suspicious pattern count: {len(suspicious_patterns)}"]
            ))
        
        return anomalies
