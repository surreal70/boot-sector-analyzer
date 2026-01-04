"""Boot sector content analysis."""

import hashlib
import logging
import math
import re
from collections import Counter
from typing import Dict, List

from .models import Pattern, ContentAnalysis
from .disassembly_engine import DisassemblyEngine
from .exceptions import (
    ContentAnalysisError,
    AnalysisError
)

logger = logging.getLogger(__name__)


class ContentAnalyzer:
    """Analyzes boot sector content for suspicious patterns and characteristics."""

    def __init__(self):
        """Initialize ContentAnalyzer with disassembly engine."""
        self.disassembly_engine = DisassemblyEngine()

    def analyze_content(self, boot_sector: bytes) -> ContentAnalysis:
        """
        Perform complete content analysis of boot sector.
        
        Args:
            boot_sector: Boot sector data to analyze
            
        Returns:
            Complete content analysis results
            
        Raises:
            ContentAnalysisError: If content analysis fails
        """
        logger.debug("Starting content analysis")
        
        try:
            # Calculate hashes
            hashes = self.calculate_hashes(boot_sector)
            
            # Extract strings and URLs
            strings = self.extract_strings(boot_sector)
            urls = self.extract_urls(boot_sector)
            
            # Detect suspicious patterns
            suspicious_patterns = self.detect_suspicious_patterns(boot_sector)
            
            # Calculate entropy
            entropy = self.analyze_entropy(boot_sector)
            
            # Disassemble boot code (first 446 bytes)
            boot_code = boot_sector[:446]  # Boot code region
            disassembly_result = self.disassemble_boot_code(boot_code)
            
            logger.info(f"Content analysis completed: {len(strings)} strings, {len(urls)} URLs, {len(suspicious_patterns)} patterns, entropy={entropy:.2f}")
            
            return ContentAnalysis(
                hashes=hashes,
                strings=strings,
                suspicious_patterns=suspicious_patterns,
                entropy=entropy,
                urls=urls,
                disassembly_result=disassembly_result
            )
            
        except Exception as e:
            error_msg = f"Failed to analyze boot sector content: {e}"
            logger.error(error_msg, exc_info=True)
            raise ContentAnalysisError(
                error_msg,
                error_code="CONTENT_ANALYSIS_ERROR",
                details={"exception_type": type(e).__name__, "error": str(e)}
            )

    def calculate_hashes(self, boot_code: bytes) -> Dict[str, str]:
        """
        Calculate MD5, SHA-256 hashes of boot code.

        Args:
            boot_code: Boot code bytes to hash

        Returns:
            Dictionary mapping hash algorithm to hex digest
            
        Raises:
            ContentAnalysisError: If hash calculation fails
        """
        logger.debug("Calculating cryptographic hashes")
        
        if not isinstance(boot_code, bytes):
            error_msg = f"Boot code must be bytes, got {type(boot_code)}"
            logger.error(error_msg)
            raise ContentAnalysisError(
                error_msg,
                error_code="INVALID_DATA_TYPE",
                details={"data_type": str(type(boot_code))}
            )
        
        hashes = {}

        try:
            # Calculate MD5
            md5_hash = hashlib.md5(boot_code)
            hashes["md5"] = md5_hash.hexdigest()

            # Calculate SHA-256
            sha256_hash = hashlib.sha256(boot_code)
            hashes["sha256"] = sha256_hash.hexdigest()

            logger.debug(
                f"Calculated hashes - MD5: {hashes['md5']}, SHA-256: {hashes['sha256']}"
            )
            return hashes
            
        except Exception as e:
            error_msg = f"Failed to calculate hashes: {e}"
            logger.error(error_msg, exc_info=True)
            raise ContentAnalysisError(
                error_msg,
                error_code="HASH_CALCULATION_ERROR",
                details={"exception_type": type(e).__name__, "error": str(e)}
            )

    def detect_suspicious_patterns(self, boot_code: bytes) -> List[Pattern]:
        """
        Identify suspicious instruction patterns.

        Args:
            boot_code: Boot code bytes to analyze

        Returns:
            List of detected suspicious patterns
            
        Raises:
            ContentAnalysisError: If pattern detection fails
        """
        logger.debug("Detecting suspicious patterns")
        
        if not isinstance(boot_code, bytes):
            error_msg = f"Boot code must be bytes, got {type(boot_code)}"
            logger.error(error_msg)
            raise ContentAnalysisError(
                error_msg,
                error_code="INVALID_DATA_TYPE",
                details={"data_type": str(type(boot_code))}
            )
        
        patterns = []

        try:
            # Look for common shellcode patterns
            shellcode_patterns = [
                (b"\xeb\xfe", "Infinite loop (JMP $)"),
                (b"\x90\x90\x90\x90", "NOP sled"),
                (b"\xcc\xcc\xcc\xcc", "INT3 debug breaks"),
                (b"\x31\xc0", "XOR EAX, EAX (common shellcode)"),
                (b"\x50\x53\x51\x52", "PUSH register sequence"),
            ]

            for pattern_bytes, description in shellcode_patterns:
                offset = 0
                while True:
                    pos = boot_code.find(pattern_bytes, offset)
                    if pos == -1:
                        break

                    patterns.append(
                        Pattern(
                            type="shellcode_pattern",
                            description=description,
                            location=pos,
                            data=pattern_bytes,
                        )
                    )
                    logger.debug(f"Shellcode pattern found at offset {pos}: {description}")
                    offset = pos + 1

            # Look for suspicious instruction sequences
            if len(boot_code) >= 4:
                for i in range(len(boot_code) - 3):
                    # Check for potential code caves (long sequences of same byte)
                    if (
                        boot_code[i]
                        == boot_code[i + 1]
                        == boot_code[i + 2]
                        == boot_code[i + 3]
                    ):
                        if boot_code[i] not in [
                            0x00,
                            0xFF,
                            0x90,
                        ]:  # Ignore common fill bytes
                            patterns.append(
                                Pattern(
                                    type="code_cave",
                                    description=f"Repeated byte sequence: 0x{boot_code[i]:02X}",
                                    location=i,
                                    data=boot_code[i : i + 4],
                                )
                            )
                            logger.debug(f"Code cave pattern found at offset {i}: 0x{boot_code[i]:02X}")

            logger.debug(f"Pattern detection completed: {len(patterns)} patterns found")
            return patterns
            
        except Exception as e:
            error_msg = f"Failed to detect suspicious patterns: {e}"
            logger.error(error_msg, exc_info=True)
            raise ContentAnalysisError(
                error_msg,
                error_code="PATTERN_DETECTION_ERROR",
                details={"exception_type": type(e).__name__, "error": str(e)}
            )

    def extract_strings(self, boot_code: bytes) -> List[str]:
        """
        Extract readable strings and URLs.

        Args:
            boot_code: Boot code bytes to analyze

        Returns:
            List of extracted strings
            
        Raises:
            ContentAnalysisError: If string extraction fails
        """
        logger.debug("Extracting strings from boot code")
        
        if not isinstance(boot_code, bytes):
            error_msg = f"Boot code must be bytes, got {type(boot_code)}"
            logger.error(error_msg)
            raise ContentAnalysisError(
                error_msg,
                error_code="INVALID_DATA_TYPE",
                details={"data_type": str(type(boot_code))}
            )
        
        strings = []

        try:
            # Extract printable ASCII strings (minimum length 4)
            ascii_pattern = re.compile(b"[\x20-\x7e]{4,}")
            matches = ascii_pattern.findall(boot_code)

            for match in matches:
                try:
                    string = match.decode("ascii")
                    strings.append(string)
                    logger.debug(f"Extracted string: {string[:50]}{'...' if len(string) > 50 else ''}")
                except UnicodeDecodeError as e:
                    logger.debug(f"Failed to decode string: {e}")
                    continue

            # Extract URLs specifically
            url_patterns = [
                rb'https?://[^\s<>"{}|\\^`\[\]]+',
                rb'ftp://[^\s<>"{}|\\^`\[\]]+',
            ]

            for pattern in url_patterns:
                matches = re.findall(pattern, boot_code, re.IGNORECASE)
                for match in matches:
                    try:
                        url = match.decode("ascii")
                        if url not in strings:
                            strings.append(url)
                            logger.debug(f"Extracted URL: {url}")
                    except UnicodeDecodeError as e:
                        logger.debug(f"Failed to decode URL: {e}")
                        continue

            logger.debug(f"String extraction completed: {len(strings)} strings found")
            return strings
            
        except Exception as e:
            error_msg = f"Failed to extract strings: {e}"
            logger.error(error_msg, exc_info=True)
            raise ContentAnalysisError(
                error_msg,
                error_code="STRING_EXTRACTION_ERROR",
                details={"exception_type": type(e).__name__, "error": str(e)}
            )

    def analyze_entropy(self, boot_code: bytes) -> float:
        """
        Calculate entropy to detect encryption/obfuscation.

        Args:
            boot_code: Boot code bytes to analyze

        Returns:
            Entropy value (0.0 to 8.0, higher = more random/encrypted)
            
        Raises:
            ContentAnalysisError: If entropy calculation fails
        """
        logger.debug("Calculating entropy")
        
        if not isinstance(boot_code, bytes):
            error_msg = f"Boot code must be bytes, got {type(boot_code)}"
            logger.error(error_msg)
            raise ContentAnalysisError(
                error_msg,
                error_code="INVALID_DATA_TYPE",
                details={"data_type": str(type(boot_code))}
            )
        
        if not boot_code:
            logger.warning("Empty boot code provided for entropy calculation")
            return 0.0

        try:
            # Count byte frequencies
            byte_counts = Counter(boot_code)
            length = len(boot_code)

            # Calculate Shannon entropy
            entropy = 0.0
            for count in byte_counts.values():
                probability = count / length
                if probability > 0:
                    entropy -= probability * math.log2(probability)

            logger.debug(f"Calculated entropy: {entropy:.2f}")
            return entropy
            
        except Exception as e:
            error_msg = f"Failed to calculate entropy: {e}"
            logger.error(error_msg, exc_info=True)
            raise ContentAnalysisError(
                error_msg,
                error_code="ENTROPY_CALCULATION_ERROR",
                details={"exception_type": type(e).__name__, "error": str(e)}
            )

    def extract_urls(self, boot_code: bytes) -> List[str]:
        """
        Extract URLs from boot code.

        Args:
            boot_code: Boot code bytes to analyze

        Returns:
            List of extracted URLs
            
        Raises:
            ContentAnalysisError: If URL extraction fails
        """
        logger.debug("Extracting URLs from boot code")
        
        if not isinstance(boot_code, bytes):
            error_msg = f"Boot code must be bytes, got {type(boot_code)}"
            logger.error(error_msg)
            raise ContentAnalysisError(
                error_msg,
                error_code="INVALID_DATA_TYPE",
                details={"data_type": str(type(boot_code))}
            )
        
        urls = []

        try:
            # URL patterns
            url_patterns = [
                rb'https?://[^\s<>"{}|\\^`\[\]]+',
                rb'ftp://[^\s<>"{}|\\^`\[\]]+',
            ]

            for pattern in url_patterns:
                matches = re.findall(pattern, boot_code, re.IGNORECASE)
                for match in matches:
                    try:
                        url = match.decode("ascii")
                        urls.append(url)
                        logger.debug(f"Extracted URL: {url}")
                    except UnicodeDecodeError as e:
                        logger.debug(f"Failed to decode URL: {e}")
                        continue

            logger.debug(f"URL extraction completed: {len(urls)} URLs found")
            return urls
            
        except Exception as e:
            error_msg = f"Failed to extract URLs: {e}"
            logger.error(error_msg, exc_info=True)
            raise ContentAnalysisError(
                error_msg,
                error_code="URL_EXTRACTION_ERROR",
                details={"exception_type": type(e).__name__, "error": str(e)}
            )

    def validate_partition_type(self, partition_type: int) -> bool:
        """
        Validate partition type code against known valid types.

        Args:
            partition_type: Partition type code to validate

        Returns:
            True if partition type is known/valid, False otherwise
            
        Raises:
            ContentAnalysisError: If validation fails
        """
        logger.debug(f"Validating partition type: 0x{partition_type:02X}")
        
        if not isinstance(partition_type, int):
            error_msg = f"Partition type must be integer, got {type(partition_type)}"
            logger.error(error_msg)
            raise ContentAnalysisError(
                error_msg,
                error_code="INVALID_PARTITION_TYPE",
                details={"partition_type": str(partition_type), "type": str(type(partition_type))}
            )
        
        if partition_type < 0 or partition_type > 255:
            error_msg = f"Partition type must be 0-255, got {partition_type}"
            logger.error(error_msg)
            raise ContentAnalysisError(
                error_msg,
                error_code="PARTITION_TYPE_OUT_OF_RANGE",
                details={"partition_type": partition_type}
            )

        try:
            # Common partition type codes
            valid_partition_types = {
                0x00: "Empty",
                0x01: "FAT12",
                0x04: "FAT16 <32M",
                0x05: "Extended",
                0x06: "FAT16",
                0x07: "HPFS/NTFS/exFAT",
                0x0B: "W95 FAT32",
                0x0C: "W95 FAT32 (LBA)",
                0x0E: "W95 FAT16 (LBA)",
                0x0F: "W95 Ext'd (LBA)",
                0x11: "Hidden FAT12",
                0x14: "Hidden FAT16 <32M",
                0x16: "Hidden FAT16",
                0x17: "Hidden HPFS/NTFS",
                0x1B: "Hidden W95 FAT32",
                0x1C: "Hidden W95 FAT32 (LBA)",
                0x1E: "Hidden W95 FAT16 (LBA)",
                0x42: "SFS",
                0x82: "Linux swap / Solaris",
                0x83: "Linux",
                0x84: "OS/2 hidden C: drive",
                0x85: "Linux extended",
                0x86: "NTFS volume set",
                0x87: "NTFS volume set",
                0x88: "Linux plaintext",
                0x8E: "Linux LVM",
                0xA0: "IBM Thinkpad hibernation",
                0xA5: "FreeBSD",
                0xA6: "OpenBSD",
                0xA7: "NeXTSTEP",
                0xA8: "Darwin UFS",
                0xA9: "NetBSD",
                0xAB: "Darwin boot",
                0xAF: "HFS / HFS+",
                0xB7: "BSDI fs",
                0xB8: "BSDI swap",
                0xBE: "Solaris boot",
                0xBF: "Solaris",
                0xC1: "DRDOS/sec (FAT-12)",
                0xC4: "DRDOS/sec (FAT-16)",
                0xC6: "DRDOS/sec (FAT-16)",
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
                0xFE: "LANstep",
                0xFF: "BBT"
            }

            is_valid = partition_type in valid_partition_types
            
            if is_valid:
                logger.debug(f"Valid partition type: 0x{partition_type:02X} ({valid_partition_types[partition_type]})")
            else:
                logger.debug(f"Unknown partition type: 0x{partition_type:02X}")
            
            return is_valid
            
        except Exception as e:
            error_msg = f"Failed to validate partition type: {e}"
            logger.error(error_msg, exc_info=True)
            raise ContentAnalysisError(
                error_msg,
                error_code="PARTITION_TYPE_VALIDATION_ERROR",
                details={"partition_type": partition_type, "exception_type": type(e).__name__, "error": str(e)}
            )

    def disassemble_boot_code(self, boot_code: bytes):
        """
        Disassemble x86/x86-64 assembly instructions from boot code.
        
        Args:
            boot_code: Boot code bytes to disassemble (typically first 446 bytes)
            
        Returns:
            DisassemblyResult with instructions and patterns
            
        Raises:
            ContentAnalysisError: If disassembly fails
        """
        logger.debug("Starting boot code disassembly")
        
        if not isinstance(boot_code, bytes):
            error_msg = f"Boot code must be bytes, got {type(boot_code)}"
            logger.error(error_msg)
            raise ContentAnalysisError(
                error_msg,
                error_code="INVALID_DATA_TYPE",
                details={"data_type": str(type(boot_code))}
            )
        
        try:
            # Use disassembly engine with error handling
            # Boot sectors typically use 16-bit mode
            disassembly_result = self.disassembly_engine.disassemble_with_error_handling(
                boot_code, 
                base_address=0x7C00,  # Standard boot sector load address
                prefer_16bit=True
            )
            
            logger.info(f"Disassembly completed: {len(disassembly_result.instructions)} instructions, "
                       f"{len(disassembly_result.invalid_instructions)} invalid, "
                       f"{len(disassembly_result.boot_patterns)} patterns")
            
            return disassembly_result
            
        except Exception as e:
            error_msg = f"Failed to disassemble boot code: {e}"
            logger.error(error_msg, exc_info=True)
            raise ContentAnalysisError(
                error_msg,
                error_code="DISASSEMBLY_ERROR",
                details={"exception_type": type(e).__name__, "error": str(e)}
            )
