"""Report generation for analysis results."""

import json
import logging

from .models import AnalysisResult, ThreatLevel
from .mbr_decoder import MBRDecoder, MBRSection
from .html_generator import HTMLGenerator

logger = logging.getLogger(__name__)


class ANSIColors:
    """ANSI color codes for terminal output."""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    
    # Foreground colors
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    # Background colors
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'


class ReportGenerator:
    """Generates structured analysis reports."""
    
    def __init__(self):
        self.mbr_decoder = MBRDecoder()
        self.html_generator = HTMLGenerator()
        # Color scheme for MBR sections
        self.section_colors = {
            MBRSection.BOOT_CODE: ANSIColors.CYAN,
            MBRSection.DISK_SIGNATURE: ANSIColors.YELLOW,
            MBRSection.PARTITION_TABLE: ANSIColors.GREEN,
            MBRSection.BOOT_SIGNATURE: ANSIColors.MAGENTA
        }

    def generate_hexdump(self, boot_sector: bytes, use_colors: bool = False) -> str:
        """
        Generate formatted hexdump of boot sector data with MBR section color coding.

        Args:
            boot_sector: 512-byte boot sector data
            use_colors: Whether to include ANSI color codes

        Returns:
            Formatted hexdump string with offset, hex bytes, and ASCII representation
        """
        if len(boot_sector) != 512:
            raise ValueError("Boot sector must be exactly 512 bytes")

        lines = self.format_hexdump_table(boot_sector, use_colors)
        return "\n".join(lines)

    def format_hexdump_table(self, boot_sector: bytes, use_colors: bool = False) -> list[str]:
        """
        Format hexdump as 17-column table with offset and hex bytes.
        Includes MBR section color coding with individual partition colors.

        Args:
            boot_sector: 512-byte boot sector data
            use_colors: Whether to include ANSI color codes for MBR sections

        Returns:
            List of formatted hexdump lines with color coding
        """
        lines = []
        
        # Header line
        header = "Offset   " + " ".join(f"{i:02X}" for i in range(16)) + "  ASCII"
        lines.append(header)
        lines.append("-" * len(header))

        # Try to parse MBR structure for partition-specific coloring
        mbr_structure = None
        if use_colors:
            try:
                mbr_structure = self.mbr_decoder.parse_mbr(boot_sector)
            except Exception as e:
                logger.debug(f"Could not parse MBR for partition coloring: {e}")

        # Process 16 bytes per row (32 rows total for 512 bytes)
        for offset in range(0, len(boot_sector), 16):
            row_data = boot_sector[offset:offset + 16]
            
            # Format offset as zero-padded uppercase hex
            offset_str = f"0x{offset:04X}"
            
            # Format hex bytes with color coding based on MBR sections and partitions
            hex_parts = []
            for i, byte in enumerate(row_data):
                byte_offset = offset + i
                hex_str = f"{byte:02X}"
                
                if use_colors:
                    try:
                        # Try partition-specific coloring first
                        section, partition_num = self.mbr_decoder.get_partition_section_type(byte_offset)
                        
                        if section == MBRSection.PARTITION_TABLE and partition_num > 0:
                            # Use partition-specific color
                            _, ansi_color, _ = self.mbr_decoder.get_partition_color_info(
                                byte_offset, mbr_structure
                            )
                            if ansi_color:
                                hex_str = f"{ansi_color}{hex_str}{ANSIColors.RESET}"
                        else:
                            # Use original section-based coloring for non-partition areas
                            section = self.mbr_decoder.get_section_type(byte_offset)
                            color = self.section_colors.get(section, "")
                            if color:
                                hex_str = f"{color}{hex_str}{ANSIColors.RESET}"
                    except ValueError:
                        # Invalid offset, use default formatting
                        pass
                
                hex_parts.append(hex_str)
            
            hex_bytes = " ".join(hex_parts)
            
            # Pad hex bytes if row is incomplete (shouldn't happen with 512-byte boot sector)
            if len(row_data) < 16:
                hex_bytes += "   " * (16 - len(row_data))
            
            # Format ASCII representation
            ascii_repr = self.format_ascii_column(row_data)
            
            # Combine into final line
            line = f"{offset_str}  {hex_bytes}  {ascii_repr}"
            lines.append(line)

        # Add legend for color coding
        if use_colors:
            lines.append("")
            lines.append("Color Legend:")
            lines.append(f"  {self.section_colors[MBRSection.BOOT_CODE]}Boot Code (0x0000-0x01BD){ANSIColors.RESET}")
            lines.append(f"  {self.section_colors[MBRSection.DISK_SIGNATURE]}Disk Signature (0x01B8-0x01BB){ANSIColors.RESET}")
            
            # Add partition-specific legend if MBR was parsed successfully
            if mbr_structure:
                partition_legend = self.mbr_decoder.generate_partition_color_legend(mbr_structure, "human")
                lines.append(partition_legend)
            else:
                # Fallback to generic partition table color
                lines.append(f"  {self.section_colors[MBRSection.PARTITION_TABLE]}Partition Table (0x01BE-0x01FD){ANSIColors.RESET}")
            
            lines.append(f"  {self.section_colors[MBRSection.BOOT_SIGNATURE]}Boot Signature (0x01FE-0x01FF){ANSIColors.RESET}")

        return lines

    def format_ascii_column(self, data: bytes) -> str:
        """
        Format ASCII representation with dots for non-printable characters.

        Args:
            data: Byte data to convert to ASCII representation

        Returns:
            ASCII string with dots for non-printable characters
        """
        ascii_chars = []
        for byte in data:
            # Check if byte is printable ASCII (32-126)
            if 32 <= byte <= 126:
                ascii_chars.append(chr(byte))
            else:
                ascii_chars.append('.')
        
        return ''.join(ascii_chars)

    def generate_report(
        self, result: AnalysisResult, format_type: str = "human"
    ) -> str:
        """
        Generate analysis report.

        Args:
            result: Complete analysis results
            format_type: "human" for human-readable, "json" for JSON format, "html" for HTML format

        Returns:
            Formatted report string
        """
        format_type = format_type.lower()
        
        if format_type == "json":
            return self._generate_json_report(result)
        elif format_type == "html":
            return self._generate_html_report(result)
        else:
            return self._generate_human_report(result)

    def _generate_human_report(self, result: AnalysisResult) -> str:
        """Generate human-readable report with enhanced MBR analysis."""
        lines = []

        # Header
        lines.append("=" * 60)
        lines.append("BOOT SECTOR ANALYSIS REPORT")
        lines.append("=" * 60)
        lines.append(f"Source: {result.source}")
        lines.append(f"Analysis Time: {result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")

        # Threat Level Summary
        threat_level = result.security_analysis.threat_level
        threat_indicator = self._get_threat_indicator(threat_level)
        lines.append(f"THREAT LEVEL: {threat_level.value.upper()} {threat_indicator}")
        lines.append("")

        # Structure Analysis - Use enhanced MBR decoder when possible, fallback to original
        lines.append("STRUCTURE ANALYSIS")
        lines.append("-" * 20)
        
        # Try enhanced MBR analysis first
        enhanced_mbr_success = False
        try:
            mbr_structure = self.mbr_decoder.parse_mbr(result.hexdump.raw_data)
            
            # Generate detailed MBR report
            mbr_report = self.mbr_decoder.generate_partition_report(mbr_structure)
            lines.append(mbr_report)
            lines.append("")
            enhanced_mbr_success = True
            
        except Exception as e:
            logger.error(f"Failed to parse MBR structure: {e}")
            enhanced_mbr_success = False
        
        # If enhanced MBR failed, use original structure analysis
        if not enhanced_mbr_success:
            struct_analysis = result.structure_analysis
            lines.append(
                f"Boot Signature Valid: {'Yes' if struct_analysis.is_valid_signature else 'No'}"
            )
            lines.append(f"Partition Count: {struct_analysis.partition_count}")

            if struct_analysis.mbr_structure.disk_signature:
                lines.append(
                    f"Disk Signature: 0x{struct_analysis.mbr_structure.disk_signature:08X}"
                )

            if struct_analysis.anomalies:
                lines.append("\nStructural Anomalies:")
                for anomaly in struct_analysis.anomalies:
                    lines.append(
                        f"  - {anomaly.description} (Severity: {anomaly.severity})"
                    )
            lines.append("")

        # Content Analysis
        lines.append("CONTENT ANALYSIS")
        lines.append("-" * 20)
        content_analysis = result.content_analysis
        lines.append("Hashes:")
        for hash_type, hash_value in content_analysis.hashes.items():
            lines.append(f"  {hash_type.upper()}: {hash_value}")

        lines.append(f"Entropy: {content_analysis.entropy:.2f}")

        if content_analysis.strings:
            lines.append(f"Strings Found: {len(content_analysis.strings)}")
            for string in content_analysis.strings[:5]:  # Show first 5
                lines.append(f"  - {string}")
            if len(content_analysis.strings) > 5:
                lines.append(f"  ... and {len(content_analysis.strings) - 5} more")

        if content_analysis.urls:
            lines.append("URLs Found:")
            for url in content_analysis.urls:
                lines.append(f"  - {url}")

        if content_analysis.suspicious_patterns:
            lines.append("Suspicious Patterns:")
            for pattern in content_analysis.suspicious_patterns:
                lines.append(f"  - {pattern.description} at offset {pattern.location}")
        lines.append("")

        # Security Analysis
        lines.append("SECURITY ANALYSIS")
        lines.append("-" * 20)
        security_analysis = result.security_analysis

        if security_analysis.detected_threats:
            lines.append("DETECTED THREATS:")
            for threat in security_analysis.detected_threats:
                lines.append(f"  ⚠️  {threat.threat_name} ({threat.threat_type})")
                lines.append(f"      Confidence: {threat.confidence:.1%}")
                lines.append(f"      Source: {threat.source}")

        if security_analysis.bootkit_indicators:
            lines.append("Bootkit Indicators:")
            for indicator in security_analysis.bootkit_indicators:
                lines.append(
                    f"  - {indicator.description} (Confidence: {indicator.confidence:.1%})"
                )
        lines.append("")

        # Threat Intelligence
        if result.threat_intelligence and result.threat_intelligence.virustotal_result:
            lines.append("THREAT INTELLIGENCE")
            lines.append("-" * 20)
            vt_result = result.threat_intelligence.virustotal_result
            lines.append(
                f"VirusTotal: {vt_result.detection_count}/{vt_result.total_engines} detections"
            )

            if vt_result.detection_count > 0:
                lines.append("Detections:")
                for engine, detection in list(vt_result.detections.items())[:5]:
                    if detection.get("detected"):
                        lines.append(
                            f"  - {engine}: {detection.get('result', 'Unknown')}"
                        )

            if vt_result.permalink:
                lines.append(f"VirusTotal Report: {vt_result.permalink}")
            lines.append("")

        # Summary
        lines.append("SUMMARY")
        lines.append("-" * 20)
        if threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            lines.append("⚠️  CRITICAL FINDINGS DETECTED!")
            lines.append("This boot sector shows signs of malicious activity.")
            lines.append("Immediate investigation and remediation recommended.")
        elif threat_level == ThreatLevel.MEDIUM:
            lines.append("⚠️  Suspicious activity detected.")
            lines.append("Further investigation recommended.")
        else:
            lines.append("✅ No significant threats detected.")
            lines.append("Boot sector appears to be clean.")
        lines.append("")

        # Disassembly Section (if available)
        if result.disassembly and result.disassembly.instructions:
            lines.append("BOOT CODE DISASSEMBLY")
            lines.append("-" * 25)
            lines.append("x86 assembly instructions from the boot code region:")
            lines.append("")
            
            # Format disassembly instructions
            for instruction in result.disassembly.instructions[:20]:  # Show first 20 instructions
                addr_str = f"0x{instruction.address:04X}"
                bytes_str = ' '.join(f'{b:02X}' for b in instruction.bytes)
                
                # Format instruction line
                line = f"{addr_str}:  {bytes_str:<12}  {instruction.mnemonic}"
                if instruction.operands:
                    line += f" {instruction.operands}"
                if instruction.comment:
                    line += f"  ; {instruction.comment}"
                
                lines.append(line)
            
            if len(result.disassembly.instructions) > 20:
                lines.append(f"... and {len(result.disassembly.instructions) - 20} more instructions")
            
            # Show invalid instructions if any
            if result.disassembly.invalid_instructions:
                lines.append("")
                lines.append("Invalid Instructions:")
                for invalid in result.disassembly.invalid_instructions[:5]:
                    addr_str = f"0x{invalid.address:04X}"
                    bytes_str = ' '.join(f'{b:02X}' for b in invalid.bytes)
                    lines.append(f"{addr_str}:  {bytes_str:<12}  ; Invalid: {invalid.reason}")
            
            # Show boot patterns if any
            if result.disassembly.boot_patterns:
                lines.append("")
                lines.append("Boot Patterns Detected:")
                for pattern in result.disassembly.boot_patterns:
                    lines.append(f"  - {pattern.pattern_type}: {pattern.description}")
                    lines.append(f"    Significance: {pattern.significance}")
            
            lines.append("")

        # Hexdump Section - Use enhanced version if MBR parsing succeeded, otherwise use original
        if enhanced_mbr_success:
            lines.append("HEXDUMP - MBR STRUCTURE")
            lines.append("-" * 30)
            lines.append("Raw boot sector data with MBR section highlighting:")
            lines.append("")
            
            # Generate color-coded hexdump
            hexdump_lines = self.format_hexdump_table(result.hexdump.raw_data, use_colors=True)
            lines.extend(hexdump_lines)
        else:
            lines.append("HEXDUMP")
            lines.append("-" * 10)
            lines.append("Raw boot sector data for manual review:")
            lines.append("")
            
            # Use original hexdump from result
            lines.extend(result.hexdump.formatted_lines)

        return "\n".join(lines)

    def _generate_json_report(self, result: AnalysisResult) -> str:
        """Generate JSON format report."""
        report_data = {
            "source": result.source,
            "timestamp": result.timestamp.isoformat(),
            "threat_level": result.security_analysis.threat_level.value,
            "structure_analysis": {
                "boot_signature_valid": result.structure_analysis.is_valid_signature,
                "partition_count": result.structure_analysis.partition_count,
                "disk_signature": result.structure_analysis.mbr_structure.disk_signature,
                "anomalies": [
                    {
                        "type": anomaly.type,
                        "description": anomaly.description,
                        "severity": anomaly.severity,
                        "location": anomaly.location,
                    }
                    for anomaly in result.structure_analysis.anomalies
                ],
            },
            "content_analysis": {
                "hashes": result.content_analysis.hashes,
                "entropy": result.content_analysis.entropy,
                "strings": result.content_analysis.strings,
                "urls": result.content_analysis.urls,
                "suspicious_patterns": [
                    {
                        "type": pattern.type,
                        "description": pattern.description,
                        "location": pattern.location,
                    }
                    for pattern in result.content_analysis.suspicious_patterns
                ],
            },
            "security_analysis": {
                "threat_level": result.security_analysis.threat_level.value,
                "detected_threats": [
                    {
                        "name": threat.threat_name,
                        "type": threat.threat_type,
                        "confidence": threat.confidence,
                        "source": threat.source,
                        "hash_match": threat.hash_match,
                    }
                    for threat in result.security_analysis.detected_threats
                ],
                "bootkit_indicators": [
                    {
                        "type": indicator.indicator_type,
                        "description": indicator.description,
                        "confidence": indicator.confidence,
                        "location": indicator.location,
                    }
                    for indicator in result.security_analysis.bootkit_indicators
                ],
            },
        }

        # Add threat intelligence if available
        if result.threat_intelligence and result.threat_intelligence.virustotal_result:
            vt_result = result.threat_intelligence.virustotal_result
            report_data["threat_intelligence"] = {
                "virustotal": {
                    "detection_count": vt_result.detection_count,
                    "total_engines": vt_result.total_engines,
                    "scan_date": (
                        vt_result.scan_date.isoformat() if vt_result.scan_date else None
                    ),
                    "permalink": vt_result.permalink,
                    "detections": vt_result.detections,
                },
                "cached": result.threat_intelligence.cached,
                "query_timestamp": result.threat_intelligence.query_timestamp.isoformat(),
            }

        # Add hexdump data
        report_data["hexdump"] = {
            "total_bytes": result.hexdump.total_bytes,
            "ascii_representation": result.hexdump.ascii_representation,
            "formatted_lines": result.hexdump.formatted_lines,
        }

        # Add disassembly data if available
        if result.disassembly:
            report_data["disassembly"] = {
                "total_bytes_disassembled": result.disassembly.total_bytes_disassembled,
                "instructions": [
                    {
                        "address": f"0x{instruction.address:04X}",
                        "bytes": [f"0x{b:02X}" for b in instruction.bytes],
                        "mnemonic": instruction.mnemonic,
                        "operands": instruction.operands,
                        "comment": instruction.comment,
                    }
                    for instruction in result.disassembly.instructions
                ],
                "invalid_instructions": [
                    {
                        "address": f"0x{invalid.address:04X}",
                        "bytes": [f"0x{b:02X}" for b in invalid.bytes],
                        "reason": invalid.reason,
                    }
                    for invalid in result.disassembly.invalid_instructions
                ],
                "boot_patterns": [
                    {
                        "pattern_type": pattern.pattern_type,
                        "description": pattern.description,
                        "significance": pattern.significance,
                        "instruction_count": len(pattern.instructions),
                    }
                    for pattern in result.disassembly.boot_patterns
                ],
            }

        return json.dumps(report_data, indent=2)

    def _generate_html_report(self, result: AnalysisResult) -> str:
        """
        Generate HTML format report using HTMLGenerator.
        
        Args:
            result: Complete analysis results
            
        Returns:
            Self-contained HTML document string
        """
        try:
            return self.html_generator.create_html_document(result)
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {e}")
            # Fallback to human-readable format if HTML generation fails
            logger.warning("Falling back to human-readable format")
            return self._generate_human_report(result)

    def _get_threat_indicator(self, threat_level: ThreatLevel) -> str:
        """Get visual indicator for threat level."""
        indicators = {
            ThreatLevel.LOW: "✅",
            ThreatLevel.MEDIUM: "⚠️",
            ThreatLevel.HIGH: "🚨",
            ThreatLevel.CRITICAL: "🔴",
        }
        return indicators.get(threat_level, "❓")
