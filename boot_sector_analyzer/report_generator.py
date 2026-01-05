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
            
            # Analysis type indicator
            analysis_type = getattr(result.threat_intelligence, 'analysis_type', 'full_boot_sector')
            analysis_label = "Boot Code Only" if analysis_type == "boot_code_only" else "Full Boot Sector"
            lines.append(f"VirusTotal Analysis ({analysis_label}):")
            
            # Enhanced detection display - prominently show negative results
            if vt_result.detection_count == 0:
                lines.append(f"  ✅ CLEAN: 0/{vt_result.total_engines} detections (No threats detected)")
            else:
                lines.append(f"  ⚠️  DETECTIONS: {vt_result.detection_count}/{vt_result.total_engines}")
            
            # Enhanced statistics display - always show for both positive and negative results
            if vt_result.stats:
                stats = vt_result.stats
                lines.append("  Scan Statistics:")
                lines.append(f"    Malicious: {stats.malicious}")
                lines.append(f"    Suspicious: {stats.suspicious}")
                lines.append(f"    Undetected: {stats.undetected}")
                lines.append(f"    Harmless: {stats.harmless}")
                if stats.timeout > 0:
                    lines.append(f"    Timeout: {stats.timeout}")
                if stats.failure > 0:
                    lines.append(f"    Failure: {stats.failure}")
            
            # Scan date and metadata - always show
            if vt_result.scan_date:
                lines.append(f"  Scan Date: {vt_result.scan_date.strftime('%Y-%m-%d %H:%M:%S')}")
            
            # Detection details with enhanced information
            if vt_result.detection_count > 0:
                lines.append("  Detection Results:")
                # Show all detections, not just first 5
                detected_engines = []
                for engine_result in vt_result.engine_results:
                    if engine_result.detected:
                        detected_engines.append(engine_result)
                
                # If no engine_results, fall back to legacy detections
                if not detected_engines and vt_result.detections:
                    for engine, detection in vt_result.detections.items():
                        if detection.get("detected"):
                            result_text = detection.get('result', 'Unknown')
                            category = detection.get('category', 'unknown')
                            lines.append(f"    - {engine}: {result_text} ({category})")
                else:
                    # Use enhanced engine results
                    for engine_result in detected_engines:
                        result_text = engine_result.result or 'Detected'
                        category = engine_result.category
                        version_info = ""
                        if engine_result.engine_version:
                            version_info = f" [v{engine_result.engine_version}]"
                        lines.append(f"    - {engine_result.engine_name}: {result_text} ({category}){version_info}")
            else:
                # Explicitly show negative result information
                lines.append("  ✅ No threats detected by any security engine")
                if vt_result.stats and vt_result.stats.undetected > 0:
                    lines.append(f"  All {vt_result.stats.undetected} engines reported the file as clean")
                
            # Detection ratio analysis - always show, including for negative results
            if vt_result.total_engines > 0:
                detection_ratio = vt_result.detection_count / vt_result.total_engines
                if detection_ratio == 0:
                    lines.append(f"  ✅ CLEAN RESULT: 0% detection ratio - All engines report clean")
                elif detection_ratio >= 0.5:
                    lines.append(f"  ⚠️  HIGH DETECTION RATIO: {detection_ratio:.1%} of engines detected threats")
                elif detection_ratio >= 0.2:
                    lines.append(f"  ⚠️  MODERATE DETECTION RATIO: {detection_ratio:.1%} of engines detected threats")
                else:
                    lines.append(f"  ℹ️  LOW DETECTION RATIO: {detection_ratio:.1%} of engines detected threats")
            
            # Additional metadata from raw response - always show when available
            if vt_result.raw_response and isinstance(vt_result.raw_response, dict):
                attributes = vt_result.raw_response.get('attributes', {})
                if attributes.get('first_submission_date'):
                    from datetime import datetime
                    first_seen = datetime.fromtimestamp(attributes['first_submission_date'])
                    lines.append(f"  First Seen: {first_seen.strftime('%Y-%m-%d %H:%M:%S')}")
                if attributes.get('times_submitted'):
                    lines.append(f"  Times Submitted: {attributes['times_submitted']}")
                if attributes.get('reputation') is not None:
                    lines.append(f"  Reputation Score: {attributes['reputation']}")

            if vt_result.permalink:
                lines.append(f"  Full Report: {vt_result.permalink}")
            lines.append("")

        # Boot Code VirusTotal Analysis
        if result.boot_code_threat_intelligence and result.boot_code_threat_intelligence.virustotal_result:
            lines.append("BOOT CODE VIRUSTOTAL ANALYSIS")
            lines.append("-" * 30)
            boot_vt_result = result.boot_code_threat_intelligence.virustotal_result
            
            lines.append("Boot Code VirusTotal Analysis (Boot Code Only):")
            
            # Enhanced detection display - prominently show negative results
            if boot_vt_result.detection_count == 0:
                lines.append(f"  ✅ CLEAN: 0/{boot_vt_result.total_engines} detections (No threats detected)")
            else:
                lines.append(f"  ⚠️  DETECTIONS: {boot_vt_result.detection_count}/{boot_vt_result.total_engines}")
            
            # Enhanced statistics display - always show for both positive and negative results
            if boot_vt_result.stats:
                stats = boot_vt_result.stats
                lines.append("  Scan Statistics:")
                lines.append(f"    Malicious: {stats.malicious}")
                lines.append(f"    Suspicious: {stats.suspicious}")
                lines.append(f"    Undetected: {stats.undetected}")
                lines.append(f"    Harmless: {stats.harmless}")
                if stats.timeout > 0:
                    lines.append(f"    Timeout: {stats.timeout}")
                if stats.failure > 0:
                    lines.append(f"    Failure: {stats.failure}")
            
            # Scan date and metadata - always show
            if boot_vt_result.scan_date:
                lines.append(f"  Scan Date: {boot_vt_result.scan_date.strftime('%Y-%m-%d %H:%M:%S')}")
            
            # Detection details with enhanced information
            if boot_vt_result.detection_count > 0:
                lines.append("  Detection Results:")
                # Show all detections, not just first 5
                detected_engines = []
                for engine_result in boot_vt_result.engine_results:
                    if engine_result.detected:
                        detected_engines.append(engine_result)
                
                # If no engine_results, fall back to legacy detections
                if not detected_engines and boot_vt_result.detections:
                    for engine, detection in boot_vt_result.detections.items():
                        if detection.get("detected"):
                            result_text = detection.get('result', 'Unknown')
                            category = detection.get('category', 'unknown')
                            lines.append(f"    - {engine}: {result_text} ({category})")
                else:
                    # Use enhanced engine results
                    for engine_result in detected_engines:
                        result_text = engine_result.result or 'Detected'
                        category = engine_result.category
                        version_info = ""
                        if engine_result.engine_version:
                            version_info = f" [v{engine_result.engine_version}]"
                        lines.append(f"    - {engine_result.engine_name}: {result_text} ({category}){version_info}")
            else:
                # Explicitly show negative result information
                lines.append("  ✅ No threats detected by any security engine")
                if boot_vt_result.stats and boot_vt_result.stats.undetected > 0:
                    lines.append(f"  All {boot_vt_result.stats.undetected} engines reported the boot code as clean")
                
            # Detection ratio analysis - always show, including for negative results
            if boot_vt_result.total_engines > 0:
                detection_ratio = boot_vt_result.detection_count / boot_vt_result.total_engines
                if detection_ratio == 0:
                    lines.append(f"  ✅ CLEAN RESULT: 0% detection ratio - All engines report clean")
                elif detection_ratio >= 0.5:
                    lines.append(f"  ⚠️  HIGH DETECTION RATIO: {detection_ratio:.1%} of engines detected threats")
                elif detection_ratio >= 0.2:
                    lines.append(f"  ⚠️  MODERATE DETECTION RATIO: {detection_ratio:.1%} of engines detected threats")
                else:
                    lines.append(f"  ℹ️  LOW DETECTION RATIO: {detection_ratio:.1%} of engines detected threats")
            
            # Additional metadata from raw response - always show when available
            if boot_vt_result.raw_response and isinstance(boot_vt_result.raw_response, dict):
                attributes = boot_vt_result.raw_response.get('attributes', {})
                if attributes.get('first_submission_date'):
                    from datetime import datetime
                    first_seen = datetime.fromtimestamp(attributes['first_submission_date'])
                    lines.append(f"  First Seen: {first_seen.strftime('%Y-%m-%d %H:%M:%S')}")
                if attributes.get('times_submitted'):
                    lines.append(f"  Times Submitted: {attributes['times_submitted']}")
                if attributes.get('reputation') is not None:
                    lines.append(f"  Reputation Score: {attributes['reputation']}")

            if boot_vt_result.permalink:
                lines.append(f"  Full Report: {boot_vt_result.permalink}")
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

        # VBR Analysis Section (if available)
        if result.vbr_analysis:
            lines.append("VOLUME BOOT RECORD (VBR) ANALYSIS")
            lines.append("-" * 40)
            lines.append(f"Analyzed {len(result.vbr_analysis)} partition(s) for VBR data:")
            lines.append("")
            
            for vbr_result in result.vbr_analysis:
                lines.append(f"Partition {vbr_result.partition_number}:")
                lines.append("-" * 15)
                
                # Partition information
                partition = vbr_result.partition_info
                lines.append(f"  System ID: 0x{partition.partition_type:02X}")
                lines.append(f"  Start LBA: {partition.start_lba}")
                lines.append(f"  Size: {partition.size_sectors} sectors")
                lines.append(f"  Bootable: {'Yes' if partition.status & 0x80 else 'No'}")
                
                if vbr_result.extraction_error:
                    lines.append(f"  VBR Extraction: Failed - {vbr_result.extraction_error}")
                    lines.append("")
                    continue
                
                if vbr_result.vbr_structure:
                    vbr = vbr_result.vbr_structure
                    lines.append(f"  Filesystem: {vbr.filesystem_type.value}")
                    lines.append(f"  Boot Signature: 0x{vbr.boot_signature:04X}")
                    
                    # Filesystem metadata
                    if vbr.filesystem_metadata.volume_label:
                        lines.append(f"  Volume Label: {vbr.filesystem_metadata.volume_label}")
                    if vbr.filesystem_metadata.cluster_size:
                        lines.append(f"  Cluster Size: {vbr.filesystem_metadata.cluster_size} bytes")
                    if vbr.filesystem_metadata.total_sectors:
                        lines.append(f"  Total Sectors: {vbr.filesystem_metadata.total_sectors}")
                
                if vbr_result.content_analysis:
                    content = vbr_result.content_analysis
                    lines.append("  VBR Hashes:")
                    for hash_type, hash_value in content.hashes.items():
                        lines.append(f"    {hash_type.upper()}: {hash_value}")
                    
                    lines.append(f"  Threat Level: {content.threat_level.value.upper()}")
                    
                    if content.detected_patterns:
                        lines.append("  Boot Patterns:")
                        for pattern in content.detected_patterns:
                            lines.append(f"    - {pattern.pattern_type}: {pattern.description}")
                    
                    if content.anomalies:
                        lines.append("  Anomalies:")
                        for anomaly in content.anomalies:
                            lines.append(f"    - {anomaly.anomaly_type}: {anomaly.description} (Severity: {anomaly.severity})")
                
                lines.append("")

        # Disassembly Section (if available)
        if result.disassembly is not None and result.disassembly.instructions:
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
        elif result.disassembly is None:
            # Handle empty boot code case
            lines.append("BOOT CODE DISASSEMBLY")
            lines.append("-" * 25)
            lines.append("No boot code present (all zeros)")
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
            
            # Enhanced VirusTotal data with complete response
            vt_data = {
                "detection_count": vt_result.detection_count,
                "total_engines": vt_result.total_engines,
                "scan_date": (
                    vt_result.scan_date.isoformat() if vt_result.scan_date else None
                ),
                "permalink": vt_result.permalink,
                "detections": vt_result.detections,
                "hash_value": vt_result.hash_value,
            }
            
            # Add enhanced statistics
            if vt_result.stats:
                vt_data["stats"] = {
                    "malicious": vt_result.stats.malicious,
                    "suspicious": vt_result.stats.suspicious,
                    "undetected": vt_result.stats.undetected,
                    "harmless": vt_result.stats.harmless,
                    "timeout": vt_result.stats.timeout,
                    "confirmed_timeout": vt_result.stats.confirmed_timeout,
                    "failure": vt_result.stats.failure,
                    "type_unsupported": vt_result.stats.type_unsupported,
                }
            
            # Add detailed engine results
            if vt_result.engine_results:
                vt_data["engine_results"] = [
                    {
                        "engine_name": engine.engine_name,
                        "detected": engine.detected,
                        "result": engine.result,
                        "category": engine.category,
                        "engine_version": engine.engine_version,
                        "engine_update": engine.engine_update,
                    }
                    for engine in vt_result.engine_results
                ]
            
            # Include complete raw response
            if vt_result.raw_response:
                vt_data["raw_response"] = vt_result.raw_response
            
            # Calculate detection ratio
            if vt_result.total_engines > 0:
                vt_data["detection_ratio"] = vt_result.detection_count / vt_result.total_engines
            
            report_data["threat_intelligence"] = {
                "virustotal": vt_data,
                "cached": result.threat_intelligence.cached,
                "query_timestamp": result.threat_intelligence.query_timestamp.isoformat(),
                "analysis_type": getattr(result.threat_intelligence, 'analysis_type', 'full_boot_sector'),
            }

        # Add boot code threat intelligence if available
        if result.boot_code_threat_intelligence and result.boot_code_threat_intelligence.virustotal_result:
            boot_vt_result = result.boot_code_threat_intelligence.virustotal_result
            
            # Enhanced VirusTotal data with complete response for boot code
            boot_vt_data = {
                "detection_count": boot_vt_result.detection_count,
                "total_engines": boot_vt_result.total_engines,
                "scan_date": (
                    boot_vt_result.scan_date.isoformat() if boot_vt_result.scan_date else None
                ),
                "permalink": boot_vt_result.permalink,
                "detections": boot_vt_result.detections,
                "hash_value": boot_vt_result.hash_value,
            }
            
            # Add enhanced statistics
            if boot_vt_result.stats:
                boot_vt_data["stats"] = {
                    "malicious": boot_vt_result.stats.malicious,
                    "suspicious": boot_vt_result.stats.suspicious,
                    "undetected": boot_vt_result.stats.undetected,
                    "harmless": boot_vt_result.stats.harmless,
                    "timeout": boot_vt_result.stats.timeout,
                    "confirmed_timeout": boot_vt_result.stats.confirmed_timeout,
                    "failure": boot_vt_result.stats.failure,
                    "type_unsupported": boot_vt_result.stats.type_unsupported,
                }
            
            # Add detailed engine results
            if boot_vt_result.engine_results:
                boot_vt_data["engine_results"] = [
                    {
                        "engine_name": engine.engine_name,
                        "detected": engine.detected,
                        "result": engine.result,
                        "category": engine.category,
                        "engine_version": engine.engine_version,
                        "engine_update": engine.engine_update,
                    }
                    for engine in boot_vt_result.engine_results
                ]
            
            # Include complete raw response
            if boot_vt_result.raw_response:
                boot_vt_data["raw_response"] = boot_vt_result.raw_response
            
            # Calculate detection ratio
            if boot_vt_result.total_engines > 0:
                boot_vt_data["detection_ratio"] = boot_vt_result.detection_count / boot_vt_result.total_engines
            
            report_data["boot_code_threat_intelligence"] = {
                "virustotal": boot_vt_data,
                "cached": result.boot_code_threat_intelligence.cached,
                "query_timestamp": result.boot_code_threat_intelligence.query_timestamp.isoformat(),
                "analysis_type": getattr(result.boot_code_threat_intelligence, 'analysis_type', 'boot_code_only'),
            }

        # Add hexdump data with partition color metadata
        partition_colors = {}
        try:
            mbr_structure = self.mbr_decoder.parse_mbr(result.hexdump.raw_data)
            for i, partition in enumerate(mbr_structure.partition_entries, 1):
                partition_colors[f"partition_{i}"] = {
                    "html_color": self.mbr_decoder.get_partition_color_info(446 + (i-1)*16, mbr_structure)[0],
                    "ansi_color": self.mbr_decoder.get_partition_color_info(446 + (i-1)*16, mbr_structure)[1],
                    "is_empty": partition.is_empty,
                    "system_id": partition.system_id if not partition.is_empty else None
                }
        except Exception as e:
            logger.debug(f"Could not parse MBR for partition color metadata: {e}")
        
        report_data["hexdump"] = {
            "total_bytes": result.hexdump.total_bytes,
            "ascii_representation": result.hexdump.ascii_representation,
            "formatted_lines": result.hexdump.formatted_lines,
            "partition_colors": partition_colors,
        }

        # Add disassembly data if available
        if result.disassembly is not None:
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
                "empty_boot_code": False,
            }
        else:
            # Handle empty boot code case
            report_data["disassembly"] = {
                "empty_boot_code": True,
                "message": "No boot code present (all zeros)",
                "total_bytes_disassembled": 0,
                "instructions": [],
                "invalid_instructions": [],
                "boot_patterns": [],
            }

        # Add VBR analysis data if available
        if result.vbr_analysis:
            report_data["vbr_analysis"] = []
            for vbr_result in result.vbr_analysis:
                vbr_data = {
                    "partition_number": vbr_result.partition_number,
                    "partition_info": {
                        "system_id": f"0x{vbr_result.partition_info.partition_type:02X}",
                        "start_lba": vbr_result.partition_info.start_lba,
                        "size_sectors": vbr_result.partition_info.size_sectors,
                        "bootable": bool(vbr_result.partition_info.status & 0x80),
                    },
                    "extraction_error": vbr_result.extraction_error,
                }
                
                if vbr_result.vbr_structure:
                    vbr_structure = vbr_result.vbr_structure
                    vbr_data["vbr_structure"] = {
                        "filesystem_type": vbr_structure.filesystem_type.value,
                        "boot_signature": f"0x{vbr_structure.boot_signature:04X}",
                        "filesystem_metadata": {
                            "volume_label": vbr_structure.filesystem_metadata.volume_label,
                            "cluster_size": vbr_structure.filesystem_metadata.cluster_size,
                            "total_sectors": vbr_structure.filesystem_metadata.total_sectors,
                            "filesystem_version": vbr_structure.filesystem_metadata.filesystem_version,
                            "creation_timestamp": (
                                vbr_structure.filesystem_metadata.creation_timestamp.isoformat()
                                if vbr_structure.filesystem_metadata.creation_timestamp else None
                            ),
                        },
                    }
                
                if vbr_result.content_analysis:
                    content = vbr_result.content_analysis
                    vbr_data["content_analysis"] = {
                        "hashes": content.hashes,
                        "boot_code_hashes": content.boot_code_hashes,
                        "threat_level": content.threat_level.value,
                        "detected_patterns": [
                            {
                                "pattern_type": pattern.pattern_type,
                                "description": pattern.description,
                                "significance": pattern.significance,
                                "filesystem_specific": pattern.filesystem_specific,
                                "instruction_count": len(pattern.instructions),
                            }
                            for pattern in content.detected_patterns
                        ],
                        "anomalies": [
                            {
                                "anomaly_type": anomaly.anomaly_type,
                                "description": anomaly.description,
                                "severity": anomaly.severity,
                                "evidence": anomaly.evidence,
                            }
                            for anomaly in content.anomalies
                        ],
                    }
                    
                    # Add VBR disassembly data if available
                    if content.disassembly_result:
                        vbr_data["content_analysis"]["disassembly"] = {
                            "total_bytes_disassembled": content.disassembly_result.total_bytes_disassembled,
                            "instructions": [
                                {
                                    "address": f"0x{instruction.address:04X}",
                                    "bytes": [f"0x{b:02X}" for b in instruction.bytes],
                                    "mnemonic": instruction.mnemonic,
                                    "operands": instruction.operands,
                                    "comment": instruction.comment,
                                }
                                for instruction in content.disassembly_result.instructions
                            ],
                            "invalid_instructions": [
                                {
                                    "address": f"0x{invalid.address:04X}",
                                    "bytes": [f"0x{b:02X}" for b in invalid.bytes],
                                    "reason": invalid.reason,
                                }
                                for invalid in content.disassembly_result.invalid_instructions
                            ],
                            "boot_patterns": [
                                {
                                    "pattern_type": pattern.pattern_type,
                                    "description": pattern.description,
                                    "significance": pattern.significance,
                                    "instruction_count": len(pattern.instructions),
                                }
                                for pattern in content.disassembly_result.boot_patterns
                            ],
                        }
                
                # Add VBR hexdump data
                if vbr_result.vbr_structure and vbr_result.vbr_structure.raw_data:
                    vbr_hexdump = self._generate_vbr_hexdump_data(vbr_result.vbr_structure.raw_data)
                    vbr_data["hexdump"] = vbr_hexdump
                
                report_data["vbr_analysis"].append(vbr_data)

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

    def _generate_vbr_hexdump_data(self, vbr_data: bytes) -> dict:
        """
        Generate hexdump data for VBR.
        
        Args:
            vbr_data: 512-byte VBR data
            
        Returns:
            Dictionary with hexdump information
        """
        if len(vbr_data) != 512:
            return {
                "total_bytes": len(vbr_data),
                "formatted_lines": [f"Invalid VBR size: {len(vbr_data)} bytes (expected 512)"],
                "ascii_representation": "",
            }
        
        # Generate formatted hexdump lines
        formatted_lines = []
        ascii_repr = ""
        
        for offset in range(0, len(vbr_data), 16):
            row_data = vbr_data[offset:offset + 16]
            
            # Format offset
            offset_str = f"0x{offset:04X}"
            
            # Format hex bytes
            hex_bytes = " ".join(f"{byte:02X}" for byte in row_data)
            
            # Pad hex bytes if row is incomplete
            if len(row_data) < 16:
                hex_bytes += "   " * (16 - len(row_data))
            
            # Format ASCII representation
            ascii_part = self.format_ascii_column(row_data)
            ascii_repr += ascii_part
            
            # Combine into line
            line = f"{offset_str}  {hex_bytes}  {ascii_part}"
            formatted_lines.append(line)
        
        return {
            "total_bytes": len(vbr_data),
            "formatted_lines": formatted_lines,
            "ascii_representation": ascii_repr,
        }
