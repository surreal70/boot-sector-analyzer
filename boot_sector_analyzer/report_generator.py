"""Report generation for analysis results."""

import json
import logging

from .models import AnalysisResult, ThreatLevel

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates structured analysis reports."""

    def generate_hexdump(self, boot_sector: bytes) -> str:
        """
        Generate formatted hexdump of boot sector data.

        Args:
            boot_sector: 512-byte boot sector data

        Returns:
            Formatted hexdump string with offset, hex bytes, and ASCII representation
        """
        if len(boot_sector) != 512:
            raise ValueError("Boot sector must be exactly 512 bytes")

        lines = self.format_hexdump_table(boot_sector)
        return "\n".join(lines)

    def format_hexdump_table(self, boot_sector: bytes) -> list[str]:
        """
        Format hexdump as 17-column table with offset and hex bytes.

        Args:
            boot_sector: 512-byte boot sector data

        Returns:
            List of formatted hexdump lines
        """
        lines = []
        
        # Header line
        header = "Offset   " + " ".join(f"{i:02X}" for i in range(16)) + "  ASCII"
        lines.append(header)
        lines.append("-" * len(header))

        # Process 16 bytes per row (32 rows total for 512 bytes)
        for offset in range(0, len(boot_sector), 16):
            row_data = boot_sector[offset:offset + 16]
            
            # Format offset as zero-padded uppercase hex
            offset_str = f"0x{offset:04X}"
            
            # Format hex bytes with proper spacing
            hex_bytes = " ".join(f"{byte:02X}" for byte in row_data)
            
            # Pad hex bytes if row is incomplete (shouldn't happen with 512-byte boot sector)
            if len(row_data) < 16:
                hex_bytes += "   " * (16 - len(row_data))
            
            # Format ASCII representation
            ascii_repr = self.format_ascii_column(row_data)
            
            # Combine into final line
            line = f"{offset_str}  {hex_bytes}  {ascii_repr}"
            lines.append(line)

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
            format_type: "human" for human-readable, "json" for JSON format

        Returns:
            Formatted report string
        """
        if format_type.lower() == "json":
            return self._generate_json_report(result)
        else:
            return self._generate_human_report(result)

    def _generate_human_report(self, result: AnalysisResult) -> str:
        """Generate human-readable report."""
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

        # Structure Analysis
        lines.append("STRUCTURE ANALYSIS")
        lines.append("-" * 20)
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

        # Hexdump Section
        lines.append("HEXDUMP")
        lines.append("-" * 20)
        lines.append("Raw boot sector data for manual review:")
        lines.append("")
        hexdump_lines = result.hexdump.formatted_lines
        lines.extend(hexdump_lines)

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

        return json.dumps(report_data, indent=2)

    def _get_threat_indicator(self, threat_level: ThreatLevel) -> str:
        """Get visual indicator for threat level."""
        indicators = {
            ThreatLevel.LOW: "✅",
            ThreatLevel.MEDIUM: "⚠️",
            ThreatLevel.HIGH: "🚨",
            ThreatLevel.CRITICAL: "🔴",
        }
        return indicators.get(threat_level, "❓")
