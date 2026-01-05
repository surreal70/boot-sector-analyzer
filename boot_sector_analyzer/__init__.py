"""Boot Sector Analyzer - A comprehensive boot sector analysis tool."""

__version__ = "0.3.0"
__author__ = "Boot Sector Analyzer Team"

from .analyzer import BootSectorAnalyzer
from .models import AnalysisResult, ThreatLevel
from .exceptions import BootSectorAnalyzerError
from .vbr_analyzer import VBRAnalyzer

__all__ = ["BootSectorAnalyzer", "AnalysisResult", "ThreatLevel", "BootSectorAnalyzerError", "VBRAnalyzer"]
