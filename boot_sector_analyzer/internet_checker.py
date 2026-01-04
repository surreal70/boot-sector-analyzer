"""Internet-based threat intelligence checking."""

import json
import logging
import time
import ssl
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
import requests
import vt

from .models import VirusTotalResult

logger = logging.getLogger(__name__)


class InternetChecker:
    """Queries online threat intelligence sources."""

    def __init__(self, api_key: Optional[str] = None, cache_dir: Optional[str] = None):
        """
        Initialize internet checker.

        Args:
            api_key: VirusTotal API key
            cache_dir: Directory for caching results
        """
        self.api_key = api_key
        self.cache_dir = (
            Path(cache_dir)
            if cache_dir
            else Path.home() / ".boot_sector_analyzer" / "cache"
        )
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Rate limiting
        self.last_request_time = 0
        self.min_request_interval = 15  # 15 seconds between requests for free API

        # Session for connection reuse with SSL certificate validation
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "BootSectorAnalyzer/1.0"})
        
        # Ensure SSL certificate validation is enabled
        self.session.verify = True
        
        # Create SSL context with certificate validation
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = True
        self.ssl_context.verify_mode = ssl.CERT_REQUIRED

    def query_virustotal(self, file_hash: str) -> Optional[VirusTotalResult]:
        """
        Query VirusTotal API v3 for threat intelligence.

        Args:
            file_hash: SHA-256 hash to query

        Returns:
            VirusTotal result or None if query failed
        """
        if not self.api_key:
            logger.warning("No VirusTotal API key provided, skipping online check")
            return None

        # Check cache first
        cached_result = self._get_cached_result(file_hash)
        if cached_result:
            logger.debug(f"Using cached VirusTotal result for {file_hash}")
            return cached_result
            
        # Check negative cache to avoid repeated queries for unknown hashes
        if self._check_negative_cache(file_hash):
            logger.debug(f"Hash {file_hash} previously not found in VirusTotal")
            return None

        # Check network connectivity before making API call
        if not self._check_network_connectivity():
            logger.warning("No network connectivity available, skipping VirusTotal query")
            return None

        # Rate limiting
        self._enforce_rate_limit()

        try:
            # Use vt-py library for API v3
            with vt.Client(self.api_key) as client:
                logger.debug(f"Querying VirusTotal API v3 for hash: {file_hash}")
                
                try:
                    file_obj = client.get_object(f"/files/{file_hash}")
                    
                    # Extract analysis results
                    stats = file_obj.last_analysis_stats
                    detection_count = stats.get("malicious", 0) + stats.get("suspicious", 0)
                    total_engines = sum(stats.values()) if stats else 0
                    
                    # Get scan date
                    scan_date = None
                    if hasattr(file_obj, 'last_analysis_date') and file_obj.last_analysis_date:
                        scan_date = datetime.fromtimestamp(file_obj.last_analysis_date)
                    
                    # Get permalink
                    permalink = f"https://www.virustotal.com/gui/file/{file_hash}"
                    
                    # Get detailed detections
                    detections = {}
                    if hasattr(file_obj, 'last_analysis_results') and file_obj.last_analysis_results:
                        for engine, result in file_obj.last_analysis_results.items():
                            if hasattr(result, 'result') and result.result:
                                detections[engine] = {
                                    'detected': result.category in ['malicious', 'suspicious'],
                                    'result': result.result,
                                    'category': result.category,
                                    'engine_name': engine
                                }

                    result = VirusTotalResult(
                        hash_value=file_hash,
                        detection_count=detection_count,
                        total_engines=total_engines,
                        scan_date=scan_date,
                        permalink=permalink,
                        detections=detections,
                    )

                    # Cache the result
                    self._cache_result(file_hash, result)

                    logger.info(
                        f"VirusTotal: {result.detection_count}/{result.total_engines} detections for {file_hash}"
                    )
                    return result
                    
                except vt.APIError as e:
                    if e.code == "NotFoundError":
                        logger.debug(f"Hash not found in VirusTotal: {file_hash}")
                        # Cache negative result to avoid repeated queries
                        self._cache_negative_result(file_hash)
                        return None
                    elif e.code == "QuotaExceededError":
                        logger.warning("VirusTotal API quota exceeded, continuing with offline analysis")
                        return None
                    else:
                        logger.error(f"VirusTotal API error: {e}")
                        return None

        except vt.APIError as e:
            logger.error(f"VirusTotal API error: {e}")
            self._handle_network_error(e)
            return None
        except requests.exceptions.SSLError as e:
            logger.error(f"SSL certificate validation failed: {e}")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"VirusTotal API request failed: {e}")
            self._handle_network_error(e)
            return None
        except Exception as e:
            logger.error(f"Unexpected error querying VirusTotal: {e}")
            return None

    def _enforce_rate_limit(self):
        """Enforce API rate limiting with adaptive intervals."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time

        if time_since_last < self.min_request_interval:
            sleep_time = self.min_request_interval - time_since_last
            logger.debug(f"Rate limiting: sleeping for {sleep_time:.1f} seconds")
            time.sleep(sleep_time)

        self.last_request_time = time.time()

    def _cache_negative_result(self, file_hash: str):
        """Cache negative result (file not found) to avoid repeated queries."""
        cache_file = self.cache_dir / f"negative_{file_hash}.json"
        
        try:
            cache_data = {
                "cached_at": datetime.now().isoformat(),
                "result": "not_found",
                "hash_value": file_hash
            }
            
            with open(cache_file, "w") as f:
                json.dump(cache_data, f, indent=2)
                
            logger.debug(f"Cached negative result for {file_hash}")
            
        except Exception as e:
            logger.warning(f"Failed to cache negative result for {file_hash}: {e}")

    def _check_negative_cache(self, file_hash: str) -> bool:
        """Check if hash has a cached negative result."""
        cache_file = self.cache_dir / f"negative_{file_hash}.json"
        
        if not cache_file.exists():
            return False
            
        try:
            with open(cache_file, "r") as f:
                data = json.load(f)
                
            # Check if cache is expired (24 hours for negative results too)
            cached_time = datetime.fromisoformat(data["cached_at"])
            if datetime.now() - cached_time > timedelta(hours=24):
                logger.debug(f"Negative cache expired for {file_hash}")
                cache_file.unlink()
                return False
                
            logger.debug(f"Found cached negative result for {file_hash}")
            return True
            
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.warning(f"Failed to load negative cache for {file_hash}: {e}")
            if cache_file.exists():
                cache_file.unlink()
            return False

    def clear_expired_cache(self) -> int:
        """
        Clear expired cache entries.
        
        Returns:
            Number of cache entries cleared
        """
        cleared_count = 0
        
        try:
            for cache_file in self.cache_dir.glob("*.json"):
                try:
                    with open(cache_file, "r") as f:
                        data = json.load(f)
                    
                    cached_time = datetime.fromisoformat(data["cached_at"])
                    if datetime.now() - cached_time > timedelta(hours=24):
                        cache_file.unlink()
                        cleared_count += 1
                        logger.debug(f"Cleared expired cache file: {cache_file.name}")
                        
                except (json.JSONDecodeError, KeyError, ValueError) as e:
                    # Remove corrupted cache files
                    cache_file.unlink()
                    cleared_count += 1
                    logger.debug(f"Cleared corrupted cache file: {cache_file.name}")
                    
        except Exception as e:
            logger.warning(f"Error clearing expired cache: {e}")
            
        if cleared_count > 0:
            logger.info(f"Cleared {cleared_count} expired cache entries")
            
        return cleared_count

    def _get_cached_result(self, file_hash: str) -> Optional[VirusTotalResult]:
        """Get cached VirusTotal result if available and not expired."""
        cache_file = self.cache_dir / f"{file_hash}.json"

        if not cache_file.exists():
            return None

        try:
            with open(cache_file, "r") as f:
                data = json.load(f)

            # Check if cache is expired (24 hours)
            cached_time = datetime.fromisoformat(data["cached_at"])
            if datetime.now() - cached_time > timedelta(hours=24):
                logger.debug(f"Cache expired for {file_hash}")
                cache_file.unlink()  # Remove expired cache
                return None

            # Reconstruct VirusTotalResult
            result_data = data["result"]
            return VirusTotalResult(
                hash_value=result_data["hash_value"],
                detection_count=result_data["detection_count"],
                total_engines=result_data["total_engines"],
                scan_date=(
                    datetime.fromisoformat(result_data["scan_date"])
                    if result_data["scan_date"]
                    else None
                ),
                permalink=result_data["permalink"],
                detections=result_data["detections"],
            )

        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.warning(f"Failed to load cached result for {file_hash}: {e}")
            # Remove corrupted cache file
            if cache_file.exists():
                cache_file.unlink()
            return None

    def _cache_result(self, file_hash: str, result: VirusTotalResult):
        """Cache VirusTotal result."""
        cache_file = self.cache_dir / f"{file_hash}.json"

        try:
            cache_data = {
                "cached_at": datetime.now().isoformat(),
                "result": {
                    "hash_value": result.hash_value,
                    "detection_count": result.detection_count,
                    "total_engines": result.total_engines,
                    "scan_date": (
                        result.scan_date.isoformat() if result.scan_date else None
                    ),
                    "permalink": result.permalink,
                    "detections": result.detections,
                },
            }

            with open(cache_file, "w") as f:
                json.dump(cache_data, f, indent=2)

            logger.debug(f"Cached VirusTotal result for {file_hash}")

        except Exception as e:
            logger.warning(f"Failed to cache result for {file_hash}: {e}")

    def cache_results(self, hash_value: str, result: dict) -> None:
        """
        Cache threat intelligence results locally.

        Args:
            hash_value: Hash value as cache key
            result: Result data to cache
        """
        # This method is for generic caching, specific to VirusTotal caching above
        cache_file = self.cache_dir / f"generic_{hash_value}.json"

        try:
            cache_data = {"cached_at": datetime.now().isoformat(), "result": result}

            with open(cache_file, "w") as f:
                json.dump(cache_data, f, indent=2)

        except Exception as e:
            logger.warning(f"Failed to cache generic result for {hash_value}: {e}")

    def handle_rate_limits(self) -> None:
        """Implement API rate limiting."""
        self._enforce_rate_limit()

    def _check_network_connectivity(self) -> bool:
        """
        Check if network connectivity is available.
        
        Returns:
            True if network is available, False otherwise
        """
        try:
            # Try to connect to a reliable endpoint
            response = self.session.get(
                "https://www.google.com", 
                timeout=5,
                verify=True
            )
            return response.status_code == 200
        except (requests.exceptions.RequestException, Exception):
            return False

    def _handle_network_error(self, error: Exception) -> None:
        """
        Handle network connectivity issues gracefully.
        
        Args:
            error: The network error that occurred
        """
        logger.warning(f"Network connectivity issue: {error}")
        logger.info("Continuing with offline analysis...")

    def _validate_ssl_certificate(self, url: str) -> bool:
        """
        Validate SSL certificate for a given URL.
        
        Args:
            url: URL to validate SSL certificate for
            
        Returns:
            True if SSL certificate is valid, False otherwise
        """
        try:
            response = self.session.get(url, timeout=10, verify=True)
            return True
        except requests.exceptions.SSLError as e:
            logger.error(f"SSL certificate validation failed for {url}: {e}")
            return False
        except Exception as e:
            logger.warning(f"Could not validate SSL certificate for {url}: {e}")
            return False
