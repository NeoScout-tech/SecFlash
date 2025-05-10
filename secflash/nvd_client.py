"""
Client for interacting with the NVD API to fetch vulnerability data.
"""

import time
from typing import List
import nvdlib
import requests

from .config import config
from .logger import get_logger

logger = get_logger(__name__)

class NVDClient:
    """Client for fetching vulnerabilities from the NVD API."""
    def __init__(self):
        self.api_key = config.NVD_API_KEY
        if not self.api_key:
            logger.info("No NVD API key provided. Operating without API key (slower requests).")
        else:
            logger.info(f"Using API key: {self.api_key[:8]}...")

    def download_vulnerabilities_by_cpe(self, cpe: str) -> List:
        """Download vulnerabilities for a given CPE from NVD."""
        retries = 3
        for attempt in range(retries):
            try:
                logger.info(f"Requesting NVD data for CPE: {cpe}")
                vulns = nvdlib.searchCVE(
                    cpeName=cpe,
                    key=self.api_key if self.api_key else None,
                    delay=6 if not self.api_key else 0.6,
                    limit=config.RESULTS_PER_PAGE
                )
                logger.info(f"Loaded {len(vulns)} vulnerabilities for CPE {cpe}")
                return vulns
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 404:
                    logger.warning(f"No vulnerabilities found for CPE {cpe}")
                    return []
                if e.response.status_code in [429, 403]:
                    wait_time = 2 ** attempt
                    logger.warning(f"Rate limit exceeded, retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                    continue
                logger.error(f"HTTP error downloading NVD data for CPE {cpe}: {str(e)}")
                return []
            except Exception as e:
                logger.error(f"Error downloading NVD data for CPE {cpe}: {str(e)}")
                return []
        logger.error(f"Failed to fetch data after {retries} attempts for CPE {cpe}")
        return []