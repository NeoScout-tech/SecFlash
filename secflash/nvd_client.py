# secflash/nvd_client.py
"""
Client for interacting with the NVD API to fetch vulnerability data.
"""

import time
import logging
from typing import List, Optional
import nvdlib
import requests

from .config import config

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class NVDClient:
    """Client for fetching vulnerabilities from the NVD API."""
    def __init__(self):
        self.api_key = config.NVD_API_KEY
        if not self.api_key:
            logging.info("No NVD API key provided. Operating without API key (slower requests).")
        else:
            logging.info(f"Using API key: {self.api_key[:8]}...")

    def download_vulnerabilities_by_cpe(self, cpe: str) -> List:
        """Download vulnerabilities for a given CPE from NVD."""
        retries = 3
        for attempt in range(retries):
            try:
                logging.info(f"Requesting NVD data for CPE: {cpe}")
                vulns = nvdlib.searchCVE(
                    cpeName=cpe,
                    key=self.api_key if self.api_key else None,  # Use None if no API key
                    delay=6 if not self.api_key else 0.6,  # Longer delay without API key
                    limit=config.RESULTS_PER_PAGE
                )
                logging.info(f"Loaded {len(vulns)} vulnerabilities for CPE {cpe}")
                return vulns
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 404:
                    logging.warning(f"No vulnerabilities found for CPE {cpe}")
                    return []
                if e.response.status_code in [429, 403]:
                    wait_time = 2 ** attempt
                    logging.warning(f"Rate limit exceeded, retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                    continue
                logging.error(f"HTTP error downloading NVD data for CPE {cpe}: {str(e)}")
                return []
            except Exception as e:
                logging.error(f"Error downloading NVD data for CPE {cpe}: {str(e)}")
                return []
        logging.error(f"Failed to fetch data after {retries} attempts for CPE {cpe}")
        return []