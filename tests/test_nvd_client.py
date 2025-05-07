# tests/test_nvd_client.py
"""
Unit tests for the NVDClient class.
"""

import unittest
from unittest.mock import MagicMock, patch
from secflash.nvd_client import NVDClient


class TestNVDClient(unittest.TestCase):
    """Test cases for NVDClient."""
    def setUp(self):
        self.client = NVDClient()

    @patch('secflash.nvd_client.nvdlib.searchCVE')
    def test_download_vulnerabilities_by_cpe(self, mock_search_cve):
        """Test downloading vulnerabilities by CPE."""
        mock_cve = MagicMock()
        mock_cve.id = "CVE-2021-44228"
        mock_search_cve.return_value = [mock_cve]

        result = self.client.download_vulnerabilities_by_cpe("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].id, "CVE-2021-44228")

    @patch('secflash.nvd_client.nvdlib.searchCVE')
    def test_download_vulnerabilities_by_cpe_empty(self, mock_search_cve):
        """Test downloading vulnerabilities with no results."""
        mock_search_cve.return_value = []
        result = self.client.download_vulnerabilities_by_cpe("cpe:2.3:a:unknown:unknown:*:*:*:*:*:*:*")
        self.assertEqual(result, [])

    @patch('secflash.nvd_client.nvdlib.searchCVE')
    def test_download_vulnerabilities_by_cpe_error(self, mock_search_cve):
        """Test handling HTTP errors."""
        from requests.exceptions import HTTPError
        mock_search_cve.side_effect = HTTPError(response=MagicMock(status_code=429))
        result = self.client.download_vulnerabilities_by_cpe("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
        self.assertEqual(result, [])


if __name__ == '__main__':
    unittest.main()