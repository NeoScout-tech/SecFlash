# tests/test_database.py
"""
Unit tests for the NVDDatabase class.
"""

import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime
from secflash.database import NVDDatabase


class TestNVDDatabase(unittest.TestCase):
    """Test cases for NVDDatabase."""
    def setUp(self):
        """Set up test fixtures."""
        self.db = NVDDatabase(db_path=":memory:")
        self.db._initialize_database()

    def test_save_vulnerabilities(self):
        """Test saving vulnerabilities to the database."""
        mock_cve = MagicMock()
        mock_cve.id = "CVE-2021-44228"
        mock_cve.descriptions = [MagicMock(lang="en", value="Test vulnerability")]
        mock_cve.published = "2021-12-10T00:00:00.000"
        mock_cve.lastModified = "2021-12-15T00:00:00.000"
        mock_cve.metrics.cvssMetricV31 = [MagicMock(cvssData=MagicMock(baseScore=9.8, vectorString="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))]
        mock_cve.references = [MagicMock(url="http://example.com")]
        mock_cve.configurations = [MagicMock(nodes=[MagicMock(cpeMatch=[MagicMock(vulnerable=True, criteria="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")])])]

        self.db.save_vulnerabilities([mock_cve], "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
        result = self.db.load_vulnerabilities_by_cpe("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
        self.assertIsNotNone(result)
        self.assertEqual(result["vulnerabilities"][0]["cve"]["id"], "CVE-2021-44228")

    def test_load_vulnerabilities(self):
        """Test loading all vulnerabilities."""
        mock_cve = MagicMock()
        mock_cve.id = "CVE-2021-44228"
        mock_cve.descriptions = [MagicMock(lang="en", value="Test vulnerability")]
        mock_cve.published = "2021-12-10T00:00:00.000"
        mock_cve.lastModified = "2021-12-15T00:00:00.000"
        mock_cve.metrics.cvssMetricV31 = [MagicMock(cvssData=MagicMock(baseScore=9.8, vectorString="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))]
        mock_cve.references = [MagicMock(url="http://example.com")]
        mock_cve.configurations = [MagicMock(nodes=[MagicMock(cpeMatch=[MagicMock(vulnerable=True, criteria="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")])])]

        self.db.save_vulnerabilities([mock_cve], "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
        result = self.db.load_vulnerabilities()
        self.assertIsNotNone(result)
        self.assertGreaterEqual(len(result["vulnerabilities"]), 1)

    def test_is_data_fresh(self):
        """Test data freshness check."""
        mock_cve = MagicMock()
        mock_cve.id = "CVE-2021-44228"
        mock_cve.descriptions = [MagicMock(lang="en", value="Test vulnerability")]
        mock_cve.published = "2021-12-10T00:00:00.000"
        mock_cve.lastModified = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")
        mock_cve.metrics.cvssMetricV31 = [MagicMock(cvssData=MagicMock(baseScore=9.8, vectorString="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))]
        mock_cve.references = [MagicMock(url="http://example.com")]
        mock_cve.configurations = [MagicMock(nodes=[MagicMock(cpeMatch=[MagicMock(vulnerable=True, criteria="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")])])]

        self.db.save_vulnerabilities([mock_cve], "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
        self.assertTrue(self.db.is_data_fresh("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"))

    def test_load_vulnerabilities_by_cpe_empty(self):
        """Test loading vulnerabilities for non-existent CPE."""
        result = self.db.load_vulnerabilities_by_cpe("cpe:2.3:a:unknown:unknown:*:*:*:*:*:*:*")
        self.assertEqual(result["vulnerabilities"], [])


if __name__ == '__main__':
    unittest.main()