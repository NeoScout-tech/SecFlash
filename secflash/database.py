"""
Database management for storing and retrieving NVD vulnerability data.
"""

import sqlite3
import logging
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from .config import config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("database.log"),
        logging.StreamHandler()
    ]
)


class NVDDatabase:
    """Class for managing NVD vulnerability data in SQLite database."""
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path if db_path is not None else config.NVD_DB_PATH
        self.conn = None
        self._initialize_database()

    def _connect_db(self) -> sqlite3.Connection:
        """Connect to the SQLite database."""
        if self.conn is None:
            try:
                self.conn = sqlite3.connect(self.db_path)
                return self.conn
            except sqlite3.Error as e:
                logging.error(f"Failed to connect to database: {str(e)}")
                raise
        return self.conn

    def _initialize_database(self):
        """Initialize the SQLite database."""
        try:
            logging.info(f"Initializing database at {self.db_path}")
            conn = self._connect_db()
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    cve_id TEXT,
                    cpe TEXT,
                    description TEXT,
                    published TEXT,
                    last_modified TEXT,
                    cvss_score REAL,
                    cvss_vector TEXT,
                    vuln_references TEXT,
                    configurations TEXT,
                    PRIMARY KEY (cve_id, cpe)
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_cpe ON vulnerabilities(cpe)")
            conn.commit()
            logging.info("Database initialized successfully")
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='vulnerabilities'")
            if cursor.fetchone():
                logging.info("Vulnerabilities table exists")
            else:
                logging.error("Vulnerabilities table was not created")
        except sqlite3.Error as e:
            logging.error(f"Failed to initialize database: {str(e)}")
            raise

    def save_vulnerabilities(self, cves: List[Any], cpe: str):
        """Save vulnerabilities to the database."""
        try:
            conn = self._connect_db()
            cursor = conn.cursor()
            saved_count = 0
            for cve in cves:
                description = next((desc.value for desc in cve.descriptions if desc.lang == "en"), "No description")
                cvss_score = None
                cvss_vector = None
                try:
                    if hasattr(cve, 'metrics'):
                        if hasattr(cve.metrics, 'cvssMetricV31') and cve.metrics.cvssMetricV31:
                            cvss_score = cve.metrics.cvssMetricV31[0].cvssData.baseScore
                            cvss_vector = cve.metrics.cvssMetricV31[0].cvssData.vectorString
                        elif hasattr(cve.metrics, 'cvssMetricV30') and cve.metrics.cvssMetricV7:
                            cvss_score = cve.metrics.cvssMetricV30[0].cvssData.baseScore
                            cvss_vector = cve.metrics.cvssMetricV30[0].cvssData.vectorString
                        elif hasattr(cve.metrics, 'cvssMetricV2') and cve.metrics.cvssMetricV2:
                            cvss_score = cve.metrics.cvssMetricV2[0].baseScore
                            cvss_vector = cve.metrics.cvssMetricV2[0].vectorString
                        else:
                            logging.warning(f"No CVSS metrics found for CVE {cve.id}")
                    else:
                        logging.warning(f"No metrics attribute for CVE {cve.id}")
                except Exception as e:
                    logging.error(f"Error extracting CVSS for CVE {cve.id}: {str(e)}")
                    continue  # Skip this CVE if CVSS extraction fails

                references = json.dumps([ref.url for ref in cve.references])
                configurations = json.dumps([
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "vulnerable": match.vulnerable,
                                        "criteria": match.criteria
                                    } for match in node.cpeMatch if hasattr(match, 'vulnerable') and hasattr(match, 'criteria')
                                ]
                            } for node in config.nodes if hasattr(node, 'cpeMatch')
                        ]
                    } for config in cve.configurations if hasattr(config, 'nodes')
                ])

                cursor.execute("""
                    INSERT OR REPLACE INTO vulnerabilities (
                        cve_id, cpe, description, published, last_modified,
                        cvss_score, cvss_vector, vuln_references, configurations
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    cve.id,
                    cpe,
                    description,
                    cve.published,
                    cve.lastModified,
                    cvss_score,
                    cvss_vector,
                    references,
                    configurations
                ))
                saved_count += 1
            conn.commit()
            logging.info(f"Saved {saved_count} vulnerabilities for CPE {cpe}")
        except sqlite3.Error as e:
            logging.error(f"Failed to save vulnerabilities: {str(e)}")
            raise

    def load_vulnerabilities(self) -> Dict[str, Any]:
        """Load all vulnerabilities from the database."""
        try:
            conn = self._connect_db()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM vulnerabilities")
            rows = cursor.fetchall()
            vulnerabilities = []
            for row in rows:
                vuln = {
                    "cve": {
                        "id": row[0],
                        "description": row[2],
                        "published": row[3],
                        "lastModified": row[4],
                        "cvss": {
                            "score": row[5],
                            "vector": row[6]
                        },
                        "references": json.loads(row[7]) if row[7] else [],
                        "configurations": json.loads(row[8]) if row[8] else []
                    },
                    "cpe": row[1]
                }
                vulnerabilities.append(vuln)
            return {"vulnerabilities": vulnerabilities}
        except sqlite3.Error as e:
            logging.error(f"Failed to load vulnerabilities: {str(e)}")
            return {"vulnerabilities": []}

    def load_vulnerabilities_by_cpe(self, cpe: str) -> Dict[str, Any]:
        """Load vulnerabilities for a specific CPE."""
        try:
            conn = self._connect_db()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM vulnerabilities WHERE cpe = ?", (cpe,))
            rows = cursor.fetchall()
            vulnerabilities = []
            for row in rows:
                vuln = {
                    "cve": {
                        "id": row[0],
                        "description": row[2],
                        "published": row[3],
                        "lastModified": row[4],
                        "cvss": {
                            "score": row[5],
                            "vector": row[6]
                        },
                        "references": json.loads(row[7]) if row[7] else [],
                        "configurations": json.loads(row[8]) if row[8] else []
                    },
                    "cpe": row[1]
                }
                vulnerabilities.append(vuln)
            return {"vulnerabilities": vulnerabilities}
        except sqlite3.Error as e:
            logging.error(f"Failed to load vulnerabilities for CPE {cpe}: {str(e)}")
            return {"vulnerabilities": []}

    def is_data_fresh(self, cpe: str) -> bool:
        """Check if data for a CPE is fresh."""
        try:
            conn = self._connect_db()
            cursor = conn.cursor()
            cursor.execute("SELECT last_modified FROM vulnerabilities WHERE cpe = ? LIMIT 1", (cpe,))
            row = cursor.fetchone()
            if not row:
                return False
            last_modified = datetime.strptime(row[0], "%Y-%m-%dT%H:%M:%S.%f")
            freshness_threshold = datetime.now() - timedelta(days=config.DATA_FRESHNESS_DAYS)
            return last_modified >= freshness_threshold
        except sqlite3.Error as e:
            logging.error(f"Failed to check data freshness for CPE {cpe}: {str(e)}")
            return False

    def __del__(self):
        """Close the database connection when the object is destroyed."""
        if self.conn:
            self.conn.close()