import sqlite3
import json
from datetime import datetime
import logging
from typing import List, Optional

from config import NVD_DB_PATH, DATA_FRESHNESS_DAYS

# Настраиваем логирование
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Адаптеры для SQLite
def adapt_datetime(dt):
    return dt.isoformat()

def convert_datetime(s):
    return datetime.fromisoformat(s.decode('utf-8'))

sqlite3.register_adapter(datetime, adapt_datetime)
sqlite3.register_converter('TIMESTAMP', convert_datetime)

class NVDDatabase:
    def __init__(self):
        self.db_path = NVD_DB_PATH
        self._init_db()

    def _init_db(self):
        """Инициализация базы данных NVD"""
        try:
            with sqlite3.connect(self.db_path, detect_types=sqlite3.PARSE_DECLTYPES) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS nvd_metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT,
                        last_updated TIMESTAMP
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS vulnerabilities (
                        cve_id TEXT PRIMARY KEY,
                        cpe TEXT,
                        description TEXT,
                        published TEXT,
                        last_modified TEXT,
                        cvss_score REAL,
                        cvss_vector TEXT,
                        severity TEXT,
                        refs TEXT,
                        cpe_match TEXT
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_cvss_score ON vulnerabilities(cvss_score)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_severity ON vulnerabilities(severity)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_cpe ON vulnerabilities(cpe)")
                
                cursor = conn.execute("SELECT value FROM nvd_metadata WHERE key = 'last_update'")
                if not cursor.fetchone():
                    conn.execute(
                        "INSERT INTO nvd_metadata (key, value, last_updated) VALUES (?, ?, ?)",
                        ("last_update", "", datetime.now())
                    )
                
                conn.commit()
        except Exception as e:
            logging.error(f"Ошибка инициализации базы данных NVD: {str(e)}")

    def _serialize_configurations(self, configurations: List) -> str:
        """Кастомная сериализация конфигураций для JSON"""
        serialized = []
        for config in configurations:
            config_data = {
                "nodes": []
            }
            for node in config.nodes:
                node_data = {
                    "operator": node.operator,
                    "negate": node.negate,
                    "cpeMatch": []
                }
                for match in node.cpeMatch:
                    match_data = {
                        "vulnerable": match.vulnerable,
                        "criteria": match.criteria,
                        "matchCriteriaId": match.matchCriteriaId
                    }
                    node_data["cpeMatch"].append(match_data)
                config_data["nodes"].append(node_data)
            serialized.append(config_data)
        return json.dumps(serialized)

    def save_vulnerabilities(self, vulnerabilities: List, cpe: str):
        """Сохранение уязвимостей в базу данных"""
        try:
            with sqlite3.connect(self.db_path, detect_types=sqlite3.PARSE_DECLTYPES) as conn:
                for cve_obj in vulnerabilities:
                    cve_id = cve_obj.id
                    description = next((d.value for d in cve_obj.descriptions if d.lang == "en"), "")
                    published = cve_obj.published
                    last_modified = cve_obj.lastModified
                    
                    cvss_data = None
                    cvss_score = None
                    cvss_vector = None
                    severity = "Unknown"

                    # Проверяем структуру metrics
                    if hasattr(cve_obj, 'metrics'):
                        if hasattr(cve_obj.metrics, 'cvssMetricV31') and cve_obj.metrics.cvssMetricV31:
                            cvss_data = cve_obj.metrics.cvssMetricV31[0].cvssData
                        elif hasattr(cve_obj.metrics, 'cvssMetricV30') and cve_obj.metrics.cvssMetricV30:
                            cvss_data = cve_obj.metrics.cvssMetricV30[0].cvssData
                        elif hasattr(cve_obj.metrics, 'cvssMetricV2') and cve_obj.metrics.cvssMetricV2:
                            cvss_data = cve_obj.metrics.cvssMetricV2[0].cvssData
                    else:
                        logging.warning(f"Неожиданный формат metrics для CVE {cve_id}: {cve_obj.metrics}")

                    if cvss_data:
                        cvss_score = cvss_data.baseScore
                        cvss_vector = cvss_data.vectorString
                        if cvss_score >= 9.0:
                            severity = "Critical"
                        elif cvss_score >= 7.0:
                            severity = "High"
                        elif cvss_score >= 4.0:
                            severity = "Medium"
                        else:
                            severity = "Low"
                    
                    refs = json.dumps([r.url for r in cve_obj.references])
                    cpe_match = self._serialize_configurations(cve_obj.configurations)
                    
                    conn.execute("""
                        INSERT OR REPLACE INTO vulnerabilities 
                        (cve_id, cpe, description, published, last_modified, cvss_score, 
                         cvss_vector, severity, refs, cpe_match)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        cve_id, cpe, description, published, last_modified,
                        cvss_score, cvss_vector, severity, refs, cpe_match
                    ))
                
                conn.execute(
                    "UPDATE nvd_metadata SET value = ?, last_updated = ? WHERE key = 'last_update'",
                    (datetime.now().isoformat(), datetime.now())
                )
                
                conn.commit()
                logging.info(f"Сохранено {len(vulnerabilities)} уязвимостей для CPE {cpe}")
        except Exception as e:
            logging.error(f"Ошибка сохранения уязвимостей: {str(e)}")
            raise

    def load_vulnerabilities_by_cpe(self, cpe: str) -> Optional[dict]:
        """Загрузка уязвимостей из базы данных по CPE"""
        try:
            with sqlite3.connect(self.db_path, detect_types=sqlite3.PARSE_DECLTYPES) as conn:
                cursor = conn.execute("""
                    SELECT cve_id, description, published, last_modified, 
                           cvss_score, cvss_vector, severity, refs, cpe_match
                    FROM vulnerabilities
                    WHERE cpe = ?
                """, (cpe,))
                
                vulnerabilities = []
                for row in cursor.fetchall():
                    vulnerabilities.append({
                        "cve": {
                            "id": row[0],
                            "descriptions": [{"lang": "en", "value": row[1]}],
                            "published": row[2],
                            "lastModified": row[3],
                            "metrics": {
                                "cvssMetricV31": [{
                                    "cvssData": {
                                        "baseScore": row[4],
                                        "vectorString": row[5]
                                    }
                                }] if row[4] is not None else []
                            },
                            "references": [{"url": url} for url in json.loads(row[7])],
                            "configurations": json.loads(row[8])
                        }
                    })
                
                return {"vulnerabilities": vulnerabilities}
        except Exception as e:
            logging.error(f"Ошибка загрузки уязвимостей для CPE {cpe}: {str(e)}")
            return None

    def load_vulnerabilities(self) -> Optional[dict]:
        """Загрузка всех уязвимостей из базы данных"""
        try:
            with sqlite3.connect(self.db_path, detect_types=sqlite3.PARSE_DECLTYPES) as conn:
                cursor = conn.execute("""
                    SELECT cve_id, description, published, last_modified, 
                           cvss_score, cvss_vector, severity, refs, cpe_match
                    FROM vulnerabilities
                """)
                
                vulnerabilities = []
                for row in cursor.fetchall():
                    vulnerabilities.append({
                        "cve": {
                            "id": row[0],
                            "descriptions": [{"lang": "en", "value": row[1]}],
                            "published": row[2],
                            "lastModified": row[3],
                            "metrics": {
                                "cvssMetricV31": [{
                                    "cvssData": {
                                        "baseScore": row[4],
                                        "vectorString": row[5]
                                    }
                                }] if row[4] is not None else []
                            },
                            "references": [{"url": url} for url in json.loads(row[7])],
                            "configurations": json.loads(row[8])
                        }
                    })
                
                return {"vulnerabilities": vulnerabilities}
        except Exception as e:
            logging.error(f"Ошибка загрузки уязвимостей из базы: {str(e)}")
            return None

    def is_data_fresh(self) -> bool:
        """Проверка актуальности данных"""
        try:
            with sqlite3.connect(self.db_path, detect_types=sqlite3.PARSE_DECLTYPES) as conn:
                cursor = conn.execute(
                    "SELECT value, last_updated FROM nvd_metadata WHERE key = 'last_update'"
                )
                row = cursor.fetchone()
                if row and row[0]:
                    last_update = datetime.fromisoformat(row[0])
                    return (datetime.now() - last_update).days < DATA_FRESHNESS_DAYS
                return False
        except Exception as e:
            logging.error(f"Ошибка проверки актуальности данных: {str(e)}")
            return False