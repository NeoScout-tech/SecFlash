"""Модуль для работы с базой данных уязвимостей."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Dict, Any
from sqlalchemy import create_engine, Column, Integer, String, DateTime, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

Base = declarative_base()

class Vulnerability(Base):
    """Модель уязвимости в базе данных."""
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True)
    cve_id = Column(String, unique=True, nullable=False)
    cpe_name = Column(String, nullable=False)
    description = Column(String)
    severity = Column(String)
    cvss_score = Column(String)
    published_date = Column(DateTime)
    last_modified_date = Column(DateTime)
    raw_data = Column(JSON)

@dataclass
class DatabaseConfig:
    """Конфигурация базы данных."""
    url: str
    echo: bool = False

class DatabaseError(Exception):
    """Базовый класс для ошибок базы данных."""
    pass

class BaseDatabase(ABC):
    """Абстрактный базовый класс для работы с базой данных."""
    
    @abstractmethod
    def save_vulnerability(self, vulnerability: Dict[str, Any]) -> None:
        """Сохранить уязвимость в базу данных."""
        pass
    
    @abstractmethod
    def get_vulnerability(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Получить уязвимость по CVE ID."""
        pass
    
    @abstractmethod
    def get_vulnerabilities_by_cpe(self, cpe_name: str) -> List[Dict[str, Any]]:
        """Получить все уязвимости для указанного CPE."""
        pass

class SQLAlchemyDatabase(BaseDatabase):
    """Реализация базы данных на SQLAlchemy."""

    def __init__(self, config: DatabaseConfig):
        self.engine = create_engine(config.url, echo=config.echo)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def _create_session(self) -> Session:
        """Создать новую сессию базы данных."""
        return self.Session()

    def save_vulnerability(self, vulnerability: Dict[str, Any]) -> None:
        """
        Сохранить уязвимость в базу данных.

        Args:
            vulnerability: Данные уязвимости

        Raises:
            DatabaseError: При ошибке сохранения
        """
        try:
            with self._create_session() as session:
                vuln = Vulnerability(
                    cve_id=vulnerability["cve"]["id"],
                    cpe_name=vulnerability["cpe_name"],
                    description=vulnerability["cve"]["descriptions"][0]["value"],
                    severity=vulnerability.get("severity"),
                    cvss_score=vulnerability.get("cvss_score"),
                    published_date=datetime.fromisoformat(vulnerability["published"]),
                    last_modified_date=datetime.fromisoformat(vulnerability["lastModified"]),
                    raw_data=vulnerability
                )
                session.merge(vuln)
                session.commit()
        except Exception as e:
            raise DatabaseError(f"Ошибка при сохранении уязвимости: {str(e)}")

    def get_vulnerability(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Получить уязвимость по CVE ID.

        Args:
            cve_id: Идентификатор CVE

        Returns:
            Optional[Dict[str, Any]]: Данные уязвимости или None
        """
        with self._create_session() as session:
            vuln = session.query(Vulnerability).filter_by(cve_id=cve_id).first()
            return vuln.raw_data if vuln else None

    def get_vulnerabilities_by_cpe(self, cpe_name: str) -> List[Dict[str, Any]]:
        """
        Получить все уязвимости для указанного CPE.

        Args:
            cpe_name: CPE имя

        Returns:
            List[Dict[str, Any]]: Список уязвимостей
        """
        with self._create_session() as session:
            vulns = session.query(Vulnerability).filter_by(cpe_name=cpe_name).all()
            return [vuln.raw_data for vuln in vulns] 