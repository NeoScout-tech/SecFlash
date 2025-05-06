"""Модуль для анализа уязвимостей безопасности."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path

from .client import BaseNVDClient, NVDClient, NVDConfig
from .database import BaseDatabase, SQLAlchemyDatabase, DatabaseConfig
from .network import Network, NetworkParser
from .report import PDFReportGenerator, ReportConfig

@dataclass
class AnalyzerConfig:
    """Конфигурация анализатора уязвимостей."""
    nvd_api_key: str
    database_url: str
    min_cvss_score: float = 0.0
    max_results: int = 100
    output_dir: Path = Path("reports")

class AnalyzerError(Exception):
    """Базовый класс для ошибок анализатора."""
    pass

class BaseVulnerabilityAnalyzer(ABC):
    """Абстрактный базовый класс для анализатора уязвимостей."""
    
    @abstractmethod
    def analyze_cpe(self, cpe_name: str) -> List[Dict[str, Any]]:
        """Проанализировать уязвимости для указанного CPE."""
        pass
    
    @abstractmethod
    def get_vulnerability_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Получить детальную информацию об уязвимости."""
        pass
    
    @abstractmethod
    def analyze_network(self, network_data: Dict[str, Any]) -> List[Path]:
        """Проанализировать уязвимости в сети."""
        pass

class VulnerabilityAnalyzer(BaseVulnerabilityAnalyzer):
    """Реализация анализатора уязвимостей."""

    def __init__(self, config: AnalyzerConfig):
        self.config = config
        self.nvd_client = NVDClient(NVDConfig(api_key=config.nvd_api_key))
        self.database = SQLAlchemyDatabase(DatabaseConfig(url=config.database_url))
        self.network_parser = NetworkParser()
        self.report_generator = PDFReportGenerator(ReportConfig(output_dir=config.output_dir))

    def analyze_cpe(self, cpe_name: str) -> List[Dict[str, Any]]:
        """
        Проанализировать уязвимости для указанного CPE.

        Args:
            cpe_name: CPE имя для анализа

        Returns:
            List[Dict[str, Any]]: Список найденных уязвимостей

        Raises:
            AnalyzerError: При ошибке анализа
        """
        try:
            # Проверяем кэш в базе данных
            cached_vulns = self.database.get_vulnerabilities_by_cpe(cpe_name)
            if cached_vulns:
                return self._filter_vulnerabilities(cached_vulns)

            # Получаем новые данные от NVD
            vulnerabilities = self.nvd_client.get_vulnerabilities(cpe_name)
            
            # Сохраняем в базу данных
            for vuln in vulnerabilities:
                vuln["cpe_name"] = cpe_name
                self.database.save_vulnerability(vuln)

            return self._filter_vulnerabilities(vulnerabilities)

        except Exception as e:
            raise AnalyzerError(f"Ошибка при анализе CPE {cpe_name}: {str(e)}")

    def get_vulnerability_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Получить детальную информацию об уязвимости.

        Args:
            cve_id: Идентификатор CVE

        Returns:
            Optional[Dict[str, Any]]: Детальная информация об уязвимости
        """
        return self.database.get_vulnerability(cve_id)

    def analyze_network(self, network_data: Dict[str, Any]) -> List[Path]:
        """
        Проанализировать уязвимости в сети.

        Args:
            network_data: JSON данные о сети

        Returns:
            List[Path]: Список путей к сгенерированным отчетам

        Raises:
            AnalyzerError: При ошибке анализа
        """
        try:
            network = self.network_parser.parse_network(network_data)
            report_files = []

            # Создаем директорию для отчетов если её нет
            self.config.output_dir.mkdir(parents=True, exist_ok=True)

            # Анализируем каждый хост
            for host in network.hosts:
                host_vulnerabilities = []
                
                # Анализируем каждый сервис
                for service in host.services:
                    cpe = self.network_parser.extract_cpe(service)
                    if cpe:
                        vulns = self.analyze_cpe(cpe)
                        host_vulnerabilities.extend(vulns)

                if host_vulnerabilities:
                    # Генерируем отчет для хоста
                    report_path = self.config.output_dir / f"vuln_report_{host.ip}.pdf"
                    self.report_generator.generate_report(
                        host_vulnerabilities,
                        report_path
                    )
                    report_files.append(report_path)

            return report_files

        except Exception as e:
            raise AnalyzerError(f"Ошибка при анализе сети: {str(e)}")

    def _filter_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Отфильтровать уязвимости по заданным критериям.

        Args:
            vulnerabilities: Список уязвимостей для фильтрации

        Returns:
            List[Dict[str, Any]]: Отфильтрованный список уязвимостей
        """
        filtered = []
        for vuln in vulnerabilities:
            cvss_score = float(vuln.get("cvss_score", "0.0"))
            if cvss_score >= self.config.min_cvss_score:
                filtered.append(vuln)
                if len(filtered) >= self.config.max_results:
                    break
        return filtered 