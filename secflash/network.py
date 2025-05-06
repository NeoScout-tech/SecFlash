"""Модуль для работы с сетевыми данными."""

from dataclasses import dataclass
from datetime import datetime
from typing import List, Dict, Any, Optional
import re

@dataclass
class NetworkHost:
    """Информация о хосте в сети."""
    ip: str
    status: str
    ports: List[int]
    services: List[str]
    time: datetime

@dataclass
class Network:
    """Информация о сети."""
    location: str
    hosts: List[NetworkHost]

class NetworkParser:
    """Парсер сетевых данных."""

    @staticmethod
    def parse_version(service: str) -> Optional[str]:
        """
        Извлечь версию из строки сервиса.
        
        Args:
            service: Строка с информацией о сервисе
            
        Returns:
            Optional[str]: Версия сервиса или None
        """
        version_pattern = r'(\d+\.\d+(?:\.\d+)?(?:[a-zA-Z0-9._-]+)?)'
        match = re.search(version_pattern, service)
        return match.group(1) if match else None

    @staticmethod
    def parse_network(data: Dict[str, Any]) -> Network:
        """
        Преобразовать JSON данные в объект Network.
        
        Args:
            data: JSON данные о сети
            
        Returns:
            Network: Объект с информацией о сети
        """
        hosts = []
        for host_data in data["hosts"]:
            host = NetworkHost(
                ip=host_data["ip"],
                status=host_data["status"],
                ports=host_data["ports"],
                services=host_data["services"],
                time=datetime.strptime(host_data["time"], "%Y-%m-%d %H:%M:%S")
            )
            hosts.append(host)
        
        return Network(
            location=data["location"],
            hosts=hosts
        )

    @staticmethod
    def extract_cpe(service: str) -> Optional[str]:
        """
        Преобразовать информацию о сервисе в CPE.
        
        Args:
            service: Строка с информацией о сервисе
            
        Returns:
            Optional[str]: CPE строка или None
        """
        # Базовая реализация, можно расширить для поддержки большего количества сервисов
        service = service.lower()
        version = NetworkParser.parse_version(service)
        
        if not version:
            return None
            
        if "windows" in service:
            return f"cpe:2.3:o:microsoft:windows:{version}:*:*:*:*:*:*:*:*"
        elif "apache" in service:
            return f"cpe:2.3:a:apache:http_server:{version}:*:*:*:*:*:*:*:*"
        elif "openssl" in service:
            return f"cpe:2.3:a:openssl:openssl:{version}:*:*:*:*:*:*:*:*"
        elif "openssh" in service:
            return f"cpe:2.3:a:openssh:openssh:{version}:*:*:*:*:*:*:*:*"
        elif "mysql" in service:
            return f"cpe:2.3:a:mysql:mysql:{version}:*:*:*:*:*:*:*:*"
        elif "php" in service:
            return f"cpe:2.3:a:php:php:{version}:*:*:*:*:*:*:*:*"
        elif "wordpress" in service:
            return f"cpe:2.3:a:wordpress:wordpress:{version}:*:*:*:*:*:*:*:*"
        elif "tomcat" in service:
            return f"cpe:2.3:a:apache:tomcat:{version}:*:*:*:*:*:*:*:*"
        elif "java" in service:
            return f"cpe:2.3:a:oracle:jre:{version}:*:*:*:*:*:*:*:*"
        elif "nginx" in service:
            return f"cpe:2.3:a:nginx:nginx:{version}:*:*:*:*:*:*:*:*"
            
        return None 