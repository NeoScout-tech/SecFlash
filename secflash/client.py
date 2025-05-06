"""NVD API клиент для получения данных об уязвимостях."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, List, Optional, Any
import requests
from requests.exceptions import RequestException

@dataclass
class NVDConfig:
    """Конфигурация для NVD клиента."""
    api_key: str
    base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    timeout: int = 30

class NVDClientError(Exception):
    """Базовый класс для ошибок NVD клиента."""
    pass

class NVDRequestError(NVDClientError):
    """Ошибка при выполнении запроса к NVD API."""
    pass

class NVDResponseError(NVDClientError):
    """Ошибка при обработке ответа от NVD API."""
    pass

class BaseNVDClient(ABC):
    """Абстрактный базовый класс для NVD клиента."""
    
    @abstractmethod
    def get_vulnerabilities(self, cpe_name: str) -> List[Dict[str, Any]]:
        """Получить уязвимости для указанного CPE."""
        pass

class NVDClient(BaseNVDClient):
    """Реализация клиента для работы с NVD API."""

    def __init__(self, config: NVDConfig):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            "apiKey": config.api_key,
            "Content-Type": "application/json"
        })

    def get_vulnerabilities(self, cpe_name: str) -> List[Dict[str, Any]]:
        """
        Получить уязвимости для указанного CPE.

        Args:
            cpe_name: CPE имя для поиска уязвимостей

        Returns:
            List[Dict[str, Any]]: Список уязвимостей

        Raises:
            NVDRequestError: При ошибке запроса
            NVDResponseError: При ошибке обработки ответа
        """
        try:
            params = {
                "cpeName": cpe_name,
                "resultsPerPage": 100
            }
            
            response = self.session.get(
                self.config.base_url,
                params=params,
                timeout=self.config.timeout
            )
            response.raise_for_status()
            
            data = response.json()
            return data.get("vulnerabilities", [])
            
        except RequestException as e:
            raise NVDRequestError(f"Ошибка при запросе к NVD API: {str(e)}")
        except (KeyError, ValueError) as e:
            raise NVDResponseError(f"Ошибка при обработке ответа: {str(e)}") 