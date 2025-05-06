import os
import time
import nvdlib
import logging
from typing import List, Optional
from time import sleep

import requests

# Настраиваем логирование
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class NVDClient:
    def __init__(self):
        self.api_key = os.getenv("NVD_API_KEY", "4b2f74a1-296c-4146-a937-6994ca3b17c9")
        if not self.api_key:
            logging.warning("API-ключ NVD не установлен в NVDClient.")
        else:
            logging.info(f"Используется API-ключ: {self.api_key[:8]}...")

    def download_vulnerabilities_by_cpe(self, cpe: str) -> List:
        retries = 3
        for attempt in range(retries):
            try:
                logging.info(f"Запрос данных NVD для CPE: {cpe}")
                vulns = nvdlib.searchCVE(cpeName=cpe, key=self.api_key, delay=0.6)
                logging.info(f"Загружено {len(vulns)} уязвимостей для CPE {cpe}")
                return vulns
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 404:
                    logging.warning(f"Нет уязвимостей для CPE {cpe}")
                    return []
                if e.response.status_code in [429, 403]:
                    logging.warning(f"Превышен лимит, повтор через {2 ** attempt} секунд...")
                    time.sleep(2 ** attempt)
                    continue
                logging.error(f"Ошибка при скачивании данных NVD для CPE {cpe}: {str(e)}")
                return []
            except Exception as e:
                logging.error(f"Ошибка при скачивании данных NVD для CPE {cpe}: {str(e)}")
                return []
        logging.error(f"Не удалось получить данные после {retries} попыток для CPE {cpe}")
        return []