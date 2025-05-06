import os

# API-ключ для NVD
os.environ['NVD_API_KEY'] = '4b2f74a1-296c-4146-a937-6994ca3b17c9'

# Пути к файлам
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
NVD_DB_PATH = os.path.join(BASE_DIR, 'nvd_data.db')
LOGO_PATH = os.path.join(BASE_DIR, 'logo.png')
FONT_DIR = os.path.join(BASE_DIR, 'fonts')

# Константы
RESULTS_PER_PAGE = 2000  # Ограничение на количество результатов за запрос
DATA_FRESHNESS_DAYS = 7  # Срок актуальности данных (в днях)