"""
Configuration settings for the SecFlash library.
"""

import os
from importlib import resources


class Config:
    """Configuration class for SecFlash library."""
    def __init__(self):
        self.NVD_API_KEY = os.getenv('NVD_API_KEY')
        self.NVD_DB_PATH = os.path.join(os.path.expanduser("~"), '.secflash', 'nvd_data.db')
        with resources.as_file(resources.files('secflash') / 'resources' / 'fonts') as font_dir:
            self.FONT_DIR = str(font_dir)
        with resources.as_file(resources.files('secflash') / 'resources' / 'logo.png') as logo_path:
            self.LOGO_PATH = str(logo_path)
        self.RESULTS_PER_PAGE = 2000
        self.DATA_FRESHNESS_DAYS = 7
        os.makedirs(os.path.dirname(self.NVD_DB_PATH), exist_ok=True)


config = Config()