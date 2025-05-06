# SecFlash

Библиотека для анализа уязвимостей безопасности программного обеспечения.

## Установка

```bash
poetry add secflash
```

## Использование

```python
from secflash import VulnerabilityAnalyzer, AnalyzerConfig, PDFReportGenerator, ReportConfig
from pathlib import Path

# Конфигурация анализатора
config = AnalyzerConfig(
    nvd_api_key="your-api-key",
    database_url="sqlite:///vulnerabilities.db",
    min_cvss_score=5.0
)

# Создание анализатора
analyzer = VulnerabilityAnalyzer(config)

# Анализ уязвимостей
vulnerabilities = analyzer.analyze_cpe("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*:*")

# Генерация отчета
report_config = ReportConfig(
    output_dir=Path("reports"),
    title="Отчет об уязвимостях Windows 10"
)
report_generator = PDFReportGenerator(report_config)
report_generator.generate_report(vulnerabilities, Path("reports/windows10_vulns.pdf"))
```

## Основные компоненты

- `VulnerabilityAnalyzer` - основной класс для анализа уязвимостей
- `NVDClient` - клиент для работы с NVD API
- `SQLAlchemyDatabase` - работа с базой данных
- `PDFReportGenerator` - генерация отчетов в PDF

## Требования

- Python 3.8+
- Poetry для управления зависимостями

## Лицензия

MIT