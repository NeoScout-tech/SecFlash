"""Модуль для генерации отчетов об уязвимостях."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

@dataclass
class ReportConfig:
    """Конфигурация генератора отчетов."""
    output_dir: Path
    title: str = "Отчет об уязвимостях"
    logo_path: Optional[Path] = None

class ReportError(Exception):
    """Базовый класс для ошибок генерации отчетов."""
    pass

class BaseReportGenerator(ABC):
    """Абстрактный базовый класс для генератора отчетов."""
    
    @abstractmethod
    def generate_report(self, vulnerabilities: List[Dict[str, Any]], output_path: Path) -> None:
        """Сгенерировать отчет об уязвимостях."""
        pass

class PDFReportGenerator(BaseReportGenerator):
    """Реализация генератора отчетов в формате PDF."""

    def __init__(self, config: ReportConfig):
        self.config = config
        self.styles = getSampleStyleSheet()
        self._setup_styles()

    def _setup_styles(self) -> None:
        """Настроить стили для отчета."""
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Title'],
            fontSize=24,
            spaceAfter=30
        ))
        self.styles.add(ParagraphStyle(
            name='CustomHeading',
            parent=self.styles['Heading1'],
            fontSize=16,
            spaceAfter=12
        ))

    def generate_report(self, vulnerabilities: List[Dict[str, Any]], output_path: Path) -> None:
        """
        Сгенерировать отчет об уязвимостях в формате PDF.

        Args:
            vulnerabilities: Список уязвимостей
            output_path: Путь для сохранения отчета

        Raises:
            ReportError: При ошибке генерации отчета
        """
        try:
            doc = SimpleDocTemplate(
                str(output_path),
                pagesize=letter,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=72
            )

            story = []
            
            # Заголовок
            story.append(Paragraph(self.config.title, self.styles['CustomTitle']))
            story.append(Spacer(1, 12))
            
            # Дата генерации
            story.append(Paragraph(
                f"Дата генерации: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                self.styles['Normal']
            ))
            story.append(Spacer(1, 24))

            # Таблица уязвимостей
            if vulnerabilities:
                data = [['CVE ID', 'Описание', 'Серьезность', 'CVSS']]
                for vuln in vulnerabilities:
                    data.append([
                        vuln['cve']['id'],
                        vuln['cve']['descriptions'][0]['value'][:100] + '...',
                        vuln.get('severity', 'N/A'),
                        vuln.get('cvss_score', 'N/A')
                    ])

                table = Table(data, colWidths=[100, 300, 100, 100])
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 14),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 1), (-1, -1), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                story.append(table)
            else:
                story.append(Paragraph("Уязвимости не найдены", self.styles['Normal']))

            doc.build(story)

        except Exception as e:
            raise ReportError(f"Ошибка при генерации отчета: {str(e)}") 