import os
from reportlab.lib.pagesizes import letter, A5
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import logging
from typing import Dict, List
from datetime import datetime

# Настраиваем логирование
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ReportGenerator:
    def __init__(self):
        # Регистрация шрифтов DejaVuSans
        try:
            font_dir = os.path.join(os.path.dirname(__file__), 'fonts')
            font_path = os.path.join(font_dir, 'DejaVuSans.ttf')
            font_bold_path = os.path.join(font_dir, 'DejaVuSans-Bold.ttf')
            if os.path.exists(font_path) and os.path.exists(font_bold_path):
                pdfmetrics.registerFont(TTFont('DejaVuSans', font_path))
                pdfmetrics.registerFont(TTFont('DejaVuSans-Bold', font_bold_path))
                self.font_name = 'DejaVuSans'
                self.font_bold = 'DejaVuSans-Bold'
                logging.info("Шрифты DejaVuSans успешно загружены")
            else:
                logging.warning("Шрифты DejaVuSans не найдены, используется Helvetica")
                self.font_name = 'Helvetica'
                self.font_bold = 'Helvetica-Bold'
        except Exception as e:
            logging.error(f"Ошибка загрузки шрифтов: {str(e)}")
            self.font_name = 'Helvetica'
            self.font_bold = 'Helvetica-Bold'

        # Инициализация стилей
        self.styles = getSampleStyleSheet()
        custom_styles = {
            'ReportTitle': {
                'fontSize': 14,
                'alignment': 1,
                'spaceAfter': 8,
                'fontName': self.font_bold,
                'textColor': colors.black
            },
            'ReportSubTitle': {
                'fontSize': 10,
                'alignment': 1,
                'spaceAfter': 8,
                'fontName': self.font_name,
                'textColor': colors.black
            },
            'ReportHeading1': {
                'fontSize': 12,
                'spaceAfter': 4,
                'fontName': self.font_bold,
                'textColor': colors.black
            },
            'ReportHeading2': {
                'fontSize': 10,
                'spaceAfter': 4,
                'fontName': self.font_bold,
                'textColor': colors.black
            },
            'ReportBodyText': {
                'fontSize': 8,
                'spaceAfter': 4,
                'fontName': self.font_name,
                'textColor': colors.black
            },
            'ReportWhiteText': {
                'fontSize': 8,
                'spaceAfter': 4,
                'fontName': self.font_name,
                'textColor': colors.whitesmoke
            },
            'ReportConclusionText': {
                'fontSize': 10,
                'spaceAfter': 4,
                'fontName': self.font_name,
                'textColor': colors.black
            },
            'ReportWhiteConclusionText': {
                'fontSize': 10,
                'spaceAfter': 4,
                'fontName': self.font_name,
                'textColor': colors.whitesmoke
            },
            'ReportCritical': {
                'fontSize': 8,
                'textColor': colors.red,
                'backColor': colors.mistyrose,
                'fontName': self.font_name
            },
            'ReportHigh': {
                'fontSize': 8,
                'textColor': colors.orangered,
                'backColor': colors.mistyrose,
                'fontName': self.font_name
            },
            'ReportMedium': {
                'fontSize': 8,
                'textColor': colors.orange,
                'backColor': colors.lemonchiffon,
                'fontName': self.font_name
            },
            'ReportLow': {
                'fontSize': 8,
                'textColor': colors.green,
                'backColor': colors.honeydew,
                'fontName': self.font_name
            },
            'ReportBullet': {
                'fontSize': 10,
                'leftIndent': 12,
                'spaceAfter': 4,
                'fontName': self.font_name,
                'textColor': colors.black,
                'bulletIndent': 6,
                'bulletFontSize': 10
            },
            'ReportWhiteBullet': {
                'fontSize': 10,
                'leftIndent': 12,
                'spaceAfter': 4,
                'fontName': self.font_name,
                'textColor': colors.whitesmoke,
                'bulletIndent': 6,
                'bulletFontSize': 10
            }
        }
        for style_name, style_params in custom_styles.items():
            self.styles.add(ParagraphStyle(name=style_name, **style_params))

        self.logo_path = os.path.join(os.path.dirname(__file__), 'logo.png')

    def _add_title_page(self, story: List, network_data: Dict, use_gradient: bool = False, white_text: bool = False, booklet: bool = False):
        def add_gradient(canvas, doc):
            canvas.saveState()
            canvas.setFillColor(colors.HexColor("#000000"))
            canvas.rect(0, 0, doc.pagesize[0], doc.pagesize[1], fill=1, stroke=0)
            canvas.setFillColor(colors.HexColor("#00a9b8"))
            canvas.setFillAlpha(0.2)
            canvas.rect(0, 0, doc.pagesize[0], doc.pagesize[1], fill=1, stroke=0)
            canvas.restoreState()

        def add_white_background(canvas, doc):
            canvas.saveState()
            canvas.setFillColor(colors.white)
            canvas.rect(0, 0, doc.pagesize[0], doc.pagesize[1], fill=1, stroke=0)
            canvas.restoreState()

        text_style = 'ReportWhiteText' if white_text else 'ReportBodyText'

        if os.path.exists(self.logo_path):
            logo_size = 0.8*inch if booklet else 1*inch
            logo = Image(self.logo_path, width=logo_size, height=logo_size)
            logo.hAlign = 'RIGHT'
            story.append(logo)
            story.append(Spacer(1, 0.15*inch if booklet else 0.2*inch))

        title_style = 'ReportTitle'
        if white_text:
            self.styles['ReportTitle'].textColor = colors.whitesmoke
            self.styles['ReportSubTitle'].textColor = colors.whitesmoke
        else:
            self.styles['ReportTitle'].textColor = colors.black
            self.styles['ReportSubTitle'].textColor = colors.black

        story.append(Paragraph("ОТЧЕТ ОБ АНАЛИЗЕ УЯЗВИМОСТЕЙ", self.styles[title_style]))
        story.append(Spacer(1, 0.3*inch if booklet else 0.5*inch))

        meta = [
            [Paragraph("Организация:", self.styles[text_style]), 
             Paragraph(network_data.get("location", "Не указана"), self.styles[text_style])],
            [Paragraph("Дата сканирования:", self.styles[text_style]), 
             Paragraph(network_data["hosts"][0]["time"] if network_data.get("hosts") else "Не указана", self.styles[text_style])],
            [Paragraph("Дата генерации отчета:", self.styles[text_style]), 
             Paragraph(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), self.styles[text_style])],
            [Paragraph("Сгенерировано:", self.styles[text_style]), 
             Paragraph("SecFlash Vulnerability Scanner", self.styles[text_style])]
        ]

        meta_table = Table(meta, colWidths=[1.2*inch if booklet else 1.5*inch, 3.2*inch if booklet else 4*inch])
        meta_table.setStyle(TableStyle([
            ('FONTNAME', (0,0), (-1,-1), self.font_name),
            ('FONTNAME', (0,0), (0,-1), self.font_bold),
            ('FONTSIZE', (0,0), (-1,-1), 9 if booklet else 11),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('ALIGN', (0,0), (0,-1), 'RIGHT'),
            ('ALIGN', (1,0), (1,-1), 'LEFT'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8 if booklet else 12),
            ('TOPPADDING', (0,0), (-1,-1), 4 if booklet else 6),
            ('TEXTCOLOR', (0,0), (-1,-1), colors.whitesmoke if white_text else colors.black),
        ]))

        story.append(meta_table)
        story.append(Spacer(1, 0.6*inch if booklet else 1*inch))
        story.append(Paragraph("Конфиденциально", self.styles[text_style]))
        story.append(Paragraph("Только для внутреннего использования", self.styles[text_style]))

        return add_gradient if use_gradient else add_white_background

    def _add_executive_summary(self, story: List, findings: List[Dict], network_data: Dict, white_text: bool = False, booklet: bool = False):
        text_style = 'ReportWhiteText' if white_text else 'ReportBodyText'
        heading_style = 'ReportHeading1'
        if white_text:
            self.styles['ReportHeading1'].textColor = colors.whitesmoke
        else:
            self.styles['ReportHeading1'].textColor = colors.black

        story.append(Paragraph("КРАТКОЕ СОДЕРЖАНИЕ", self.styles[heading_style]))

        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "N/A": 0}
        for f in findings:
            severity = f["severity"] if f["severity"] in severity_counts else "N/A"
            severity_counts[severity] += 1

        summary_text = (
            f"В ходе анализа сети было обнаружено <b>{len(findings)} уязвимостей</b> на "
            f"<b>{len([h for h in network_data.get('hosts', []) if h.get('status') == 'active'])} хостах</b>.\n\n"
            f"<b>Распределение по критичности:</b>\n"
            f"• <font color=red>Критические: {severity_counts['Critical']}</font>\n"
            f"• <font color=orangered>Высокие: {severity_counts['High']}</font>\n"
            f"• <font color=orange>Средние: {severity_counts['Medium']}</font>\n"
            f"• <font color=green>Низкие: {severity_counts['Low']}</font>\n"
            f"• Неизвестно (N/A): {severity_counts['N/A']}\n\n"
            f"<b>Наиболее опасные уязвимости:</b>\n"
        )

        top_critical = sorted(
            [f for f in findings if f["severity"] in ["Critical", "High"]],
            key=lambda x: float(x["cvss"]) if x["cvss"] != "N/A" else 0,
            reverse=True
        )[:3]

        for vuln in top_critical:
            summary_text += (
                f"• <b>{vuln['cve_id']}</b> ({vuln['service']} на {vuln['ip']}) - "
                f"CVSS: <font color={'red' if float(vuln['cvss']) >= 9.0 else 'orange'}>{vuln['cvss']}</font>\n"
            )

        if not top_critical:
            summary_text += "• Отсутствуют критические или высокие уязвимости\n"

        story.append(Paragraph(summary_text, self.styles[text_style]))
        story.append(Spacer(1, 0.15*inch if booklet else 0.25*inch))

    def _add_vulnerabilities_table(self, story: List, findings: List[Dict], white_text: bool = False, booklet: bool = False):
        heading_style = 'ReportHeading1'
        if white_text:
            self.styles['ReportHeading1'].textColor = colors.whitesmoke
        else:
            self.styles['ReportHeading1'].textColor = colors.black
        text_style = 'ReportWhiteText' if white_text else 'ReportBodyText'

        story.append(Paragraph("ДЕТАЛЬНЫЙ ОТЧЕТ ОБ УЯЗВИМОСТЯХ", self.styles[heading_style]))
        story.append(Spacer(1, 0.15*inch if booklet else 0.2*inch))

        if not findings:
            story.append(Paragraph("Уязвимости не обнаружены", self.styles[text_style]))
            return

        vuln_data = [["IP", "Порты", "Сервис", "CVE ID", "Крит.", "CVSS", "Описание"]]
        for finding in findings:
            max_desc_length = 150 if booklet else 200
            description = finding["description"]
            if len(description) > max_desc_length:
                description = description[:max_desc_length] + "..."

            vuln_data.append([
                Paragraph(finding["ip"], self.styles["ReportBodyText"]),
                Paragraph(", ".join(map(str, finding["ports"])), self.styles["ReportBodyText"]),
                Paragraph(finding["service"], self.styles["ReportBodyText"]),
                Paragraph(finding["cve_id"], self.styles["ReportBodyText"]),
                self._get_severity_paragraph(finding["severity"]),
                Paragraph(str(finding["cvss"]), self.styles["ReportBodyText"]),
                Paragraph(description, self.styles["ReportBodyText"])
            ])

        colWidths = (
            [0.5*inch, 0.4*inch, 1.0*inch, 0.7*inch, 0.4*inch, 0.4*inch, 1.6*inch] if booklet
            else [0.6*inch, 0.5*inch, 1.2*inch, 0.8*inch, 0.5*inch, 0.5*inch, 2.0*inch]
        )

        vuln_table = Table(
            vuln_data,
            colWidths=colWidths,
            repeatRows=1,
            splitByRow=1,
            splitInRow=0
        )

        vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#003366")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,0), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), self.font_bold),
            ('FONTSIZE', (0,0), (-1,0), 6 if booklet else 7),
            ('BOTTOMPADDING', (0,0), (-1,0), 3 if booklet else 4),
            ('BACKGROUND', (0,1), (-1,-1), colors.beige),
            ('GRID', (0,0), (-1,-1), 1, colors.black),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('ALIGN', (0,1), (3,-1), 'LEFT'),
            ('ALIGN', (4,1), (4,-1), 'CENTER'),
            ('ALIGN', (5,1), (5,-1), 'CENTER'),
            ('FONTNAME', (0,1), (-1,-1), self.font_name),
            ('FONTSIZE', (0,1), (-1,-1), 5 if booklet else 6),
            ('LEFTPADDING', (0,1), (-1,-1), 1 if booklet else 2),
            ('RIGHTPADDING', (0,1), (-1,-1), 1 if booklet else 2),
            ('BOTTOMPADDING', (0,1), (-1,-1), 1 if booklet else 2),
            ('TOPPADDING', (0,1), (-1,-1), 1 if booklet else 2),
            ('WORDWRAP', (0,1), (-1,-1), 'CJK'),
            ('TEXTCOLOR', (0,1), (3,-1), colors.black),
            ('TEXTCOLOR', (5,1), (6,-1), colors.black),
        ]))

        story.append(vuln_table)
        story.append(Spacer(1, 0.15*inch if booklet else 0.2*inch))

    def _add_recommendations_section(self, story: List, findings: List[Dict], white_text: bool = False, booklet: bool = False):
        heading_style = 'ReportHeading1'
        if white_text:
            self.styles['ReportHeading1'].textColor = colors.whitesmoke
        else:
            self.styles['ReportHeading1'].textColor = colors.black
        text_style = 'ReportWhiteText' if white_text else 'ReportBodyText'

        story.append(PageBreak())
        story.append(Paragraph("РЕКОМЕНДАЦИИ ПО УСТРАНЕНИЮ", self.styles[heading_style]))
        story.append(Spacer(1, 0.15*inch if booklet else 0.2*inch))

        if not findings:
            story.append(Paragraph("Рекомендации отсутствуют: уязвимости не обнаружены", self.styles[text_style]))
            return

        rec_data = [["CVE ID", "IP", "Рекомендации"]]
        for finding in sorted(findings, key=lambda x: (
            -float(x["cvss"]) if x["cvss"] != "N/A" else 0,
            x["ip"],
            x["cve_id"]
        )):
            recommendations = "\n".join(f"• {rec}" for rec in finding["recommendations"])
            rec_data.append([
                Paragraph(finding["cve_id"], self.styles["ReportBodyText"]),
                Paragraph(finding["ip"], self.styles["ReportBodyText"]),
                Paragraph(recommendations, self.styles["ReportBodyText"])
            ])

        colWidths = (
            [0.6*inch, 0.6*inch, 3.7*inch] if booklet
            else [0.7*inch, 0.7*inch, 4.6*inch]
        )

        rec_table = Table(
            rec_data,
            colWidths=colWidths,
            repeatRows=1,
            splitByRow=1,
            splitInRow=0
        )

        rec_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#006600")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,0), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), self.font_bold),
            ('FONTSIZE', (0,0), (-1,0), 6 if booklet else 7),
            ('BOTTOMPADDING', (0,0), (-1,0), 3 if booklet else 4),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor("#f0fff0")),
            ('GRID', (0,0), (-1,-1), 1, colors.black),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('FONTSIZE', (0,1), (-1,-1), 5 if booklet else 6),
            ('LEFTPADDING', (0,1), (-1,-1), 1 if booklet else 1),
            ('RIGHTPADDING', (0,1), (-1,-1), 1 if booklet else 1),
            ('BOTTOMPADDING', (0,1), (-1,-1), 1 if booklet else 2),
            ('TOPPADDING', (0,1), (-1,-1), 1 if booklet else 1),
            ('WORDWRAP', (0,1), (-1,-1), 'CJK'),
            ('TEXTCOLOR', (0,1), (-1,-1), colors.black),
        ]))

        story.append(rec_table)
        story.append(Spacer(1, 0.15*inch if booklet else 0.2*inch))

    def _add_conclusions_section(self, story: List, findings: List[Dict], white_text: bool = False, booklet: bool = False):
        heading_style = 'ReportHeading1'
        text_style = 'ReportWhiteConclusionText' if white_text else 'ReportConclusionText'
        bullet_style = 'ReportWhiteBullet' if white_text else 'ReportBullet'

        if white_text:
            self.styles['ReportHeading1'].textColor = colors.whitesmoke
        else:
            self.styles['ReportHeading1'].textColor = colors.black

        story.append(PageBreak())
        story.append(Paragraph("ВЫВОДЫ", self.styles[heading_style]))
        story.append(Spacer(1, 0.15*inch if booklet else 0.2*inch))

        if not findings:
            story.append(Paragraph(
                "Уязвимости не обнаружены, рисков эксплуатации нет.",
                self.styles[text_style]
            ))
            return

        critical_findings = [f for f in findings if f["severity"] in ["Critical", "High"] and float(f["cvss"]) >= 7.0]
        critical_findings = sorted(critical_findings, key=lambda x: float(x["cvss"]) if x["cvss"] != "N/A" else 0, reverse=True)

        intro_text = (
            "Обнаруженные уязвимости представляют значительные риски для безопасности сети. "
            "Игнорирование рекомендаций по их устранению может привести к серьезным последствиям, включая:"
        )
        story.append(Paragraph(intro_text, self.styles[text_style]))
        story.append(Spacer(1, 0.1*inch if booklet else 0.15*inch))

        if not critical_findings:
            story.append(Paragraph(
                "Критические и высокие уязвимости отсутствуют. Однако игнорирование низких и средних уязвимостей "
                "может привести к накоплению рисков, которые в будущем могут быть использованы для атак.",
                self.styles[text_style]
            ))
            return

        for finding in critical_findings[:5]:
            cve_id = finding["cve_id"]
            service = finding["service"]
            ip = finding["ip"]
            cvss = float(finding["cvss"]) if finding["cvss"] != "N/A" else 0
            description = finding["description"][:200] + "..." if len(finding["description"]) > 200 else finding["description"]

            risk_description = self._generate_risk_description(description, cvss)
            conclusion = f"<b>{cve_id}</b> ({service} на {ip}, CVSS: {cvss}): {risk_description}"
            story.append(Paragraph(conclusion, self.styles[bullet_style]))
            story.append(Spacer(1, 0.05*inch if booklet else 0.1*inch))

    def _generate_risk_description(self, description: str, cvss: float) -> str:
        description = description.lower()
        risks = []

        if any(keyword in description for keyword in ["remote code execution", "rce", "execute arbitrary code"]):
            risks.append("выполнение произвольного кода, что может привести к полной компрометации системы")
        if any(keyword in description for keyword in ["denial of service", "dos", "crash"]):
            risks.append("отказ в обслуживании, приводящий к недоступности сервиса")
        if any(keyword in description for keyword in ["information disclosure", "data leak", "sensitive data"]):
            risks.append("утечка конфиденциальных данных, включая учетные записи и коммерческую информацию")
        if any(keyword in description for keyword in ["privilege escalation", "gain unauthorized access"]):
            risks.append("получение несанкционированного доступа или повышение привилегий")
        if any(keyword in description for keyword in ["authentication bypass", "bypass authentication"]):
            risks.append("обход аутентификации, позволяющий атакующим получить доступ без учетных данных")

        if cvss >= 9.0:
            risks.append("высокая вероятность эксплуатации в реальных условиях")
        elif cvss >= 7.0:
            risks.append("возможность эксплуатации при наличии определенных условий")

        if not risks:
            risks.append("потенциальная компрометация системы или данных в зависимости от контекста уязвимости")

        return "; ".join(risks) + "."

    def _get_severity_paragraph(self, severity: str) -> Paragraph:
        style_map = {
            "Critical": "ReportCritical",
            "High": "ReportHigh",
            "Medium": "ReportMedium",
            "Low": "ReportLow"
        }
        return Paragraph(severity, self.styles[style_map.get(severity, "ReportBodyText")])

    def _generate_report(self, network_data: Dict, findings: List[Dict], filename: str, 
                        use_gradient: bool, white_text: bool, booklet: bool) -> str:
        pagesize = A5 if booklet else letter
        doc = SimpleDocTemplate(
            filename,
            pagesize=pagesize,
            title="Отчет об уязвимостях",
            author="SecFlash Vulnerability Scanner",
            leftMargin=0.3*inch,
            rightMargin=0.3*inch,
            topMargin=0.3*inch,
            bottomMargin=0.3*inch
        )

        story = []
        add_background = self._add_title_page(story, network_data, use_gradient, white_text, booklet)
        story.append(PageBreak())

        self._add_executive_summary(story, findings, network_data, white_text, booklet)
        self._add_vulnerabilities_table(story, findings, white_text, booklet)
        self._add_recommendations_section(story, findings, white_text, booklet)
        self._add_conclusions_section(story, findings, white_text, booklet)

        try:
            doc.build(story, onFirstPage=add_background, onLaterPages=add_background)
            logging.info(f"PDF отчет успешно создан: {filename}")
            return filename
        except Exception as e:
            logging.error(f"Ошибка генерации PDF отчета: {str(e)}")
            raise

    def generate_no_gradient_black(self, network_data: Dict, findings: List[Dict]) -> str:
        return self._generate_report(
            network_data, findings, 
            filename="report_no_gradient_black.pdf",
            use_gradient=False, white_text=False, booklet=False
        )

    def generate_no_gradient_black_booklet(self, network_data: Dict, findings: List[Dict]) -> str:
        return self._generate_report(
            network_data, findings, 
            filename="report_no_gradient_black_booklet.pdf",
            use_gradient=False, white_text=False, booklet=True
        )

    def generate_gradient_white_black(self, network_data: Dict, findings: List[Dict]) -> str:
        return self._generate_report(
            network_data, findings, 
            filename="report_gradient_white_black.pdf",
            use_gradient=True, white_text=True, booklet=False
        )

    def generate_gradient_white_black_booklet(self, network_data: Dict, findings: List[Dict]) -> str:
        return self._generate_report(
            network_data, findings, 
            filename="report_gradient_white_black_booklet.pdf",
            use_gradient=True, white_text=True, booklet=True
        )