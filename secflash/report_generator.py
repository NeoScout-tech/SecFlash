# secflash/report_generator.py
"""
PDF report generator for vulnerability scan results.
"""

import os
from reportlab.lib.pagesizes import letter, A5
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import logging
from typing import Dict, List, Any
from datetime import datetime
from babel.support import Translations

from .config import config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("report_generator.log"),
        logging.StreamHandler()
    ]
)


class ReportGenerator:
    """A class for generating security vulnerability reports.
    
    This class provides functionality to create detailed PDF reports
    about security vulnerabilities found during analysis.
    
    Attributes:
        template (SimpleDocTemplate): PDF document template
        styles (Dict): Dictionary of paragraph styles
    """

    def __init__(self, output_path: str = "vulnerability_report.pdf") -> None:
        """Initialize the ReportGenerator.
        
        Args:
            output_path (str): Path where the PDF report will be saved.
                Defaults to "vulnerability_report.pdf".
        """
        self.output_path = output_path
        self._setup_document()

    def _setup_document(self):
        # Load fonts
        font_path = os.path.join(config.FONT_DIR, 'DejaVuSans.ttf')
        font_bold_path = os.path.join(config.FONT_DIR, 'DejaVuSans-Bold.ttf')
        
        try:
            if os.path.exists(font_path) and os.path.exists(font_bold_path):
                pdfmetrics.registerFont(TTFont('DejaVuSans', font_path))
                pdfmetrics.registerFont(TTFont('DejaVuSans-Bold', font_bold_path))
                self.font_name = 'DejaVuSans'
                self.font_bold = 'DejaVuSans-Bold'
                logging.info("DejaVuSans fonts loaded successfully")
            else:
                raise FileNotFoundError("DejaVuSans fonts not found")
        except Exception as e:
            logging.warning(f"Font loading error: {str(e)}. Using Helvetica")
            self.font_name = 'Helvetica'
            self.font_bold = 'Helvetica-Bold'

        # Initialize styles
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

        self.logo_path = config.LOGO_PATH
        if not os.path.exists(self.logo_path):
            logging.warning("Logo file not found, reports will be generated without a logo")

    def _load_translations(self, language: str) -> Translations:
        """Load translations for the specified language."""
        try:
            translations = Translations.load(
                dirname=os.path.join(os.path.dirname(__file__), 'translations'),
                locales=[language],
                domain='messages'
            )
            logging.info(f"Loaded translations for language: {language}")
            return translations
        except Exception as e:
            logging.error(f"Failed to load translations for {language}: {str(e)}")
            return Translations.load(
                dirname=os.path.join(os.path.dirname(__file__), 'translations'),
                locales=['en'],
                domain='messages'
            )

    def _add_title_page(self, story: List, network_data: Dict, use_gradient: bool = False, 
                        white_text: bool = False, booklet: bool = False, language: str = "en"):
        """Add the title page to the report."""
        translations = self._load_translations(language)

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

        story.append(Paragraph(
            translations.gettext("VULNERABILITY ANALYSIS REPORT"),
            self.styles[title_style]
        ))
        story.append(Spacer(1, 0.3*inch if booklet else 0.5*inch))

        meta = [
            [
                Paragraph(translations.gettext("Organization:"), self.styles[text_style]),
                Paragraph(
                    network_data.get("location", translations.gettext("Not specified")),
                    self.styles[text_style]
                )
            ],
            [
                Paragraph(translations.gettext("Scan Date:"), self.styles[text_style]),
                Paragraph(
                    network_data["hosts"][0]["time"] if network_data.get("hosts") else translations.gettext("Not specified"),
                    self.styles[text_style]
                )
            ],
            [
                Paragraph(translations.gettext("Report Generated:"), self.styles[text_style]),
                Paragraph(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), self.styles[text_style])
            ],
            [
                Paragraph(translations.gettext("Generated By:"), self.styles[text_style]),
                Paragraph(translations.gettext("SecFlash Vulnerability Scanner"), self.styles[text_style])
            ]
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
        story.append(Paragraph(translations.gettext("Confidential"), self.styles[text_style]))
        story.append(Paragraph(translations.gettext("For internal use only"), self.styles[text_style]))

        return add_gradient if use_gradient else add_white_background

    def _add_executive_summary(self, story: List, findings: List[Dict], network_data: Dict, 
                              white_text: bool = False, booklet: bool = False, language: str = "en"):
        """Add executive summary section to the report."""
        translations = self._load_translations(language)
        text_style = 'ReportWhiteText' if white_text else 'ReportBodyText'
        heading_style = 'ReportHeading1'
        if white_text:
            self.styles['ReportHeading1'].textColor = colors.whitesmoke
        else:
            self.styles['ReportHeading1'].textColor = colors.black

        story.append(Paragraph(translations.gettext("EXECUTIVE SUMMARY"), self.styles[heading_style]))

        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "N/A": 0}
        for f in findings:
            severity = f["severity"] if f["severity"] in severity_counts else "N/A"
            severity_counts[severity] += 1

        host_count = len([h for h in network_data.get('hosts', []) if h.get('status') == 'active'])
        summary_text = translations.gettext(
            "Network analysis identified <b>{count} vulnerabilities</b> across <b>{host_count} hosts</b>."
        ).format(count=len(findings), host_count=host_count) + "\n\n"
        summary_text += f"<b>{translations.gettext('Severity Distribution:')}</b>\n"
        summary_text += f"• <font color=red>{translations.gettext('Critical:')} {severity_counts['Critical']}</font>\n"
        summary_text += f"• <font color=orangered>{translations.gettext('High:')} {severity_counts['High']}</font>\n"
        summary_text += f"• <font color=orange>{translations.gettext('Medium:')} {severity_counts['Medium']}</font>\n"
        summary_text += f"• <font color=green>{translations.gettext('Low:')} {severity_counts['Low']}</font>\n"
        summary_text += f"• {translations.gettext('Unknown (N/A):')} {severity_counts['N/A']}\n\n"
        summary_text += f"<b>{translations.gettext('Most Severe Vulnerabilities:')}</b>\n"

        top_critical = sorted(
            [f for f in findings if f["severity"] in ["Critical", "High"]],
            key=lambda x: float(x["cvss"]) if x["cvss"] != "N/A" else 0,
            reverse=True
        )[:3]

        for vuln in top_critical:
            summary_text += (
                f"• <b>{vuln['cve_id']}</b> ({vuln['service']} on {vuln['ip']}) - "
                f"CVSS: <font color={'red' if float(vuln['cvss']) >= 9.0 else 'orange'}>{vuln['cvss']}</font>\n"
            )

        if not top_critical:
            summary_text += f"• {translations.gettext('No critical or high vulnerabilities detected')}\n"

        story.append(Paragraph(summary_text, self.styles[text_style]))
        story.append(Spacer(1, 0.15*inch if booklet else 0.25*inch))

    def _add_vulnerabilities_table(self, story: List, findings: List[Dict], 
                                   white_text: bool = False, booklet: bool = False, language: str = "en"):
        """Add detailed vulnerabilities table to the report."""
        translations = self._load_translations(language)
        heading_style = 'ReportHeading1'
        if white_text:
            self.styles['ReportHeading1'].textColor = colors.whitesmoke
        else:
            self.styles['ReportHeading1'].textColor = colors.black
        text_style = 'ReportWhiteText' if white_text else 'ReportBodyText'

        story.append(Paragraph(
            translations.gettext("DETAILED VULNERABILITY REPORT"),
            self.styles[heading_style]
        ))
        story.append(Spacer(1, 0.15*inch if booklet else 0.2*inch))

        if not findings:
            story.append(Paragraph(
                translations.gettext("No vulnerabilities detected"),
                self.styles[text_style]
            ))
            return

        vuln_data = [[
            translations.gettext("IP"),
            translations.gettext("Ports"),
            translations.gettext("Service"),
            translations.gettext("CVE ID"),
            translations.gettext("Sev."),
            translations.gettext("CVSS"),
            translations.gettext("Description")
        ]]
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

    def _add_recommendations_section(self, story: List, findings: List[Dict], 
                                    white_text: bool = False, booklet: bool = False, language: str = "en"):
        """Add recommendations section to the report."""
        translations = self._load_translations(language)
        heading_style = 'ReportHeading1'
        if white_text:
            self.styles['ReportHeading1'].textColor = colors.whitesmoke
        else:
            self.styles['ReportHeading1'].textColor = colors.black
        text_style = 'ReportWhiteText' if white_text else 'ReportBodyText'

        story.append(PageBreak())
        story.append(Paragraph(
            translations.gettext("RECOMMENDATIONS FOR REMEDIATION"),
            self.styles[heading_style]
        ))
        story.append(Spacer(1, 0.15*inch if booklet else 0.2*inch))

        if not findings:
            story.append(Paragraph(
                translations.gettext("No recommendations: no vulnerabilities detected"),
                self.styles[text_style]
            ))
            return

        rec_data = [[
            translations.gettext("CVE ID"),
            translations.gettext("IP"),
            translations.gettext("Recommendations")
        ]]
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

    def _add_conclusions_section(self, story: List, findings: List[Dict], 
                                white_text: bool = False, booklet: bool = False, language: str = "en"):
        """Add conclusions section to the report."""
        translations = self._load_translations(language)
        heading_style = 'ReportHeading1'
        text_style = 'ReportWhiteConclusionText' if white_text else 'ReportConclusionText'
        bullet_style = 'ReportWhiteBullet' if white_text else 'ReportBullet'

        if white_text:
            self.styles['ReportHeading1'].textColor = colors.whitesmoke
        else:
            self.styles['ReportHeading1'].textColor = colors.black

        story.append(PageBreak())
        story.append(Paragraph(
            translations.gettext("CONCLUSIONS"),
            self.styles[heading_style]
        ))
        story.append(Spacer(1, 0.15*inch if booklet else 0.2*inch))

        if not findings:
            story.append(Paragraph(
                translations.gettext("No vulnerabilities detected; no exploitation risks identified."),
                self.styles[text_style]
            ))
            return

        critical_findings = [f for f in findings if f["severity"] in ["Critical", "High"] and float(f["cvss"]) >= 7.0]
        critical_findings = sorted(critical_findings, key=lambda x: float(x["cvss"]) if x["cvss"] != "N/A" else 0, reverse=True)

        intro_text = translations.gettext(
            "The identified vulnerabilities pose significant risks to network security. "
            "Ignoring remediation recommendations may lead to serious consequences, including:"
        )
        story.append(Paragraph(intro_text, self.styles[text_style]))
        story.append(Spacer(1, 0.1*inch if booklet else 0.15*inch))

        if not critical_findings:
            story.append(Paragraph(
                translations.gettext(
                    "No critical or high vulnerabilities detected. However, ignoring low and medium "
                    "vulnerabilities may lead to cumulative risks that could be exploited in the future."
                ),
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
            conclusion = f"<b>{cve_id}</b> ({service} on {ip}, CVSS: {cvss}): {risk_description}"
            story.append(Paragraph(conclusion, self.styles[bullet_style]))
            story.append(Spacer(1, 0.05*inch if booklet else 0.1*inch))

    def _generate_risk_description(self, description: str, cvss: float) -> str:
        """Generate risk description based on vulnerability details."""
        description = description.lower()
        risks = []

        if any(keyword in description for keyword in ["remote code execution", "rce", "execute arbitrary code"]):
            risks.append("execution of arbitrary code, potentially leading to full system compromise")
        if any(keyword in description for keyword in ["denial of service", "dos", "crash"]):
            risks.append("denial of service, causing service unavailability")
        if any(keyword in description for keyword in ["information disclosure", "data leak", "sensitive data"]):
            risks.append("leakage of sensitive data, including credentials and commercial information")
        if any(keyword in description for keyword in ["privilege escalation", "gain unauthorized access"]):
            risks.append("unauthorized access or privilege escalation")
        if any(keyword in description for keyword in ["authentication bypass", "bypass authentication"]):
            risks.append("authentication bypass, allowing attackers to gain access without credentials")

        if cvss >= 9.0:
            risks.append("high likelihood of exploitation in real-world conditions")
        elif cvss >= 7.0:
            risks.append("possible exploitation under certain conditions")

        if not risks:
            risks.append("potential system or data compromise depending on the vulnerability context")

        return "; ".join(risks) + "."

    def _get_severity_paragraph(self, severity: str) -> Paragraph:
        """Return a styled Paragraph for severity."""
        style_map = {
            "Critical": "ReportCritical",
            "High": "ReportHigh",
            "Medium": "ReportMedium",
            "Low": "ReportLow"
        }
        return Paragraph(severity, self.styles[style_map.get(severity, "ReportBodyText")])

    def _generate_report(self, network_data: Dict, findings: List[Dict], filename: str, 
                        use_gradient: bool, white_text: bool, booklet: bool, language: str = "en") -> str:
        """Generate a PDF report with the specified style."""
        pagesize = A5 if booklet else letter
        doc = SimpleDocTemplate(
            filename,
            pagesize=pagesize,
            title="Vulnerability Report",
            author="SecFlash Vulnerability Scanner",
            leftMargin=0.3*inch,
            rightMargin=0.3*inch,
            topMargin=0.3*inch,
            bottomMargin=0.3*inch
        )

        story = []
        add_background = self._add_title_page(story, network_data, use_gradient, white_text, booklet, language)
        story.append(PageBreak())

        self._add_executive_summary(story, findings, network_data, white_text, booklet, language)
        self._add_vulnerabilities_table(story, findings, white_text, booklet, language)
        self._add_recommendations_section(story, findings, white_text, booklet, language)
        self._add_conclusions_section(story, findings, white_text, booklet, language)

        try:
            doc.build(story, onFirstPage=add_background, onLaterPages=add_background)
            logging.info(f"PDF report generated successfully: {filename}")
            return filename
        except Exception as e:
            logging.error(f"Failed to generate PDF report: {str(e)}")
            raise

    def generate_no_gradient_black(self, network_data: Dict, findings: List[Dict], language: str = "en") -> str:
        """Generate a black-text report without gradient background."""
        return self._generate_report(
            network_data, findings, 
            filename=f"report_no_gradient_black_{language}.pdf",
            use_gradient=False, white_text=False, booklet=False, language=language
        )

    def generate_no_gradient_black_booklet(self, network_data: Dict, findings: List[Dict], language: str = "en") -> str:
        """Generate a black-text booklet report without gradient background."""
        return self._generate_report(
            network_data, findings, 
            filename=f"report_no_gradient_black_booklet_{language}.pdf",
            use_gradient=False, white_text=False, booklet=True, language=language
        )

    def generate_gradient_white_black(self, network_data: Dict, findings: List[Dict], language: str = "en") -> str:
        """Generate a white-text report with gradient background."""
        return self._generate_report(
            network_data, findings, 
            filename=f"report_gradient_white_black_{language}.pdf",
            use_gradient=True, white_text=True, booklet=False, language=language
        )

    def generate_gradient_white_black_booklet(self, network_data: Dict, findings: List[Dict], language: str = "en") -> str:
        """Generate a white-text booklet report with gradient background."""
        return self._generate_report(
            network_data, findings, 
            filename=f"report_gradient_white_black_booklet_{language}.pdf",
            use_gradient=True, white_text=True, booklet=True, language=language
        )

    def generate(self, analysis_results: Dict[str, Any]) -> None:
        """Generate a PDF report from analysis results.
        
        Args:
            analysis_results (Dict[str, Any]): Results from vulnerability analysis
                containing:
                - total_vulnerabilities: Total number of vulnerabilities
                - severity_distribution: Distribution by severity
                - vulnerability_types: Types of vulnerabilities
                - recommendations: Security recommendations
        """
        # ... existing code ...