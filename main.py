from vulnerability_analyzer import VulnerabilityAnalyzer
from report_generator import ReportGenerator
import logging

logging.basicConfig(level=logging.INFO)

def main():
    analyzer = VulnerabilityAnalyzer()

    # Тестовая сеть
    test_network = {
        "location": "ООО 'ТехноПром'",
        "hosts": [
            {
                "ip": "192.168.1.10",
                "status": "active",
                "ports": [80, 443, 22],
                "services": ["Apache httpd 2.4.49", "OpenSSL 1.1.1", "OpenSSH 8.2p1"],
                "time": "2024-05-05 10:00:00"
            },
            {
                "ip": "192.168.1.20",
                "status": "active",
                "ports": [3389, 445],
                "services": ["Windows Server 2019 10.0.17763", "SMB 3.1.1"],
                "time": "2024-05-05 10:05:00"
            },
            {
                "ip": "192.168.1.30",
                "status": "active",
                "ports": [3306, 80],
                "services": ["MySQL 5.7.33", "PHP 7.4.16", "WordPress 5.7.2"],
                "time": "2024-05-05 10:10:00"
            },
            {
                "ip": "192.168.1.40",
                "status": "active",
                "ports": [8080, 8443],
                "services": ["Tomcat 9.0.45", "Java 1.8.0_291"],
                "time": "2024-05-05 10:15:00"
            },
            {
                "ip": "192.168.1.50",
                "status": "active",
                "ports": [22, 80],
                "services": ["Ubuntu 20.04.5 LTS", "OpenSSH 8.2p1", "Nginx 1.18.0"],
                "time": "2024-05-05 10:20:00"
            }
        ]
    }

    # Генерация всех отчетов
    report_files = analyzer.generate_all_reports(test_network)
    for report_file in report_files:
        logging.info(f"Отчет создан: {report_file}")

if __name__ == "__main__":
    main()