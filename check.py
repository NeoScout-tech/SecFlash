# check_network.py
"""
Script to analyze a network for vulnerabilities and generate reports in multiple languages.
"""

import logging
from secflash import VulnerabilityAnalyzer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("network_check.log"),
        logging.StreamHandler()
    ]
)

# Network data
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

def check_network():
    """Analyze the network and generate reports in Russian and English."""
    analyzer = VulnerabilityAnalyzer(db_path=":memory:")
    
    # Analyze network
    logging.info("Starting network analysis")
    findings = analyzer.analyze_network(test_network)
    logging.info(f"Analysis complete. Found {len(findings)} vulnerabilities")
    
    # Print findings
    for finding in findings:
        print(f"IP: {finding['ip']}")
        print(f"Service: {finding['service']}")
        print(f"CVE: {finding['cve_id']}")
        print(f"Severity: {finding['severity']}")
        print(f"CVSS: {finding['cvss']}")
        print(f"Description: {finding['description'][:100]}...")
        print(f"Recommendations: {'; '.join(finding['recommendations'])}")
        print("-" * 80)
    
    # Generate reports in Russian
    logging.info("Generating reports in Russian")
    ru_result = analyzer.generate_all_reports(test_network, language="ru")
    print(f"Russian reports: {ru_result['reports']}")
    print(f"Russian archive: {ru_result['archive']}")
    
    # Generate reports in English
    logging.info("Generating reports in English")
    en_result = analyzer.generate_all_reports(test_network, language="en")
    print(f"English reports: {en_result['reports']}")
    print(f"English archive: {en_result['archive']}")

if __name__ == "__main__":
    check_network()