# SecFlash - Vulnerability Hunter

![SecFlash](https://i.imgur.com/CyRxxXa.png)

Yo, welcome to **SecFlash** — your new secret weapon for hunting security holes and dropping pro-level vulnerability reports. Built by the cyber wizards at [NeoScout](https://neoscout.ru/), this Python beast chews through networks, sniffs out CVEs, and spits out slick PDF reports. Plug it in, point it at your network, and let it do the dirty work.

## What Does SecFlash Do?
- **Scans your network** for services and matches them to known vulnerabilities (CVE/NVD style).
- **Caches and stores** all the juicy findings in SQLite so you don't lose a thing.
- **Generates PDF reports** that even your boss will understand (with localization, because we're global).
- **Flexible and extensible** — hack it, script it, automate it, make it yours.

## Features That Hit Hard
- **Service & CPE Scanning**: Finds what's running and checks it against the NVD.
- **Smart Caching**: No more hammering the API — results are saved locally.
- **PDF Reports**: One command, instant executive summary.
- **Localization**: Reports in your language (well, at least English and Russian for now).
- **API Key Support**: Use your NVD API key for turbo mode (or go slow and free).

## Requirements
- Python 3.11+
- pip (or Poetry, if you're fancy)

## Installation
```bash
pip install secflash
```

## How To Wield This Power
Here's how you unleash SecFlash on your network:
```python
from secflash import VulnerabilityAnalyzer

network_data = {
    "location": "Your Corp",
    "hosts": [
        {
            "ip": "192.168.1.10",
            "status": "active",
            "ports": [80, 443],
            "services": ["Apache httpd 2.4.49"],
            "time": "2024-05-05 10:00:00"
        }
    ]
}

analyzer = VulnerabilityAnalyzer()
findings = analyzer.analyze_network(network_data)
# Drop all the reports you need
analyzer.generate_all_reports(network_data)
```

## Project Structure
```
secflash/
├── vulnerability_analyzer.py   # The mastermind
├── report_generator.py         # PDF wizardry
├── nvd_client.py               # NVD API wrangler
├── database.py                 # SQLite muscle
├── config.py                   # All your settings
└── ...                         # More magic
```
tests/ — Unit tests to keep you safe

## Testing
```bash
pytest
```

## Roadmap
- **100%**: Network & vulnerability scanning, PDF reports, caching, localization, API key support
- **75%**: More report templates, more languages
- **50%**: Web dashboard for your findings
- **25%**: Real-time scan progress, cloud sync
- **10%**: Push notifications, mobile app, AI-powered recommendations

## Contributing
Got skills? Want to make SecFlash even meaner? Fork, hack, PR — we love it. Ideas, bugfixes, new features, or just want to say hi? Hit us up!

## License
MIT — use it, break it, improve it, just give credit.

## Contact
Drop a line at [saikonohack](mailto:saintklovus@gmail.com) or open an issue. We're always up for a chat.

**NeoScout — Scan. Analyze. Take control.**