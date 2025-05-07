# SecFlash

A powerful Python library for security vulnerability analysis using the National Vulnerability Database (NVD).

## Features

* Comprehensive vulnerability analysis
* Detailed PDF report generation
* NVD API integration with rate limiting
* Local vulnerability database caching
* Multi-language support
* Customizable analysis parameters

## Quick Start

```bash
# Install using Poetry
poetry install

# Set up environment
cp .env.example .env
# Add your NVD API key to .env

# Basic usage
from secflash import VulnerabilityAnalyzer

analyzer = VulnerabilityAnalyzer()
results = analyzer.analyze(keywords=["remote code execution"])
```

## Documentation

Comprehensive documentation is available in the `docs` directory. To build the docs:

```bash
cd docs
poetry run make html
```

Then open `docs/_build/html/index.html` in your browser.

## Development

We use modern Python development tools:

* Poetry for dependency management
* pytest for testing
* black for code formatting
* mypy for type checking
* flake8 for linting

```bash
# Install dev dependencies
poetry install

# Run tests
poetry run pytest

# Format code
poetry run black secflash
poetry run isort secflash

# Type checking
poetry run mypy secflash
```

## Architecture

SecFlash follows a modular architecture:

* VulnerabilityAnalyzer: Core analysis engine
* NVDClient: NVD API interaction
* ReportGenerator: PDF report generation
* NVDDatabase: Local data caching

For more details, see the architecture documentation.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and linting
5. Submit a pull request

## License

MIT
