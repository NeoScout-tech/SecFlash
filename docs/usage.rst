Usage
=====

Basic Usage
----------

.. code-block:: python

    from secflash import VulnerabilityAnalyzer, ReportGenerator

    # Create analyzer
    analyzer = VulnerabilityAnalyzer()

    # Analyze vulnerabilities
    results = analyzer.analyze()

    # Generate report
    report = ReportGenerator()
    report.generate(results)

Working with NVD API
------------------

.. code-block:: python

    from secflash import NVDClient

    client = NVDClient()
    
    # Search vulnerabilities
    vulnerabilities = client.search_vulnerabilities(
        keyword="remote code execution",
        published_from="2024-01-01"
    )

    # Advanced search
    results = client.search_vulnerabilities(
        keywords=["buffer overflow", "critical"],
        cve_id="CVE-2024-1234",
        published_from="2024-01-01",
        published_to="2024-03-01",
        severity="HIGH"
    )

Database Operations
-----------------

.. code-block:: python

    from secflash import NVDDatabase

    db = NVDDatabase()
    
    # Save vulnerabilities
    db.save_vulnerabilities(vulnerabilities)
    
    # Query vulnerabilities
    stored_vulns = db.get_vulnerabilities()
    
    # Advanced queries
    critical_vulns = db.get_vulnerabilities(
        severity="CRITICAL",
        date_from="2024-01-01",
        limit=100
    )

Customizing Reports
-----------------

.. code-block:: python

    from secflash import ReportGenerator

    # Custom report path
    report = ReportGenerator("custom_report.pdf")

    # Generate with options
    report.generate(
        results,
        include_graphs=True,
        severity_threshold="HIGH",
        language="en"
    ) 