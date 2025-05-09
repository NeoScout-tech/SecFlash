# setup.py
"""
Setup script for the SecFlash library.
"""

from setuptools import setup, find_packages

setup(
    name="secflash",
    version="0.1.1",
    description="A vulnerability scanning and reporting library based on NVD data",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="saikonohack",
    author_email="saintklovus@gmail.com",
    url="https://github.com/NeoScout-tech/SecFlash",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "nvdlib>=0.7.6",
        "reportlab>=3.6.13",
        "requests>=2.31.0",
        "packaging>=25.0",
        "colorlog>=6.9.0",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
)