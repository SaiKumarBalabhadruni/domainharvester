#!/usr/bin/env python3
"""
Setup script for DomainHarvester
"""

from setuptools import setup, find_packages

with open("requirements.txt") as f:
    requirements = f.read().splitlines()

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="domainharvester",
    version="11.0.0",
    author="Sai Kumar Balabhadruni",
    description="Production-grade defensive security scanner for domain reconnaissance",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/saikumarbalabhadruni/domainharvester",
    packages=find_packages(),
    py_modules=['domainharvester'],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        'console_scripts': [
            'domainharvester=domainharvester:main',
        ],
    },
    keywords="security scanner reconnaissance domain whois dns ssl",
    project_urls={
        "Bug Reports": "https://github.com/saikumarbalabhadruni/domainharvester/issues",
        "Source": "https://github.com/saikumarbalabhadruni/domainharvester",
        "LinkedIn": "https://www.linkedin.com/in/saikumarbalabhadruni/",
    },
)