#!/usr/bin/env python3

from setuptools import setup, find_packages
import os

# Read the README file
readme_path = os.path.join(os.path.dirname(__file__), '..', '..', 'README.md')
with open(readme_path, 'r', encoding='utf-8') as f:
    long_description = f.read()

# Read requirements
with open('requirements.txt', 'r', encoding='utf-8') as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name="ouroboros-protocol",
    version="0.1.0",
    author="Ouroboros Project",
    author_email="",
    description="Quantum-resistant secure channel protocol for IoT devices",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/ouroboros",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security :: Cryptography",
        "Topic :: System :: Networking",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "isort>=5.11.0",
            "mypy>=1.0.0",
            "flake8>=6.0.0",
        ],
        "docs": [
            "sphinx>=5.0.0",
            "sphinx-rtd-theme>=1.2.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "ouroboros-keygen=ouroboros.tools.keygen:main",
            "ouroboros-analyzer=ouroboros.tools.packet_analyzer:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
