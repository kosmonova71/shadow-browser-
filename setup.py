#!/usr/bin/env python3
"""
Setup script for ShadowBrowser - A privacy-focused web browser built with GTK4 and WebKitGTK.
"""

from setuptools import setup, find_packages
import os

# Read the README file for long description
def read_readme():
    readme_path = os.path.join(os.path.dirname(__file__), 'README.md')
    if os.path.exists(readme_path):
        with open(readme_path, 'r', encoding='utf-8') as f:
            return f.read()
    return "A privacy-focused web browser built with GTK4 and WebKitGTK."

# Read requirements from requirements.txt
def read_requirements():
    requirements_path = os.path.join(os.path.dirname(__file__), 'requirements.txt')
    if os.path.exists(requirements_path):
        with open(requirements_path, 'r', encoding='utf-8') as f:
            # Filter out comments and empty lines, and system dependencies
            lines = []
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and not 'sudo apt-get' in line and not 'sudo dnf' in line and not 'sudo pacman' in line:
                    lines.append(line)
            return lines
    return []

# Package data files
def get_package_data():
    return {
        'shadow': [
            'bookmarks.json',
            'history.json',
            'session.json',
            'tabs.json',
            'easylist_cache.txt',
            'block_patterns_cache.pkl',
            '*.png',
            '*.html'
        ]
    }

setup(
    name="shadowbrowser",
    version="1.0.0",
    author="ShadowyFigure",
    author_email="",  # Add email if available
    description="A privacy-focused web browser built with GTK4 and WebKitGTK",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/shadowyfigure/shadow-browser-",
    packages=find_packages(where='shadow'),
    package_dir={'': 'shadow'},
    package_data=get_package_data(),
    include_package_data=True,
    install_requires=read_requirements(),
    extras_require={
        'dev': [
            'pytest>=6.2.5',
            'pytest-cov>=2.12.1',
            'black>=21.12b0',
            'flake8>=4.0.1',
            'mypy>=0.930'
        ],
        'obfuscation': [
            # Optional obfuscation modules would go here if they become pip-installable
        ]
    },
    entry_points={
        'console_scripts': [
            'shadowbrowser=shadow.shadowbrowser:main',
        ],
        'gui_scripts': [
            'shadowbrowser-gui=shadow.shadowbrowser:main',
        ]
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: End Users/Desktop",
        "License :: OSI Approved :: MIT License",  # Adjust if different license
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Internet :: WWW/HTTP :: Browsers",
        "Topic :: Security",
        "Topic :: Desktop Environment",
    ],
    python_requires=">=3.8",
    keywords="browser webkit gtk privacy security tor adblock",
    project_urls={
        "Bug Reports": "https://github.com/shadowyfigure/shadow-browser-/issues",
        "Source": "https://github.com/shadowyfigure/shadow-browser-",
        "Documentation": "https://github.com/shadowyfigure/shadow-browser-/wiki",
    },
    zip_safe=False,
    platforms=["Linux"],
)
