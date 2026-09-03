# 🛡️ Threat Intelligence Aggregator (Minimal)

> A lightweight, single-file threat intelligence aggregator that collects IOCs (Indicators of Compromise) from public APIs and exports them in multiple formats.

[![Python](https://img.shields.io/badge/Python-3.6+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Size](https://img.shields.io/badge/Size-%3C200%20lines-lightgrey.svg)]()
[![Dependencies](https://img.shields.io/badge/Dependencies-requests-orange.svg)]()

---

## 📋 Table of Contents

- [Features](#-features)
- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Usage](#-usage)
- [Output Formats](#-output-formats)
- [Data Sources](#-data-sources)
- [Adding Custom Sources](#-adding-custom-sources)
- [Commands Reference](#-commands-reference)
- [Examples](#-examples)
- [Project Structure](#-project-structure)
- [License](#-license)

---

## ✨ Features

- **Multi-source collection** - Aggregates IOCs from multiple public APIs
- **Automatic deduplication** - Removes duplicate indicators
- **Confidence filtering** - Filter by confidence threshold
- **Multiple export formats** - JSON, CSV, and plain text blocklist
- **Mock mode** - Test without API calls using sample data
- **Single file** - Entire tool in one Python file (< 200 lines)
- **Zero external dependencies** - Only requires `requests` library

---

## 🚀 Quick Start

```bash
# Clone or download
git clone https://github.com/Believe-sec-io/threat-intel-aggregator.git
cd threat-intel-aggregator

# Install dependencies
pip install requests

# Run with mock data (no API calls)
python ioc_aggregator.py --mock

# Run with real APIs
python ioc_aggregator.py

# That's it! Check the generated files
ls iocs_*.json iocs_*.csv blocklist_*.txt
