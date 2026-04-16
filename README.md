# SOC Engine Core

<p align="center">
  <img src="https://img.shields.io/badge/Status-Active-brightgreen" alt="Status">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue" alt="Python">
  <img src="https://img.shields.io/badge/License-Proprietary-red" alt="License">
</p>

## Overview

**SOC Engine Core** is the backbone of CyberAlam Solutions' automated Security Operations Center platform. Developed in-house at our Shah Alam, Selangor headquarters, this engine ingests, correlates, and triages security events from multiple data sources in real-time.

> ⚠️ **NOTICE:** This repository contains the open-source components of our SOC automation framework. The proprietary analysis modules (Project IRENE) are maintained in a separate, private repository.

## Features

- **Real-time Log Ingestion** — Parses syslog, Windows Event Logs, and cloud audit trails
- **Alert Correlation Engine** — Groups related events using temporal and contextual analysis
- **Automated Triage** — Classifies alerts by severity using configurable rule sets
- **Webhook Integration** — Pushes enriched alerts to Slack, Microsoft Teams, and PagerDuty
- **Modular Architecture** — Extend the engine with custom parsers and response playbooks

## Architecture

```
┌──────────────┐     ┌──────────────────┐     ┌────────────────┐
│  Data Sources │────▶│  Ingestion Layer  │────▶│  Alert Engine  │
│  (Syslog/API) │     │  (engine.py)      │     │ (alert_handler)│
└──────────────┘     └──────────────────┘     └───────┬────────┘
                                                       │
                                                       ▼
                                               ┌──────────────┐
                                               │  Triage &     │
                                               │  Enrichment   │
                                               └──────┬───────┘
                                                       │
                                                       ▼
                                               ┌──────────────┐
                                               │  Webhooks /   │
                                               │  Notifications│
                                               └──────────────┘
```

## Quick Start

```bash
# Clone the repository
git clone https://github.com/CyberAlam-Solutions/SOC-Engine-Core.git
cd SOC-Engine-Core

# Install dependencies
pip install -r requirements.txt

# Configure your environment
cp config/settings.yaml config/settings.local.yaml
# Edit settings.local.yaml with your data source endpoints

# Run the engine
python -m src.engine --config config/settings.local.yaml
```

## Configuration

All configuration is managed via `config/settings.yaml`. Key settings include:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `ingestion.poll_interval` | Seconds between log polls | `30` |
| `alerts.severity_threshold` | Minimum severity to trigger notification | `medium` |
| `webhooks.slack.enabled` | Enable Slack notifications | `false` |
| `engine.workers` | Number of parallel processing workers | `4` |

## Team

| Role | Name | GitHub |
|------|------|--------|
| Lead Engineer | Ahmad Razif | [@ahmdrazif](https://github.com/ahmdrazif) |
| Backend Developer | Nur Aisyah | [@nuraisyah-dev](https://github.com/nuraisyah-dev) |
| DevOps / Infra (Contractor) | Jamal Doe | [@jdoe-devops](https://github.com/jdoe-devops) |

## Contributing

Please read our [Contributing Guidelines](CONTRIBUTING.md) before submitting any pull requests.

## License

Copyright © 2025-2026 CyberAlam Solutions Sdn Bhd. All rights reserved.

This software is proprietary. Unauthorized copying, distribution, or modification is strictly prohibited. See `LICENSE` for details.
