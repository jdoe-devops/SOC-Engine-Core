# Contributing to SOC Engine Core

Thank you for your interest in contributing to the SOC Engine Core project. This document outlines our development workflow and guidelines.

## Team & Roles

| Role | Contact |
|------|---------|
| Project Lead | Ahmad Razif ([@ahmdrazif](https://github.com/ahmdrazif)) |
| Backend Engineer | Nur Aisyah ([@nuraisyah-dev](https://github.com/nuraisyah-dev)) |
| Infra / DevOps (External Contractor) | Jamal Doe ([@jdoe-devops](https://github.com/jdoe-devops)) |

> **Note:** External contractors should fork the repository and submit changes via Pull Request. Direct pushes to `main` are restricted to core team members only.

## Getting Started

1. **Fork** the repository to your own GitHub account.
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/SOC-Engine-Core.git
   ```
3. Create a **feature branch** for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```
4. Make your changes and commit with descriptive messages.
5. Push to your fork and open a **Pull Request** against `main`.

## Branch Naming Convention

- `feature/*` — New features or enhancements
- `bugfix/*` — Bug fixes
- `infra/*` — Infrastructure and DevOps changes
- `docs/*` — Documentation updates

## Commit Message Format

Use clear, descriptive commit messages:

```
type: brief description

Detailed explanation if necessary.
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `infra`, `chore`

## Code Standards

- **Python 3.10+** is required
- Follow PEP 8 style guidelines
- All modules must include docstrings
- Type hints are strongly encouraged
- Run `flake8` and `mypy` before submitting PRs

## Security Policy

> ⚠️ **IMPORTANT:** Never commit credentials, API keys, or sensitive configuration data to this repository. Use environment variables and reference them in `settings.yaml` using the `${VARIABLE}` syntax.

If you discover a security vulnerability, please report it privately to security@cyberalam.my — **do not** open a public issue.

## Infrastructure Changes

Infrastructure and deployment configurations (network configs, firewall rules, DevStack setups) should be tested locally using the `infra-testing` branch before proposing changes to the main deployment pipeline.

Contractor **@jdoe-devops** is currently responsible for maintaining the testing infrastructure. Coordinate with them for any infra-related changes.

## Questions?

Open a GitHub Issue or reach out to the team on our internal Slack channel `#soc-engine-dev`.
