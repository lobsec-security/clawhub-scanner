# ClawHub Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/lobsec-security/clawhub-scanner/releases)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/lobsec-security/clawhub-scanner/actions)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![OpenClaw](https://img.shields.io/badge/OpenClaw-Compatible-orange.svg)](https://openclaw.ai/)

Security scanner for OpenClaw skill directories. Detects malicious patterns including data exfiltration, prompt injection, wallet drains, persistence mechanisms, supply chain attacks, and arbitrary code execution.

## Usage

```bash
# Scan a skill directory
python3 scanner.py scan <skill_directory>

# JSON output
python3 scanner.py scan <skill_directory> --format json

# Save to file
python3 scanner.py scan <skill_directory> --format json --output report.json

# List all detection patterns
python3 scanner.py list-patterns

# Version
python3 scanner.py version
```

## Detection Categories

| Category | Patterns | Description |
|----------|----------|-------------|
| Data Exfiltration | 6 | Unauthorized data transmission |
| Prompt Injection | 5 | System prompt override attempts |
| Wallet Drain | 5 | Cryptocurrency theft |
| Persistence | 6 | Backdoor installation |
| Supply Chain | 5 | Dependency manipulation |
| Code Execution | 4 | Arbitrary code/command execution |

## Risk Scoring

- **Clean** (0): No findings
- **Low** (<10): Minor issues
- **Medium** (<30): Moderate risk
- **High** (<60): Significant risk
- **Critical** (60+): Severe threats detected

## Test Samples

```bash
# Should detect findings:
python3 scanner.py scan test_samples/exfil_skill/
python3 scanner.py scan test_samples/wallet_drain_skill/
python3 scanner.py scan test_samples/prompt_inject_skill/
python3 scanner.py scan test_samples/persistence_skill/
python3 scanner.py scan test_samples/supply_chain_skill/

# Should be clean:
python3 scanner.py scan test_samples/benign_skill/
```
