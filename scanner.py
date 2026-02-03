#!/usr/bin/env python3
"""
ClawHub Scanner - Security scanner for OpenClaw skill directories.

Scans skill code for malicious patterns including data exfiltration,
prompt injection, wallet drains, persistence mechanisms, supply chain
attacks, and arbitrary code execution.

Usage:
    python3 scanner.py scan <skill_directory> [--output report.json] [--format json|text]
    python3 scanner.py list-patterns
    python3 scanner.py version
"""

import argparse
import json
import os
import re
import sys
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional


__version__ = "1.0.0"

# File extensions to scan
SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".sh", ".bash", ".yaml", ".yml",
    ".json", ".toml", ".cfg", ".ini", ".conf", ".md", ".txt",
    ".env", ".dockerfile", ".rb", ".go", ".rs", ".lua",
}

# Max file size to scan (1MB)
MAX_FILE_SIZE = 1_048_576


@dataclass
class Finding:
    """A single security finding."""
    rule_id: str
    rule_name: str
    category: str
    severity: str
    confidence: str
    description: str
    file_path: str
    line_number: int
    line_content: str
    match_text: str


@dataclass
class ScanReport:
    """Complete scan report."""
    scanner_version: str
    scan_timestamp: str
    skill_path: str
    skill_name: str
    files_scanned: int
    total_findings: int
    risk_score: float
    risk_level: str
    findings: list = field(default_factory=list)
    category_summary: dict = field(default_factory=dict)
    file_hashes: dict = field(default_factory=dict)


class PatternLoader:
    """Loads security patterns from JSON file."""

    def __init__(self, patterns_path: Optional[str] = None):
        if patterns_path is None:
            patterns_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "patterns.json"
            )
        self.patterns_path = patterns_path
        self.categories = {}
        self._load()

    def _load(self):
        """Load patterns from JSON file."""
        try:
            with open(self.patterns_path, "r") as f:
                data = json.load(f)
        except FileNotFoundError:
            print(f"Error: Patterns file not found: {self.patterns_path}", file=sys.stderr)
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"Error: Failed to parse patterns JSON: {e}", file=sys.stderr)
            sys.exit(1)

        self.version = data.get("version", "unknown")
        raw_categories = data.get("categories", {})

        for cat_id, cat_data in raw_categories.items():
            compiled_patterns = []
            for p in cat_data.get("patterns", []):
                try:
                    compiled = re.compile(p["pattern"])
                    compiled_patterns.append({
                        "id": p["id"],
                        "name": p["name"],
                        "regex": compiled,
                        "description": p["description"],
                        "severity": p["severity"],
                        "confidence": p["confidence"],
                    })
                except re.error as e:
                    print(f"Warning: Failed to compile pattern {p['id']}: {e}", file=sys.stderr)

            self.categories[cat_id] = {
                "name": cat_data["name"],
                "severity": cat_data["severity"],
                "description": cat_data["description"],
                "patterns": compiled_patterns,
            }

    def get_all_patterns(self):
        """Yield (category_id, category_name, pattern_dict) for all patterns."""
        for cat_id, cat_data in self.categories.items():
            for pattern in cat_data["patterns"]:
                yield cat_id, cat_data["name"], pattern

    def list_patterns(self):
        """Print all loaded patterns."""
        for cat_id, cat_data in self.categories.items():
            print(f"\n{'='*60}")
            print(f"Category: {cat_data['name']} [{cat_id}]")
            print(f"Severity: {cat_data['severity']}")
            print(f"Description: {cat_data['description']}")
            print(f"{'='*60}")
            for p in cat_data["patterns"]:
                print(f"  [{p['id']}] {p['name']}")
                print(f"    Severity: {p['severity']} | Confidence: {p['confidence']}")
                print(f"    {p['description']}")
                print()


class SkillScanner:
    """Scans OpenClaw skill directories for security issues."""

    SEVERITY_WEIGHTS = {
        "critical": 10,
        "high": 7,
        "medium": 4,
        "low": 1,
    }

    CONFIDENCE_MULTIPLIERS = {
        "high": 1.0,
        "medium": 0.6,
        "low": 0.3,
    }

    def __init__(self, patterns: PatternLoader):
        self.patterns = patterns
        self.findings: list[Finding] = []

    def scan_directory(self, skill_path: str) -> ScanReport:
        """Scan an entire skill directory."""
        skill_path = os.path.abspath(skill_path)
        if not os.path.isdir(skill_path):
            print(f"Error: Not a directory: {skill_path}", file=sys.stderr)
            sys.exit(1)

        skill_name = os.path.basename(skill_path)
        self.findings = []
        files_scanned = 0
        file_hashes = {}

        for root, _dirs, files in os.walk(skill_path):
            # Skip hidden directories and common non-code dirs
            _dirs[:] = [d for d in _dirs if not d.startswith(".") and d not in {"node_modules", "__pycache__", ".git", "venv", ".venv"}]

            for filename in files:
                filepath = os.path.join(root, filename)
                ext = os.path.splitext(filename)[1].lower()

                # Also scan extensionless files if they look like scripts
                if ext not in SCANNABLE_EXTENSIONS and ext != "":
                    continue

                # Skip files that are too large
                try:
                    if os.path.getsize(filepath) > MAX_FILE_SIZE:
                        continue
                except OSError:
                    continue

                rel_path = os.path.relpath(filepath, skill_path)
                file_hash = self._hash_file(filepath)
                if file_hash:
                    file_hashes[rel_path] = file_hash

                self._scan_file(filepath, rel_path)
                files_scanned += 1

        # Build report
        risk_score = self._calculate_risk_score()
        risk_level = self._risk_level(risk_score)
        category_summary = self._build_category_summary()

        report = ScanReport(
            scanner_version=__version__,
            scan_timestamp=datetime.now(timezone.utc).isoformat(),
            skill_path=skill_path,
            skill_name=skill_name,
            files_scanned=files_scanned,
            total_findings=len(self.findings),
            risk_score=round(risk_score, 1),
            risk_level=risk_level,
            findings=[asdict(f) for f in self.findings],
            category_summary=category_summary,
            file_hashes=file_hashes,
        )
        return report

    def _scan_file(self, filepath: str, rel_path: str):
        """Scan a single file for pattern matches."""
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except (OSError, PermissionError):
            return

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                # Skip empty lines and pure comments (but still scan
                # strings that contain comments with suspicious content)
                if stripped.startswith("#") and len(stripped) < 3:
                    continue

            for cat_id, cat_name, pattern in self.patterns.get_all_patterns():
                match = pattern["regex"].search(line)
                if match:
                    finding = Finding(
                        rule_id=pattern["id"],
                        rule_name=pattern["name"],
                        category=cat_name,
                        severity=pattern["severity"],
                        confidence=pattern["confidence"],
                        description=pattern["description"],
                        file_path=rel_path,
                        line_number=line_num,
                        line_content=stripped[:200],  # Truncate long lines
                        match_text=match.group(0)[:100],
                    )
                    self.findings.append(finding)

    def _hash_file(self, filepath: str) -> Optional[str]:
        """SHA256 hash of a file."""
        try:
            h = hashlib.sha256()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except (OSError, PermissionError):
            return None

    def _calculate_risk_score(self) -> float:
        """Calculate aggregate risk score from findings."""
        if not self.findings:
            return 0.0

        total = 0.0
        for f in self.findings:
            weight = self.SEVERITY_WEIGHTS.get(f.severity, 1)
            multiplier = self.CONFIDENCE_MULTIPLIERS.get(f.confidence, 0.3)
            total += weight * multiplier

        # Normalize: cap at 100
        score = min(total, 100.0)
        return score

    def _risk_level(self, score: float) -> str:
        """Convert numeric score to risk level."""
        if score == 0:
            return "clean"
        elif score < 10:
            return "low"
        elif score < 30:
            return "medium"
        elif score < 60:
            return "high"
        else:
            return "critical"

    def _build_category_summary(self) -> dict:
        """Summarize findings by category."""
        summary = {}
        for f in self.findings:
            cat = f.category
            if cat not in summary:
                summary[cat] = {"count": 0, "severities": {}}
            summary[cat]["count"] += 1
            sev = f.severity
            summary[cat]["severities"][sev] = summary[cat]["severities"].get(sev, 0) + 1
        return summary


def format_text_report(report: ScanReport) -> str:
    """Format report as human-readable text."""
    lines = []
    lines.append("=" * 60)
    lines.append("  ClawHub Security Scanner Report")
    lines.append("=" * 60)
    lines.append(f"  Skill: {report.skill_name}")
    lines.append(f"  Path:  {report.skill_path}")
    lines.append(f"  Time:  {report.scan_timestamp}")
    lines.append(f"  Files: {report.files_scanned} scanned")
    lines.append("")
    lines.append(f"  Risk Score: {report.risk_score}/100")
    lines.append(f"  Risk Level: {report.risk_level.upper()}")
    lines.append(f"  Findings:   {report.total_findings}")
    lines.append("=" * 60)

    if report.category_summary:
        lines.append("\n  Category Summary:")
        lines.append("  " + "-" * 40)
        for cat, data in report.category_summary.items():
            lines.append(f"    {cat}: {data['count']} findings")
            for sev, count in data["severities"].items():
                lines.append(f"      - {sev}: {count}")

    if report.findings:
        lines.append(f"\n  Detailed Findings ({len(report.findings)}):")
        lines.append("  " + "-" * 40)
        for i, f in enumerate(report.findings, 1):
            lines.append(f"\n  [{i}] {f['rule_id']} - {f['rule_name']}")
            lines.append(f"      Severity: {f['severity']} | Confidence: {f['confidence']}")
            lines.append(f"      Category: {f['category']}")
            lines.append(f"      File: {f['file_path']}:{f['line_number']}")
            lines.append(f"      Match: {f['match_text']}")
            lines.append(f"      Line: {f['line_content'][:120]}")
    else:
        lines.append("\n  ✅ No security findings detected.")

    lines.append("\n" + "=" * 60)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        prog="clawhub-scanner",
        description="ClawHub Security Scanner - Scan OpenClaw skills for malicious patterns",
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a skill directory")
    scan_parser.add_argument("directory", help="Path to skill directory")
    scan_parser.add_argument("--output", "-o", help="Output file path (default: stdout)")
    scan_parser.add_argument("--format", "-f", choices=["json", "text"], default="text",
                             help="Output format (default: text)")
    scan_parser.add_argument("--patterns", "-p", help="Path to patterns.json file")

    # list-patterns command
    list_parser = subparsers.add_parser("list-patterns", help="List all security patterns")
    list_parser.add_argument("--patterns", "-p", help="Path to patterns.json file")

    # version command
    subparsers.add_parser("version", help="Show scanner version")

    args = parser.parse_args()

    if args.command == "version":
        print(f"ClawHub Scanner v{__version__}")
        return

    if args.command == "list-patterns":
        loader = PatternLoader(getattr(args, "patterns", None))
        loader.list_patterns()
        return

    if args.command == "scan":
        loader = PatternLoader(getattr(args, "patterns", None))
        scanner = SkillScanner(loader)
        report = scanner.scan_directory(args.directory)

        if args.format == "json":
            output = json.dumps(asdict(report), indent=2)
        else:
            output = format_text_report(report)

        if args.output:
            with open(args.output, "w") as f:
                f.write(output)
            print(f"Report written to {args.output}")
        else:
            print(output)

        # Exit with non-zero if findings found
        sys.exit(1 if report.total_findings > 0 else 0)

    parser.print_help()


if __name__ == "__main__":
    main()
