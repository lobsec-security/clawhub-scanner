"""Tests for ClawHub Scanner"""
import pytest
import json
import os
import sys

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import PatternLoader, ScanReport, Finding, SCANNABLE_EXTENSIONS


class TestPatternLoader:
    """Test pattern loading functionality"""
    
    def test_pattern_loader_initializes(self):
        """PatternLoader should initialize without error"""
        loader = PatternLoader()
        assert loader is not None
    
    def test_pattern_loader_has_categories(self):
        """Loaded patterns should have categories"""
        loader = PatternLoader()
        assert hasattr(loader, 'categories')
        assert isinstance(loader.categories, dict)
    
    def test_pattern_loader_has_version(self):
        """Pattern loader should have version info"""
        loader = PatternLoader()
        assert hasattr(loader, 'version')


class TestScanReport:
    """Test scan report data structure"""
    
    def test_scan_report_creation(self):
        """ScanReport should be creatable with required fields"""
        report = ScanReport(
            scanner_version="1.0.0",
            scan_timestamp="2026-02-05T00:00:00Z",
            skill_path="/test/path",
            skill_name="test-skill",
            files_scanned=5,
            total_findings=0,
            risk_score=0.0,
            risk_level="low"
        )
        assert report.skill_name == "test-skill"
        assert report.risk_level == "low"
    
    def test_scan_report_findings_list(self):
        """ScanReport should have empty findings list by default"""
        report = ScanReport(
            scanner_version="1.0.0",
            scan_timestamp="2026-02-05T00:00:00Z",
            skill_path="/test",
            skill_name="test",
            files_scanned=0,
            total_findings=0,
            risk_score=0.0,
            risk_level="low"
        )
        assert isinstance(report.findings, list)
        assert len(report.findings) == 0


class TestFinding:
    """Test finding data structure"""
    
    def test_finding_creation(self):
        """Finding should store all required fields"""
        finding = Finding(
            rule_id="EXEC001",
            rule_name="Shell Execution",
            category="code_execution",
            severity="high",
            confidence="high",
            description="Detected shell command execution",
            file_path="/test/script.py",
            line_number=42,
            line_content="os.system('rm -rf /')",
            match_text="os.system"
        )
        assert finding.severity == "high"
        assert finding.line_number == 42


class TestScannableExtensions:
    """Test file extension filtering"""
    
    def test_python_files_scannable(self):
        """Python files should be scannable"""
        assert ".py" in SCANNABLE_EXTENSIONS
    
    def test_javascript_files_scannable(self):
        """JavaScript files should be scannable"""
        assert ".js" in SCANNABLE_EXTENSIONS
    
    def test_markdown_files_scannable(self):
        """Markdown files should be scannable (for SKILL.md)"""
        assert ".md" in SCANNABLE_EXTENSIONS
    
    def test_shell_files_scannable(self):
        """Shell scripts should be scannable"""
        assert ".sh" in SCANNABLE_EXTENSIONS


class TestPatternFile:
    """Test patterns.json structure"""
    
    def test_patterns_json_exists(self):
        """patterns.json should exist"""
        patterns_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "patterns.json"
        )
        assert os.path.exists(patterns_path)
    
    def test_patterns_json_valid(self):
        """patterns.json should be valid JSON"""
        patterns_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "patterns.json"
        )
        with open(patterns_path) as f:
            data = json.load(f)
        assert "categories" in data or "version" in data


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
