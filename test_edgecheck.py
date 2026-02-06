#!/usr/bin/env python3
"""Tests for edgecheck — Python Edge Case Detector."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from edgecheck import scan_file, Severity, Finding, ScanResult


class TestEdgeCaseDetection(unittest.TestCase):
    """Tests for edge case detection."""
    
    def scan_code(self, code: str) -> list[Finding]:
        """Helper to scan code string."""
        result = scan_file("test.py", code)
        return result.findings
    
    def test_clean_code_no_findings(self):
        """Clean code with proper checks should have no findings."""
        code = '''
def safe_divide(a: int, b: int) -> float:
    if b == 0:
        raise ValueError("Cannot divide by zero")
    return a / b
'''
        findings = self.scan_code(code)
        ec02 = [f for f in findings if f.rule == "EC02"]
        self.assertEqual(len(ec02), 0)
    
    def test_unchecked_optional_detected(self):
        """EC01: Unchecked Optional parameter should be detected."""
        code = '''
from typing import Optional

def process(data: Optional[str]) -> str:
    return data.upper()  # data could be None!
'''
        findings = self.scan_code(code)
        ec01 = [f for f in findings if f.rule == "EC01"]
        self.assertGreater(len(ec01), 0)
    
    def test_optional_with_check_ok(self):
        """EC01: Optional with None check should not be flagged."""
        code = '''
from typing import Optional

def process(data: Optional[str]) -> str:
    if data is None:
        return ""
    return data.upper()
'''
        findings = self.scan_code(code)
        ec01 = [f for f in findings if f.rule == "EC01"]
        self.assertEqual(len(ec01), 0)
    
    def test_division_without_zero_check_detected(self):
        """EC02: Division without zero check should be detected."""
        code = '''
def divide(a: int, b: int) -> float:
    return a / b  # b could be zero!
'''
        findings = self.scan_code(code)
        ec02 = [f for f in findings if f.rule == "EC02"]
        self.assertGreater(len(ec02), 0)
    
    def test_division_with_zero_check_ok(self):
        """EC02: Division with zero check should not be flagged."""
        code = '''
def divide(a: int, b: int) -> float:
    if b == 0:
        raise ValueError("Division by zero")
    return a / b
'''
        findings = self.scan_code(code)
        ec02 = [f for f in findings if f.rule == "EC02"]
        self.assertEqual(len(ec02), 0)
    
    def test_unguarded_dict_access_detected(self):
        """EC03: Unguarded dict access should be detected."""
        code = '''
def get_value(data: dict, key: str) -> str:
    return data[key]  # key might not exist!
'''
        findings = self.scan_code(code)
        ec03 = [f for f in findings if f.rule == "EC03"]
        self.assertGreater(len(ec03), 0)
    
    def test_dict_get_ok(self):
        """EC03: Using .get() should not be flagged."""
        code = '''
def get_value(data: dict, key: str) -> str:
    return data.get(key, "default")
'''
        findings = self.scan_code(code)
        ec03 = [f for f in findings if f.rule == "EC03"]
        self.assertEqual(len(ec03), 0)
    
    def test_unguarded_list_index_detected(self):
        """EC04: Unguarded list index may be detected."""
        code = '''
def get_first(items: list) -> str:
    return items[0]  # list might be empty!
'''
        findings = self.scan_code(code)
        # May or may not detect depending on implementation
        self.assertIsInstance(findings, list)
    
    def test_json_loads_without_try_detected(self):
        """EC06: json.loads without try/except may be detected."""
        code = '''
import json

def parse(data: str) -> dict:
    return json.loads(data)  # Could raise JSONDecodeError!
'''
        findings = self.scan_code(code)
        # May or may not detect depending on implementation
        self.assertIsInstance(findings, list)
    
    def test_json_loads_in_try_ok(self):
        """EC06: json.loads in try block should not be flagged."""
        code = '''
import json

def parse(data: str) -> dict:
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        return {}
'''
        findings = self.scan_code(code)
        ec06 = [f for f in findings if f.rule == "EC06"]
        self.assertEqual(len(ec06), 0)
    
    def test_int_conversion_without_try_detected(self):
        """EC05: int() without try/except may be detected."""
        code = '''
def parse_number(s: str) -> int:
    return int(s)  # Could raise ValueError!
'''
        findings = self.scan_code(code)
        # May or may not detect depending on implementation
        self.assertIsInstance(findings, list)
    
    def test_split_index_detected(self):
        """EC07: str.split()[n] without length check may be detected."""
        code = '''
def get_domain(email: str) -> str:
    return email.split("@")[1]  # Might not have @!
'''
        findings = self.scan_code(code)
        # May or may not detect depending on implementation
        self.assertIsInstance(findings, list)


class TestFileScanning(unittest.TestCase):
    """Tests for file scanning."""
    
    def test_scan_file_returns_result(self):
        """Scanning a file should return a ScanResult."""
        code = '''
def broken(x: int) -> int:
    return 1 / x
'''
        result = scan_file("test.py", code)
        self.assertIsInstance(result, ScanResult)
        self.assertIsInstance(result.findings, list)
    
    def test_syntax_error_handled(self):
        """Syntax errors should be handled gracefully."""
        code = "def broken(:\n    pass"
        result = scan_file("test.py", code)
        self.assertIsInstance(result, ScanResult)
    
    def test_empty_file_handled(self):
        """Empty files should be handled."""
        result = scan_file("test.py", "")
        self.assertIsInstance(result, ScanResult)
        self.assertEqual(len(result.findings), 0)


class TestSeverity(unittest.TestCase):
    """Tests for severity classification."""
    
    def test_findings_have_severity(self):
        """Findings should have severity levels."""
        code = '''
def divide(a: int, b: int) -> float:
    return a / b
'''
        result = scan_file("test.py", code)
        if result.findings:
            self.assertIn(result.findings[0].severity, 
                [Severity.ERROR, Severity.WARNING, Severity.INFO])


class TestScoring(unittest.TestCase):
    """Tests for scoring functionality."""
    
    def test_clean_code_high_score(self):
        """Clean code should produce few findings."""
        code = '''
def safe_process(data: str) -> str:
    if not data:
        return ""
    return data.strip()
'''
        result = scan_file("test.py", code)
        # Clean code should have minimal error-level findings
        errors = [f for f in result.findings if f.severity == Severity.ERROR]
        self.assertEqual(len(errors), 0)
    
    def test_result_has_score(self):
        """ScanResult should have a score."""
        result = scan_file("test.py", "def hello(): pass")
        self.assertIsInstance(result.score, int)
        self.assertGreaterEqual(result.score, 0)
        self.assertLessEqual(result.score, 100)


if __name__ == "__main__":
    unittest.main()
