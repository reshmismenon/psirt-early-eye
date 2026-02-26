#!/usr/bin/env python3
"""
Code Vulnerability Scanner Agent
Scans source code for security vulnerabilities using AI
"""

import os
import re
from typing import Dict, List, Any
from pathlib import Path


class CodeScannerAgent:
    """Agent for scanning code for security vulnerabilities"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.watsonx_api_key = config.get('watsonx_api_key')
        self.watsonx_url = config.get('watsonx_url')
        
        # Vulnerability patterns to check
        self.vulnerability_patterns = {
            'sql_injection': [
                r'execute\s*\(\s*["\'].*?\+.*?["\']',
                r'query\s*\(\s*["\'].*?\+.*?["\']',
                r'SELECT.*?FROM.*?\+',
            ],
            'xss': [
                r'innerHTML\s*=',
                r'document\.write\s*\(',
                r'eval\s*\(',
            ],
            'hardcoded_secrets': [
                r'password\s*=\s*["\'][^"\']+["\']',
                r'api[_-]?key\s*=\s*["\'][^"\']+["\']',
                r'secret\s*=\s*["\'][^"\']+["\']',
                r'token\s*=\s*["\'][^"\']+["\']',
            ],
            'insecure_crypto': [
                r'MD5\s*\(',
                r'SHA1\s*\(',
                r'DES\s*\(',
            ],
            'path_traversal': [
                r'\.\./',
                r'\.\.\\',
            ],
            'command_injection': [
                r'exec\s*\(',
                r'system\s*\(',
                r'shell_exec\s*\(',
            ]
        }
        
        # File extensions to scan
        self.scannable_extensions = {
            '.py', '.js', '.ts', '.java', '.go', '.rb', '.php',
            '.c', '.cpp', '.cs', '.swift', '.kt', '.rs', '.jsx', '.tsx'
        }
    
    def scan(self, changed_files: List[str]) -> Dict[str, Any]:
        """
        Scan changed files for code vulnerabilities
        
        Args:
            changed_files: List of file paths that changed in PR
            
        Returns:
            Dictionary containing vulnerability scan results
        """
        vulnerabilities = []
        scanned_files = []
        
        for file_path in changed_files:
            ext = Path(file_path).suffix
            if ext in self.scannable_extensions and os.path.exists(file_path):
                scanned_files.append(file_path)
                file_vulns = self._scan_file(file_path)
                vulnerabilities.extend(file_vulns)
        
        # AI-powered deep analysis
        ai_analysis = self._ai_deep_scan(scanned_files, vulnerabilities)
        
        return {
            'scanned_files': scanned_files,
            'vulnerabilities': vulnerabilities,
            'total_count': len(vulnerabilities),
            'by_severity': self._categorize_by_severity(vulnerabilities),
            'ai_analysis': ai_analysis
        }
    
    def _scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Scan a single file for vulnerabilities"""
        vulnerabilities = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            for line_num, line in enumerate(lines, 1):
                # Check each vulnerability pattern
                for vuln_type, patterns in self.vulnerability_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            vulnerabilities.append({
                                'type': vuln_type,
                                'file': file_path,
                                'line': line_num,
                                'code': line.strip(),
                                'pattern': pattern,
                                'severity': self._get_severity(vuln_type)
                            })
        
        except Exception as e:
            print(f"Warning: Failed to scan {file_path}: {e}")
        
        return vulnerabilities
    
    def _get_severity(self, vuln_type: str) -> str:
        """Determine severity level for vulnerability type"""
        severity_map = {
            'sql_injection': 'CRITICAL',
            'command_injection': 'CRITICAL',
            'xss': 'HIGH',
            'hardcoded_secrets': 'HIGH',
            'insecure_crypto': 'MEDIUM',
            'path_traversal': 'HIGH'
        }
        return severity_map.get(vuln_type, 'MEDIUM')
    
    def _categorize_by_severity(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """Categorize vulnerabilities by severity"""
        categories = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'MEDIUM')
            categories[severity] = categories.get(severity, 0) + 1
        
        return categories
    
    def _ai_deep_scan(self, files: List[str], basic_vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Perform AI-powered deep analysis of code
        This would call watsonx AI in production
        """
        
        # Simulate AI analysis
        analysis = {
            'confidence_scores': {},
            'false_positive_likelihood': {},
            'additional_findings': [],
            'context_analysis': {}
        }
        
        # In production, this would:
        # 1. Send code snippets to watsonx AI
        # 2. Get semantic understanding of code
        # 3. Identify context-aware vulnerabilities
        # 4. Reduce false positives
        # 5. Provide remediation suggestions
        
        for vuln in basic_vulns:
            vuln_key = f"{vuln['file']}:{vuln['line']}"
            
            # Simulate confidence scoring
            if vuln['type'] in ['sql_injection', 'command_injection']:
                analysis['confidence_scores'][vuln_key] = 0.95
            else:
                analysis['confidence_scores'][vuln_key] = 0.75
            
            # Simulate false positive detection
            if 'test' in vuln['file'].lower() or 'mock' in vuln['file'].lower():
                analysis['false_positive_likelihood'][vuln_key] = 0.8
            else:
                analysis['false_positive_likelihood'][vuln_key] = 0.2
        
        # AI would also find additional issues not caught by regex
        analysis['additional_findings'] = self._ai_find_logic_flaws(files)
        
        return analysis
    
    def _ai_find_logic_flaws(self, files: List[str]) -> List[Dict[str, Any]]:
        """
        Use AI to find logic flaws and business logic vulnerabilities
        This requires semantic understanding of code
        """
        findings = []
        
        # In production, AI would analyze:
        # - Authentication bypass opportunities
        # - Authorization flaws
        # - Race conditions
        # - Business logic errors
        # - Insecure defaults
        
        for file_path in files:
            if not os.path.exists(file_path):
                continue
                
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Simple heuristics (AI would do much better)
                if 'authenticate' in content.lower() and 'return true' in content.lower():
                    findings.append({
                        'type': 'authentication_bypass',
                        'file': file_path,
                        'severity': 'CRITICAL',
                        'description': 'Potential authentication bypass detected',
                        'confidence': 0.6
                    })
                
                if 'admin' in content.lower() and 'role' not in content.lower():
                    findings.append({
                        'type': 'authorization_flaw',
                        'file': file_path,
                        'severity': 'HIGH',
                        'description': 'Potential missing authorization check',
                        'confidence': 0.5
                    })
            
            except Exception as e:
                print(f"Warning: Failed to analyze {file_path}: {e}")
        
        return findings
    
    def _generate_remediation(self, vuln: Dict[str, Any]) -> str:
        """Generate remediation advice for vulnerability"""
        remediation_map = {
            'sql_injection': 'Use parameterized queries or prepared statements',
            'xss': 'Sanitize user input and use Content Security Policy',
            'hardcoded_secrets': 'Use environment variables or secret management service',
            'insecure_crypto': 'Use modern cryptographic algorithms (SHA-256, AES-256)',
            'path_traversal': 'Validate and sanitize file paths',
            'command_injection': 'Avoid shell execution, use safe APIs'
        }
        
        return remediation_map.get(vuln['type'], 'Review and fix the security issue')

# Made with Bob
