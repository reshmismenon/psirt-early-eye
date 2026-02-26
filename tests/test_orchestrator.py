#!/usr/bin/env python3
"""
Unit tests for PSIRT-Early-Eye Orchestrator
"""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from orchestrator import PSIRTOrchestrator


class TestPSIRTOrchestrator:
    """Test cases for PSIRT-Early-Eye Orchestrator"""
    
    @pytest.fixture
    def config(self):
        """Test configuration"""
        return {
            'pr_number': '123',
            'repo_name': 'test/repo',
            'base_branch': 'main',
            'head_branch': 'feature/test',
            'watsonx_api_key': 'test-key',
            'watsonx_project_id': 'test-project',
            'watsonx_url': 'https://test.ibm.com',
            'github_token': 'test-token'
        }
    
    @pytest.fixture
    def orchestrator(self, config):
        """Create orchestrator instance"""
        with patch('orchestrator.DependencyAgent'), \
             patch('orchestrator.CodeScannerAgent'), \
             patch('orchestrator.CVECheckerAgent'), \
             patch('orchestrator.RiskAssessmentAgent'):
            return PSIRTOrchestrator(config)
    
    def test_orchestrator_initialization(self, orchestrator):
        """Test orchestrator initializes correctly"""
        assert orchestrator.pr_number == '123'
        assert orchestrator.repo_name == 'test/repo'
        assert 'dependency' in orchestrator.agents
        assert 'code_scanner' in orchestrator.agents
        assert 'cve_checker' in orchestrator.agents
        assert 'risk_assessor' in orchestrator.agents
    
    def test_orchestrate_scan_with_no_vulnerabilities(self, orchestrator):
        """Test scan with no vulnerabilities found"""
        # Mock agent responses
        orchestrator.agents['dependency'].scan = Mock(return_value={
            'dependencies': [],
            'total_count': 0
        })
        orchestrator.agents['code_scanner'].scan = Mock(return_value={
            'vulnerabilities': [],
            'total_count': 0,
            'by_severity': {}
        })
        orchestrator.agents['cve_checker'].check = Mock(return_value={
            'cves': [],
            'max_cve_score': 0.0
        })
        orchestrator.agents['risk_assessor'].assess = Mock(return_value={
            'max_cve_score': 0.0,
            'severity': 'NONE',
            'findings': [],
            'recommendations': []
        })
        
        # Run scan
        result = orchestrator.orchestrate_scan(['test.js'])
        
        # Verify
        assert result['status'] == 'PASS'
        assert result['cve_score'] == 0.0
        assert result['severity'] == 'NONE'
    
    def test_orchestrate_scan_with_critical_cve(self, orchestrator):
        """Test scan with critical CVE"""
        # Mock critical CVE
        orchestrator.agents['dependency'].scan = Mock(return_value={
            'dependencies': [{'name': 'lodash', 'version': '4.17.0'}],
            'total_count': 1
        })
        orchestrator.agents['code_scanner'].scan = Mock(return_value={
            'vulnerabilities': [],
            'total_count': 0,
            'by_severity': {}
        })
        orchestrator.agents['cve_checker'].check = Mock(return_value={
            'cves': [{
                'cve_id': 'CVE-2021-23337',
                'cvss_score': 9.5,
                'severity': 'CRITICAL'
            }],
            'max_cve_score': 9.5
        })
        orchestrator.agents['risk_assessor'].assess = Mock(return_value={
            'max_cve_score': 9.5,
            'severity': 'CRITICAL',
            'findings': [{
                'type': 'CVE',
                'severity': 'CRITICAL',
                'title': 'Critical vulnerability'
            }],
            'recommendations': []
        })
        
        # Run scan
        result = orchestrator.orchestrate_scan(['package.json'])
        
        # Verify
        assert result['status'] == 'BLOCK'
        assert result['cve_score'] == 9.5
        assert result['severity'] == 'CRITICAL'
    
    def test_orchestrate_scan_with_high_severity(self, orchestrator):
        """Test scan with high severity issues"""
        orchestrator.agents['dependency'].scan = Mock(return_value={
            'dependencies': [],
            'total_count': 0
        })
        orchestrator.agents['code_scanner'].scan = Mock(return_value={
            'vulnerabilities': [{
                'type': 'sql_injection',
                'severity': 'HIGH'
            }],
            'total_count': 1,
            'by_severity': {'HIGH': 1}
        })
        orchestrator.agents['cve_checker'].check = Mock(return_value={
            'cves': [],
            'max_cve_score': 7.5
        })
        orchestrator.agents['risk_assessor'].assess = Mock(return_value={
            'max_cve_score': 7.5,
            'severity': 'HIGH',
            'findings': [],
            'recommendations': []
        })
        
        # Run scan
        result = orchestrator.orchestrate_scan(['app.js'])
        
        # Verify
        assert result['status'] == 'BLOCK'
        assert result['severity'] == 'HIGH'
    
    def test_orchestrate_scan_with_medium_severity(self, orchestrator):
        """Test scan with medium severity issues"""
        orchestrator.agents['dependency'].scan = Mock(return_value={
            'dependencies': [],
            'total_count': 0
        })
        orchestrator.agents['code_scanner'].scan = Mock(return_value={
            'vulnerabilities': [],
            'total_count': 0,
            'by_severity': {}
        })
        orchestrator.agents['cve_checker'].check = Mock(return_value={
            'cves': [],
            'max_cve_score': 5.0
        })
        orchestrator.agents['risk_assessor'].assess = Mock(return_value={
            'max_cve_score': 5.0,
            'severity': 'MEDIUM',
            'findings': [],
            'recommendations': []
        })
        
        # Run scan
        result = orchestrator.orchestrate_scan(['test.py'])
        
        # Verify
        assert result['status'] == 'WARN'
        assert result['severity'] == 'MEDIUM'
    
    def test_generate_error_report(self, orchestrator):
        """Test error report generation"""
        error_msg = "Test error"
        report = orchestrator._generate_error_report(error_msg)
        
        assert report['status'] == 'ERROR'
        assert report['error'] == error_msg
        assert report['pr_number'] == '123'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

# Made with Bob
