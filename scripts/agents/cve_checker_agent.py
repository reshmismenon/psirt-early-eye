#!/usr/bin/env python3
"""
CVE Database Checker Agent
Checks dependencies against CVE databases for known vulnerabilities
"""

import os
import json
import requests
from typing import Dict, List, Any
from datetime import datetime


class CVECheckerAgent:
    """Agent for checking CVE databases for vulnerability information"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.watsonx_api_key = config.get('watsonx_api_key')
        
        # CVE data sources
        self.data_sources = {
            'nvd': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
            'github': 'https://api.github.com/advisories',
            'osv': 'https://api.osv.dev/v1/query'
        }
        
        # CVE severity scoring
        self.severity_thresholds = {
            'CRITICAL': (9.0, 10.0),
            'HIGH': (7.0, 8.9),
            'MEDIUM': (4.0, 6.9),
            'LOW': (0.1, 3.9),
            'NONE': (0.0, 0.0)
        }
    
    def check(self, dependencies: List[Dict[str, str]]) -> Dict[str, Any]:
        """
        Check dependencies against CVE databases
        
        Args:
            dependencies: List of dependency dictionaries
            
        Returns:
            Dictionary containing CVE check results
        """
        cve_results = []
        max_cve_score = 0.0
        
        print(f"   Checking {len(dependencies)} dependencies against CVE databases...")
        
        for dep in dependencies:
            cves = self._check_dependency(dep)
            if cves:
                cve_results.extend(cves)
                
                # Track maximum CVE score
                for cve in cves:
                    score = cve.get('cvss_score', 0.0)
                    if score > max_cve_score:
                        max_cve_score = score
        
        # AI enrichment of CVE data
        enriched_results = self._ai_enrich_cve_data(cve_results)
        
        return {
            'cves': enriched_results,
            'total_cves': len(enriched_results),
            'max_cve_score': max_cve_score,
            'severity_distribution': self._calculate_severity_distribution(enriched_results),
            'critical_cves': [cve for cve in enriched_results if cve.get('severity') == 'CRITICAL'],
            'high_cves': [cve for cve in enriched_results if cve.get('severity') == 'HIGH']
        }
    
    def _check_dependency(self, dependency: Dict[str, str]) -> List[Dict[str, Any]]:
        """Check a single dependency for CVEs"""
        cves = []
        
        # Check OSV database (open source vulnerabilities)
        osv_cves = self._check_osv(dependency)
        cves.extend(osv_cves)
        
        # Check GitHub Advisory Database
        github_cves = self._check_github_advisory(dependency)
        cves.extend(github_cves)
        
        # Check NVD (National Vulnerability Database)
        nvd_cves = self._check_nvd(dependency)
        cves.extend(nvd_cves)
        
        return cves
    
    def _check_osv(self, dependency: Dict[str, str]) -> List[Dict[str, Any]]:
        """Check OSV database for vulnerabilities"""
        cves = []
        
        try:
            # Prepare query based on package ecosystem
            ecosystem_map = {
                'npm': 'npm',
                'python': 'PyPI',
                'maven': 'Maven',
                'go': 'Go',
                'rust': 'crates.io',
                'php': 'Packagist'
            }
            
            ecosystem = ecosystem_map.get(dependency['type'], dependency['type'])
            
            query = {
                'package': {
                    'name': dependency['name'],
                    'ecosystem': ecosystem
                },
                'version': dependency['version']
            }
            
            # In production, make actual API call
            # response = requests.post(self.data_sources['osv'], json=query, timeout=10)
            # if response.status_code == 200:
            #     data = response.json()
            #     for vuln in data.get('vulns', []):
            #         cves.append(self._parse_osv_vulnerability(vuln, dependency))
            
            # Simulated response for demo
            cves.extend(self._simulate_osv_check(dependency))
            
        except Exception as e:
            print(f"   Warning: OSV check failed for {dependency['name']}: {e}")
        
        return cves
    
    def _check_github_advisory(self, dependency: Dict[str, str]) -> List[Dict[str, Any]]:
        """Check GitHub Advisory Database"""
        cves = []
        
        try:
            # In production, query GitHub Advisory API
            # This requires authentication and proper API calls
            
            # Simulated check
            cves.extend(self._simulate_github_check(dependency))
            
        except Exception as e:
            print(f"   Warning: GitHub Advisory check failed for {dependency['name']}: {e}")
        
        return cves
    
    def _check_nvd(self, dependency: Dict[str, str]) -> List[Dict[str, Any]]:
        """Check National Vulnerability Database"""
        cves = []
        
        try:
            # In production, query NVD API
            # Note: NVD has rate limits and requires API key
            
            # Simulated check
            cves.extend(self._simulate_nvd_check(dependency))
            
        except Exception as e:
            print(f"   Warning: NVD check failed for {dependency['name']}: {e}")
        
        return cves
    
    def _simulate_osv_check(self, dependency: Dict[str, str]) -> List[Dict[str, Any]]:
        """Simulate OSV database check (for demo purposes)"""
        # Simulate finding CVEs for certain packages
        risky_packages = {
            'lodash': {'cve': 'CVE-2021-23337', 'score': 7.2, 'description': 'Prototype pollution'},
            'log4j': {'cve': 'CVE-2021-44228', 'score': 10.0, 'description': 'Remote code execution'},
            'jackson-databind': {'cve': 'CVE-2020-36518', 'score': 7.5, 'description': 'Deserialization vulnerability'},
            'spring-core': {'cve': 'CVE-2022-22965', 'score': 9.8, 'description': 'Spring4Shell RCE'},
        }
        
        cves = []
        for pkg_name, cve_info in risky_packages.items():
            if pkg_name.lower() in dependency['name'].lower():
                cves.append({
                    'cve_id': cve_info['cve'],
                    'cvss_score': cve_info['score'],
                    'severity': self._score_to_severity(cve_info['score']),
                    'description': cve_info['description'],
                    'dependency': dependency['name'],
                    'version': dependency['version'],
                    'source': 'OSV',
                    'published_date': '2021-01-01',
                    'fixed_versions': [self._suggest_fixed_version(dependency['version'])]
                })
        
        return cves
    
    def _simulate_github_check(self, dependency: Dict[str, str]) -> List[Dict[str, Any]]:
        """Simulate GitHub Advisory check"""
        return []  # Most CVEs already covered by OSV
    
    def _simulate_nvd_check(self, dependency: Dict[str, str]) -> List[Dict[str, Any]]:
        """Simulate NVD check"""
        return []  # Most CVEs already covered by OSV
    
    def _score_to_severity(self, score: float) -> str:
        """Convert CVSS score to severity level"""
        for severity, (min_score, max_score) in self.severity_thresholds.items():
            if min_score <= score <= max_score:
                return severity
        return 'UNKNOWN'
    
    def _suggest_fixed_version(self, current_version: str) -> str:
        """Suggest a fixed version (simplified)"""
        try:
            parts = current_version.split('.')
            if len(parts) >= 2:
                major = int(parts[0])
                minor = int(parts[1])
                return f"{major}.{minor + 1}.0"
        except:
            pass
        return "latest"
    
    def _calculate_severity_distribution(self, cves: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate distribution of CVEs by severity"""
        distribution = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'NONE': 0}
        
        for cve in cves:
            severity = cve.get('severity', 'UNKNOWN')
            if severity in distribution:
                distribution[severity] += 1
        
        return distribution
    
    def _ai_enrich_cve_data(self, cves: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Use AI to enrich CVE data with context and impact analysis
        In production, this would call watsonx AI
        """
        enriched = []
        
        for cve in cves:
            # AI would provide:
            # 1. Exploitability assessment
            # 2. Business impact analysis
            # 3. Remediation priority
            # 4. Contextual risk scoring
            
            enriched_cve = cve.copy()
            
            # Simulate AI enrichment
            enriched_cve['ai_analysis'] = {
                'exploitability': self._assess_exploitability(cve),
                'business_impact': self._assess_business_impact(cve),
                'remediation_priority': self._calculate_priority(cve),
                'exploit_available': self._check_exploit_availability(cve),
                'patch_available': True if cve.get('fixed_versions') else False
            }
            
            enriched.append(enriched_cve)
        
        return enriched
    
    def _assess_exploitability(self, cve: Dict[str, Any]) -> str:
        """Assess how easily the vulnerability can be exploited"""
        score = cve.get('cvss_score', 0)
        
        if score >= 9.0:
            return 'HIGH - Easily exploitable, likely automated attacks'
        elif score >= 7.0:
            return 'MEDIUM - Exploitable with moderate effort'
        else:
            return 'LOW - Requires specific conditions'
    
    def _assess_business_impact(self, cve: Dict[str, Any]) -> str:
        """Assess business impact of the vulnerability"""
        severity = cve.get('severity', 'UNKNOWN')
        
        impact_map = {
            'CRITICAL': 'SEVERE - Potential data breach, system compromise',
            'HIGH': 'SIGNIFICANT - Service disruption, data exposure',
            'MEDIUM': 'MODERATE - Limited impact, requires mitigation',
            'LOW': 'MINIMAL - Low risk, monitor for updates'
        }
        
        return impact_map.get(severity, 'UNKNOWN')
    
    def _calculate_priority(self, cve: Dict[str, Any]) -> str:
        """Calculate remediation priority"""
        score = cve.get('cvss_score', 0)
        
        if score >= 9.0:
            return 'P0 - Immediate action required'
        elif score >= 7.0:
            return 'P1 - Fix within 24 hours'
        elif score >= 4.0:
            return 'P2 - Fix within 1 week'
        else:
            return 'P3 - Fix in next release'
    
    def _check_exploit_availability(self, cve: Dict[str, Any]) -> bool:
        """Check if public exploits are available"""
        # In production, check exploit databases
        # For now, assume high-severity CVEs have exploits
        return cve.get('cvss_score', 0) >= 8.0

# Made with Bob
