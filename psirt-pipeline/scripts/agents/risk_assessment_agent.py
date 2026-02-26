#!/usr/bin/env python3
"""
Risk Assessment Agent
Uses AI to perform comprehensive risk assessment and generate recommendations
"""

import os
from typing import Dict, List, Any


class RiskAssessmentAgent:
    """Agent for AI-powered risk assessment and decision making"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.watsonx_api_key = config.get('watsonx_api_key')
        self.watsonx_url = config.get('watsonx_url')
        self.watsonx_project_id = config.get('watsonx_project_id')
    
    def assess(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform comprehensive risk assessment using AI
        
        Args:
            scan_results: Combined results from all scanning agents
            
        Returns:
            Risk assessment with severity, findings, and recommendations
        """
        # Extract data from scan results
        dependencies = scan_results.get('dependencies', {})
        code_vulns = scan_results.get('code_vulnerabilities', {})
        cve_data = scan_results.get('cve_data', {})
        
        # Calculate maximum CVE score
        max_cve_score = cve_data.get('max_cve_score', 0.0)
        
        # Determine overall severity
        severity = self._determine_severity(max_cve_score, code_vulns, cve_data)
        
        # Aggregate all findings
        findings = self._aggregate_findings(dependencies, code_vulns, cve_data)
        
        # Generate AI-powered recommendations
        recommendations = self._generate_recommendations(findings, severity)
        
        # Calculate risk metrics
        risk_metrics = self._calculate_risk_metrics(scan_results)
        
        # AI contextual analysis
        ai_context = self._ai_contextual_analysis(scan_results)
        
        return {
            'max_cve_score': max_cve_score,
            'severity': severity,
            'findings': findings,
            'recommendations': recommendations,
            'risk_metrics': risk_metrics,
            'ai_context': ai_context,
            'summary': self._generate_summary(findings, severity, max_cve_score)
        }
    
    def _determine_severity(
        self, 
        max_cve_score: float, 
        code_vulns: Dict[str, Any],
        cve_data: Dict[str, Any]
    ) -> str:
        """Determine overall severity level"""
        
        # Check for critical CVEs
        if max_cve_score >= 9.0:
            return 'CRITICAL'
        
        # Check for critical code vulnerabilities
        code_severity = code_vulns.get('by_severity', {})
        if code_severity.get('CRITICAL', 0) > 0:
            return 'CRITICAL'
        
        # Check for high severity issues
        if max_cve_score >= 7.0:
            return 'HIGH'
        
        if code_severity.get('HIGH', 0) > 0:
            return 'HIGH'
        
        # Check for medium severity
        if max_cve_score >= 4.0:
            return 'MEDIUM'
        
        if code_severity.get('MEDIUM', 0) > 0:
            return 'MEDIUM'
        
        # Low or no issues
        if max_cve_score > 0 or code_severity.get('LOW', 0) > 0:
            return 'LOW'
        
        return 'NONE'
    
    def _aggregate_findings(
        self,
        dependencies: Dict[str, Any],
        code_vulns: Dict[str, Any],
        cve_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Aggregate all findings from different agents"""
        findings = []
        
        # Add CVE findings
        for cve in cve_data.get('cves', []):
            findings.append({
                'type': 'CVE',
                'severity': cve.get('severity', 'UNKNOWN'),
                'title': f"{cve.get('cve_id', 'Unknown')} in {cve.get('dependency', 'Unknown')}",
                'description': cve.get('description', 'No description'),
                'cvss_score': cve.get('cvss_score', 0.0),
                'affected_component': cve.get('dependency'),
                'remediation': f"Update to version {cve.get('fixed_versions', ['latest'])[0]}"
            })
        
        # Add code vulnerability findings
        for vuln in code_vulns.get('vulnerabilities', []):
            findings.append({
                'type': 'CODE_VULNERABILITY',
                'severity': vuln.get('severity', 'MEDIUM'),
                'title': f"{vuln.get('type', 'Unknown').replace('_', ' ').title()} in {vuln.get('file', 'Unknown')}",
                'description': f"Line {vuln.get('line', 0)}: {vuln.get('code', 'N/A')}",
                'location': f"{vuln.get('file')}:{vuln.get('line')}",
                'remediation': self._get_code_remediation(vuln.get('type'))
            })
        
        # Add dependency risk findings
        risky_deps = dependencies.get('risk_flags', [])
        for risk in risky_deps:
            findings.append({
                'type': 'DEPENDENCY_RISK',
                'severity': 'MEDIUM',
                'title': 'Risky Dependency Detected',
                'description': risk,
                'remediation': 'Review and update dependency'
            })
        
        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'NONE': 4}
        findings.sort(key=lambda x: severity_order.get(x.get('severity', 'NONE'), 5))
        
        return findings
    
    def _get_code_remediation(self, vuln_type: str) -> str:
        """Get remediation advice for code vulnerability"""
        remediation_map = {
            'sql_injection': 'Use parameterized queries or ORM with prepared statements',
            'xss': 'Sanitize user input, use Content Security Policy, encode output',
            'hardcoded_secrets': 'Move secrets to environment variables or secret manager',
            'insecure_crypto': 'Use SHA-256 or SHA-3 for hashing, AES-256 for encryption',
            'path_traversal': 'Validate and sanitize file paths, use allowlist',
            'command_injection': 'Avoid shell execution, use safe APIs with input validation'
        }
        return remediation_map.get(vuln_type, 'Review and fix security issue')
    
    def _generate_recommendations(
        self,
        findings: List[Dict[str, Any]],
        severity: str
    ) -> List[Dict[str, str]]:
        """Generate prioritized recommendations"""
        recommendations = []
        
        # Critical/High severity recommendations
        if severity in ['CRITICAL', 'HIGH']:
            recommendations.append({
                'priority': 'IMMEDIATE',
                'action': 'Block PR merge until critical issues are resolved',
                'reason': f'{severity} severity vulnerabilities detected'
            })
            
            recommendations.append({
                'priority': 'IMMEDIATE',
                'action': 'Notify security team for immediate review',
                'reason': 'High-risk vulnerabilities require expert assessment'
            })
        
        # Medium severity recommendations
        elif severity == 'MEDIUM':
            recommendations.append({
                'priority': 'HIGH',
                'action': 'Require security team approval before merge',
                'reason': 'Medium severity issues need review'
            })
        
        # Specific recommendations based on findings
        cve_findings = [f for f in findings if f['type'] == 'CVE']
        if cve_findings:
            recommendations.append({
                'priority': 'HIGH',
                'action': f'Update {len(cve_findings)} vulnerable dependencies',
                'reason': 'Known CVEs present in dependencies'
            })
        
        code_vulns = [f for f in findings if f['type'] == 'CODE_VULNERABILITY']
        if code_vulns:
            recommendations.append({
                'priority': 'HIGH',
                'action': f'Fix {len(code_vulns)} code vulnerabilities',
                'reason': 'Security issues detected in source code'
            })
        
        # General recommendations
        recommendations.append({
            'priority': 'MEDIUM',
            'action': 'Run security tests in staging environment',
            'reason': 'Validate fixes before production deployment'
        })
        
        recommendations.append({
            'priority': 'LOW',
            'action': 'Update security documentation',
            'reason': 'Document security changes and decisions'
        })
        
        return recommendations
    
    def _calculate_risk_metrics(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate various risk metrics"""
        cve_data = scan_results.get('cve_data', {})
        code_vulns = scan_results.get('code_vulnerabilities', {})
        
        return {
            'total_vulnerabilities': (
                len(cve_data.get('cves', [])) + 
                len(code_vulns.get('vulnerabilities', []))
            ),
            'critical_count': (
                len(cve_data.get('critical_cves', [])) +
                code_vulns.get('by_severity', {}).get('CRITICAL', 0)
            ),
            'high_count': (
                len(cve_data.get('high_cves', [])) +
                code_vulns.get('by_severity', {}).get('HIGH', 0)
            ),
            'exploitable_count': sum(
                1 for cve in cve_data.get('cves', [])
                if cve.get('ai_analysis', {}).get('exploit_available', False)
            ),
            'risk_score': self._calculate_risk_score(scan_results)
        }
    
    def _calculate_risk_score(self, scan_results: Dict[str, Any]) -> float:
        """Calculate overall risk score (0-100)"""
        cve_data = scan_results.get('cve_data', {})
        code_vulns = scan_results.get('code_vulnerabilities', {})
        
        # Weight factors
        max_cve_score = cve_data.get('max_cve_score', 0.0)
        critical_count = len(cve_data.get('critical_cves', []))
        high_count = len(cve_data.get('high_cves', []))
        code_critical = code_vulns.get('by_severity', {}).get('CRITICAL', 0)
        
        # Calculate weighted risk score
        risk_score = (
            (max_cve_score * 10) +  # Max CVE contributes heavily
            (critical_count * 15) +  # Each critical CVE adds 15 points
            (high_count * 8) +       # Each high CVE adds 8 points
            (code_critical * 12)     # Each critical code vuln adds 12 points
        )
        
        # Cap at 100
        return min(risk_score, 100.0)
    
    def _ai_contextual_analysis(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform AI-powered contextual analysis
        In production, this would call watsonx AI for deep analysis
        """
        
        # This would use watsonx AI to:
        # 1. Understand the business context
        # 2. Assess real-world exploitability
        # 3. Prioritize based on attack surface
        # 4. Consider compensating controls
        # 5. Provide strategic recommendations
        
        return {
            'attack_surface_analysis': self._analyze_attack_surface(scan_results),
            'exploit_likelihood': self._assess_exploit_likelihood(scan_results),
            'business_context': self._assess_business_context(scan_results),
            'compensating_controls': self._identify_compensating_controls(scan_results)
        }
    
    def _analyze_attack_surface(self, scan_results: Dict[str, Any]) -> str:
        """Analyze the attack surface"""
        code_vulns = scan_results.get('code_vulnerabilities', {})
        
        if code_vulns.get('by_severity', {}).get('CRITICAL', 0) > 0:
            return 'HIGH - Critical vulnerabilities expose significant attack surface'
        elif code_vulns.get('by_severity', {}).get('HIGH', 0) > 0:
            return 'MEDIUM - Some attack vectors present'
        else:
            return 'LOW - Limited attack surface'
    
    def _assess_exploit_likelihood(self, scan_results: Dict[str, Any]) -> str:
        """Assess likelihood of exploitation"""
        cve_data = scan_results.get('cve_data', {})
        max_score = cve_data.get('max_cve_score', 0.0)
        
        if max_score >= 9.0:
            return 'HIGH - Exploits likely available, active exploitation possible'
        elif max_score >= 7.0:
            return 'MEDIUM - Exploitation possible with moderate effort'
        else:
            return 'LOW - Exploitation requires specific conditions'
    
    def _assess_business_context(self, scan_results: Dict[str, Any]) -> str:
        """Assess business impact context"""
        # In production, AI would consider:
        # - Application criticality
        # - Data sensitivity
        # - User base size
        # - Regulatory requirements
        
        return 'Standard business impact - follow security policies'
    
    def _identify_compensating_controls(self, scan_results: Dict[str, Any]) -> List[str]:
        """Identify possible compensating controls"""
        controls = []
        
        cve_data = scan_results.get('cve_data', {})
        if cve_data.get('cves'):
            controls.append('WAF rules to block known exploit patterns')
            controls.append('Network segmentation to limit blast radius')
            controls.append('Enhanced monitoring and alerting')
        
        return controls
    
    def _generate_summary(
        self,
        findings: List[Dict[str, Any]],
        severity: str,
        max_cve_score: float
    ) -> str:
        """Generate executive summary"""
        
        critical_count = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
        high_count = sum(1 for f in findings if f.get('severity') == 'HIGH')
        
        if severity == 'CRITICAL':
            return (
                f"🚨 CRITICAL: {critical_count} critical vulnerabilities detected "
                f"(Max CVE Score: {max_cve_score}). Immediate action required. "
                f"PR must be blocked until issues are resolved."
            )
        elif severity == 'HIGH':
            return (
                f"⚠️ HIGH: {high_count} high-severity vulnerabilities detected "
                f"(Max CVE Score: {max_cve_score}). Security review required before merge."
            )
        elif severity == 'MEDIUM':
            return (
                f"⚠️ MEDIUM: {len(findings)} vulnerabilities detected "
                f"(Max CVE Score: {max_cve_score}). Review and approval needed."
            )
        elif severity == 'LOW':
            return (
                f"ℹ️ LOW: {len(findings)} minor issues detected. "
                f"Consider addressing in future updates."
            )
        else:
            return "✅ No significant security vulnerabilities detected."

# Made with Bob
