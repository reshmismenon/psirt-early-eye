#!/usr/bin/env python3
"""
AI-Powered PSIRT-Early-Eye Orchestrator
Coordinates multiple AI agents to detect security vulnerabilities in PRs
"""

import os
import sys
import json
import argparse
from typing import Dict, List, Any
from datetime import datetime

# Import AI agents
from agents.dependency_agent import DependencyAgent
from agents.code_scanner_agent import CodeScannerAgent
from agents.cve_checker_agent import CVECheckerAgent
from agents.risk_assessment_agent import RiskAssessmentAgent


class PSIRTOrchestrator:
    """Main orchestrator for PSIRT-Early-Eye security scanning"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.pr_number = config.get('pr_number')
        self.repo_name = config.get('repo_name')
        
        # Initialize AI agents
        print("🤖 Initializing AI agents...")
        self.agents = {
            'dependency': DependencyAgent(config),
            'code_scanner': CodeScannerAgent(config),
            'cve_checker': CVECheckerAgent(config),
            'risk_assessor': RiskAssessmentAgent(config)
        }
        print("✅ All agents initialized successfully\n")
        
    def orchestrate_scan(self, changed_files: List[str]) -> Dict[str, Any]:
        """
        Main orchestration logic - coordinates all agents
        
        Args:
            changed_files: List of files changed in the PR
            
        Returns:
            Complete scan report with CVE scores and recommendations
        """
        print(f"🔍 Starting PSIRT-Early-Eye scan for PR #{self.pr_number}")
        print(f"📁 Analyzing {len(changed_files)} changed files\n")
        
        scan_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'pr_number': self.pr_number,
            'repo': self.repo_name,
            'changed_files': changed_files,
            'agent_results': {}
        }
        
        try:
            # Step 1: Dependency Analysis
            print("📦 Step 1/4: Analyzing dependencies...")
            dependency_results = self.agents['dependency'].scan(changed_files)
            scan_results['agent_results']['dependencies'] = dependency_results
            print(f"   Found {len(dependency_results.get('dependencies', []))} dependencies\n")
            
            # Step 2: Code Vulnerability Scanning
            print("🔎 Step 2/4: Scanning code for vulnerabilities...")
            code_scan_results = self.agents['code_scanner'].scan(changed_files)
            scan_results['agent_results']['code_vulnerabilities'] = code_scan_results
            print(f"   Found {len(code_scan_results.get('vulnerabilities', []))} potential issues\n")
            
            # Step 3: CVE Database Check
            print("🗄️  Step 3/4: Checking CVE databases...")
            cve_results = self.agents['cve_checker'].check(
                dependency_results.get('dependencies', [])
            )
            scan_results['agent_results']['cve_data'] = cve_results
            print(f"   Found {len(cve_results.get('cves', []))} CVE entries\n")
            
            # Step 4: AI Risk Assessment
            print("🧠 Step 4/4: Performing AI risk assessment...")
            risk_assessment = self.agents['risk_assessor'].assess(scan_results['agent_results'])
            scan_results['risk_assessment'] = risk_assessment
            print(f"   Risk Level: {risk_assessment.get('severity', 'UNKNOWN')}\n")
            
            # Generate final report
            final_report = self._generate_final_report(scan_results)
            
            print("=" * 60)
            print(f"✅ Scan Complete!")
            print(f"   Status: {final_report['status']}")
            print(f"   CVE Score: {final_report['cve_score']}")
            print(f"   Severity: {final_report['severity']}")
            print("=" * 60)
            
            return final_report
            
        except Exception as e:
            print(f"❌ Error during scan: {str(e)}")
            return self._generate_error_report(str(e))
    
    def _generate_final_report(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate final consolidated report"""
        risk_assessment = scan_results.get('risk_assessment', {})
        
        cve_score = risk_assessment.get('max_cve_score', 0.0)
        severity = risk_assessment.get('severity', 'UNKNOWN')
        
        # Determine action based on CVE score
        if cve_score >= 9.0:
            status = 'BLOCK'
            action = 'PR must be blocked - Critical vulnerability detected'
        elif cve_score >= 7.0:
            status = 'BLOCK'
            action = 'PR must be blocked - High severity vulnerability detected'
        elif cve_score >= 4.0:
            status = 'WARN'
            action = 'Security team review required before merge'
        else:
            status = 'PASS'
            action = 'No significant vulnerabilities detected'
        
        return {
            'status': status,
            'cve_score': cve_score,
            'severity': severity,
            'action': action,
            'timestamp': scan_results['timestamp'],
            'pr_number': scan_results['pr_number'],
            'repo': scan_results['repo'],
            'summary': {
                'total_dependencies': len(scan_results['agent_results'].get('dependencies', {}).get('dependencies', [])),
                'total_vulnerabilities': len(scan_results['agent_results'].get('code_vulnerabilities', {}).get('vulnerabilities', [])),
                'total_cves': len(scan_results['agent_results'].get('cve_data', {}).get('cves', [])),
            },
            'findings': risk_assessment.get('findings', []),
            'recommendations': risk_assessment.get('recommendations', []),
            'detailed_results': scan_results['agent_results']
        }
    
    def _generate_error_report(self, error_message: str) -> Dict[str, Any]:
        """Generate error report when scan fails"""
        return {
            'status': 'ERROR',
            'cve_score': 0.0,
            'severity': 'UNKNOWN',
            'action': 'Scan failed - manual review required',
            'error': error_message,
            'timestamp': datetime.utcnow().isoformat(),
            'pr_number': self.pr_number,
            'repo': self.repo_name
        }


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='AI-Powered PSIRT-Early-Eye Security Scanner'
    )
    parser.add_argument(
        '--pr-number',
        required=True,
        help='Pull request number'
    )
    parser.add_argument(
        '--changed-files',
        required=True,
        help='Comma-separated list of changed files'
    )
    parser.add_argument(
        '--base-branch',
        required=True,
        help='Base branch name'
    )
    parser.add_argument(
        '--head-branch',
        required=True,
        help='Head branch name'
    )
    parser.add_argument(
        '--repo',
        required=True,
        help='Repository name (owner/repo)'
    )
    parser.add_argument(
        '--output-file',
        default='psirt_early_eye_report.json',
        help='Output file for scan report'
    )
    
    return parser.parse_args()


def main():
    """Main entry point"""
    args = parse_arguments()
    
    # Parse changed files
    changed_files = [f.strip() for f in args.changed_files.split(',') if f.strip()]
    
    # Configuration
    config = {
        'pr_number': args.pr_number,
        'repo_name': args.repo,
        'base_branch': args.base_branch,
        'head_branch': args.head_branch,
        'watsonx_api_key': os.getenv('WATSONX_API_KEY'),
        'watsonx_project_id': os.getenv('WATSONX_PROJECT_ID'),
        'watsonx_url': os.getenv('WATSONX_URL', 'https://us-south.ml.cloud.ibm.com'),
        'github_token': os.getenv('GITHUB_TOKEN')
    }
    
    # Validate configuration
    if not config['watsonx_api_key']:
        print("❌ Error: WATSONX_API_KEY environment variable not set")
        sys.exit(1)
    
    # Create orchestrator and run scan
    orchestrator = PSIRTOrchestrator(config)
    report = orchestrator.orchestrate_scan(changed_files)
    
    # Save report to file
    with open(args.output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n📄 Report saved to: {args.output_file}")
    
    # Exit with appropriate code
    if report['status'] == 'BLOCK':
        sys.exit(1)
    elif report['status'] == 'ERROR':
        sys.exit(2)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()

# Made with Bob
