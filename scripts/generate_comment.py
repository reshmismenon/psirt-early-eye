#!/usr/bin/env python3
"""
Generate PR Comment from PSIRT-Early-Eye Scan Report
Creates a formatted markdown comment for GitHub PR
"""

import json
import argparse
from typing import Dict, Any


def generate_comment(report: Dict[str, Any]) -> str:
    """Generate formatted PR comment from scan report"""
    
    status = report.get('status', 'UNKNOWN')
    severity = report.get('severity', 'UNKNOWN')
    cve_score = report.get('cve_score', 0.0)
    summary_text = report.get('summary', {})
    
    # Header with status emoji
    status_emoji = {
        'PASS': '✅',
        'WARN': '⚠️',
        'BLOCK': '🚨',
        'ERROR': '❌'
    }
    
    emoji = status_emoji.get(status, '❓')
    
    comment = f"""## {emoji} PSIRT-Early-Eye Security Scan Results

**Status:** {status}  
**Severity:** {severity}  
**Max CVE Score:** {cve_score:.1f}/10.0

---

"""
    
    # Summary section
    if isinstance(summary_text, str):
        comment += f"### Summary\n\n{summary_text}\n\n---\n\n"
    
    # Metrics
    summary = report.get('summary', {})
    comment += f"""### Scan Metrics

| Metric | Count |
|--------|-------|
| Dependencies Scanned | {summary.get('total_dependencies', 0)} |
| Code Vulnerabilities | {summary.get('total_vulnerabilities', 0)} |
| CVEs Found | {summary.get('total_cves', 0)} |

---

"""
    
    # Findings
    findings = report.get('findings', [])
    if findings:
        comment += "### 🔍 Findings\n\n"
        
        # Group by severity
        critical = [f for f in findings if f.get('severity') == 'CRITICAL']
        high = [f for f in findings if f.get('severity') == 'HIGH']
        medium = [f for f in findings if f.get('severity') == 'MEDIUM']
        
        if critical:
            comment += f"#### 🚨 Critical ({len(critical)})\n\n"
            for finding in critical[:5]:  # Show top 5
                comment += format_finding(finding)
            if len(critical) > 5:
                comment += f"\n*...and {len(critical) - 5} more critical findings*\n"
            comment += "\n"
        
        if high:
            comment += f"#### ⚠️ High ({len(high)})\n\n"
            for finding in high[:5]:  # Show top 5
                comment += format_finding(finding)
            if len(high) > 5:
                comment += f"\n*...and {len(high) - 5} more high findings*\n"
            comment += "\n"
        
        if medium:
            comment += f"#### ℹ️ Medium ({len(medium)})\n\n"
            for finding in medium[:3]:  # Show top 3
                comment += format_finding(finding)
            if len(medium) > 3:
                comment += f"\n*...and {len(medium) - 3} more medium findings*\n"
            comment += "\n"
        
        comment += "---\n\n"
    
    # Recommendations
    recommendations = report.get('recommendations', [])
    if recommendations:
        comment += "### 📋 Recommendations\n\n"
        
        for rec in recommendations[:5]:  # Show top 5
            priority = rec.get('priority', 'UNKNOWN')
            action = rec.get('action', 'No action specified')
            reason = rec.get('reason', '')
            
            priority_emoji = {
                'IMMEDIATE': '🔴',
                'HIGH': '🟠',
                'MEDIUM': '🟡',
                'LOW': '🟢'
            }
            
            comment += f"{priority_emoji.get(priority, '⚪')} **{priority}:** {action}\n"
            if reason:
                comment += f"   *{reason}*\n"
            comment += "\n"
        
        comment += "---\n\n"
    
    # Action required
    if status == 'BLOCK':
        comment += """### ❌ Action Required

This PR is **BLOCKED** due to critical or high severity vulnerabilities.

**Next Steps:**
1. Review the findings above
2. Fix critical and high severity issues
3. Update dependencies to patched versions
4. Re-run the security scan
5. Contact the security team if you need assistance

**Do not merge this PR until all critical issues are resolved.**

"""
    elif status == 'WARN':
        comment += """### ⚠️ Security Review Required

This PR requires security team approval before merging.

**Next Steps:**
1. Review the findings above
2. Address medium severity issues if possible
3. Request security team review
4. Wait for approval before merging

"""
    else:
        comment += """### ✅ Security Scan Passed

No significant security vulnerabilities detected. You may proceed with the merge after standard code review.

"""
    
    # Footer
    comment += """---

<details>
<summary>📊 View Detailed Report</summary>

**Download Full Report:**
1. Go to [Actions](../../actions) tab
2. Click on this workflow run
3. Scroll to **Artifacts** section
4. Download **psirt-security-report.zip**

The report includes:
- `psirt_report.json` - Complete scan results with all details
- `pr_comment.md` - This formatted report

</details>

*Powered by AI-Driven PSIRT-Early-Eye Security Scanner*
"""
    
    return comment


def format_finding(finding: Dict[str, Any]) -> str:
    """Format a single finding for display"""
    title = finding.get('title', 'Unknown Issue')
    description = finding.get('description', 'No description')
    remediation = finding.get('remediation', 'No remediation available')
    
    # Truncate long descriptions
    if len(description) > 200:
        description = description[:197] + "..."
    
    output = f"**{title}**\n"
    output += f"- {description}\n"
    output += f"- *Fix:* {remediation}\n\n"
    
    return output


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Generate PR comment from PSIRT-Early-Eye report')
    parser.add_argument('--report-file', required=True, help='Path to PSIRT-Early-Eye report JSON')
    parser.add_argument('--output-file', required=True, help='Path to output markdown file')
    
    args = parser.parse_args()
    
    # Load report
    with open(args.report_file, 'r') as f:
        report = json.load(f)
    
    # Generate comment
    comment = generate_comment(report)
    
    # Save to file
    with open(args.output_file, 'w') as f:
        f.write(comment)
    
    print(f"✅ PR comment generated: {args.output_file}")


if __name__ == '__main__':
    main()

# Made with Bob
