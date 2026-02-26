# AI-Powered PSIRT-Early-Eye Security Scanner

An intelligent security scanning system for CI/CD pipelines that uses AI agents to detect vulnerabilities, check CVE databases, and provide actionable security insights before code is merged.

## 🎯 Overview

This PSIRT (Product Security Incident Response Team) scanner integrates into your GitHub Actions workflow to automatically scan pull requests for security vulnerabilities. It uses multiple specialized AI agents orchestrated together to provide comprehensive security analysis.

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Orchestrator                         │
│              (Coordinates all agents)                   │
└─────────────────────────────────────────────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
        ▼                 ▼                 ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│  Dependency  │  │     Code     │  │     CVE      │
│   Analyzer   │  │   Scanner    │  │   Checker    │
└──────────────┘  └──────────────┘  └──────────────┘
        │                 │                 │
        └─────────────────┼─────────────────┘
                          ▼
                  ┌──────────────┐
                  │     Risk     │
                  │  Assessment  │
                  └──────────────┘
                          │
                          ▼
                  ┌──────────────┐
                  │    Report    │
                  │  Generation  │
                  └──────────────┘
```

## 🤖 AI Agents

### 1. **Dependency Analyzer Agent**
- Parses dependency files (package.json, pom.xml, requirements.txt, etc.)
- Identifies outdated and risky packages
- Supports multiple package ecosystems (npm, Maven, Python, Go, Rust, PHP)

### 2. **Code Scanner Agent**
- Scans source code for security vulnerabilities
- Detects: SQL injection, XSS, hardcoded secrets, insecure crypto, command injection
- Uses pattern matching + AI-powered semantic analysis

### 3. **CVE Checker Agent**
- Queries multiple CVE databases (NVD, OSV, GitHub Advisory)
- Calculates CVSS scores
- Identifies exploitable vulnerabilities

### 4. **Risk Assessment Agent**
- AI-powered risk analysis and prioritization
- Generates actionable recommendations
- Provides business context and impact assessment

## 🚀 Quick Start

### Prerequisites

- GitHub repository with Actions enabled
- IBM watsonx AI account (for production use)
- Python 3.11+

### Installation

1. **Copy the pipeline to your repository:**

```bash
cp -r psirt-early-eye /path/to/your/repo/
```

2. **Set up GitHub Secrets:**

Go to your repository Settings → Secrets and variables → Actions, and add:

- `WATSONX_API_KEY`: Your IBM watsonx API key
- `WATSONX_PROJECT_ID`: Your watsonx project ID
- `SLACK_SECURITY_WEBHOOK`: (Optional) Slack webhook for notifications

3. **Enable the workflow:**

The workflow will automatically trigger on pull requests to `main`, `develop`, or `release/*` branches.

## 📋 Configuration

### CVE Score Actions

| CVE Score | Severity | Action | Notification |
|-----------|----------|--------|--------------|
| 9.0-10.0 | CRITICAL | ❌ Block PR | Security team, CISO, Author |
| 7.0-8.9 | HIGH | ❌ Block PR | Security team, Author |
| 4.0-6.9 | MEDIUM | ⚠️ Warn + Require Approval | Author, Reviewers |
| 0.1-3.9 | LOW | ✅ Pass with notification | Author |
| 0.0 | NONE | ✅ Pass | None |

### Customization

Edit `config/config.yaml` to customize:
- CVE score thresholds
- File extensions to scan
- Notification settings
- AI model parameters
- Exemptions and exclusions

## 📊 Example Output

### PR Comment

```markdown
## 🚨 PSIRT-Early-Eye Security Scan Results

**Status:** BLOCK
**Severity:** HIGH
**Max CVE Score:** 8.5/10.0

---

### Summary
⚠️ HIGH: 2 high-severity vulnerabilities detected (Max CVE Score: 8.5). 
Security review required before merge.

---

### Scan Metrics

| Metric | Count |
|--------|-------|
| Dependencies Scanned | 45 |
| Code Vulnerabilities | 3 |
| CVEs Found | 2 |

---

### 🔍 Findings

#### ⚠️ High (2)

**CVE-2021-23337 in lodash**
- Prototype pollution vulnerability in lodash
- *Fix:* Update to version 4.17.21

**SQL Injection in src/api/users.js**
- Line 42: query("SELECT * FROM users WHERE id=" + userId)
- *Fix:* Use parameterized queries or prepared statements

---

### 📋 Recommendations

🔴 **IMMEDIATE:** Block PR merge until critical issues are resolved
🟠 **HIGH:** Update 2 vulnerable dependencies
🟠 **HIGH:** Fix 3 code vulnerabilities

---

### ❌ Action Required

This PR is **BLOCKED** due to critical or high severity vulnerabilities.

**Next Steps:**
1. Review the findings above
2. Fix critical and high severity issues
3. Update dependencies to patched versions
4. Re-run the security scan
```

## 🔧 Local Testing

Test the scanner locally before pushing:

```bash
# Install dependencies
pip install -r psirt-early-eye/requirements.txt

# Set environment variables
export WATSONX_API_KEY="your-api-key"
export WATSONX_PROJECT_ID="your-project-id"

# Run the scanner
python psirt-early-eye/scripts/orchestrator.py \
  --pr-number 123 \
  --changed-files "src/app.js,package.json" \
  --base-branch main \
  --head-branch feature/new-feature \
  --repo owner/repo \
  --output-file report.json

# View the report
cat report.json | jq
```

## 🎓 How It Works

### Workflow Execution

1. **Trigger**: PR opened/updated
2. **Checkout**: Get PR code and changes
3. **Scan**: Run orchestrator with all agents
4. **Analyze**: AI agents perform parallel analysis
5. **Assess**: Risk assessment agent evaluates findings
6. **Report**: Generate detailed report and PR comment
7. **Decide**: Block, warn, or pass based on severity
8. **Notify**: Alert security team if needed

### Decision Logic

```python
if max_cve_score >= 9.0 or critical_vulns > 0:
    action = "BLOCK"
    notify = ["security-team", "ciso"]
elif max_cve_score >= 7.0 or high_vulns > 0:
    action = "BLOCK"
    notify = ["security-team"]
elif max_cve_score >= 4.0 or medium_vulns > 0:
    action = "WARN"
    require_approval = True
else:
    action = "PASS"
```

## 🔐 Security Best Practices

1. **Secrets Management**: Never commit API keys or secrets
2. **Regular Updates**: Keep dependencies and scanner updated
3. **Review Exemptions**: Regularly audit exempted CVEs
4. **Monitor Alerts**: Act on security notifications promptly
5. **Team Training**: Ensure team understands security findings

## 🛠️ Troubleshooting

### Common Issues

**Issue**: Scan fails with "WATSONX_API_KEY not set"
- **Solution**: Add the secret in GitHub repository settings

**Issue**: Too many false positives
- **Solution**: Adjust confidence thresholds in `config/config.yaml`

**Issue**: Scan timeout
- **Solution**: Increase `scan_timeout` in configuration

**Issue**: Missing CVEs
- **Solution**: Ensure CVE databases are accessible from your network

## 📈 Metrics and Reporting

The scanner tracks:
- Total vulnerabilities detected
- CVE score distribution
- Scan duration and performance
- False positive rates
- Remediation time

Reports are stored as workflow artifacts for 90 days.

## 🤝 Contributing

Contributions welcome! Areas for improvement:
- Additional language support
- More CVE data sources
- Enhanced AI models
- Better false positive detection
- Performance optimizations

## 📄 License

MIT License - See LICENSE file for details

## 🆘 Support

- **Issues**: Open a GitHub issue
- **Security**: Contact security@company.com
- **Documentation**: See `/docs` folder

## 🔗 Related Resources

- [IBM watsonx AI Documentation](https://www.ibm.com/watsonx)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CVE Database](https://cve.mitre.org/)
- [GitHub Security Advisories](https://github.com/advisories)

---

**Built with ❤️ by PSIRT-Early-Eye - AI-powered security automation**