# Security Policy & Ethical Guidelines

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | ✅ Active support  |
| 1.0.x   | ❌ No longer supported |

## Reporting Vulnerabilities (Responsible Disclosure)

If you discover a security vulnerability within the **Automatic Reconnaissance Tool** codebase or any of its dependencies, please report it responsibly following our disclosure guidelines:

1. **DO NOT** open a public GitHub issue for security vulnerabilities.
2. Report the vulnerability directly via email to: **dharamshiyash1810@gmail.com**
3. Please include the following details in your report:
   - Clear description of the vulnerability and its potential impact
   - Detailed steps to reproduce the issue (proof-of-concept scripts or screenshots)
   - Affected system components or modules
   - Suggested remediation or patches (if available)

### Disclosure Timeline
- **Acknowledgment:** You will receive confirmation of your report within 48 hours.
- **Triage & Assessment:** We will assess the vulnerability and provide a status update within 7 business days.
- **Fix & Advisory:** Once confirmed, a patch will be prepared and deployed promptly before any public disclosure.

---

## Ethical Usage & Legal Compliance (No Misuse)

### Strict Authorization Required
The **Automatic Reconnaissance Tool** is engineered strictly for **educational purposes, defensive cybersecurity engineering, and authorized security assessments**.

By downloading, installing, or using this software, you explicitly agree to the following terms:
- ✅ **Authorized Targets Only:** You must possess explicit, documented, legal authorization from the system owner before executing scans or reconnaissance against any network, domain, or server.
- ✅ **Defensive Focus:** The tool must be used strictly to identify posture weaknesses, enhance organizational defenses, and streamline authorized penetration testing workflows.
- ❌ **No Misuse:** Unauthorized scanning, denial-of-service attempts, data exfiltration, or targeting critical infrastructure without consent is strictly prohibited and constitutes illegal activity under applicable cybercrime laws (e.g., Computer Fraud and Abuse Act, GDPR, IT Act).

The author (**Yash Dharamshi**) and contributors assume no liability and are not responsible for any misuse, damage, or legal consequences caused by the utilization of this framework.

---

## Secure Credential Management

To maintain a secure development and execution environment:
- Always use `.env` files (which are git-ignored by default) to store sensitive variables such as SMTP passwords and Shodan API keys.
- **Never** hardcode credentials directly inside Python source code files.
- Rotate any third-party API keys or application passwords regularly.
- Ensure exported PDF and HTML reconnaissance reports containing sensitive target reconnaissance data are stored securely and transmitted via encrypted channels.
