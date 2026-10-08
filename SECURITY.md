# Security Policy

## Supported Versions

Security fixes are currently provided for the latest released version.

| Version | Supported |
| --- | --- |
| Latest release | ✅ |
| Older releases | ❌ |

## Reporting a Vulnerability

Please do not report security vulnerabilities through public GitHub issues.

Email reports to:

**security@r3trive.io**

Include:

- A clear description of the vulnerability
- The affected version, commit, or component
- Steps to reproduce the issue
- Proof-of-concept code or commands, if available
- Potential impact
- Suggested mitigation, if known

Please avoid including real credentials, private keys, personal data, or production-sensitive information in the initial report.

## Response Process

Maintainers will:

1. Acknowledge receipt of the report.
2. Validate and assess the impact.
3. Coordinate a fix and release when appropriate.
4. Credit the reporter unless they request anonymity.
5. Publish a security advisory when disclosure is appropriate.

We ask reporters to allow reasonable time for remediation before public disclosure.

## Security Scope

Reports involving the following areas are especially important:

- Privilege escalation
- Unauthorized automated response actions
- API authentication or authorization bypasses
- Command injection
- Plugin isolation failures
- Insecure deserialization
- Sensitive data or credential exposure
- Release and installer integrity
- Sensor or telemetry tampering
