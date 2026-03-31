# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in WiFi Sentinel, please report it responsibly.

Email: security@ismaelmartinez.dev

Please include a description of the vulnerability, steps to reproduce it, and any relevant context. We will respond within 48 hours and aim to release a fix within 7 days for critical issues.

Do not open a public GitHub issue for security vulnerabilities.

## Scope

WiFi Sentinel runs system commands locally and stores scan data in `~/.wifisentinel/`. The security scope covers command injection, path traversal, data exposure through the dashboard API, and XSS in the HTML report renderer.

## Supported Versions

Only the latest release on the `main` branch receives security updates.
