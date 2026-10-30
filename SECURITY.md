# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ Yes |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

To report a vulnerability, please use GitHub's private [Security Advisories](https://github.com/disappointingsupernova/Unifi-Rules-to-All-Private-Zones/security/advisories/new) feature for this repository.

Please include:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- The version(s) affected
- Any suggested mitigations, if known

You will receive an acknowledgement within **48 hours** and a resolution timeline within **7 days**.

## Security Design Notes

- Credentials are **never stored** — they are prompted at runtime and held only in memory for the duration of the session
- SSL certificate verification is disabled for local UDM connections (self-signed certificates). Do not use this tool over untrusted networks
- Backup files encrypted with this tool use AES-256-GCM with a scrypt-derived key (`N=2^17, r=8, p=1`). The encryption password is never stored or logged
- `clusters.yaml` contains no credentials and is safe to commit to version control
