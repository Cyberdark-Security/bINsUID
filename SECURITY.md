# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 1.2.x   | Yes       |
| 1.1.x   | Yes       |
| 1.0.x   | Yes       |

## Reporting a vulnerability

Report vulnerabilities via a [private GitHub Security Advisory](https://github.com/Cyberdark-Security/bINsUID/security/advisories/new).

Please include:

- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

## Scope

bINsUID is a **privilege escalation tool for authorized security testing**.
It is designed to execute shell commands when the operator confirms escalation.

Do not run bINsUID on systems without explicit written permission.

## Safe defaults

- Confirmation prompt before escalation (bypass with `-y` only when intended)
- Dry-run mode (`--dry-run`) to preview commands without execution
- JSON output (`--json --scan-only`) for automation without interactive prompts
