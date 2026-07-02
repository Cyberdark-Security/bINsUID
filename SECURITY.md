# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 1.0.x   | Yes       |

## Reporting a vulnerability

Email **security@cyberdark.local** or open a private security advisory on GitHub.

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
- Dry-run mode (`--dry-run`) for classroom demonstrations
- JSON output (`--json`) for automation without interactive prompts
