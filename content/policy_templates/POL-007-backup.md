---
code: POL-007
title: Backup and Recovery Policy
type: policy
acknowledge: false
controls: [KC-TEC-13, KC-TEC-14, KC-ORG-30]
---
# Backup and Recovery Policy

- Business-critical systems and data are backed up automatically, at a frequency that meets their recovery point objective (RPO).
- At least one backup copy is kept isolated from production (immutable or offline), so ransomware cannot reach it.
- Backups are encrypted and access to them is restricted.
- Restores are tested at least every quarter for critical systems, and results are recorded.
- Backup failures are alerted on and investigated.
