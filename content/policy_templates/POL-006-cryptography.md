---
code: POL-006
title: Cryptography Policy
type: standard
acknowledge: false
controls: [KC-TEC-24]
---
# Cryptography Policy

- Data in transit over untrusted networks is encrypted with TLS 1.2 or later. Older protocols and weak ciphers are disabled.
- Laptops, phones and cloud storage holding Confidential or Restricted data are encrypted at rest using current, widely reviewed algorithms (for example AES-256).
- Keys and secrets are stored in an approved key or secret management service, never in source code or chat messages.
- Keys are rotated when someone with access leaves, when compromise is suspected, and according to the service's rotation schedule.
- Certificates are tracked and renewed before they expire.
