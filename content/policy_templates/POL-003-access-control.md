---
code: POL-003
title: Access Control Policy
type: policy
acknowledge: false
controls: [KC-ORG-15, KC-ORG-16, KC-ORG-17, KC-ORG-18, KC-TEC-02, KC-TEC-03, KC-TEC-05, KC-ORG-03]
---
# Access Control Policy

## Principles
- **Least privilege:** people and services get only the access they need for their role.
- **Need to know:** access to confidential and restricted information is limited to those who need it.
- **Segregation of duties:** conflicting tasks (for example requesting and approving access) are split between different people.

## Identities
Every person and service has a unique identity managed in the central identity provider. Shared accounts are not allowed unless approved and recorded, with an owner.

## Authentication
- Multi-factor authentication (MFA) is required for all user accounts. Phishing-resistant methods are required for administrators.
- Passwords are at least 12 characters, never reused across systems, and stored in the approved password manager.
- Default passwords are changed before a system goes into use.

## Joiners, movers and leavers
- Access is requested by the person's manager and approved by the system owner.
- When someone changes role, access they no longer need is removed within 5 working days.
- When someone leaves, all access is revoked on their last working day.

## Privileged access
Administrative rights use separate admin accounts, are granted only to named people, and are reviewed every quarter.

## Access reviews
System owners review user access at least every six months and privileged access every quarter. Results and changes are recorded as evidence.
