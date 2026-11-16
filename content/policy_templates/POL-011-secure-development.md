---
code: POL-011
title: Secure Development Policy
type: policy
acknowledge: false
when: develops_software
controls: [KC-TEC-25, KC-TEC-26, KC-TEC-27, KC-TEC-28, KC-TEC-29, KC-TEC-31, KC-TEC-04, KC-TEC-33]
---
# Secure Development Policy

- Security requirements are defined for every new system or significant feature, including threat modelling for higher-risk changes.
- All code changes are peer reviewed before merging. The main branch is protected.
- Dependencies are tracked and scanned for known vulnerabilities, and critical findings are fixed before release.
- Secrets never go into source code; automated secret scanning is turned on.
- Development, test and production environments are separate. Production data is not used for testing unless it is masked.
- Developers complete secure coding training at least once a year.
- Applications that are exposed to the internet are penetration tested at least once a year.
