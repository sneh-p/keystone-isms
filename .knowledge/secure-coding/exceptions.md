---
type: Exception Register
title: Security Exception Register
description: Human-approved, time-limited exceptions to MUST rules. Code may only reference exception IDs listed here.
tags: [security, exceptions]
status: draft
generated: { by: claude/claude-opus-5-5, at: 2026-11-16T00:00:00Z }
---

# Register

| ID | Rule | Location | Reason and compensating control | Approved by | Expires |
|---|---|---|---|---|---|

# Process

Only AppSec adds rows; this file is CODEOWNERS-protected. Code references an entry with
`security-exception: EX-NNN` on the same line as the suppression. Expired entries fail
`scripts/check-suppressions.sh` and are reviewed monthly, then either renewed or removed together with the code they
cover.

# Examples

| ID | Rule | Location | Reason and compensating control | Approved by | Expires |
|---|---|---|---|---|---|
| EX-001 | SC-CRY-002 | `keystone/integrations/backoff.py` | `random` used only for retry jitter; not security-relevant | human:jdoe | 2027-04-30 |

```python
delay = base * 2 ** attempt + random.uniform(0, 1)  # noqa: S311 -- security-exception: EX-001 retry jitter only
```
