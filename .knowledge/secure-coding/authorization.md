---
type: Secure Coding Standard
title: Authorization
description: Deny by default, enforce a permission on every route and in every service, isolate portal-only and public users, and never trust client-supplied identity.
tags: [security, backend, authorization]
rule_prefix: SC-AUTHZ
applies_to: ["keystone/**/*.py", "tests/test_api.py"]
load_when: ["new or changed endpoint", "new or changed service function", "scheduled job acting for a user", "query by ID", "create or update from request data", "public endpoint"]
status: stable
verified: { by: human:sneh, at: 2026-11-16T02:55:39Z }
generated: { by: claude/claude-opus-5-5, at: 2026-11-16T00:00:00Z }
stale_after: 2027-05-16T00:00:00Z
---

# Tenancy in this repository

Keystone serves a single organisation, so there is no tenant column. The isolation boundaries are:

- **roles** (`keystone/core/rbac.py`): each role has an explicit permission set;
- **employees**: the `employee` role sees only its own portal data, never ISMS records;
- **public visitors**: `/api/public/*` exposes only published Trust Center items and the holder's own access
  request.

Where this standard says "another tenant", read "outside the caller's boundary": an employee asking for an ISMS
record, or a visitor asking for an unpublished or someone else's item.

# Rules

### SC-AUTHZ-001 — Deny by default; check every request
**MUST · critical** · `tests/test_api.py::test_every_write_route_declares_a_permission` · CWE-862, CWE-863 · A01:2025 · ASVS V8

Every route declares its permission with `Depends(perm("<permission>"))`, and every service function that reads
sensitive data or writes calls `authorize(session, actor, "<permission>")` from `keystone/core/services.py`. Both
checks run server-side on every call; the service check means a new router or job can't bypass it. A handler or
service without an explicit permission is a bug.

### SC-AUTHZ-002 — Scope object access in the query itself
**MUST · critical** · CWE-639 · A01:2025 · ASVS V8

Fetch objects with `get_or_404()` and apply the boundary in the query. For portal data, filter by the caller:
`where(TrainingCompletion.user_id == actor.id)`. For public data, filter by published state and by the hashed
access token. Return 404, not 403, for objects outside the caller's boundary.

```python
# Do: a visitor can only download a published document, with their own valid grant
doc = session.scalar(select(TrustDocument).where(TrustDocument.public_id == public_id, TrustDocument.published.is_(True)))
if doc is None:
    raise NotFound("Not found")

# Don't: any caller can fetch any attachment by guessing IDs
return read_attachment(session.get(Attachment, attachment_id))
```

### SC-AUTHZ-003 — Identity comes only from the verified session
**MUST · critical** · CWE-639, CWE-807

Take the user, role and permissions from `current_user` (the verified session). Never take them from the body,
query, path or headers (for example `body.user_id`, `X-User-Role`). Actions "on behalf of" someone else (an
admin resetting a password) name the target explicitly and check the actor's permission.

### SC-AUTHZ-004 — No mass assignment
**MUST · critical** · CWE-915

Request models list only client-writable fields, and services apply them through allowlists (`apply_fields`).
Fields such as `role`, `active`, `password_hash`, `status` transitions, `approved_by_id`, `created_by_id`,
`author_id`, `token_hash`, `secret_enc` and `api_key_enc` are never client-writable through a general update; they
change only through dedicated, permission-checked service functions (approval, role change, offboarding).

### SC-AUTHZ-005 — Prove it with negative tests
**MUST · high** · ASVS V8

Every new or changed endpoint is covered by:

- an unauthenticated caller gets 401 (`test_every_route_requires_sign_in`, or a dedicated test for public routes)
- a caller without the permission gets 403 (`test_roles_cannot_call_write_routes_they_lack`, plus a test for
  read routes that need more than `read`)
- a caller outside the boundary gets 404: an employee for ISMS records, a visitor for unpublished items or
  another visitor's request

Segregation-of-duties rules get their own test (author can't approve, assignee can't approve their own task).
Scanners can't detect missing authorization, so these tests are the control.

### SC-AUTHZ-006 — Least privilege for code identities
**SHOULD · medium** · CWE-250, CWE-272

Integration credentials are read-only (GitHub fine-grained read, AWS `SecurityAudit`), the collector uses a
read-only Entra role, and the app's database user should not be a superuser. Never use admin or owner
credentials at runtime.
