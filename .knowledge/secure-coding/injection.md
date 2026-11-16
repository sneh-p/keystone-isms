---
type: Secure Coding Standard
title: Injection Prevention
description: Build SQL, shell, PowerShell, template and code-evaluation calls so input can never change their structure.
tags: [security, backend, injection, database]
rule_prefix: SC-INJ
applies_to: ["keystone/**/*.py", "scripts/**/*.py", "migrations/**/*.py", "collector/**/*.ps1"]
load_when: ["database query", "sqlalchemy text()", "subprocess", "PowerShell Invoke-Expression", "eval or exec", "template rendering", "deserialization or YAML"]
status: stable
verified: { by: human:sneh, at: 2026-11-16T02:55:39Z }
generated: { by: claude/claude-opus-5-5, at: 2026-11-16T00:00:00Z }
stale_after: 2027-05-16T00:00:00Z
---

# Rules

### SC-INJ-001 — Parameterize every query
**MUST · critical** · Semgrep `sc-inj-001-sql-string-building`, ruff `S608` · CWE-89 · A05:2025 · ASVS V1

Use the SQLAlchemy ORM or Core (`select()`, `update()`), which binds values. Raw SQL goes through `text()` with
bound parameters. Dynamic identifiers such as sort columns come from a fixed map keyed by a validated `Literal`.

```python
# Do
stmt = select(Risk).where(Risk.owner_id == owner_id, Risk.title.ilike(f"%{term}%"))  # value is bound
session.execute(text("SELECT id FROM risks WHERE status = :status"), {"status": status})

SORT_COLUMNS = {"created": Risk.created_at, "title": Risk.title}
stmt = stmt.order_by(SORT_COLUMNS[sort])  # sort: Literal["created", "title"]
```

```python
# Don't
session.execute(text(f"SELECT * FROM risks WHERE title = '{title}'"))
session.execute(text("SELECT * FROM risks ORDER BY " + sort))
```

Alembic migrations use `op.execute()` only with constant SQL.

### SC-INJ-002 — Block NoSQL operator injection
**MUST · critical** · CWE-943 · A05:2025

Not applicable to the current stack (SQL only). If a document store or JSON-path query is added, validate types
before querying so an operator object such as `{"$ne": null}` can't arrive where a string is expected, and never
pass input to server-side code evaluation (`$where`, `$function`).

### SC-INJ-003 — No shell; pass arguments as a list
**MUST · critical** · ruff `S602`, `S604`, `S605`, `S606` · CWE-78, CWE-88

Prefer a library over a subprocess. If you must run a process, use `subprocess.run([...], shell=False,
timeout=...)` with an argument list. Never use `shell=True`, `os.system` or `os.popen`. Put `--` before
user-supplied values where the program supports it.

```python
subprocess.run(["git", "log", "--format=%H", "--", path], check=True, timeout=10, capture_output=True)
```

In the PowerShell collector, never use `Invoke-Expression`, `iex` or `& ([scriptblock]::Create(...))`, and never
build a Graph URL by concatenating unescaped input: every Graph call goes through `Invoke-GraphGet`.

### SC-INJ-004 — No dynamic code execution
**MUST NOT · critical** · ruff `S102`, `S307` · CWE-94, CWE-95

No `eval`, `exec`, `compile` of input, and no `importlib.import_module()` or `__import__()` of names derived from
input. Integration providers come from the fixed `PROVIDERS` registry, never from a module name in a request.

### SC-INJ-005 — Templates are code; user input is only data
**MUST NOT · critical** · CWE-1336

Never compile a template from user-supplied text. Policy templates in `content/policy_templates/` are trusted
repository files; `keystone/onboarding/service.render()` substitutes values into them and never evaluates
expressions. If a template engine is added, enable autoescaping and pass user data only as variables.

### SC-INJ-006 — Safe deserialization only
**MUST · critical** · ruff `S301`, `S506` · CWE-502 · ASVS V1

Accept JSON (then a Pydantic model or JSON Schema) or YAML through `yaml.safe_load`. Never use `pickle`,
`marshal`, `shelve`, `yaml.load` with an unsafe loader, or `jsonpickle` on data that crossed a trust boundary.
