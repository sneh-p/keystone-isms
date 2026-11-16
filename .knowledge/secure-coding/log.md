# Secure Coding Standard Update Log

## 2026-11-16
* **Initialization**: Adapted the "Secure Coding Standard for Coding Agents" (TypeScript/Node edition) to
  Keystone ISMS: Python 3 / FastAPI / Pydantic / SQLAlchemy backend, React + TypeScript web app, PowerShell
  collector. Rule IDs and enforcement design kept; code examples and tool configs changed. All concepts drafted
  as `status: draft`. Pending AppSec review and `verified` sign-off.

## 2026-11-16 (sign-off)
* **AppSec sign-off**: all concepts reviewed and approved by human:sneh; `status: stable` with `verified` recorded.
  Code Owner team set to `@Sneh/appsec`.
* **Baseline confirmed**: the Semgrep baseline commit (`request-host-used` in `deploy/nginx/keystone-proxy.conf`), the
  `ruff.toml` per-file-ignores for tests and the demo password, and the scanner exclusions listed in
  `docs/secure-coding-adoption.md` are accepted until the listed escalations are fixed.
