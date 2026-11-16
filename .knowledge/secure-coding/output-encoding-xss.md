---
type: Secure Coding Standard
title: Output Encoding and XSS
description: Render untrusted data in React, Markdown, attributes and URLs without letting it become markup or script.
tags: [security, frontend, xss]
rule_prefix: SC-XSS
applies_to: ["web/src/**/*.tsx", "web/src/**/*.ts", "web/index.html", "keystone/api/app.py"]
load_when: ["rendering user or model content", "Markdown", "href or src from data", "redirects", "building HTML", "Content Security Policy"]
status: stable
verified: { by: human:sneh, at: 2026-11-16T02:55:39Z }
generated: { by: claude/claude-opus-5-5, at: 2026-11-16T00:00:00Z }
stale_after: 2027-05-16T00:00:00Z
---

# Rules

### SC-XSS-001 — Let React escape; no raw HTML sinks
**MUST · critical** · ESLint `react/no-danger`, `no-unsanitized/*` · CWE-79 · A05:2025 · ASVS V1, V3

Render through JSX. Don't use `dangerouslySetInnerHTML`, `innerHTML`, `outerHTML`, `insertAdjacentHTML` or
`document.write`. Markdown (policies, training, Trust Center text, AI output) is rendered only through
`web/src/components/Markdown.tsx`, which uses `react-markdown` without raw HTML (no `rehype-raw`).

If the product genuinely needs user-authored HTML, sanitize it with DOMPurify immediately before rendering, and
only under a registered exception:

```tsx
{/* eslint-disable-next-line react/no-danger -- security-exception: EX-003 rich text, sanitized at render */}
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(comment.html) }} />
```

### SC-XSS-002 — Allowlist URL schemes
**MUST · high** · CWE-79, CWE-83

Any URL taken from data and used as an `href`, `src` or `action` goes through `safeHref()` from
`web/src/lib/safe-url.ts`, because `javascript:` and `data:` URLs execute code.

```ts
import { safeHref } from "@/lib/safe-url";

<a href={safeHref(link)} target="_blank" rel="noopener noreferrer">…</a>
```

Internal links use React Router `<Link to>` with paths built by the app, and API downloads use `downloadUrl()`.

### SC-XSS-003 — No HTML built by string concatenation
**MUST NOT · high** · CWE-79

Don't assemble HTML, SVG or inline scripts from strings, in Python or in the browser. Exports are built with
openpyxl / python-docx APIs, never with HTML. To embed data in a page, return JSON from the API.

### SC-XSS-004 — Keep the CSP strict
**MUST NOT · high** · CWE-79, CWE-693 · ASVS V3

The Content Security Policy lives in `security_headers()` in `keystone/api/app.py`. Never add `'unsafe-inline'` or
`'unsafe-eval'` to `script-src`, never add wildcard sources to `script-src`, `connect-src` or `img-src`, and keep
`frame-ancestors` configurable only through `KEYSTONE_FRAME_ANCESTORS`. See
[HTTP and Configuration](/http-and-config.md).

### SC-XSS-005 — No open redirects
**MUST · high** · Semgrep `sc-xss-005-open-redirect` · CWE-601

Redirect only to relative paths that start with a single `/`, or to allowlisted hosts. In the API, never build
a `RedirectResponse` from a query or form value; in the web app, a `from` path after sign-in must pass
`safeRedirectPath()`.

```ts
export function safeRedirectPath(raw: unknown): string {
  return typeof raw === "string" && raw.startsWith("/") && !raw.startsWith("//") && !raw.startsWith("/\\") ? raw : "/";
}
```
