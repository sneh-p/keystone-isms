---
type: Secure Coding Standard
title: Outbound Requests (SSRF)
description: Rules for server-side requests whose destination is influenced by input, including integrations and website checks.
tags: [security, backend, ssrf, network]
rule_prefix: SC-SSRF
applies_to: ["keystone/integrations/**", "keystone/ai/**", "keystone/**/*.py"]
load_when: ["httpx, requests, urllib or boto3 with a non-constant URL or host", "new integration provider", "webhooks", "URL previews or imports", "fetching files by URL"]
status: stable
verified: { by: human:sneh, at: 2026-11-16T20:00:00Z }
generated: { by: claude/claude-opus-5-5, at: 2026-11-16T00:00:00Z }
stale_after: 2027-05-16T00:00:00Z
---

# Rules

### SC-SSRF-001 — Allowlist destinations
**MUST · critical** · CWE-918 · A01:2025

A URL influenced by input may be fetched only if all of these hold: its host is on an allowlist, it uses HTTPS, it
contains no credentials and no explicit port, redirects are refused, and the request has a timeout. The GitHub,
AWS and Claude integrations follow this: their hosts are fixed in code (`https://api.github.com`, the AWS SDK
endpoints for the configured region, the Anthropic SDK default), and input only fills path segments or
parameters.

```python
API = "https://api.github.com"
org = validate_org_login(config["org"])          # [A-Za-z0-9-]{1,39}
c = httpx.Client(base_url=API, timeout=15.0, follow_redirects=False)
c.get(f"/orgs/{org}")
```

Attack surface connectors go through `keystone/integrations/http.py`: each declares exact vendor hosts, or the vendor's
domain for customer-specific consoles (for example `*.sentinelone.net`, `*.central.sophos.com`); pagination links
returned by an API are checked against the same rule.

### SC-SSRF-002 — Arbitrary URLs need network-level controls
**MUST · critical** · CWE-918

The website integration must fetch user-chosen hosts, so no allowlist is possible. Then all of these are
required:

- Resolve DNS and reject loopback, private, link-local, carrier-grade NAT, multicast, reserved and
  cloud-metadata addresses (`assert_public_host()` in `keystone/integrations/providers/website.py`):
  `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `100.64.0.0/10`, `0.0.0.0/8`,
  `::1`, `::ffff:0:0/96`, `fc00::/7`, `fe80::/10`.
- Connect to the validated IP, so DNS rebinding can't swap in a different address, or route the request through
  an egress proxy that enforces the same rules.
- Re-validate every redirect hop.
- Set timeouts and cap the response size.

The website integration implements all of these: `assert_public_host()` resolves once, requires every address to
be globally routable (including IPv4-mapped IPv6 and carrier-grade NAT checks) and returns the IP; every request and
the TLS check connect to that IP while presenting the original host name for `Host` and SNI, so certificates are
still verified (`_pinned()`); responses are streamed and their bodies never read; each redirect hop is re-validated
over HTTPS only. Changing this design is an escalation per [SC-AGT-006](/agent-conduct.md); reuse this code rather
than hand-rolling a new fetcher (`keystone/integrations/http.py` reuses its validation and pinning).

Two more features reach hosts an administrator chooses: the SMTP relay (`keystone/notifications/mailer.py`) and
self-hosted RMM servers (N-central, ConnectWise Automate). Both resolve once, require public addresses and connect to the
validated IP. An internal relay or server is allowed only when the server operator lists its name in
`KEYSTONE_SMTP_PRIVATE_HOSTS` or `KEYSTONE_INTEGRATION_PRIVATE_HOSTS`, never from the web UI; loopback, link-local and
metadata addresses are refused even then.

### SC-SSRF-003 — Never send credentials to input-chosen hosts
**MUST NOT · critical** · CWE-918, CWE-201

Never attach integration secrets, session cookies, the Anthropic key or cloud credentials to a request whose
host came from input. Credentials are sent only to hosts the connector's policy allows (SC-SSRF-001). Where an
administrator chooses the host (SMTP relay, self-hosted RMM servers), the stored credential is bound to that host:
changing the host discards it, so it can't be redirected to a host it wasn't entered for.
