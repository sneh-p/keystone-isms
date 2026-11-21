"""GitHub organisation: read-only checks with a fine-grained token (Administration/Metadata read)."""

from __future__ import annotations

import re

import httpx

from .base import CheckDef, ConfigField, Outcome, PermissionReport, Provider, SetupStep

API = "https://api.github.com"
# Classic token scopes that only read. Anything else (repo, admin:*, write:*, workflow, delete_repo...) can change things.
READ_ONLY_SCOPES = frozenset({"read:org", "read:user", "user:email", "read:packages", "read:discussion", "read:project", "read:gpg_key", "read:public_key",
                              "read:repo_hook", "read:enterprise", "read:audit_log", "read:ssh_signing_key"})
MAX_OWNERS = 3
ORG_LOGIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}")


class GitHubProvider(Provider):
    key = "github"
    name = "GitHub"
    description = ("Checks your GitHub organisation for 2FA enforcement, branch protection, secret scanning, Dependabot, outside collaborators, "
                   "the number of owners, signed commits, code scanning and code owners.")
    fields = (
        ConfigField("org", "Organisation login", help="e.g. my-company", example="my-company"),
        ConfigField("token", "Read-only token", secret=True, help="Fine-grained token with read access to organisation administration and repository metadata."),
    )
    checks = (
        CheckDef("org_2fa", "Two-factor authentication required for members", ("KC-TEC-05", "KC-ORG-17")),
        CheckDef("branch_protection", "Default branches protected", ("KC-TEC-25", "KC-TEC-28", "KC-TEC-32")),
        CheckDef("secret_scanning", "Secret scanning enabled", ("KC-TEC-28", "KC-ORG-17")),
        CheckDef("dependabot", "Dependabot security updates enabled", ("KC-TEC-08", "KC-ORG-21")),
        CheckDef("outside_collaborators", "No outside collaborators", ("KC-TEC-04", "KC-ORG-18")),
        CheckDef("few_owners", f"At most {MAX_OWNERS} organisation owners", ("KC-TEC-02",)),
        CheckDef("signed_commits", "Default branches require signed commits", ("KC-TEC-25", "KC-TEC-04")),
        CheckDef("code_scanning", "Code scanning runs on every repository", ("KC-TEC-28", "KC-TEC-29")),
        CheckDef("code_owners", "Every repository has code owners", ("KC-TEC-04", "KC-TEC-32")),
    )
    setup = (
        SetupStep(
            "Create a fine-grained, read-only token",
            "Sign in as an organisation owner and create a fine-grained personal access token. Resource owner: "
            "{org}. Repository access: All repositories. Repository permissions: Administration Read-only and Code scanning "
            "alerts Read-only (Metadata Read-only is added automatically). Organisation permissions: Administration Read-only "
            "and Members Read-only. "
            "Choose an expiry and note it: the integration starts failing when the token expires. If your "
            "organisation requires approval for fine-grained tokens, approve the request under the organisation's "
            "settings.",
            link="https://github.com/settings/personal-access-tokens/new", link_label="Create token on GitHub",
        ),
        SetupStep(
            "Check the permissions are read-only",
            "On the token's page, every permission must say Read-only. Nothing else should be listed.",
            kind="verify",
            link="https://github.com/settings/personal-access-tokens", link_label="Your fine-grained tokens",
        ),
        SetupStep(
            "Check the token can read what the checks need",
            "Paste the token where shown. Expect the organisation's two-factor setting (true or false) and an HTTP "
            "200 for the repository list. A missing line or HTTP 403 means a permission is missing. Close the "
            "terminal afterwards so the token is not left in it.",
            kind="verify",
            code="read -rs GH_TOKEN   # paste the token, then press Enter\n"
                 "curl -s -H \"Authorization: Bearer $GH_TOKEN\" https://api.github.com/orgs/{org} | grep two_factor_requirement_enabled\n"
                 "curl -s -o /dev/null -w '%{http_code}\\n' -H \"Authorization: Bearer $GH_TOKEN\" 'https://api.github.com/orgs/{org}/repos?per_page=1'\n"
                 "unset GH_TOKEN",
        ),
    )

    def __init__(self, client_factory=None):
        self.client_factory = client_factory

    def _client(self, config: dict, secrets: dict):
        org = (config.get("org") or "").strip()
        if not ORG_LOGIN.fullmatch(org):  # SC-VAL-002 / SC-SSRF-001: input only fills a validated path segment
            raise ValueError("Enter the organisation login (letters, digits and single hyphens, up to 39 characters).")
        headers = {"Authorization": f"Bearer {secrets['token']}", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        factory = self.client_factory or (lambda: httpx.Client(base_url=API, headers=headers, timeout=20.0, follow_redirects=False))
        return org, factory()

    def permissions(self, config: dict, secrets: dict) -> PermissionReport:
        """Classic tokens list their scopes in a response header; fine-grained tokens don't, so those are "unknown"."""
        org, client = self._client(config, secrets)
        with client as c:
            r = c.get(f"/orgs/{org}")
        if r.status_code in (401, 403, 404):
            raise ValueError(f"GitHub returned {r.status_code}: check the organisation name and token permissions.")
        scopes = r.headers.get("x-oauth-scopes")
        if scopes is None:
            return PermissionReport("unknown", "Fine-grained token: GitHub doesn't tell a token its own permissions. On the token's page, every permission must say Read-only.")
        extra = sorted({x.strip() for x in scopes.split(",") if x.strip()} - READ_ONLY_SCOPES)
        if extra:
            return PermissionReport("fail", f"Classic token that can change things ({', '.join(extra)}). Replace it with a fine-grained, read-only token.", extra)
        return PermissionReport("pass", "Classic token with read-only scopes only. A fine-grained token is still preferred.")

    def run(self, config: dict, secrets: dict, session=None) -> list[Outcome]:
        org, client = self._client(config, secrets)
        out = []
        with client as c:
            r = c.get(f"/orgs/{org}")
            if r.status_code in (401, 403, 404):
                raise ValueError(f"GitHub returned {r.status_code}: check the organisation name and token permissions.")
            info = r.json()
            tfa = info.get("two_factor_requirement_enabled")
            out.append(Outcome("org_2fa", "unknown" if tfa is None else ("pass" if tfa else "fail"), "Token cannot see this setting" if tfa is None else ("Required" if tfa else "Not required")))
            repos = [x for x in c.get(f"/orgs/{org}/repos", params={"per_page": 100, "type": "all"}).json() if not x.get("archived")]
            unprotected, no_secret, no_dep, unsigned, no_scan, no_owners, scan_unknown = [], [], [], [], [], [], []
            for repo in repos:
                b = c.get(f"/repos/{org}/{repo['name']}/branches/{repo['default_branch']}/protection")
                if b.status_code == 404:
                    unprotected.append(repo["name"])
                if b.status_code != 200 or not ((b.json() or {}).get("required_signatures") or {}).get("enabled"):
                    unsigned.append(repo["name"])
                a = c.get(f"/repos/{org}/{repo['name']}/code-scanning/analyses", params={"per_page": 1})
                if a.status_code == 200 and a.json():
                    pass
                elif a.status_code in (200, 404):
                    no_scan.append(repo["name"])
                else:  # 403: not licensed for this repository, or no permission
                    scan_unknown.append(repo["name"])
                if c.get(f"/repos/{org}/{repo['name']}/codeowners/errors").status_code == 404:
                    no_owners.append(repo["name"])
                sa = repo.get("security_and_analysis") or {}
                if (sa.get("secret_scanning") or {}).get("status") != "enabled":
                    no_secret.append(repo["name"])
                if (sa.get("dependabot_security_updates") or {}).get("status") != "enabled":
                    no_dep.append(repo["name"])

            def res(key: str, bad: list[str], what: str) -> Outcome:
                if not repos:
                    return Outcome(key, "unknown", "No repositories visible to the token")
                return Outcome(key, "pass" if not bad else "fail", f"All {len(repos)} repositories {what}" if not bad else f"{len(bad)} of {len(repos)} repositories not {what}: {', '.join(bad[:8])}", {"failing": bad})

            out += [res("branch_protection", unprotected, "protected"), res("secret_scanning", no_secret, "scanned"), res("dependabot", no_dep, "covered"),
                    res("signed_commits", unsigned, "requiring signed commits"), res("code_owners", no_owners, "with a CODEOWNERS file")]
            if no_scan or not scan_unknown:
                out.append(res("code_scanning", no_scan, "scanned by code scanning"))
            else:
                out.append(Outcome("code_scanning", "unknown", f"Code scanning couldn't be read for {len(scan_unknown)} repositories (not licensed, or the token lacks Code scanning alerts: read)"))
            r = c.get(f"/orgs/{org}/outside_collaborators", params={"per_page": 100})
            if r.status_code == 200:
                logins = sorted(x.get("login", "") for x in r.json())
                out.append(Outcome("outside_collaborators", "fail" if logins else "pass", f"{len(logins)} outside collaborator(s): {', '.join(logins[:8])}" if logins else "None",
                                   {"collaborators": logins}))
            else:
                out.append(Outcome("outside_collaborators", "unknown", f"GitHub returned {r.status_code}: the token needs Members: read"))
            r = c.get(f"/orgs/{org}/members", params={"role": "admin", "per_page": 100})
            if r.status_code == 200:
                owners = sorted(x.get("login", "") for x in r.json())
                out.append(Outcome("few_owners", "pass" if len(owners) <= MAX_OWNERS else "fail", f"{len(owners)} owner(s): {', '.join(owners[:8])}", {"owners": owners}))
            else:
                out.append(Outcome("few_owners", "unknown", f"GitHub returned {r.status_code}: the token needs Members: read"))
        return out
