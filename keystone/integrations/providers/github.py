"""GitHub organisation: read-only checks with a fine-grained token (Administration/Metadata read)."""

from __future__ import annotations

import re

import httpx

from .base import CheckDef, ConfigField, Outcome, Provider, SetupStep

API = "https://api.github.com"
ORG_LOGIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}")


class GitHubProvider(Provider):
    key = "github"
    name = "GitHub"
    description = "Checks your GitHub organisation for 2FA enforcement, branch protection, secret scanning and Dependabot alerts."
    fields = (
        ConfigField("org", "Organisation login", help="e.g. my-company", example="my-company"),
        ConfigField("token", "Read-only token", secret=True, help="Fine-grained token with read access to organisation administration and repository metadata."),
    )
    checks = (
        CheckDef("org_2fa", "Two-factor authentication required for members", ("KC-TEC-05", "KC-ORG-17")),
        CheckDef("branch_protection", "Default branches protected", ("KC-TEC-25", "KC-TEC-28", "KC-TEC-32")),
        CheckDef("secret_scanning", "Secret scanning enabled", ("KC-TEC-28", "KC-ORG-17")),
        CheckDef("dependabot", "Dependabot security updates enabled", ("KC-TEC-08", "KC-ORG-21")),
    )
    setup = (
        SetupStep(
            "Create a fine-grained, read-only token",
            "Sign in as an organisation owner and create a fine-grained personal access token. Resource owner: "
            "{org}. Repository access: All repositories. Repository permissions: Administration Read-only "
            "(Metadata Read-only is added automatically). Organisation permissions: Administration Read-only. "
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

    def run(self, config: dict, secrets: dict, session=None) -> list[Outcome]:
        org = (config.get("org") or "").strip()
        if not ORG_LOGIN.fullmatch(org):  # SC-VAL-002 / SC-SSRF-001: input only fills a validated path segment
            raise ValueError("Enter the organisation login (letters, digits and single hyphens, up to 39 characters).")
        headers = {"Authorization": f"Bearer {secrets['token']}", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        factory = self.client_factory or (lambda: httpx.Client(base_url=API, headers=headers, timeout=20.0, follow_redirects=False))
        out = []
        with factory() as c:
            r = c.get(f"/orgs/{org}")
            if r.status_code in (401, 403, 404):
                raise ValueError(f"GitHub returned {r.status_code}: check the organisation name and token permissions.")
            info = r.json()
            tfa = info.get("two_factor_requirement_enabled")
            out.append(Outcome("org_2fa", "unknown" if tfa is None else ("pass" if tfa else "fail"), "Token cannot see this setting" if tfa is None else ("Required" if tfa else "Not required")))
            repos = [x for x in c.get(f"/orgs/{org}/repos", params={"per_page": 100, "type": "all"}).json() if not x.get("archived")]
            unprotected, no_secret, no_dep = [], [], []
            for repo in repos:
                b = c.get(f"/repos/{org}/{repo['name']}/branches/{repo['default_branch']}/protection")
                if b.status_code == 404:
                    unprotected.append(repo["name"])
                sa = repo.get("security_and_analysis") or {}
                if (sa.get("secret_scanning") or {}).get("status") != "enabled":
                    no_secret.append(repo["name"])
                if (sa.get("dependabot_security_updates") or {}).get("status") != "enabled":
                    no_dep.append(repo["name"])

            def res(key: str, bad: list[str], what: str) -> Outcome:
                if not repos:
                    return Outcome(key, "unknown", "No repositories visible to the token")
                return Outcome(key, "pass" if not bad else "fail", f"All {len(repos)} repositories {what}" if not bad else f"{len(bad)} of {len(repos)} repositories not {what}: {', '.join(bad[:8])}", {"failing": bad})

            out += [res("branch_protection", unprotected, "protected"), res("secret_scanning", no_secret, "scanned"), res("dependabot", no_dep, "covered")]
        return out
