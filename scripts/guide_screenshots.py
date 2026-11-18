"""Take the screenshots in docs/user-guide.md from a freshly seeded demo.

    cd web && npm run build && cd ..
    pip install -e ".[e2e]"
    python scripts/guide_screenshots.py              # every screenshot
    python scripts/guide_screenshots.py risks assets # only those whose name starts with one of these

It seeds the fictional Alpine Ski House demo into a new, temporary data directory and serves it from this process,
so no other data is touched and nothing real can appear in a screenshot. Images are written to docs/user-guide/ as 256-colour
PNGs to keep the repository small.
"""

from __future__ import annotations

import os
import socket
import sys
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import httpx
from PIL import Image
from playwright.sync_api import Locator, Page, ViewportSize, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "user-guide"
PUBLIC_URL = "https://isms.alpineskihouse.example"
DESKTOP: ViewportSize = {"width": 1440, "height": 900}
PHONE: ViewportSize = {"width": 390, "height": 844}


@dataclass
class Shot:
    name: str
    path: str
    act: Callable[[Page], None] | None = None
    user: str = "admin"
    dark: bool = False
    phone: bool = False
    full: bool = False  # the whole page rather than the first screen


def row(text: str) -> Callable[[Page], None]:
    """Open the record in the first table row (or card) containing `text`."""
    def act(p: Page) -> None:
        p.locator("main tbody tr, main [role=button], main button").filter(has_text=text).first.click()
        p.wait_for_timeout(900)
    return act


def tab(name: str) -> Callable[[Page], None]:
    def act(p: Page) -> None:
        p.get_by_role("tab", name=name).first.click()
        p.evaluate("() => document.activeElement && document.activeElement.blur()")
        p.wait_for_timeout(700)
    return act


def button(name: str) -> Callable[[Page], None]:
    def act(p: Page) -> None:
        p.get_by_role("button", name=name).first.click()
        p.wait_for_timeout(800)
    return act


def click(get: Callable[[Page], Locator], wait: int = 900) -> Callable[[Page], None]:
    """Click what `get` finds, then give the page time to open it."""
    def act(p: Page) -> None:
        get(p).click()
        p.wait_for_timeout(wait)
    return act


def palette(p: Page) -> None:
    p.keyboard.press("Control+k")
    p.keyboard.type("ransom")
    p.wait_for_timeout(1200)


def mask_keys(p: Page) -> None:
    """Shorten enrolment keys on the Agents tab: they belong to a throwaway demo, but shouldn't look reusable."""
    p.evaluate("""() => { const w = document.createTreeWalker(document.querySelector('main'), NodeFilter.SHOW_TEXT);
      for (let n = w.nextNode(); n; n = w.nextNode()) n.nodeValue = n.nodeValue.replace(/kenr_[A-Za-z0-9_-]{6,}/g, 'kenr_…'); }""")


def new_module(p: Page) -> None:
    """The module editor with an example filled in (not saved)."""
    p.get_by_role("button", name="New module").click()
    d = p.get_by_role("dialog")
    d.get_by_label("Title").fill("Building access and visitors")
    d.get_by_label("Summary").fill("Badges, tailgating and signing visitors in.")
    d.get_by_label("Content").fill("## Badges\nWear your badge where it can be seen, and never lend it.\n\n## Visitors\nSign every visitor in at reception and stay with them.")
    d.get_by_label("Question 1", exact=True).fill("A visitor asks to borrow your badge for a minute. What do you do?")
    d.get_by_label("Question 1, answer 1").fill("Lend it: it's only a minute")
    d.get_by_label("Question 1, answer 2").fill("Say no, and take them to reception")
    d.get_by_label("Answer 2 is right").check()
    p.wait_for_timeout(400)


def record_training(p: Page) -> None:
    p.get_by_role("button", name="Record training").click()
    d = p.get_by_role("dialog")
    d.get_by_role("combobox", name="Person").click()
    p.get_by_role("option", name="Raj Patel").click()
    d.get_by_role("combobox", name="Counts as module").click()
    p.get_by_role("option", name="Phishing and social engineering").click()
    d.get_by_label("Provider").fill("In-house workshop")
    p.wait_for_timeout(400)


def tour(step: int) -> Callable[[Page], None]:
    def act(p: Page) -> None:
        reset_tours(p, None)
        dlg = p.get_by_role("dialog", name="Keystone tour")
        dlg.wait_for()
        for _ in range(step):
            dlg.get_by_role("button", name="Start tour").or_(dlg.get_by_role("button", name="Next")).click()
            p.wait_for_timeout(350)
    return act


SHOTS: list[Shot] = [
    # getting started
    Shot("login", "/login", user=""),
    Shot("tour-welcome", "/", tour(0)),
    Shot("tour-section", "/", tour(3)),
    Shot("help", "/help#risk-register"),
    Shot("search", "/", palette),
    Shot("notifications", "/", click(lambda p: p.locator("[data-tour=notifications] button").first), user="mia.isms"),
    Shot("dashboard", "/"),
    Shot("onboarding", "/onboarding"),
    # compliance
    Shot("frameworks", "/frameworks"),
    Shot("framework-detail", "/frameworks", click(lambda p: p.get_by_role("link", name="View requirements").nth(1), 1200)),
    Shot("controls", "/controls"),
    Shot("control-detail", "/controls", row("KC-GOV-")),
    Shot("tasks", "/tasks"),
    Shot("task-detail", "/tasks", click(lambda p: p.locator("main").get_by_text("Carry out the internal audit programme").first)),
    Shot("calendar", "/calendar"),
    Shot("policies", "/policies"),
    Shot("policy-detail", "/policies", row("Information Security Policy")),
    Shot("evidence", "/evidence"),
    Shot("soa", "/soa"),
    Shot("obligations", "/registers/obligations"),
    Shot("exceptions", "/exceptions"),
    Shot("privacy", "/privacy"),
    Shot("privacy-requests", "/privacy?tab=requests"),
    # risk
    Shot("risks", "/risks"),
    Shot("risk-detail", "/risks", row("RSK-0001")),
    Shot("assets", "/assets"),
    Shot("asset-detail", "/assets", row("Online booking platform")),
    Shot("attack-surface", "/attack-surface"),
    Shot("attack-surface-vulnerabilities", "/attack-surface?tab=vulnerabilities"),
    Shot("configuration", "/configuration"),
    Shot("configuration-targets", "/configuration?tab=targets"),
    Shot("configuration-target", "/configuration?tab=targets", row("ash-web-01")),
    Shot("configuration-baselines", "/configuration?tab=baselines"),
    Shot("configuration-baseline", "/configuration?tab=baselines", row("Linux servers")),
    Shot("configuration-custom", "/configuration?tab=custom"),
    Shot("configuration-custom-new", "/configuration?tab=custom", button("New custom check")),
    Shot("configuration-agents", "/configuration?tab=agents", mask_keys),
    Shot("change", "/registers/changes", row("Open the Wi-Fi guest network")),
    Shot("findings", "/registers/findings"),
    Shot("applications", "/registers/applications"),
    Shot("crypto", "/registers/crypto"),
    # third parties
    Shot("vendors", "/vendors"),
    Shot("vendor-detail", "/vendors", row("Fabrikam Backup")),
    Shot("vendor-questionnaires", "/questionnaires"),
    Shot("vendor-assessments", "/assessments"),
    Shot("exposure", "/exposure"),
    # trust and people
    Shot("people", "/people"),
    Shot("training", "/people?tab=training"),
    Shot("training-module", "/people?tab=training", new_module),
    Shot("training-external", "/people?tab=training", record_training),
    Shot("access-reviews", "/access-reviews"),
    Shot("access-check", "/access-check"),
    Shot("trust-center", "/trust-center"),
    Shot("trust-public", "/trust/alpine-ski-house", user=""),
    Shot("customer-questionnaires", "/security-questionnaires"),
    Shot("integrations", "/integrations"),
    # operations
    Shot("security-reports", "/security-reports"),
    Shot("alerts", "/alerts"),
    Shot("incidents", "/incidents"),
    Shot("incident-detail", "/incidents", row("Guest list emailed")),
    Shot("continuity", "/continuity"),
    Shot("nonconformities", "/nonconformities"),
    Shot("audits", "/audits"),
    Shot("audit-programme", "/audits", tab("Programme")),
    Shot("management-review", "/reviews"),
    Shot("workload", "/workload"),
    Shot("reports", "/reports"),
    Shot("backups", "/registers/backups"),
    Shot("indicators", "/indicators"),
    Shot("maturity", "/maturity"),
    Shot("physical-security", "/registers/sites"),
    # settings
    Shot("account", "/settings/account"),
    Shot("organisation", "/settings/organisation"),
    Shot("users", "/settings/users"),
    Shot("audit-log", "/settings/audit-log"),
    # employee portal, dark mode, phone
    Shot("portal", "/portal", user="nina.weber@alpineskihouse.example"),
    Shot("dark-mode", "/", dark=True),
    Shot("phone", "/risks", phone=True),
    Shot("phone-menu", "/", click(lambda p: p.get_by_role("button", name="Open menu"), 500), phone=True),
]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def start_demo(data_dir: Path):
    """Seed the demo into `data_dir` and serve it on a free local port, in this process (no shell, no subprocess)."""
    os.environ.update({"KEYSTONE_DATA_DIR": str(data_dir), "KEYSTONE_DISABLE_SCHEDULER": "1", "KEYSTONE_PUBLIC_URL": PUBLIC_URL})
    for k in ("KEYSTONE_DB_URL", "ANTHROPIC_API_KEY", "KEYSTONE_SECRET_KEY"):
        os.environ.pop(k, None)
    # Imported only now: Keystone reads its settings from the environment set above.
    import uvicorn

    from keystone import demo
    from keystone.api.app import create_app
    from keystone.core import auth, db

    db.configure()
    db.migrate()
    with db.session_scope() as s:
        admin = auth.create_user(s, None, username="admin", display_name="Demo Admin", password=demo.DEMO_PASSWORD)
    with db.session_scope(admin) as s:
        demo.seed(s, s.get(auth.User, admin.id))
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(create_app(migrate=False), host="127.0.0.1", port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    url = f"http://127.0.0.1:{port}"
    for _ in range(200):
        try:
            if httpx.get(f"{url}/api/auth/status", timeout=1).status_code == 200:
                return server, url, demo.DEMO_PASSWORD
        except httpx.HTTPError:
            time.sleep(0.1)
    raise RuntimeError("Keystone did not start")


BASE = ""
SIGN_IN = {"password": ""}  # the demo's documented password, filled in from keystone.demo at start


def reset_tours(p: Page, outcome: str | None) -> None:
    csrf = p.request.get(f"{BASE}/api/auth/me").json()["csrf_token"]
    for t in ("app", "portal"):
        p.request.put(f"{BASE}/api/portal/tours/{t}", data={"outcome": outcome}, headers={"X-CSRF-Token": csrf})
    p.reload(wait_until="networkidle")


def login(p: Page, user: str) -> None:
    p.goto(f"{BASE}/login", wait_until="networkidle")
    p.get_by_label("Username").fill(user)
    p.locator("input[type=password]").fill(SIGN_IN["password"])
    p.get_by_role("button", name="Sign in").click()
    p.wait_for_url(lambda u: "/login" not in u)
    reset_tours(p, "skipped")


def save(png: Path) -> None:
    """256 colours, no dithering: screenshots of an interface lose nothing visible and shrink by about two thirds."""
    with Image.open(png) as im:
        im.convert("RGB").quantize(colors=256, method=Image.Quantize.FASTOCTREE, dither=Image.Dither.NONE).save(png, optimize=True)


def main(only: list[str]) -> None:
    global BASE
    shots = [s for s in SHOTS if not only or any(s.name.startswith(o) for o in only)]
    OUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        server, BASE, SIGN_IN["password"] = start_demo(Path(tmp))
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch()
                contexts: dict[tuple, tuple] = {}
                for s in shots:
                    key = (s.user, s.dark, s.phone)
                    if key not in contexts:
                        ctx = browser.new_context(viewport=PHONE if s.phone else DESKTOP, color_scheme="dark" if s.dark else "light", device_scale_factor=2 if s.phone else 1)
                        page = ctx.new_page()
                        page.goto(f"{BASE}/login", wait_until="networkidle")
                        page.evaluate("t => localStorage.setItem('ks-theme', t)", "dark" if s.dark else "light")
                        if s.user:
                            login(page, s.user)
                        contexts[key] = (ctx, page)
                    page = contexts[key][1]
                    page.goto(BASE + s.path, wait_until="networkidle")
                    page.wait_for_timeout(700)
                    if s.act:
                        s.act(page)
                    target = OUT / f"{s.name}.png"
                    page.screenshot(path=str(target), full_page=s.full)
                    save(target)
                    if s.name.startswith("tour"):
                        page.keyboard.press("Escape")
                    page.keyboard.press("Escape")
                    print(f"{s.name}: {target.stat().st_size // 1024} KB")
                browser.close()
        finally:
            server.should_exit = True


if __name__ == "__main__":
    main(sys.argv[1:])
