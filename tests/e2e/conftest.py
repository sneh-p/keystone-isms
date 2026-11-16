"""End-to-end browser tests. Opt in with KEYSTONE_E2E=1 (needs the built web app and Playwright):

    cd web && npm run build && cd ..
    pip install -e ".[e2e]" && playwright install chromium
    KEYSTONE_E2E=1 pytest tests/e2e -v

Each server runs in its own process with a fresh data directory, so no other data is touched.
"""

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[2]
PASSWORD = "Demo-Password-2026!"

if not os.environ.get("KEYSTONE_E2E"):
    pytest.skip("browser tests run only with KEYSTONE_E2E=1", allow_module_level=True)
playwright = pytest.importorskip("playwright.sync_api")
if not (ROOT / "web" / "dist" / "index.html").exists():
    pytest.skip("build the web app first (cd web && npm run build)", allow_module_level=True)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _start(data_dir: Path, seed: bool):
    env = {**os.environ, "KEYSTONE_DATA_DIR": str(data_dir), "KEYSTONE_DISABLE_SCHEDULER": "1"}
    env.pop("KEYSTONE_DB_URL", None)
    env.pop("ANTHROPIC_API_KEY", None)
    if seed:
        subprocess.run([sys.executable, str(ROOT / "scripts" / "seed_demo.py")], env=env, check=True, cwd=ROOT, capture_output=True)
    port = _free_port()
    proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "keystone.api.app:create_app", "--factory", "--host", "127.0.0.1", "--port", str(port)], env=env, cwd=ROOT,
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    url = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            if httpx.get(f"{url}/api/auth/status", timeout=1).status_code == 200:
                return proc, url
        except httpx.HTTPError:
            time.sleep(0.1)
    proc.kill()
    raise RuntimeError("server did not start: " + proc.stderr.read().decode()[-2000:])


@pytest.fixture(scope="session")
def demo_server(tmp_path_factory):
    proc, url = _start(tmp_path_factory.mktemp("demo"), seed=True)
    yield url
    proc.terminate()
    proc.wait(10)


@pytest.fixture
def empty_server(tmp_path):
    proc, url = _start(tmp_path, seed=False)
    yield url
    proc.terminate()
    proc.wait(10)


@pytest.fixture(scope="session")
def browser():
    with playwright.sync_playwright() as p:
        b = p.chromium.launch()
        yield b
        b.close()


class Page:
    """A browser page that records page errors; tests assert there are none."""

    def __init__(self, browser, base: str):
        self.ctx = browser.new_context(viewport={"width": 1440, "height": 950})
        self.page = self.ctx.new_page()
        self.base = base
        self.errors: list[str] = []
        self.page.on("pageerror", lambda e: self.errors.append(str(e)[:300]))

    def go(self, path: str):
        self.page.goto(self.base + path, wait_until="networkidle")
        return self.page

    def login(self, username: str, password: str = PASSWORD):
        p = self.go("/login")
        p.get_by_label("Username").fill(username)
        p.locator("input[type=password]").fill(password)
        p.get_by_role("button", name="Sign in").click()
        p.wait_for_url(lambda u: "/login" not in u)
        return p


@pytest.fixture
def open_page(browser):
    pages = []

    def make(base: str) -> Page:
        pg = Page(browser, base)
        pages.append(pg)
        return pg

    yield make
    for pg in pages:
        assert pg.errors == [], pg.errors
        pg.ctx.close()
