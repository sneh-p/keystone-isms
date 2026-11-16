"""Key user journeys in a real browser against a real server."""

import io
import re

import yaml
from openpyxl import Workbook, load_workbook

from tests.e2e.conftest import ROOT

STAFF_ROUTES = ["/", "/frameworks", "/controls", "/soa", "/evidence", "/risks", "/tasks", "/people", "/trust-center", "/integrations",
                "/security-questionnaires", "/assets", "/vendors", "/questionnaires", "/assessments", "/exposure", "/policies", "/incidents",
                "/nonconformities", "/audits", "/reviews", "/reports", "/settings/organisation", "/settings/users", "/settings/audit-log",
                "/settings/account", "/settings/ai"]


def test_every_screen_renders(demo_server, open_page):
    pg = open_page(demo_server)
    p = pg.login("admin")
    for route in STAFF_ROUTES:
        pg.go(route)
        assert p.locator("h1").count() >= 1, route
        assert "Page not found" not in p.inner_text("main"), route


def test_onboarding_wizard_on_a_new_install(empty_server, open_page):
    pg = open_page(empty_server)
    p = pg.go("/setup")
    p.get_by_label("Username").fill("founder")
    p.get_by_label("Your name").fill("Founder")
    for field in p.locator("input[type=password]").all():
        field.fill("Setup-Passphrase-2026!")
    p.get_by_role("button", name=re.compile("Create")).click()
    p.wait_for_url(lambda u: "/setup" not in u)
    pg.go("/")
    p.get_by_role("button", name="Start setup").first.click()
    p.wait_for_url("**/onboarding")
    p.get_by_label("Company name").fill("Fabrikam Outdoor")
    p.get_by_role("button", name="Continue").click()
    p.get_by_role("button", name="Microsoft 365").click()
    p.get_by_role("button", name="Continue").click()
    p.get_by_role("button", name="Continue").click()
    p.get_by_role("button", name="Continue").click()
    p.get_by_role("button", name="Continue").click()
    p.get_by_role("button", name="Generate my ISMS").click()
    p.wait_for_selector("text=policies", timeout=20000)
    pg.go("/policies")
    assert p.locator("tbody tr").count() >= 10  # draft policies generated from templates
    pg.go("/tasks")
    assert "Run setup to generate tasks" not in p.inner_text("main")


def test_task_submit_and_independent_approval(demo_server, open_page):
    mia = open_page(demo_server)
    p = mia.login("mia.isms")
    tasks = p.request.get(f"{demo_server}/api/tasks").json()
    task = next(t for t in tasks if t["status"] == "todo" and t["assignee_id"] is not None)
    mia.go("/tasks")
    p.get_by_label("List view").click()
    p.get_by_text(task["title"]).first.click()
    p.get_by_role("button", name="Start").click()
    p.get_by_label("Notes for the reviewer").fill("Done; records on the IT share.")
    p.get_by_role("button", name="Submit for review").click()
    p.wait_for_timeout(500)
    assert p.request.get(f"{demo_server}/api/tasks/{task['id']}").json()["status"] == "in_review"

    admin = open_page(demo_server)
    a = admin.login("admin")
    admin.go("/tasks")
    a.get_by_label("List view").click()
    a.get_by_text(task["title"]).first.click()
    a.get_by_role("button", name="Approve").click()
    a.wait_for_timeout(500)
    assert a.request.get(f"{demo_server}/api/tasks/{task['id']}").json()["status"] == "done"


def test_employee_invite_portal_and_isolation(demo_server, open_page):
    admin = open_page(demo_server)
    a = admin.login("admin")
    admin.go("/people")
    a.get_by_role("button", name="Add person").click()
    a.get_by_label("Full name").fill("Jo Rivera")
    a.get_by_label("Work email").fill("jo.rivera@alpineskihouse.example")
    a.get_by_role("button", name="Add", exact=True).click()
    a.get_by_role("button", name="Create invitation link").click()
    link = a.locator("input[readonly]").input_value()
    assert "#token=" in link and "/invite/" not in link  # token only in the fragment
    path = link[link.index("/invite"):]

    emp = open_page(demo_server)
    e = emp.go(path)
    pw = e.locator("input[type=password]")
    pw.nth(0).fill("Jo-Rivera-Secure-2026")
    pw.nth(1).fill("Jo-Rivera-Secure-2026")
    e.get_by_role("button", name="Create my account").click()
    e.wait_for_url("**/portal")
    e.get_by_role("button", name="Read and accept").first.click()
    e.get_by_role("button", name="I have read and understood this policy").click()
    e.wait_for_timeout(400)
    module = yaml.safe_load((ROOT / "content" / "training" / "02-phishing.yaml").read_text(encoding="utf-8"))
    e.get_by_role("link", name=module["title"]).click()
    e.wait_for_url("**/training/phishing")
    for i, q in enumerate(module["quiz"]):
        e.locator(f"input[name=q{i}]").nth(q["answer"]).check()
    e.get_by_role("button", name="Submit answers").click()
    e.wait_for_selector("text=Passed with")
    emp.go("/risks")
    assert e.url.endswith("/portal")  # employees cannot reach ISMS records
    assert e.request.get(f"{demo_server}/api/risks").status == 403


def test_trust_center_access_request_nda_and_download(demo_server, open_page):
    visitor = open_page(demo_server)
    v = visitor.go("/trust/alpine-ski-house")
    assert "Security at Alpine Ski House" in v.inner_text("body")
    v.get_by_label("Name").fill("Dana Smith")
    v.get_by_label("Work email").fill("dana@customer.example")
    v.get_by_label("Company").fill("Customer Ltd")
    v.get_by_role("button", name="Request access").click()
    v.wait_for_selector("text=We'll review your request")

    admin = open_page(demo_server)
    a = admin.login("admin")
    admin.go("/trust-center")
    a.get_by_role("button", name="Approve").first.click()
    link = a.locator("[role=dialog] input[readonly]").input_value()
    assert "#access=" in link and "?access=" not in link
    v.goto(demo_server + link[link.index("/trust/"):], wait_until="networkidle")
    v.get_by_label("Type your full name to sign").fill("Dana Smith")
    v.get_by_role("button", name="I agree").click()
    v.wait_for_selector("text=Access granted")
    with v.expect_download() as d:
        v.get_by_role("button", name="Download").last.click()  # fetched with the X-Trust-Access header, saved in the browser
    assert d.value.suggested_filename.endswith(".pdf")


def test_security_questionnaire_manual_mode(demo_server, open_page, tmp_path):
    wb = Workbook()
    ws = wb.active
    ws.append(["Question", "Response"])
    ws.append(["Do you encrypt customer data at rest?", None])
    ws.append(["Do you test restores from backup?", None])
    f = tmp_path / "customer.xlsx"
    wb.save(f)

    pg = open_page(demo_server)
    p = pg.login("mia.isms")
    pg.go("/security-questionnaires")
    assert "AI drafting is off" in p.inner_text("main")
    p.get_by_role("button", name="New questionnaire").click()
    p.get_by_label("Title").fill("Customer review")
    p.locator("[role=dialog] input[type=file]").set_input_files(str(f))
    p.get_by_role("button", name="Import questions").click()
    p.wait_for_url("**/security-questionnaires/*")
    assert p.get_by_role("button", name="Draft open answers with AI").count() == 0
    p.get_by_role("button", name="Fill from knowledge base").click()
    p.wait_for_selector("text=Knowledge base")
    p.locator("li button").filter(has_text="Do you encrypt customer data at rest?").click()
    p.get_by_role("button", name="Approve and next").click()
    p.wait_for_timeout(400)
    p.keyboard.press("Escape")
    p.get_by_role("button", name="Export").click()
    with p.expect_download() as d:
        p.get_by_role("menuitem", name="Approved answers (.xlsx)").click()
    out = load_workbook(io.BytesIO(open(d.value.path(), "rb").read())).active
    assert out.cell(row=2, column=2).value.startswith("Yes.") and out.cell(row=3, column=2).value in (None, "")
