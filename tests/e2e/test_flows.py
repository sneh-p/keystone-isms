"""Key user journeys in a real browser against a real server."""

import io
import re

import yaml
from openpyxl import Workbook, load_workbook

from tests.e2e.conftest import ROOT, set_tours

STAFF_ROUTES = ["/", "/frameworks", "/controls", "/soa", "/evidence", "/risks", "/tasks", "/people", "/trust-center", "/integrations",
                "/security-questionnaires", "/assets", "/vendors", "/questionnaires", "/assessments", "/exposure", "/policies", "/incidents",
                "/nonconformities", "/audits", "/reviews", "/reports", "/settings/organisation", "/settings/users", "/settings/audit-log",
                "/settings/account", "/settings/ai",
                # round 3 screens
                "/attack-surface", "/attack-surface?tab=vulnerabilities", "/attack-surface?tab=external", "/privacy", "/privacy?tab=dpias",
                "/privacy?tab=requests", "/privacy?tab=breaches", "/continuity", "/continuity?tab=plans", "/continuity?tab=tests", "/settings/system",
                "/calendar", "/workload", "/access-reviews", "/settings/provisioning",
                # configuration baselines
                "/configuration", "/configuration?tab=targets", "/configuration?tab=baselines", "/configuration?tab=agents", "/configuration?tab=upload",
                # round 4
                "/configuration?tab=custom", "/people?tab=training",
                # round 6: in-app help
                "/help", "/help#risk-register",
                # round 8: security expansion, batch 1
                "/registers/obligations", "/registers/changes", "/registers/policy-exceptions", "/registers/screening", "/registers/confidentiality",
                "/registers/sites", "/registers/visitors", "/registers/physical-checks", "/exceptions", "/security-reports", "/access-check",
                # batch 2
                "/alerts", "/alerts?tab=sources", "/registers/pentests", "/registers/findings", "/registers/applications", "/registers/threat-models",
                "/registers/release-signoffs", "/registers/crypto", "/registers/backups", "/indicators", "/maturity",
                "/phishing", "/domain-protection", "/domain-protection?tab=dmarc", "/vendor-breaches", "/on-call"]


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
    tour = p.get_by_role("dialog", name="Keystone tour")  # a new administrator is offered the tour first
    tour.wait_for()
    tour.get_by_role("button", name="Skip tour").click()
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
    tour = e.get_by_role("dialog", name="Employee portal tour")  # a new employee is offered the portal tour
    tour.wait_for()
    tour.get_by_role("button", name="Skip tour").click()
    e.get_by_role("button", name="Read and accept").first.click()
    accept = e.get_by_role("button", name="I have read and understood this policy")
    assert accept.is_disabled()  # an e-signature is needed first
    e.get_by_label("Sign by typing your full name", exact=False).fill("Jo Rivera")
    accept.click()
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


A11Y_ROUTES = STAFF_ROUTES + ["/frameworks/ISO27001_2022", "/onboarding"]
AXE_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice"]


def test_help_opens_at_the_page_and_searches(demo_server, open_page):
    pg = open_page(demo_server)
    p = pg.login("raj.risk")
    pg.go("/configuration?tab=baselines")
    p.get_by_role("link", name="Help for this page").click()
    p.wait_for_url("**/help#configuration")
    p.locator("h3#configuration").wait_for()
    assert p.locator("article img").count() > 3  # the guide's own screenshots
    p.get_by_label("Search help").fill("treatment plan")
    results = p.get_by_role("region", name="Search results").get_by_role("button")
    assert results.count() >= 1 and "Risk register" in results.first.inner_text()
    results.first.click()
    p.wait_for_url("**/help#risk-register")
    p.locator("[data-tour=account]").click()  # also in the account menu
    p.get_by_role("menuitem", name="Help").click()
    p.wait_for_url("**/help")


def test_employees_get_the_portal_help_only(demo_server, open_page):
    pg = open_page(demo_server)
    p = pg.login("nina.weber@alpineskihouse.example")
    p.get_by_role("link", name="Help").click()
    p.wait_for_url("**/portal/help")
    p.get_by_text("How the employee portal works").wait_for()
    assert "Policies to accept" in p.inner_text("main") and p.locator("article img").count() >= 1
    pg.go("/help")
    assert p.url.endswith("/portal")  # the staff guide is for staff


def test_own_training_module_reaches_the_portal(demo_server, open_page):
    mgr = open_page(demo_server)
    p = mgr.login("mia.isms")
    mgr.go("/people?tab=training")
    p.get_by_role("button", name="New module").click()
    d = p.get_by_role("dialog")
    d.get_by_label("Title").fill("Clean desk")
    d.get_by_label("Summary").fill("Lock your screen and clear your desk.")
    d.get_by_label("Content").fill("## Before you leave\nLock the screen and put papers away.")
    d.get_by_label("Question 1", exact=True).fill("What do you do before leaving your desk?")
    d.get_by_label("Question 1, answer 1").fill("Nothing")
    d.get_by_label("Question 1, answer 2").fill("Lock the screen")
    d.get_by_label("Answer 2 is right").check()
    d.get_by_role("button", name="Create module").click()
    p.get_by_role("cell", name="Clean desk").first.wait_for()

    emp = open_page(demo_server)
    e = emp.login("nina.weber@alpineskihouse.example")
    e.get_by_role("link", name="Clean desk").click()
    e.wait_for_url("**/portal/training/**")
    e.get_by_label("Lock the screen").check()
    e.get_by_role("button", name="Submit answers").click()
    e.wait_for_selector("text=Passed with")


def test_report_from_the_portal_and_triage(demo_server, open_page):
    emp = open_page(demo_server)
    e = emp.login("nina.weber@alpineskihouse.example")
    e.get_by_role("button", name="Report something").click()
    d = e.get_by_role("dialog")
    d.get_by_role("combobox", name="What happened").click()
    e.get_by_role("option", name="Lost or stolen device").click()
    d.get_by_label("Tell us more").fill("Left my work phone on the train this morning.")
    d.get_by_role("button", name="Send report").click()
    e.get_by_text("With the security team").first.wait_for()

    mgr = open_page(demo_server)
    m = mgr.login("mia.isms")
    mgr.go("/security-reports")
    m.get_by_role("cell", name="Lost or stolen device").first.click()
    m.get_by_role("button", name="Open an incident").click()
    m.get_by_role("dialog").last.get_by_role("button", name="Open incident").click()
    m.get_by_text("Handled as an incident").first.wait_for()


def test_first_sign_in_tour(demo_server, open_page):
    pg = open_page(demo_server)
    p = pg.login("mia.isms", tour=True)
    set_tours(p, demo_server, None)  # as if signing in for the first time
    tour = p.get_by_role("dialog", name="Keystone tour")
    tour.wait_for()
    assert "Step 1 of" in tour.inner_text()
    tour.get_by_role("button", name="Start tour").click()
    assert "Search or jump to" in tour.inner_text()
    p.keyboard.press("ArrowRight")
    assert "Overview" in tour.inner_text()
    p.keyboard.press("Escape")  # ending the tour early is remembered
    tour.wait_for(state="detached")
    pg.go("/risks")
    p.wait_for_timeout(500)
    assert p.get_by_role("dialog", name="Keystone tour").count() == 0
    assert p.request.get(f"{demo_server}/api/portal/tours").json()["app"]["outcome"] == "skipped"
    p.locator("[data-tour=account]").click()  # and it can be taken again
    p.get_by_role("menuitem", name="Take the tour").click()
    tour.wait_for()
    while tour.get_by_role("button", name="Finish").count() == 0:
        tour.get_by_role("button", name=re.compile("Start tour|Next")).click()
    tour.get_by_role("button", name="Finish").click()
    tour.wait_for(state="detached")
    p.wait_for_timeout(300)
    assert p.request.get(f"{demo_server}/api/portal/tours").json()["app"]["outcome"] == "completed"


def _axe(page) -> list[dict]:
    page.add_script_tag(path=str(ROOT / "web" / "node_modules" / "axe-core" / "axe.min.js"))
    return page.evaluate("async (tags) => (await axe.run(document, {runOnly: {type: 'tag', values: tags}})).violations"
                         ".map(v => ({id: v.id, impact: v.impact, nodes: v.nodes.slice(0, 3).map(n => n.target.join(' '))}))", AXE_TAGS)


def test_accessibility_wcag21_aa(demo_server, browser):
    """WCAG 2.1 AA + axe best practices on every screen, in light and dark mode, plus the public pages.
    The test browser bypasses the app's CSP only to inject axe; the app itself is unchanged."""
    problems = {}
    for scheme in ("light", "dark"):
        ctx = browser.new_context(viewport={"width": 1440, "height": 900}, color_scheme=scheme, bypass_csp=True)
        page = ctx.new_page()
        page.goto(demo_server + "/login", wait_until="networkidle")
        if scheme == "light":
            problems["/login"] = _axe(page)
        page.get_by_label("Username").fill("admin")
        page.locator("input[type=password]").fill("Demo-Password-2026!")
        page.get_by_role("button", name="Sign in").click()
        page.wait_for_url(lambda u: "/login" not in u)
        if scheme == "light":  # the guided tour opens on first sign-in: check it, then end it
            set_tours(page, demo_server, None)
            page.get_by_role("dialog", name="Keystone tour").wait_for()
            problems["tour"] = _axe(page)
            page.keyboard.press("Escape")
            page.get_by_role("dialog", name="Keystone tour").wait_for(state="detached")
        for route in A11Y_ROUTES:
            page.goto(demo_server + route, wait_until="networkidle")
            found = _axe(page)
            if found:
                problems[f"{scheme} {route}"] = found
        ctx.close()
    ctx = browser.new_context(viewport={"width": 1280, "height": 900}, bypass_csp=True)
    page = ctx.new_page()
    page.goto(demo_server + "/trust/alpine-ski-house", wait_until="networkidle")
    problems["/trust/alpine-ski-house"] = _axe(page)
    page.goto(demo_server + "/phish#t=not-a-real-token-123", wait_until="networkidle")
    page.get_by_role("heading", name="This was a practice phishing email").wait_for()
    assert "#t=" not in page.url  # the token doesn't stay in the address bar
    problems["/phish"] = _axe(page)
    ctx.close()
    problems = {k: v for k, v in problems.items() if v}
    assert not problems, problems
