"""Managing training: the organisation's own modules, switching modules off, copying built-ins, and training done
elsewhere (with certificates). Quiz answers never reach the portal; certificates only reach people managers."""

from datetime import timedelta

from keystone.core.services import today
from keystone.people import service as ppl

from .conftest import api_login

QUIZ = [{"q": "Where do you report a lost badge?", "options": ["Reception", "The security desk", "Nobody"], "answer": 1},
        {"q": "Can visitors borrow a badge?", "options": ["Yes", "No"], "answer": 1}]
MODULE = {"title": "Building access and visitors", "summary": "Badges, tailgating and visitors.", "minutes": 5,
          "body": "## Badges\nWear your badge at all times.", "quiz": QUIZ, "pass_mark": 2}
PDF = b"%PDF-1.4\n% fictional certificate\n%%EOF\n"


def _portal_training(api) -> dict:
    return {m["key"]: m for m in api.get("/api/portal").json()["training"]}


def test_own_module_lifecycle(api, ready_users):
    api_login(api, "admin")
    r = api.post("/api/training/modules", json=MODULE)
    assert r.status_code == 200, r.text
    key = r.json()["key"]
    assert key.startswith("own-building-access") and r.json()["version"] == 1
    listed = {m["key"]: m for m in api.get("/api/training/assignments").json()["modules"]}
    assert listed[key]["source"] == "custom" and listed[key]["active"] is True and listed["phishing"]["source"] == "builtin"
    assert api.get(f"/api/training/modules/{key}").json()["quiz"][0]["answer"] == 1  # managers see the answers

    api_login(api, "employee")
    assert key in _portal_training(api)
    public = api.get(f"/api/portal/training/{key}").json()
    assert all("answer" not in q for q in public["quiz"])  # the portal never gets the answers
    assert api.get(f"/api/training/modules/{key}").status_code == 403
    assert api.post(f"/api/portal/training/{key}", json={"answers": [1, 1]}).json()["passed"] is True
    assert _portal_training(api)[key]["completed_at"] is not None

    api_login(api, "admin")
    fix = api.put(f"/api/training/modules/{key}", json=MODULE | {"summary": "Badges, tailgating and visitors (typo fixed)."})
    assert fix.json()["version"] == 1  # a correction doesn't ask people again
    new = api.put(f"/api/training/modules/{key}", json=MODULE | {"retake": True})
    assert new.json()["version"] == 2
    api_login(api, "employee")
    assert _portal_training(api)[key]["completed_at"] is None  # the pass was for version 1

    api_login(api, "admin")
    assert api.put(f"/api/training/modules/{key}/active", json={"active": False}).status_code == 200
    api_login(api, "employee")
    assert key not in _portal_training(api)
    assert api.get(f"/api/portal/training/{key}").status_code == 404

    api_login(api, "admin")
    r = api.delete(f"/api/training/modules/{key}")
    assert r.status_code == 400 and "Switch it off" in r.json()["detail"]  # someone took it: a training record


def test_module_validation(api, ready_users):
    api_login(api, "admin")
    bad = [
        {"pass_mark": 3},  # more than the number of questions
        {"quiz": [{"q": "Q", "options": ["Same", "same"], "answer": 0}], "pass_mark": 1},
        {"quiz": [{"q": "Q", "options": ["A", "B"], "answer": 2}], "pass_mark": 1},
    ]
    for b in bad:
        assert api.post("/api/training/modules", json=MODULE | b).status_code in (400, 422), b
    assert api.post("/api/training/modules", json=MODULE | {"quiz": []}).status_code == 422
    assert api.post("/api/training/modules", json=MODULE | {"key": "phishing"}).status_code == 422  # keys are Keystone's
    assert api.post("/api/training/modules", json=MODULE | {"minutes": 0}).status_code == 422
    assert api.put("/api/training/modules/phishing", json=MODULE).status_code == 400  # built-ins can't be edited
    assert api.put("/api/training/modules/nope", json=MODULE).status_code == 404


def test_permissions(api, ready_users):
    assert api.post("/api/training/modules", json=MODULE).status_code == 401
    api_login(api, "viewer")
    assert api.post("/api/training/modules", json=MODULE).status_code == 403
    assert api.put("/api/training/modules/phishing/active", json={"active": False}).status_code == 403
    assert api.get("/api/training/modules/phishing").status_code == 403  # the answers are for managers only
    assert api.get("/api/training/external").status_code == 403
    assert api.post("/api/training/external", data={"person_id": "1", "completed_on": str(today())}).status_code == 403
    api_login(api, "employee")
    assert api.get("/api/training/external").status_code == 403


def test_copying_a_builtin_module(api, ready_users):
    api_login(api, "admin")
    api.put("/api/training/assignments/phishing", json={"audience": {"departments": ["Finance"], "employment_types": []}, "due_days": 14})
    r = api.post("/api/training/modules/phishing/copy")
    assert r.status_code == 200
    key = r.json()["key"]
    mods = {m["key"]: m for m in api.get("/api/training/assignments").json()["modules"]}
    assert mods["phishing"]["active"] is False and mods[key]["active"] is True and mods[key]["copied_from"] == "phishing"
    assert mods[key]["due_days"] == 14 and mods[key]["audience"]["departments"] == ["Finance"]
    full = api.get(f"/api/training/modules/{key}").json()
    assert full["title"] == "Phishing and social engineering" and full["source"] == "custom"
    assert api.put(f"/api/training/modules/{key}", json={**MODULE, "title": full["title"]}).status_code == 200
    assert api.delete(f"/api/training/modules/{key}").status_code == 200  # nobody took the copy yet
    assert api.post("/api/training/modules/own-nothing/copy").status_code == 404


def test_training_done_elsewhere(api, ready_users, db):
    api_login(api, "admin")
    no_account = api.post("/api/people", json={"full_name": "Rafael Ortiz", "email": "rafael@example.example"}).json()["id"]
    when = str(today() - timedelta(days=30))
    r = api.post("/api/training/external", data={"person_id": str(no_account), "module_key": "phishing", "completed_on": when, "provider": "Classroom session"},
                 files={"file": ("certificate.pdf", PDF, "application/pdf")})
    assert r.status_code == 200, r.text
    rec = r.json()
    assert rec["title"] == "Phishing and social engineering" and rec["valid_until"] == str(today() - timedelta(days=30) + timedelta(days=365))
    assert api.get(f"/api/attachments/{rec['attachment_id']}").status_code == 200  # the people manager can open it
    import io

    from openpyxl import load_workbook

    ws = load_workbook(io.BytesIO(api.get("/api/training/matrix.xlsx").content)).active
    rows = {r[0]: r for r in ws.iter_rows(values_only=True)}
    headers = rows["Person"]
    assert "done elsewhere" in rows["Rafael Ortiz"][headers.index("Phishing and social engineering")]

    # It counts for someone with an account too, in their portal.
    with db.session_scope() as s:
        p = ppl.save_person(s, ready_users["admin"], full_name="Emp Loyee", email="emp@example.example")
        ppl.link_user(s, ready_users["admin"], p.id, ready_users["employee"].id)
        pid = p.id
    api.post("/api/training/external", data={"person_id": str(pid), "module_key": "phishing", "completed_on": when})
    api_login(api, "employee")
    assert _portal_training(api)["phishing"]["completed_at"] is not None

    api_login(api, "viewer")
    assert api.get(f"/api/attachments/{rec['attachment_id']}").status_code == 404  # certificates are personal data

    api_login(api, "admin")
    bad = [
        ({"person_id": str(no_account), "module_key": "phishing", "completed_on": str(today() + timedelta(days=1))}, None),
        ({"person_id": str(no_account), "module_key": "phishing", "completed_on": when, "valid_until": when}, None),
        ({"person_id": str(no_account), "completed_on": when}, None),  # neither a module nor a name
        ({"person_id": str(no_account), "module_key": "phishing", "completed_on": when}, ("cert.exe", b"MZ\x90\x00", "application/octet-stream")),
        ({"person_id": str(no_account), "module_key": "phishing", "completed_on": when}, ("cert.pdf", b"not a pdf", "application/pdf")),
        ({"person_id": "99999", "module_key": "phishing", "completed_on": when}, None),
        ({"person_id": str(no_account), "module_key": "nope", "completed_on": when}, None),
    ]
    for data, f in bad:
        r = api.post("/api/training/external", data=data, files={"file": f} if f else None)
        assert r.status_code in (400, 404, 422), (data, r.status_code)
    other = api.post("/api/training/external", data={"person_id": str(no_account), "title": "First aid at work", "completed_on": when}).json()
    assert other["module_key"] is None
    listed = api.get(f"/api/training/external?person_id={no_account}").json()
    assert {x["title"] for x in listed} == {"Phishing and social engineering", "First aid at work"} and listed[0]["person"] == "Rafael Ortiz"
    assert api.delete(f"/api/training/external/{other['id']}").status_code == 200
    assert len(api.get(f"/api/training/external?person_id={no_account}").json()) == 1


def test_a_copy_keeps_the_builtin_passes_until_its_next_version(session, users):
    u = users["viewer"]
    b = ppl.module(session, "phishing")
    ppl.submit_quiz(session, u, "phishing", [q["answer"] for q in b["quiz"]])
    copy = ppl.copy_builtin(session, users["admin"], "phishing")
    mine = {m["key"] for m in ppl.my_training(session, u) if m["completed_at"]}
    assert copy.key in mine and "phishing" not in {m["key"] for m in ppl.my_training(session, u)}  # the built-in is off
    ppl.save_module(session, users["admin"], copy.key, title=copy.title, summary=copy.summary, minutes=copy.minutes, body=copy.body + "\nNew rule.",
                    quiz=copy.quiz, pass_mark=copy.pass_mark, retake=True)
    assert copy.key not in {m["key"] for m in ppl.my_training(session, u) if m["completed_at"]}


def test_switching_off_a_builtin_hides_it_everywhere(session, users):
    ppl.set_module_active(session, users["admin"], "phishing", False)
    assert "phishing" not in [m["key"] for m in ppl.modules(session)]
    assert "phishing" in [m["key"] for m in ppl.modules(session, include_off=True)]
    headers, _ = ppl.training_matrix(session, users["admin"])
    assert "Phishing and social engineering" not in headers
    assert ppl.training_overdue(session, today() + timedelta(days=400)).get("Phishing and social engineering") is None
    ppl.set_module_active(session, users["admin"], "phishing", True)
    assert "phishing" in [m["key"] for m in ppl.modules(session)]
