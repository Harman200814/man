"""Run: python -m pytest -q   (or: pip install pytest first)"""
import os, tempfile
import app as m

def client():
    m.DB = os.path.join(tempfile.mkdtemp(), "t.db"); m.FAILS.clear()
    with m.app.app_context():
        m.init_db(); m.db().executescript(m.AUDIT)
    return m.app.test_client()

def login(c, u="planner", p="plan123"): return c.post("/api/login", json={"username": u, "password": p})
def tok(c): return {"X-CSRF-Token": c.get("/api/state").get_json()["csrf"]}
ORDER = {"product_id": 1, "qty": 10, "due_days": 5}

def test_requires_login():
    assert client().get("/api/state").status_code == 403

def test_csrf_blocks_forged_requests():
    c = client(); login(c)
    assert c.post("/api/orders", json=ORDER).status_code == 403
    assert c.post("/api/orders", json=ORDER, headers={"X-CSRF-Token": "wrong"}).status_code == 403
    assert c.post("/api/orders", json=ORDER, headers=tok(c)).status_code == 200

def test_supervisor_cannot_plan():
    c = client(); login(c, "supervisor", "sup123")
    assert c.post("/api/orders", json=ORDER, headers=tok(c)).status_code == 403
    assert c.post("/api/progress", json={"schedule_id": 1, "qty": 1}, headers=tok(c)).status_code == 200

def test_validation_and_injection():
    c = client(); login(c); h = tok(c)
    assert c.post("/api/orders", json={**ORDER, "qty": -5}, headers=h).status_code == 400
    assert c.post("/api/orders", json={**ORDER, "product_id": "1 OR 1=1"}, headers=h).status_code == 400
    assert login(c, "' OR 1=1 --", "x").status_code == 401

def test_order_edit_cancel_and_audit():
    c = client(); login(c); h = tok(c)
    assert c.put("/api/orders/1", json={"due_day": 9, "priority": "Low"}, headers=h).status_code == 200
    assert c.delete("/api/orders/1", headers=h).status_code == 200
    assert all(o["order_id"] != 1 for o in c.get("/api/state").get_json()["orders"])
    assert any("DELETE" in a["action"] for a in c.get("/api/users").get_json()["audit"])

def test_weak_password_rejected():
    c = client(); login(c); h = tok(c)
    assert c.post("/api/password", json={"old": "plan123", "new": "short"}, headers=h).status_code == 400

def test_security_headers():
    r = client().get("/")
    assert r.headers["X-Frame-Options"] == "DENY" and "default-src 'self'" in r.headers["Content-Security-Policy"]

def test_lockout_after_failed_logins():
    c = client()
    for _ in range(5): login(c, "planner", "bad")
    assert login(c).status_code == 429

def test_assistant_answers_and_requires_login():
    c = client(); assert c.post("/api/assistant", json={"message": "hi"}).status_code == 403
    login(c); h = tok(c)
    r = c.post("/api/assistant", json={"message": "How do I create an order?"}, headers=h).get_json()
    assert "Orders page" in r["reply"] and r["source"] in ("built-in", "claude")
    assert c.post("/api/assistant", json={"message": ""}, headers=h).status_code == 400
