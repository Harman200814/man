"""Manufacturing Production Planning System - Flask + SQLite server.
Run:  pip install -r requirements.txt  then  python app.py   (http://127.0.0.1:5000)
Logins: planner / plan123 (full access), supervisor / sup123 (progress, schedule, materials view)."""
import csv, io, json, math, os, re, secrets, sqlite3, time, urllib.request
from functools import wraps
from flask import Flask, Response, g, jsonify, request, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
def _key():
    if os.environ.get("SECRET_KEY"): return os.environ["SECRET_KEY"]
    if not os.path.exists(".secret_key"):
        with open(".secret_key", "w") as f: f.write(secrets.token_hex(32))
    return open(".secret_key").read().strip()
app.secret_key = _key()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=os.environ.get("HTTPS") == "1",
                  PERMANENT_SESSION_LIFETIME=7200, MAX_CONTENT_LENGTH=64 * 1024)
DB, DAY = "planning.db", 8
code = lambda i: "O-%d" % (100 + i)

SCHEMA = """
CREATE TABLE users(username TEXT PRIMARY KEY, pw TEXT, role TEXT);
CREATE TABLE setting(k TEXT PRIMARY KEY, v INT);
CREATE TABLE product(product_id INTEGER PRIMARY KEY, name TEXT NOT NULL);
CREATE TABLE stage(stage_id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL);
CREATE TABLE product_stage(product_id INT, stage_id INT, seq INT, hrs REAL, PRIMARY KEY(product_id, stage_id));
CREATE TABLE material(material_id INTEGER PRIMARY KEY, name TEXT UNIQUE, unit TEXT, stock REAL, reorder REAL);
CREATE TABLE bom(product_id INT, material_id INT, qty REAL, PRIMARY KEY(product_id, material_id));
CREATE TABLE machine(machine_id INTEGER PRIMARY KEY, name TEXT, stage_id INT, down INT DEFAULT 0);
CREATE TABLE worker(worker_id INTEGER PRIMARY KEY, name TEXT, stage_id INT);
CREATE TABLE prod_order(order_id INTEGER PRIMARY KEY, product_id INT, qty INT, due_day INT, priority TEXT);
CREATE TABLE schedule(schedule_id INTEGER PRIMARY KEY, order_id INT, stage_id INT, machine_id INT,
  worker_id INT, start_h INT, end_h INT, done INT DEFAULT 0);
CREATE TABLE progress_log(log_id INTEGER PRIMARY KEY, schedule_id INT, qty INT, at_h INT, by_user TEXT);
CREATE TABLE activity(id INTEGER PRIMARY KEY, at_h INT, msg TEXT);
"""

# ---------- database helpers ----------
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d: d.close()

def q(sql, a=()): return [dict(r) for r in db().execute(sql, a).fetchall()]
def one(sql, a=()):
    r = q(sql, a)
    return r[0] if r else None
def run(sql, a=()):
    c = db().execute(sql, a); db().commit(); return c.lastrowid
def now(): return one("SELECT v FROM setting WHERE k='now'")["v"]
def log(msg): run("INSERT INTO activity(at_h,msg) VALUES(?,?)", (now(), msg))

# ---------- scheduling ----------
def machine_free(mid, skip=None):
    r = one("SELECT MAX(end_h) m FROM schedule WHERE machine_id=? AND schedule_id IS NOT ?", (mid, skip))
    return r["m"] or 0

def plan(oid, frm):
    """Create one schedule row per stage, in order, on the machine that frees up first."""
    o = one("SELECT * FROM prod_order WHERE order_id=?", (oid,)); prev = frm
    for ps in q("SELECT * FROM product_stage WHERE product_id=? ORDER BY seq", (o["product_id"],)):
        dur = max(2, math.ceil(ps["hrs"] * o["qty"] / 5))
        ms = q("SELECT * FROM machine WHERE stage_id=?", (ps["stage_id"],))
        m = min([x for x in ms if not x["down"]] or ms, key=lambda x: machine_free(x["machine_id"]))
        ws = q("SELECT * FROM worker WHERE stage_id=?", (ps["stage_id"],))
        w = min(ws, key=lambda x: one("SELECT COUNT(*) c FROM schedule WHERE worker_id=?", (x["worker_id"],))["c"])
        s = max(prev, machine_free(m["machine_id"]))
        run("INSERT INTO schedule(order_id,stage_id,machine_id,worker_id,start_h,end_h) VALUES(?,?,?,?,?,?)",
            (oid, ps["stage_id"], m["machine_id"], w["worker_id"], s, s + dur))
        prev = s + dur

def advance(h):
    n = now() + h
    run("UPDATE setting SET v=? WHERE k='now'", (n,))
    for r in q("SELECT s.*, o.qty FROM schedule s JOIN prod_order o ON o.order_id=s.order_id"):
        if r["end_h"] <= n: t = r["qty"]
        elif r["start_h"] < n: t = r["qty"] * (n - r["start_h"]) // (r["end_h"] - r["start_h"])
        else: t = 0
        if t > r["done"]:
            run("UPDATE schedule SET done=? WHERE schedule_id=?", (t, r["schedule_id"]))
            if t == r["qty"] and h: log("%s %s finished" % (code(r["order_id"]), one("SELECT name FROM stage WHERE stage_id=?", (r["stage_id"],))["name"]))

# ---------- auth ----------
def need(*roles):
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            if session.get("role") not in roles:
                return jsonify(error="You do not have access to this action."), 403
            return f(*a, **k)
        return w
    return deco

FAILS = {}  # (ip, username) -> [failed attempts, locked until]
AUDIT = "CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, at TEXT, user TEXT, action TEXT, ip TEXT);"

@app.before_request
def csrf_guard():
    """Every state-changing request must carry the token issued at login."""
    if request.method in ("POST", "PUT", "DELETE") and request.path != "/api/login":
        if not session.get("csrf") or not secrets.compare_digest(request.headers.get("X-CSRF-Token", ""), session["csrf"]):
            return jsonify(error="Security check failed. Reload the page and sign in again."), 403

@app.after_request
def harden(resp):
    resp.headers.update({
        "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
                                   "frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        "Cache-Control": "no-store" if request.path.startswith("/api") else "no-cache"})
    if request.method != "GET" and session.get("user") and resp.status_code < 400:
        run("INSERT INTO audit(at,user,action,ip) VALUES(?,?,?,?)",
            (time.strftime("%Y-%m-%d %H:%M:%S"), session["user"], request.method + " " + request.path, request.remote_addr))
    return resp

@app.post("/api/login")
def login():
    d = request.get_json(silent=True) or {}
    name = str(d.get("username", "")).strip().lower()[:40]; key = (request.remote_addr, name)
    cnt, until = FAILS.get(key, [0, 0])
    if until > time.time(): return jsonify(error="Too many failed attempts. Try again in 5 minutes."), 429
    u = one("SELECT * FROM users WHERE username=?", (name,))
    if not u or not check_password_hash(u["pw"], str(d.get("password", ""))[:200]):
        FAILS[key] = [cnt + 1, time.time() + 300 if cnt + 1 >= 5 else 0]
        return jsonify(error="Wrong username or password."), 401
    FAILS.pop(key, None); session.clear(); session.permanent = True
    session.update(role=u["role"], user=u["username"], csrf=secrets.token_hex(16))
    return jsonify(ok=True)

@app.post("/api/logout")
def logout():
    session.clear(); return jsonify(ok=True)

# ---------- read model ----------
@app.get("/api/state")
@need("Planner", "Supervisor")
def state():
    n = now()
    S = q("""SELECT s.*, st.name stage, m.name machine, w.name worker, o.qty
             FROM schedule s JOIN stage st ON st.stage_id=s.stage_id JOIN machine m ON m.machine_id=s.machine_id
             JOIN worker w ON w.worker_id=s.worker_id JOIN prod_order o ON o.order_id=s.order_id ORDER BY s.start_h""")
    for r in S: r["code"] = code(r["order_id"])
    O = q("SELECT o.*, p.name product FROM prod_order o JOIN product p ON p.product_id=o.product_id")
    for o in O:
        rows = [r for r in S if r["order_id"] == o["order_id"]]
        end = max(r["end_h"] for r in rows)
        pct = round(sum(min(1, r["done"] / o["qty"]) for r in rows) / len(rows) * 100)
        o.update(code=code(o["order_id"]), end_h=end, pct=pct,
                 status="Completed" if pct >= 100 else "Delayed" if end > o["due_day"] * DAY
                 else "In progress" if pct else "Scheduled")
    bom, need_q = q("SELECT * FROM bom"), {}
    for o in (x for x in O if x["status"] != "Completed"):
        for b in bom:
            if b["product_id"] == o["product_id"]:
                need_q[b["material_id"]] = need_q.get(b["material_id"], 0) + b["qty"] * o["qty"]
    M = q("SELECT * FROM material")
    for m in M:
        m["need"] = round(need_q.get(m["material_id"], 0), 1)
        m["status"] = "Shortage" if m["need"] > m["stock"] else "Reorder" if m["stock"] <= m["reorder"] else "OK"
    MC = q("SELECT m.*, s.name stage FROM machine m JOIN stage s ON s.stage_id=m.stage_id")
    for m in MC:
        m["running"] = any(r["machine_id"] == m["machine_id"] and r["start_h"] <= n < r["end_h"] for r in S)
    return jsonify(now=n, csrf=session["csrf"], role=session["role"], user=session["user"], orders=O, schedule=S, machines=MC,
                   materials=M, products=q("SELECT * FROM product"),
                   activity=q("SELECT * FROM activity ORDER BY id DESC LIMIT 12"))

# ---------- actions ----------
@app.post("/api/orders")
@need("Planner")
def create_order():
    d = request.get_json(silent=True) or {}
    try:
        pid, qty, due = int(d["product_id"]), int(d["qty"]), int(d["due_days"])
    except (KeyError, ValueError, TypeError):
        return jsonify(error="Product, quantity and due days are required numbers."), 400
    if not one("SELECT 1 FROM product WHERE product_id=?", (pid,)) or not 1 <= qty <= 10000 or due < 1:
        return jsonify(error="Check the product, quantity (1 to 10000) and due days."), 400
    pr = d.get("priority") if d.get("priority") in ("High", "Medium", "Low") else "Medium"
    oid = run("INSERT INTO prod_order(product_id,qty,due_day,priority) VALUES(?,?,?,?)",
              (pid, qty, now() // DAY + due, pr))
    plan(oid, now()); log("Created " + code(oid)); return jsonify(ok=True)

@app.post("/api/progress")
@need("Planner", "Supervisor")
def progress():
    d = request.get_json(silent=True) or {}
    try: sid, n = int(d["schedule_id"]), int(d["qty"])
    except (KeyError, ValueError, TypeError): return jsonify(error="Stage and units are required."), 400
    r = one("SELECT s.*, o.qty total FROM schedule s JOIN prod_order o ON o.order_id=s.order_id WHERE schedule_id=?", (sid,))
    if not r or n < 1: return jsonify(error="Unknown stage or invalid units."), 400
    done = min(r["total"], r["done"] + n)
    run("UPDATE schedule SET done=? WHERE schedule_id=?", (done, sid))
    run("INSERT INTO progress_log(schedule_id,qty,at_h,by_user) VALUES(?,?,?,?)", (sid, n, now(), session["user"]))
    log("%s: %d/%d units done (by %s)" % (code(r["order_id"]), done, r["total"], session["user"]))
    return jsonify(ok=True)

@app.post("/api/tick")
@need("Planner", "Supervisor")
def tick():
    h = int((request.get_json(silent=True) or {}).get("hours", 1))
    advance(max(1, min(h, 48))); return jsonify(ok=True)

@app.post("/api/schedule/<int:sid>/machine")
@need("Planner")
def reassign(sid):
    mid = int((request.get_json(silent=True) or {}).get("machine_id", 0))
    s, m = one("SELECT * FROM schedule WHERE schedule_id=?", (sid,)), one("SELECT * FROM machine WHERE machine_id=?", (mid,))
    if not s or not m or m["stage_id"] != s["stage_id"]: return jsonify(error="That machine cannot do this stage."), 400
    if one("SELECT 1 FROM schedule WHERE machine_id=? AND schedule_id!=? AND start_h<? AND ?<end_h",
           (mid, sid, s["end_h"], s["start_h"])):
        return jsonify(error=m["name"] + " is already booked during that time."), 409
    run("UPDATE schedule SET machine_id=? WHERE schedule_id=?", (mid, sid)); return jsonify(ok=True)

@app.post("/api/machines/<int:mid>/toggle")
@need("Planner")
def toggle(mid):
    m = one("SELECT * FROM machine WHERE machine_id=?", (mid,))
    if not m: return jsonify(error="Unknown machine."), 404
    run("UPDATE machine SET down=? WHERE machine_id=?", (1 - m["down"], mid))
    if m["down"]: log(m["name"] + " is back online"); return jsonify(moved=0)
    moved = 0
    for r in q("SELECT * FROM schedule WHERE machine_id=? AND end_h>?", (mid, now())):
        alts = [x for x in q("SELECT * FROM machine WHERE stage_id=? AND down=0 AND machine_id!=?", (m["stage_id"], mid))]
        if not alts: continue
        alt = min(alts, key=lambda x: machine_free(x["machine_id"], r["schedule_id"]))
        f = machine_free(alt["machine_id"], r["schedule_id"])
        run("UPDATE schedule SET machine_id=? WHERE schedule_id=?", (alt["machine_id"], r["schedule_id"]))
        if f > r["start_h"]:
            run("UPDATE schedule SET start_h=start_h+?, end_h=end_h+? WHERE order_id=? AND start_h>=?",
                (f - r["start_h"], f - r["start_h"], r["order_id"], r["start_h"]))
        moved += 1
    log("%s broke down; %d task(s) moved" % (m["name"], moved)); return jsonify(moved=moved)

@app.post("/api/materials/<int:mid>/restock")
@need("Planner")
def restock(mid):
    n = float((request.get_json(silent=True) or {}).get("qty", 100))
    if n <= 0: return jsonify(error="Quantity must be positive."), 400
    run("UPDATE material SET stock=stock+? WHERE material_id=?", (n, mid)); return jsonify(ok=True)

def strong(p): return len(p) >= 8 and re.search(r"[A-Za-z]", p) and re.search(r"\d", p)
WEAK = "8+ characters with at least one letter and one digit"

@app.put("/api/orders/<int:oid>")
@need("Planner")
def edit_order(oid):
    d = request.get_json(silent=True) or {}
    try: due = int(d["due_day"])
    except (KeyError, ValueError, TypeError): return jsonify(error="Due day is required."), 400
    if not one("SELECT 1 FROM prod_order WHERE order_id=?", (oid,)) or due < 1 or d.get("priority") not in ("High", "Medium", "Low"):
        return jsonify(error="Check the order, due day and priority."), 400
    run("UPDATE prod_order SET due_day=?, priority=? WHERE order_id=?", (due, d["priority"], oid))
    log("Edited " + code(oid)); return jsonify(ok=True)

@app.delete("/api/orders/<int:oid>")
@need("Planner")
def cancel_order(oid):
    if not one("SELECT 1 FROM prod_order WHERE order_id=?", (oid,)): return jsonify(error="Unknown order."), 404
    run("DELETE FROM progress_log WHERE schedule_id IN (SELECT schedule_id FROM schedule WHERE order_id=?)", (oid,))
    run("DELETE FROM schedule WHERE order_id=?", (oid,)); run("DELETE FROM prod_order WHERE order_id=?", (oid,))
    log("Cancelled " + code(oid)); return jsonify(ok=True)

@app.get("/api/users")
@need("Planner")
def list_users():
    return jsonify(users=q("SELECT username, role FROM users"), audit=q("SELECT * FROM audit ORDER BY id DESC LIMIT 25"))

@app.post("/api/users")
@need("Planner")
def add_user():
    d = request.get_json(silent=True) or {}
    n, p = str(d.get("username", "")).strip().lower(), str(d.get("password", ""))
    if not re.fullmatch(r"[a-z0-9_]{3,20}", n) or not strong(p) or d.get("role") not in ("Planner", "Supervisor"):
        return jsonify(error="Username: 3-20 letters, digits or _. Password: " + WEAK + "."), 400
    if one("SELECT 1 FROM users WHERE username=?", (n,)): return jsonify(error="That username is taken."), 409
    run("INSERT INTO users VALUES(?,?,?)", (n, generate_password_hash(p), d["role"])); return jsonify(ok=True)

@app.post("/api/password")
@need("Planner", "Supervisor")
def change_pw():
    d = request.get_json(silent=True) or {}; u = one("SELECT * FROM users WHERE username=?", (session["user"],))
    if not check_password_hash(u["pw"], str(d.get("old", ""))) or not strong(str(d.get("new", ""))):
        return jsonify(error="Current password is wrong, or the new one is too weak (" + WEAK + ")."), 400
    run("UPDATE users SET pw=? WHERE username=?", (generate_password_hash(d["new"]), u["username"])); return jsonify(ok=True)

@app.get("/api/docs")
@need("Planner", "Supervisor")
def docs():
    return jsonify(routes=sorted("%s %s" % (",".join(sorted(r.methods - {"HEAD", "OPTIONS"})), r.rule)
                                 for r in app.url_map.iter_rules() if r.rule.startswith("/api")))

# ---------- in-app assistant ----------
KB = [
 (("create", "new order", "add order", "place order"), "Create an order on the Orders page: choose a product, quantity, due days and priority, then press Create order. The system plans every stage in order, on the machine that frees up first."),
 (("idle",), "Idle means a machine has no task running right now. Many idle machines mean spare capacity; an idle machine while orders wait can point to a gap in the plan."),
 (("breakdown", "offline", "broke", "fails"), "On the Schedule page press Report breakdown next to the machine. It goes offline and its remaining tasks move to another machine of the same stage. Later stages shift, so the order may become Delayed."),
 (("progress", "log", "units", "finished"), "Log finished work on the Progress page: pick an order and stage, enter the units and press Log progress. Order progress is the average completion across all its stages."),
 (("material", "stock", "shortage", "reorder"), "Materials compares stock with what all open orders need. Shortage means need is higher than stock; Reorder means stock is at or below the reorder level. Planners can add stock."),
 (("clock", "play", "simulat", "hour"), "The clock in the header simulates factory time. Play moves it forward one hour per second and updates stage progress by itself. +1 hr and +1 day jump ahead."),
 (("role", "planner", "supervisor", "permission", "access"), "Planners can create and edit orders, move machines, manage users and read the audit log. Supervisors can view the plan and log progress."),
 (("status", "scheduled", "completed", "in progress"), "Order status: Scheduled = planned, nothing done yet; In progress = some work done; Delayed = planned finish is after the due day; Completed = every stage finished."),
 (("timeline", "gantt", "bar", "red line"), "The timeline shows one row per machine. Each coloured bar is a stage of an order. The red line is the current time. Click a bar to log progress for that stage."),
 (("audit", "log of", "history"), "The audit log (Account page, Planners only) records who changed what and when."),
]
SYSTEM = ("You are the in-app guide for a Manufacturing Production Planning System used by first-year engineering students. "
          "Explain features in short, plain language. Only answer about this app and basic production planning ideas. Facts about the app: "
          + " ".join(a for _, a in KB))
RATE = {}

def ask_claude(key, msg, live):
    body = json.dumps({"model": os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-5-5"), "max_tokens": 400,
                       "system": SYSTEM + " Live plant data: " + live, "messages": [{"role": "user", "content": msg}]}).encode()
    req = urllib.request.Request("https://api.anthropic.com/v1/messages", body, {
        "x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as r: return json.load(r)["content"][0]["text"]

@app.post("/api/assistant")
@need("Planner", "Supervisor")
def assistant():
    msg = str((request.get_json(silent=True) or {}).get("message", "")).strip()[:500]
    if not msg: return jsonify(error="Type a question first."), 400
    hits = [t for t in RATE.get(session["user"], []) if t > time.time() - 60]
    if len(hits) >= 15: return jsonify(error="Please wait a minute before asking more questions."), 429
    RATE[session["user"]] = hits + [time.time()]
    st = state().get_json()
    late = [o["code"] for o in st["orders"] if o["status"] == "Delayed"]
    short = [m["name"] for m in st["materials"] if m["status"] == "Shortage"]
    idle = [m["name"] for m in st["machines"] if not m["down"] and not m["running"]]
    down = [m["name"] for m in st["machines"] if m["down"]]
    live = "Delayed orders: %s. Material shortages: %s. Idle machines: %s. Offline machines: %s." % tuple(", ".join(x) or "none" for x in (late, short, idle, down))
    key = os.environ.get("ANTHROPIC_API_KEY")
    if key:
        try: return jsonify(reply=ask_claude(key, msg, live), source="claude")
        except Exception: pass  # fall back to the built-in guide
    low = msg.lower(); out = [a for kw, a in KB if any(k in low for k in kw)][:2]
    if any(k in low for k in ("delay", "late", "behind", "now", "today", "why", "which", "problem", "wrong", "short", "idle")):
        out.append("Right now in the plant: " + live)
    return jsonify(reply="\n\n".join(out) or "I can explain orders, scheduling, machines, breakdowns, materials, progress, the clock, roles and reports, and tell you what is delayed or short right now. Try one of those.", source="built-in")

@app.get("/api/export/<kind>.csv")
@need("Planner")
def export(kind):
    s = state().get_json()
    rows = ([["Order", "Product", "Qty", "Due day", "Priority", "Status", "Progress %"]] +
            [[o["code"], o["product"], o["qty"], o["due_day"], o["priority"], o["status"], o["pct"]] for o in s["orders"]]
            if kind == "orders" else
            [["Order", "Stage", "Machine", "Worker", "Start h", "End h", "Done"]] +
            [[r["code"], r["stage"], r["machine"], r["worker"], r["start_h"], r["end_h"], r["done"]] for r in s["schedule"]])
    out = io.StringIO(); csv.writer(out).writerows(rows)
    return Response(out.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=%s.csv" % kind})

@app.get("/")
def home(): return send_from_directory("static", "index.html")

# ---------- first-run seed ----------
def init_db():
    d = db(); d.executescript(SCHEMA)
    stages = ["Cutting", "Machining", "Welding", "Assembly", "Painting", "QC"]
    sid = {n: i + 1 for i, n in enumerate(stages)}
    d.executemany("INSERT INTO stage(name) VALUES(?)", [(s,) for s in stages])
    d.executemany("INSERT INTO users VALUES(?,?,?)", [("planner", generate_password_hash("plan123"), "Planner"),
                  ("supervisor", generate_password_hash("sup123"), "Supervisor")])
    d.execute("INSERT INTO setting VALUES('now',20)")
    d.executemany("INSERT INTO product(name) VALUES(?)", [("Gearbox Housing",), ("Steel Chair",)])
    seq = {}
    for p, s, h in [(1,"Cutting",1),(1,"Machining",2),(1,"Assembly",1.5),(1,"Painting",1),(1,"QC",.5),
                    (2,"Cutting",.5),(2,"Welding",1.5),(2,"Painting",1),(2,"QC",.5)]:
        seq[p] = seq.get(p, 0) + 1
        d.execute("INSERT INTO product_stage VALUES(?,?,?,?)", (p, sid[s], seq[p], h))
    d.executemany("INSERT INTO material(name,unit,stock,reorder) VALUES(?,?,?,?)",
        [("Steel sheet","kg",900,200),("Steel rod","kg",400,100),("Bearings","pcs",120,50),("Paint","litre",60,20),("Fasteners","pcs",2000,500)])
    d.executemany("INSERT INTO bom VALUES(?,?,?)", [(1,1,12),(1,3,2),(1,4,.4),(1,5,8),(2,2,6),(2,1,3),(2,4,.3),(2,5,6)])
    for n, s in [("Laser Cutter A","Cutting"),("Laser Cutter B","Cutting"),("CNC Lathe","Machining"),("Weld Station","Welding"),
                 ("Assembly Line","Assembly"),("Paint Booth","Painting"),("QC Bench","QC")]:
        d.execute("INSERT INTO machine(name,stage_id) VALUES(?,?)", (n, sid[s]))
    for n, s in [("Ravi Kumar","Cutting"),("Pooja Rani","Cutting"),("Simran Kaur","Machining"),("Amit Sharma","Welding"),
                 ("Gurpreet Singh","Assembly"),("Neha Verma","Painting"),("Joginder Singh","QC")]:
        d.execute("INSERT INTO worker(name,stage_id) VALUES(?,?)", (n, sid[s]))
    d.commit()
    for p, qty, due, pr in [(1, 40, 7, "High"), (2, 60, 6, "Medium"), (1, 25, 4, "High")]:
        oid = run("INSERT INTO prod_order(product_id,qty,due_day,priority) VALUES(?,?,?,?)", (p, qty, due, pr))
        plan(oid, 0)
    advance(0)

if __name__ == "__main__":
    with app.app_context():
        if not os.path.exists(DB): init_db()
        db().executescript(AUDIT)
    app.run(debug=os.environ.get("DEBUG") == "1")
