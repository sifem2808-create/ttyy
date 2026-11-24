"""Core ERP for many markets: one file, run with:  python app.py
Admin login: /admin/login   (password: set ADMIN_PASSWORD, default sife1234)
Market login: /login
"""
import csv
import io
import os
import secrets
import sqlite3
import time
from datetime import date
from jinja2 import DictLoader
from flask import (Flask, Response, flash, g, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "data")
os.makedirs(os.path.join(DATA, "markets"), exist_ok=True)
MASTER = os.path.join(DATA, "master.db")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "2233")


def load_secret():
    if os.environ.get("SECRET_KEY"):
        return os.environ["SECRET_KEY"]
    path = os.path.join(DATA, "secret.key")
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(secrets.token_hex(32))
    return open(path).read().strip()


app = Flask(__name__, static_folder=None)
app.secret_key = load_secret()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

# ---------------------------------------------------------------- schemas
MASTER_SCHEMA = """
CREATE TABLE IF NOT EXISTS markets(
  id INTEGER PRIMARY KEY, name TEXT NOT NULL,
  username TEXT UNIQUE NOT NULL COLLATE NOCASE, password_hash TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1, created TEXT NOT NULL DEFAULT (date('now')));
"""

# Every market gets its OWN database file with these tables, so data never mixes.
SCHEMA = """
CREATE TABLE IF NOT EXISTS products(
  id INTEGER PRIMARY KEY, sku TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
  price REAL NOT NULL, cost REAL NOT NULL, stock INTEGER NOT NULL DEFAULT 0,
  min_stock INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS partners(
  id INTEGER PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('customer','supplier')),
  name TEXT NOT NULL, phone TEXT, email TEXT);
CREATE TABLE IF NOT EXISTS orders(
  id INTEGER PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('sale','purchase')),
  partner_id INTEGER NOT NULL REFERENCES partners(id),
  product_id INTEGER NOT NULL REFERENCES products(id),
  qty INTEGER NOT NULL CHECK(qty > 0), price REAL NOT NULL, unit_cost REAL,
  created TEXT NOT NULL DEFAULT (date('now')));
CREATE TABLE IF NOT EXISTS journal_entries(
  id INTEGER PRIMARY KEY, entry_date TEXT NOT NULL, description TEXT NOT NULL,
  order_id INTEGER REFERENCES orders(id));
CREATE TABLE IF NOT EXISTS journal_lines(
  id INTEGER PRIMARY KEY, entry_id INTEGER NOT NULL REFERENCES journal_entries(id),
  account TEXT NOT NULL, debit REAL NOT NULL DEFAULT 0, credit REAL NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS employees(
  id INTEGER PRIMARY KEY, code TEXT UNIQUE NOT NULL, name TEXT NOT NULL, salary REAL NOT NULL);
CREATE TABLE IF NOT EXISTS salary_payments(
  id INTEGER PRIMARY KEY, employee_id INTEGER NOT NULL REFERENCES employees(id),
  month TEXT NOT NULL, amount REAL NOT NULL, paid_date TEXT NOT NULL,
  UNIQUE(employee_id, month));
"""


def market_path(mid):
    return os.path.join(DATA, "markets", f"{int(mid)}.db")


def master():
    m = sqlite3.connect(MASTER)
    m.row_factory = sqlite3.Row
    m.executescript(MASTER_SCHEMA)
    return m


# ---------------------------------------------------------------- tenant isolation
def db():
    """The database of the market that is logged in. No other market's file is ever opened."""
    if "db" not in g:
        g.db = sqlite3.connect(market_path(session["market_id"]))
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()


FAILS = {}


def too_many_attempts():
    now, ip = time.time(), request.remote_addr
    FAILS[ip] = [t for t in FAILS.get(ip, []) if now - t < 600]
    return len(FAILS[ip]) >= 5


def record_fail():
    FAILS.setdefault(request.remote_addr, []).append(time.time())


@app.before_request
def guard():
    ep = request.endpoint or ""
    if ep in ("style", "login", "admin_login"):
        return
    if ep.startswith("admin"):
        return None if session.get("admin") else redirect(url_for("admin_login"))
    mid = session.get("market_id")
    if mid:
        with master() as m:
            g.market = m.execute("SELECT * FROM markets WHERE id=? AND active=1", (mid,)).fetchone()
    if not mid or not g.market:
        session.pop("market_id", None)
        return redirect(url_for("login"))


@app.context_processor
def inject():
    return {"market": getattr(g, "market", None)}


# ---------------------------------------------------------------- login (markets)
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if too_many_attempts():
            flash("Too many attempts. Wait 10 minutes and try again.")
            return render_template("login.html", title="Market login")
        with master() as m:
            row = m.execute("SELECT * FROM markets WHERE username=? AND active=1",
                            (request.form["username"].strip(),)).fetchone()
        if row and check_password_hash(row["password_hash"], request.form["password"]):
            session.clear()
            session["market_id"] = row["id"]
            return redirect(url_for("dashboard"))
        record_fail()
        flash("Wrong username or password.")
    return render_template("login.html", title="Market login")


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------- admin (you, the seller)
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        if too_many_attempts():
            flash("Too many attempts. Wait 10 minutes and try again.")
        elif secrets.compare_digest(request.form["password"], ADMIN_PASSWORD):
            session.clear()
            session["admin"] = True
            return redirect(url_for("admin"))
        else:
            record_fail()
            flash("Wrong admin password.")
    return render_template("login.html", title="Admin login", admin=True)


@app.route("/admin", methods=["GET", "POST"])
def admin():
    with master() as m:
        if request.method == "POST":
            f = request.form
            try:
                cur = m.execute("INSERT INTO markets(name,username,password_hash) VALUES(?,?,?)",
                                (f["name"].strip(), f["username"].strip(), generate_password_hash(f["password"])))
                with sqlite3.connect(market_path(cur.lastrowid)) as c:
                    c.executescript(SCHEMA)
                flash(f"Market created. Username: {f['username'].strip()}")
            except sqlite3.IntegrityError:
                flash("That username is already taken.")
            return redirect(url_for("admin"))
        rows = m.execute("SELECT * FROM markets ORDER BY id DESC").fetchall()
    return render_template("admin.html", rows=rows)


@app.post("/admin/<int:mid>/toggle")
def admin_toggle(mid):
    with master() as m:
        m.execute("UPDATE markets SET active=1-active WHERE id=?", (mid,))
    return redirect(url_for("admin"))


@app.post("/admin/<int:mid>/password")
def admin_password(mid):
    with master() as m:
        m.execute("UPDATE markets SET password_hash=? WHERE id=?",
                  (generate_password_hash(request.form["password"]), mid))
    flash("Password changed.")
    return redirect(url_for("admin"))


@app.get("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))


# ---------------------------------------------------------------- journal helper
def post_journal(c, order_id, kind, day, qty, price, cost, partner, product):
    amount = qty * price
    if kind == "sale":
        desc = f"Sale of {qty} x {product} to {partner}"
        lines = [("Cash", amount, 0), ("Sales revenue", 0, amount),
                 ("Cost of goods sold", qty * cost, 0), ("Inventory", 0, qty * cost)]
    else:
        desc = f"Purchase of {qty} x {product} from {partner}"
        lines = [("Inventory", amount, 0), ("Cash", 0, amount)]
    cur = c.execute("INSERT INTO journal_entries(entry_date,description,order_id) VALUES(?,?,?)",
                    (day, desc, order_id))
    c.executemany("INSERT INTO journal_lines(entry_id,account,debit,credit) VALUES(?,?,?,?)",
                  [(cur.lastrowid, a, dr, cr) for a, dr, cr in lines])


# ---------------------------------------------------------------- market pages
@app.get("/")
def dashboard():
    q = lambda s, *a: db().execute(s, a).fetchone()[0] or 0
    today = date.today().isoformat()
    month = today[:7]
    stats = {
        "revenue": q("SELECT SUM(qty*price) FROM orders WHERE kind='sale'"),
        "profit": q("SELECT SUM(qty*(price-unit_cost)) FROM orders WHERE kind='sale'"),
        "spend": q("SELECT SUM(qty*price) FROM orders WHERE kind='purchase'"),
        "stock_value": q("SELECT SUM(stock*cost) FROM products"),
        "today_rev": q("SELECT SUM(qty*price) FROM orders WHERE kind='sale' AND created=?", today),
        "today_profit": q("SELECT SUM(qty*(price-unit_cost)) FROM orders WHERE kind='sale' AND created=?", today),
        "month_profit": q("SELECT SUM(qty*(price-unit_cost)) FROM orders WHERE kind='sale' AND substr(created,1,7)=?", month),
        "staff": q("SELECT COUNT(*) FROM employees"),
        "unpaid": q("SELECT COUNT(*) FROM employees WHERE id NOT IN (SELECT employee_id FROM salary_payments WHERE month=?)", month),
    }
    low = db().execute("SELECT * FROM products WHERE stock<=min_stock ORDER BY stock").fetchall()
    recent = db().execute("""SELECT o.*, p.name product, r.name partner FROM orders o
        JOIN products p ON p.id=o.product_id JOIN partners r ON r.id=o.partner_id
        ORDER BY o.id DESC LIMIT 8""").fetchall()
    return render_template("dashboard.html", s=stats, low=low, recent=recent)


@app.route("/products", methods=["GET", "POST"])
def products():
    if request.method == "POST":
        f = request.form
        try:
            db().execute("INSERT INTO products(sku,name,price,cost,stock,min_stock) VALUES(?,?,?,?,?,?)",
                         (f["sku"].strip(), f["name"].strip(), float(f["price"]), float(f["cost"]),
                          int(f["stock"]), int(f["min_stock"])))
            db().commit()
            flash("Product added.")
        except sqlite3.IntegrityError:
            flash("That SKU already exists.")
        return redirect(url_for("products"))
    rows = db().execute("SELECT * FROM products ORDER BY name").fetchall()
    return render_template("products.html", rows=rows)


@app.post("/products/<int:pid>/delete")
def delete_product(pid):
    try:
        db().execute("DELETE FROM products WHERE id=?", (pid,))
        db().commit()
        flash("Product deleted.")
    except sqlite3.IntegrityError:
        flash("This product has orders, so it can't be deleted.")
    return redirect(url_for("products"))


def partners(kind):
    if request.method == "POST":
        f = request.form
        db().execute("INSERT INTO partners(kind,name,phone,email) VALUES(?,?,?,?)",
                     (kind, f["name"].strip(), f.get("phone", ""), f.get("email", "")))
        db().commit()
        flash("Saved.")
        return redirect(request.path)
    rows = db().execute("SELECT * FROM partners WHERE kind=? ORDER BY name", (kind,)).fetchall()
    return render_template("partners.html", rows=rows, kind=kind)


app.add_url_rule("/customers", "customers", lambda: partners("customer"), methods=["GET", "POST"])
app.add_url_rule("/suppliers", "suppliers", lambda: partners("supplier"), methods=["GET", "POST"])


def orders(kind):
    d = db()
    if request.method == "POST":
        f = request.form
        pid, qty, price = int(f["product_id"]), int(f["qty"]), float(f["price"])
        p = d.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
        partner = d.execute("SELECT name FROM partners WHERE id=?", (int(f["partner_id"]),)).fetchone()
        if not p or not partner:
            flash("Pick an existing product and partner.")
        elif kind == "sale" and qty > p["stock"]:
            flash(f"Only {p['stock']} of {p['name']} in stock.")
        else:
            today = date.today().isoformat()
            unit_cost = p["cost"] if kind == "sale" else price
            cur = d.execute("INSERT INTO orders(kind,partner_id,product_id,qty,price,created,unit_cost) VALUES(?,?,?,?,?,?,?)",
                            (kind, int(f["partner_id"]), pid, qty, price, today, unit_cost))
            post_journal(d, cur.lastrowid, kind, today, qty, price, p["cost"], partner["name"],
                         f'{p["name"]} [SKU {p["sku"]}]')
            if kind == "sale":
                d.execute("UPDATE products SET stock=stock-? WHERE id=?", (qty, pid))
            else:
                d.execute("UPDATE products SET stock=stock+?, cost=? WHERE id=?", (qty, price, pid))
            d.commit()
            flash("Order recorded. Stock updated.")
        return redirect(request.path)
    who = "customer" if kind == "sale" else "supplier"
    return render_template("orders.html", kind=kind,
        parties=d.execute("SELECT * FROM partners WHERE kind=?", (who,)).fetchall(),
        prods=d.execute("SELECT * FROM products ORDER BY name").fetchall(),
        rows=d.execute("""SELECT o.*, p.name product, r.name partner FROM orders o
            JOIN products p ON p.id=o.product_id JOIN partners r ON r.id=o.partner_id
            WHERE o.kind=? ORDER BY o.id DESC""", (kind,)).fetchall())


app.add_url_rule("/sales", "sales", lambda: orders("sale"), methods=["GET", "POST"])
app.add_url_rule("/purchases", "purchases", lambda: orders("purchase"), methods=["GET", "POST"])


def this_month():
    return date.today().strftime("%Y-%m")


EMP_SQL = """SELECT e.*, p.paid_date FROM employees e
    LEFT JOIN salary_payments p ON p.employee_id=e.id AND p.month=?"""


@app.route("/employees", methods=["GET", "POST"])
def employees():
    d = db()
    if request.method == "POST":
        f = request.form
        try:
            d.execute("INSERT INTO employees(code,name,salary) VALUES(?,?,?)",
                      (f["code"].strip(), f["name"].strip(), float(f["salary"])))
            d.commit()
            flash("Employee added.")
        except sqlite3.IntegrityError:
            flash("That code is already used.")
        return redirect(url_for("employees"))
    code = request.args.get("code", "").strip()
    found = d.execute(EMP_SQL + " WHERE lower(e.code)=lower(?)", (this_month(), code)).fetchone() if code else None
    rows = d.execute(EMP_SQL + " ORDER BY e.code", (this_month(),)).fetchall()
    return render_template("employees.html", rows=rows, found=found, code=code, month=this_month())


@app.post("/employees/<int:eid>/pay")
def pay_salary(eid):
    d = db()
    e = d.execute("SELECT * FROM employees WHERE id=?", (eid,)).fetchone()
    if not e:
        return redirect(url_for("employees"))
    month, today = this_month(), date.today().isoformat()
    try:
        d.execute("INSERT INTO salary_payments(employee_id,month,amount,paid_date) VALUES(?,?,?,?)",
                  (eid, month, e["salary"], today))
    except sqlite3.IntegrityError:
        flash("This salary is already paid for this month.")
        return redirect(url_for("employees", code=e["code"]))
    cur = d.execute("INSERT INTO journal_entries(entry_date,description) VALUES(?,?)",
                    (today, f"Salary {month} paid to {e['name']} ({e['code']})"))
    d.executemany("INSERT INTO journal_lines(entry_id,account,debit,credit) VALUES(?,?,?,?)",
                  [(cur.lastrowid, "Salaries expense", e["salary"], 0), (cur.lastrowid, "Cash", 0, e["salary"])])
    d.commit()
    flash(f"Salary paid to {e['name']} for {month}.")
    return redirect(url_for("employees", code=e["code"]))


@app.get("/reports")
def reports():
    d = db()
    q = """SELECT {g} k, SUM(qty*price) revenue, SUM(qty*(price-unit_cost)) profit
           FROM orders WHERE kind='sale' GROUP BY k ORDER BY k DESC"""
    days = d.execute(q.format(g="created")).fetchall()
    months = {r["k"]: {"revenue": r["revenue"], "profit": r["profit"], "salaries": 0}
              for r in d.execute(q.format(g="substr(created,1,7)"))}
    for r in d.execute("SELECT month, SUM(amount) s FROM salary_payments GROUP BY month"):
        m = months.setdefault(r["month"], {"revenue": 0, "profit": 0, "salaries": 0})
        m["salaries"] = r["s"]
    return render_template("reports.html", days=days, months=dict(sorted(months.items(), reverse=True)))


def journal_rows(day, newest_first=True):
    sql = """SELECT e.id, e.entry_date, e.description, l.account, l.debit, l.credit
        FROM journal_entries e JOIN journal_lines l ON l.entry_id=e.id"""
    args = []
    if day:
        sql += " WHERE e.entry_date=?"
        args.append(day)
    order = "DESC" if newest_first else "ASC"
    return db().execute(f"{sql} ORDER BY e.entry_date {order}, e.id {order}, l.id", args).fetchall()


@app.get("/journal")
def journal():
    day = request.args.get("date", "")
    days = {}
    for r in journal_rows(day):
        dd = days.setdefault(r["entry_date"], {"entries": {}, "debit": 0, "credit": 0})
        e = dd["entries"].setdefault(r["id"], {"desc": r["description"], "lines": []})
        e["lines"].append(r)
        dd["debit"] += r["debit"]
        dd["credit"] += r["credit"]
    return render_template("journal.html", days=days, day=day)


@app.get("/journal.csv")
def journal_csv():
    day = request.args.get("date", "")
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["date", "entry", "description", "account", "debit", "credit"])
    for r in journal_rows(day, newest_first=False):
        w.writerow([r["entry_date"], r["id"], r["description"], r["account"], r["debit"], r["credit"]])
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=journal-{day or 'all'}.csv"})


# ================================================================= PAGES (HTML templates)
# Everything lives in this one file: code, pages and styling.
TEMPLATES = {
    "admin.html": r"""{% extends "base.html" %}{% block body %}
<h2>Markets <a class="small" href="{{ url_for('admin_logout') }}">Log out</a></h2>
<div class="panel"><h3>Add a market</h3><form method="post">
<label>Market name<input name="name" required></label>
<label>Login username<input name="username" required></label>
<label>Login password<input name="password" type="text" minlength="6" required></label>
<button>Create market</button></form>
<p class="muted">Each market gets its own separate database. Markets can never see each other's data.</p></div>
<div class="panel"><table><tr><th>Name</th><th>Username</th><th>Created</th><th>Status</th><th></th><th></th></tr>
{% for r in rows %}<tr><td>{{ r.name }}</td><td>{{ r.username }}</td><td>{{ r.created }}</td>
<td>{{ 'Active' if r.active else 'Suspended' }}</td>
<td><form method="post" action="{{ url_for('admin_toggle', mid=r.id) }}"><button>{{ 'Suspend' if r.active else 'Activate' }}</button></form></td>
<td><form method="post" action="{{ url_for('admin_password', mid=r.id) }}"><input name="password" minlength="6" placeholder="New password" required><button>Change</button></form></td></tr>
{% else %}<tr><td colspan="6" class="muted">No markets yet. Add your first one above.</td></tr>{% endfor %}</table></div>
{% endblock %}
""",
    "base.html": r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Core ERP</title>
<link rel="stylesheet" href="{{ url_for('style') }}"></head>
<body>
{% if market %}<nav><h1>Core ERP</h1>
{% for ep, label in [('dashboard','Dashboard'),('products','Products'),('customers','Customers'),('suppliers','Suppliers'),('sales','Sales'),('purchases','Purchases'),('reports','Income'),('employees','Employees'),('journal','Journal')] %}
<a href="{{ url_for(ep) }}" class="{{ 'on' if request.endpoint == ep }}">{{ label }}</a>{% endfor %}
<span class="who">{{ market.name }}</span><a href="{{ url_for('logout') }}">Log out</a></nav>{% endif %}
<main class="{% block mainclass %}{% endblock %}">
{% for m in get_flashed_messages() %}<div class="flash">{{ m }}</div>{% endfor %}
{% block body %}{% endblock %}
</main></body></html>
""",
    "dashboard.html": r"""{% extends "base.html" %}{% block body %}
<h2>Dashboard</h2>
<div class="grid">
<div class="stat"><b>{{ '{:,.0f}'.format(s.today_rev) }}</b><span>Today's revenue (EGP)</span></div>
<div class="stat"><b>{{ '{:,.0f}'.format(s.today_profit) }}</b><span>Today's profit</span></div>
<div class="stat"><b>{{ '{:,.0f}'.format(s.month_profit) }}</b><span>This month's profit</span></div>
<div class="stat"><b>{{ s.unpaid }} of {{ s.staff }}</b><span>Salaries unpaid this month</span></div></div>
<div class="grid">
<div class="stat"><b>{{ '{:,.0f}'.format(s.revenue) }}</b><span>Sales revenue (EGP)</span></div>
<div class="stat"><b>{{ '{:,.0f}'.format(s.profit) }}</b><span>Gross profit</span></div>
<div class="stat"><b>{{ '{:,.0f}'.format(s.spend) }}</b><span>Purchases</span></div>
<div class="stat"><b>{{ '{:,.0f}'.format(s.stock_value) }}</b><span>Stock value (at cost)</span></div></div>
<div class="panel"><h3>Needs restocking</h3>
{% for p in low %}<p>{{ p.name }}: <b class="low">{{ p.stock }}</b> left (minimum {{ p.min_stock }})</p>
{% else %}<p class="muted">All products are above their minimum level.</p>{% endfor %}</div>
<div class="panel"><h3>Recent activity</h3>
<table><tr><th>Date</th><th>Type</th><th>Partner</th><th>Product</th><th>Total</th></tr>
{% for o in recent %}<tr><td>{{ o.created }}</td><td>{{ o.kind }}</td><td>{{ o.partner }}</td><td>{{ o.product }}</td><td>{{ '{:,.2f}'.format(o.qty*o.price) }}</td></tr>
{% else %}<tr><td colspan="5" class="muted">No orders yet.</td></tr>{% endfor %}</table></div>
{% endblock %}
""",
    "employees.html": r"""{% extends "base.html" %}{% block body %}
<h2>Employees and salaries</h2>
<div class="panel"><h3>Check salary by code ({{ month }})</h3>
<form method="get"><label>Employee code<input name="code" value="{{ code }}" required autofocus></label><button>Check</button></form>
{% if code %}{% if found %}
<p><b>{{ found.name }}</b> ({{ found.code }}) &middot; salary {{ '{:,.2f}'.format(found.salary) }}</p>
{% if found.paid_date %}<p class="ok">PAID on {{ found.paid_date }}</p>
{% else %}<p class="low">NOT PAID for {{ month }}</p>
<form method="post" action="{{ url_for('pay_salary', eid=found.id) }}"><button>Pay salary now</button></form>{% endif %}
{% else %}<p class="low">No employee with code {{ code }}.</p>{% endif %}{% endif %}</div>
<div class="panel"><h3>Add employee</h3><form method="post">
<label>Name<input name="name" required></label><label>Code<input name="code" required></label>
<label>Monthly salary<input name="salary" type="number" min="0" step="0.01" required></label>
<button>Add employee</button></form></div>
<div class="panel"><table><tr><th>Code</th><th>Name</th><th class="n">Salary</th><th>{{ month }}</th></tr>
{% for e in rows %}<tr><td>{{ e.code }}</td><td>{{ e.name }}</td><td class="n">{{ '{:,.2f}'.format(e.salary) }}</td>
<td>{% if e.paid_date %}Paid {{ e.paid_date }}{% else %}<span class="low">Not paid</span>{% endif %}</td></tr>
{% else %}<tr><td colspan="4" class="muted">No employees yet.</td></tr>{% endfor %}</table></div>
{% endblock %}
""",
    "journal.html": r"""{% extends "base.html" %}{% block body %}
<h2>Daily journal</h2>
<div class="panel"><form method="get">
<label>Day<input type="date" name="date" value="{{ day }}"></label>
<button>Show day</button>
<a href="{{ url_for('journal') }}">All days</a>
<a href="{{ url_for('journal_csv', date=day) }}">Download CSV</a></form></div>
{% for d, data in days.items() %}
<div class="panel"><h3>{{ d }}</h3>
<table><tr><th>Account</th><th class="n">Debit</th><th class="n">Credit</th></tr>
{% for eid, e in data.entries.items() %}
<tr class="desc"><td colspan="3">Entry {{ eid }}: {{ e.desc }}</td></tr>
{% for l in e.lines %}<tr><td class="{{ 'cr' if l.credit }}">{{ l.account }}</td>
<td class="n">{{ '{:,.2f}'.format(l.debit) if l.debit else '' }}</td>
<td class="n">{{ '{:,.2f}'.format(l.credit) if l.credit else '' }}</td></tr>{% endfor %}
{% endfor %}
<tr class="tot"><td>Day total {{ '(balanced)' if data.debit == data.credit else '(NOT balanced)' }}</td>
<td class="n">{{ '{:,.2f}'.format(data.debit) }}</td><td class="n">{{ '{:,.2f}'.format(data.credit) }}</td></tr></table></div>
{% else %}<div class="panel muted">No journal entries{{ ' for ' ~ day if day }}. Record a sale or purchase and it appears here.</div>
{% endfor %}
{% endblock %}
""",
    "login.html": r"""{% extends "base.html" %}{% block mainclass %}narrow{% endblock %}{% block body %}
<h2>{{ title }}</h2>
<div class="panel"><form method="post">
<label>{{ 'Password' if admin else 'Username' }}{% if admin %}<input name="password" type="password" required autofocus>{% else %}<input name="username" required autofocus>{% endif %}</label>
{% if not admin %}<label>Password<input name="password" type="password" required></label>{% endif %}
<button>Log in</button></form></div>
{% endblock %}
""",
    "orders.html": r"""{% extends "base.html" %}{% block body %}
<h2>{{ 'Sales' if kind == 'sale' else 'Purchases' }}</h2>
{% if not parties or not prods %}<div class="panel muted">Add at least one {{ 'customer' if kind == 'sale' else 'supplier' }} and one product before recording orders.</div>{% endif %}
<div class="panel"><form method="post">
<label>{{ 'Customer' if kind == 'sale' else 'Supplier' }}<select name="partner_id" required>
{% for p in parties %}<option value="{{ p.id }}">{{ p.name }}</option>{% endfor %}</select></label>
<label>Product<select name="product_id" id="prod" required>
{% for p in prods %}<option value="{{ p.id }}" data-price="{{ p.price if kind == 'sale' else p.cost }}">{{ p.name }} ({{ p.stock }} in stock)</option>{% endfor %}</select></label>
<label>Quantity<input name="qty" type="number" min="1" value="1" required></label>
<label>Unit price<input name="price" id="price" type="number" step="0.01" min="0" required></label>
<button>Record {{ 'sale' if kind == 'sale' else 'purchase' }}</button></form></div>
<div class="panel"><table><tr><th>Date</th><th>Partner</th><th>Product</th><th>Qty</th><th>Total</th></tr>
{% for o in rows %}<tr><td>{{ o.created }}</td><td>{{ o.partner }}</td><td>{{ o.product }}</td><td>{{ o.qty }}</td><td>{{ '{:,.2f}'.format(o.qty*o.price) }}</td></tr>
{% else %}<tr><td colspan="5" class="muted">No orders yet.</td></tr>{% endfor %}</table></div>
<script>
const s=document.getElementById('prod'),p=document.getElementById('price');
const sync=()=>{if(s.selectedOptions[0])p.value=s.selectedOptions[0].dataset.price};
s.onchange=sync;sync();
</script>
{% endblock %}
""",
    "partners.html": r"""{% extends "base.html" %}{% block body %}
<h2>{{ 'Customers' if kind == 'customer' else 'Suppliers' }}</h2>
<div class="panel"><form method="post">
<label>Name<input name="name" required></label><label>Phone<input name="phone"></label><label>Email<input name="email" type="email"></label>
<button>Save</button></form></div>
<div class="panel"><table><tr><th>Name</th><th>Phone</th><th>Email</th></tr>
{% for r in rows %}<tr><td>{{ r.name }}</td><td>{{ r.phone }}</td><td>{{ r.email }}</td></tr>
{% else %}<tr><td colspan="3" class="muted">Nothing here yet.</td></tr>{% endfor %}</table></div>
{% endblock %}
""",
    "products.html": r"""{% extends "base.html" %}{% block body %}
<h2>Products</h2>
<div class="panel"><h3>Add product</h3>
<form method="post">
<label>Name<input name="name" required></label><label>SKU<input name="sku" required></label>
<label>Sell price<input name="price" type="number" step="0.01" min="0" required></label>
<label>Cost<input name="cost" type="number" step="0.01" min="0" required></label>
<label>Opening stock<input name="stock" type="number" min="0" value="0" required></label>
<label>Minimum stock<input name="min_stock" type="number" min="0" value="5" required></label>
<button>Add product</button></form></div>
<div class="panel"><table><tr><th>SKU</th><th>Name</th><th>Price</th><th>Cost</th><th>Stock</th><th></th></tr>
{% for p in rows %}<tr><td>{{ p.sku }}</td><td>{{ p.name }}</td><td>{{ p.price }}</td><td>{{ p.cost }}</td>
<td class="{{ 'low' if p.stock <= p.min_stock }}">{{ p.stock }}</td>
<td><form method="post" action="{{ url_for('delete_product', pid=p.id) }}"><button class="link">Delete</button></form></td></tr>
{% else %}<tr><td colspan="6" class="muted">No products yet.</td></tr>{% endfor %}</table></div>
{% endblock %}
""",
    "reports.html": r"""{% extends "base.html" %}{% block body %}
<h2>Daily and monthly income</h2>
<p class="muted">Profit = selling price minus wholesale cost, for every unit sold. Net income = profit minus salaries paid.</p>
<div class="panel"><h3>By month</h3>
<table><tr><th>Month</th><th class="n">Revenue</th><th class="n">Profit</th><th class="n">Salaries paid</th><th class="n">Net income</th></tr>
{% for m, v in months.items() %}<tr><td>{{ m }}</td><td class="n">{{ '{:,.2f}'.format(v.revenue) }}</td><td class="n">{{ '{:,.2f}'.format(v.profit) }}</td>
<td class="n">{{ '{:,.2f}'.format(v.salaries) }}</td><td class="n"><b>{{ '{:,.2f}'.format(v.profit - v.salaries) }}</b></td></tr>
{% else %}<tr><td colspan="5" class="muted">No sales yet.</td></tr>{% endfor %}</table></div>
<div class="panel"><h3>By day</h3>
<table><tr><th>Day</th><th class="n">Revenue</th><th class="n">Profit</th></tr>
{% for r in days %}<tr><td>{{ r.k }}</td><td class="n">{{ '{:,.2f}'.format(r.revenue) }}</td><td class="n">{{ '{:,.2f}'.format(r.profit) }}</td></tr>
{% else %}<tr><td colspan="3" class="muted">No sales yet.</td></tr>{% endfor %}</table></div>
{% endblock %}
""",
}
app.jinja_loader = DictLoader(TEMPLATES)

# ================================================================= STYLE (black and white)
CSS = r""":root{--bg:#fff;--card:#fff;--ink:#000;--muted:#555;--line:#000}
*{box-sizing:border-box}
body{margin:0;display:flex;min-height:100vh;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,"Segoe UI",sans-serif}
nav{width:200px;background:#000;padding:22px 12px;display:flex;flex-direction:column;gap:4px}
nav h1{color:#fff;font-size:20px;margin:0 8px 18px}
nav a{color:#fff;opacity:.75;text-decoration:none;padding:8px 12px;border-radius:6px;font-weight:600}
nav a:hover{opacity:1}
nav a.on{background:#fff;color:#000;opacity:1}
main{flex:1;padding:28px 40px;max-width:1100px;min-width:0}
h2{font-size:28px;margin:0 0 18px}
.panel{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:18px;margin-bottom:20px;overflow-x:auto}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin-bottom:20px}
.stat{border-left:5px solid #000;padding-left:12px}.stat b{display:block;font-size:26px}.stat span{color:var(--muted);font-size:13px}
table{width:100%;border-collapse:collapse}th{text-align:left;color:var(--muted);font-weight:600}
th,td{padding:8px 10px;border-bottom:1px solid #ccc}
th.n,td.n{text-align:right}
form{display:flex;flex-wrap:wrap;gap:10px;align-items:end}
label{display:flex;flex-direction:column;font-size:13px;color:var(--muted);flex:1 1 130px}
input,select{padding:8px;border:1px solid #000;border-radius:6px;font:inherit;background:#fff;color:#000}
button{background:#000;color:#fff;border:2px solid #000;border-radius:6px;padding:9px 16px;font:inherit;font-weight:600;cursor:pointer}
button:hover{background:#fff;color:#000}
button.link{background:none;color:#000;border:0;padding:0;text-decoration:underline}
.low{font-weight:800;text-decoration:underline}.ok{font-weight:800}.muted{color:var(--muted)}
.flash{background:#000;color:#fff;padding:10px 14px;border-radius:6px;margin-bottom:16px}
tr.desc td{background:#eee;font-weight:600}
td.cr{padding-left:32px}
tr.tot td{font-weight:800;border-top:2px solid #000}
form a{align-self:center;color:#000;font-weight:600}
@media(max-width:760px){body{flex-direction:column}nav{width:100%;flex-direction:row;flex-wrap:wrap}main{padding:20px 16px}}
.narrow{max-width:420px;margin:10vh auto;flex:none;width:100%}
nav .who{color:#fff;opacity:.6;font-size:13px;margin:auto 8px 4px}
a.small{font-size:14px;font-weight:600;margin-left:12px;color:#000}
td form{flex-wrap:nowrap}td input{width:130px}
"""


@app.get("/style.css")
def style():
    return Response(CSS, mimetype="text/css")


if __name__ == "__main__":
    master().close()
    app.run(debug=os.environ.get("DEBUG") == "1")
