#!/usr/bin/env python3
# --- Bootstrap: auto-install missing deps BEFORE importing Flask ---
import os, sys, subprocess, importlib.util, importlib
from pathlib import Path
REQUIREMENTS = Path(__file__).with_name("requirements.txt")
REQUIRED_IMPORTS = [("flask","Flask"),("flask_sqlalchemy","Flask-SQLAlchemy"),("flask_login","Flask-Login"),("flask_wtf","Flask-WTF"),("click","click")]
def _missing():
    return [(m,p) for m,p in REQUIRED_IMPORTS if importlib.util.find_spec(m) is None]
def ensure_dependencies():
    if os.environ.get("SKIP_AUTO_PIP") in ("1","true","True"): return
    miss = _missing()
    if not miss: return
    print("[bootstrap] Missing packages:", ", ".join(p for _,p in miss), flush=True)
    if REQUIREMENTS.exists():
        cmd=[sys.executable,"-m","pip","install","-r",str(REQUIREMENTS)]
    else:
        pkgs=sorted({p for _,p in miss}); cmd=[sys.executable,"-m","pip","install",*pkgs]
    try:
        print("[bootstrap] Running:", " ".join(cmd), flush=True)
        subprocess.check_call(cmd); importlib.invalidate_caches()
        print("[bootstrap] Dependencies installed.", flush=True)
    except Exception as e:
        print("[bootstrap] Warning: dependency install failed:", e, file=sys.stderr, flush=True)
ensure_dependencies()

# --- App imports ---
import threading, socketserver, re
from queue import Queue, Empty
from datetime import datetime, timedelta
from urllib.parse import urlencode
from flask import Flask, render_template, request, redirect, url_for, Response, flash, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_wtf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
import click

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY","dev-change-me")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL","sqlite:///syslog.db")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SYSLOG_HOST"] = os.environ.get("SYSLOG_HOST","0.0.0.0")
    app.config["SYSLOG_PORT"] = int(os.environ.get("SYSLOG_PORT","5514"))
    app.config["SYSLOG_TCP_PORT"] = int(os.environ.get("SYSLOG_TCP_PORT","5515"))
    app.config["SYSLOG_ENABLE_UDP"] = os.environ.get("SYSLOG_ENABLE_UDP","1") not in ("0","false","False")
    app.config["SYSLOG_ENABLE_TCP"] = os.environ.get("SYSLOG_ENABLE_TCP","1") not in ("0","false","False")
    app.config["EXPORT_REQUIRES_LOGIN"] = os.environ.get("EXPORT_REQUIRES_LOGIN","1") not in ("0","false","False")
    return app

app = create_app()
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, index=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_reviewer = db.Column(db.Boolean, default=False)
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    received_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    host = db.Column(db.String(255), index=True)
    facility = db.Column(db.Integer, index=True)
    severity = db.Column(db.Integer, index=True)
    app_name = db.Column(db.String(255), index=True)
    procid = db.Column(db.String(64), index=True)
    msgid = db.Column(db.String(64), index=True)
    message = db.Column(db.Text)
    raw = db.Column(db.Text)
    protocol = db.Column(db.String(16))
    source_ip = db.Column(db.String(64), index=True)
    source_port = db.Column(db.Integer)

class Setting(db.Model):
    key = db.Column(db.String(64), primary_key=True)
    value = db.Column(db.String(255))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

def get_setting(key, default=None):
    s = Setting.query.get(key)
    return s.value if s else default

def set_setting(key, value):
    s = Setting.query.get(key)
    if not s:
        s = Setting(key=key, value=str(value) if value is not None else None)
    else:
        s.value = str(value) if value is not None else None
    db.session.add(s)
    db.session.commit()

@login_manager.user_loader
def load_user(user_id): return User.query.get(int(user_id))

PRI_RE = re.compile(r"^<(\d{1,3})>")
RFC3164_RE = re.compile(r"^<(?P<pri>\d{1,3})>(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<tag>[^:]+):\s?(?P<msg>.*)$")
RFC5424_RE = re.compile(r"^<(?P<pri>\d{1,3})>1\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+(?P<procid>\S+)\s+(?P<msgid>\S+)\s+(?P<sd>-|\[.*?\])\s*(?P<msg>.*)$")
def decode_pri(pri): return pri // 8, pri % 8

def parse_syslog_line(line:str):
    line = line.strip("\x00\r\n")
    m = RFC5424_RE.match(line)
    if m:
        pri = int(m.group("pri")); fac, sev = decode_pri(pri)
        ts = m.group("ts")
        try: dt = datetime.fromisoformat(ts.replace("Z","+00:00")).replace(tzinfo=None)
        except Exception: dt = datetime.utcnow()
        return dict(host=m.group("host"), facility=fac, severity=sev, app_name=m.group("app"),
                    procid=None if m.group("procid")=="-" else m.group("procid"),
                    msgid=None if m.group("msgid")=="-" else m.group("msgid"),
                    message=m.group("msg"), received_at=dt)
    m = RFC3164_RE.match(line)
    if m:
        pri = int(m.group("pri")); fac, sev = decode_pri(pri)
        ts = m.group("ts")
        try: dt = datetime.strptime(f"{ts} {datetime.utcnow().year}", "%b %d %H:%M:%S %Y")
        except Exception: dt = datetime.utcnow()
        tag = m.group("tag"); appn, procid = tag, None
        m2 = re.match(r"^(?P<app>[^\[\]]+)\[(?P<pid>[^\]]+)\]$", tag)
        if m2: appn, procid = m2.group("app"), m2.group("pid")
        return dict(host=m.group("host"), facility=fac, severity=sev, app_name=appn, procid=procid, msgid=None, message=m.group("msg"), received_at=dt)
    m = PRI_RE.match(line); fac=sev=None
    if m: fac, sev = decode_pri(int(m.group(1)))
    return dict(host=None, facility=fac, severity=sev, app_name=None, procid=None, msgid=None, message=line, received_at=datetime.utcnow())

_queue = Queue()
_shutdown = threading.Event()

class SyslogUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0]
        if isinstance(data, bytes): data = data.decode("utf-8","replace")
        src_ip, src_port = self.client_address
        _queue.put(("UDP", data, src_ip, src_port))

class ThreadingUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer): allow_reuse_address = True

class SyslogTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request; src_ip, src_port = self.client_address
        buf = b""; sock.settimeout(1.0)
        import re as _re
        while not _shutdown.is_set():
            try: chunk = sock.recv(4096)
            except Exception: continue
            if not chunk: break
            buf += chunk
            while True:
                m = _re.match(br"^(\d+)\s", buf)
                if m:
                    length = int(m.group(1)); head = len(m.group(0))
                    if len(buf) >= head + length:
                        msg = buf[head:head+length]; buf = buf[head+length:]
                        _queue.put(("TCP", msg.decode("utf-8","replace"), src_ip, src_port)); continue
                    break
                if b"\n" in buf:
                    line, buf = buf.split(b"\n",1)
                    _queue.put(("TCP", line.decode("utf-8","replace"), src_ip, src_port)); continue
                break

class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer): allow_reuse_address = True

def writer(app):
    with app.app_context():
        while not _shutdown.is_set():
            try: proto, data, ip, port = _queue.get(timeout=0.5)
            except Empty: continue
            try:
                p = parse_syslog_line(data)
                ev = Event(received_at=p.get("received_at", datetime.utcnow()), host=p.get("host"),
                           facility=p.get("facility"), severity=p.get("severity"), app_name=p.get("app_name"),
                           procid=p.get("procid"), msgid=p.get("msgid"), message=p.get("message"),
                           raw=data, protocol=proto, source_ip=ip, source_port=port)
                db.session.add(ev); db.session.commit()
            except Exception: db.session.rollback()

def start_servers(app):
    servers=[]
    if app.config["SYSLOG_ENABLE_UDP"]:
        u = ThreadingUDPServer((app.config["SYSLOG_HOST"], app.config["SYSLOG_PORT"]), SyslogUDPHandler)
        threading.Thread(target=u.serve_forever, daemon=True).start(); servers.append(u)
    if app.config["SYSLOG_ENABLE_TCP"]:
        t = ThreadingTCPServer((app.config["SYSLOG_HOST"], app.config["SYSLOG_TCP_PORT"]), SyslogTCPHandler)
        threading.Thread(target=t.serve_forever, daemon=True).start(); servers.append(t)
    threading.Thread(target=writer, args=(app,), daemon=True).start()
    return servers

from sqlalchemy import asc, desc
def build_filters(q):
    from datetime import datetime as dt
    a = request.args
    if a.get("host"): q = q.filter(Event.host == a["host"])
    if a.get("app"): q = q.filter(Event.app_name == a["app"])
    if a.get("srcip"): q = q.filter(Event.source_ip == a["srcip"])
    if a.get("proto") in ("UDP","TCP"): q = q.filter(Event.protocol == a["proto"])
    if a.get("severity","").isdigit(): q = q.filter(Event.severity == int(a["severity"]))
    if a.get("facility","").isdigit(): q = q.filter(Event.facility == int(a["facility"]))
    if a.get("q"): q = q.filter(Event.message.ilike(f"%{a['q']}%"))
    if a.get("start"):
        try: q = q.filter(Event.received_at >= dt.fromisoformat(a["start"]))
        except Exception: pass
    if a.get("end"):
        try: q = q.filter(Event.received_at <= dt.fromisoformat(a["end"]))
        except Exception: pass
    return q

SORT = {"received_at": Event.received_at, "host": Event.host, "severity": Event.severity,
        "facility": Event.facility, "app": Event.app_name, "source_ip": Event.source_ip, "protocol": Event.protocol}

def apply_sort(q):
    s = request.args.get("sort","received_at"); o = request.args.get("order","desc")
    col = SORT.get(s, Event.received_at); return q.order_by(asc(col) if o=="asc" else desc(col))

def pagination(q):
    try: per_page = min(max(int(request.args.get("per_page",50)),1),500)
    except Exception: per_page = 50
    try: page = max(int(request.args.get("page",1)),1)
    except Exception: page = 1
    total = q.count(); items = q.offset((page-1)*per_page).limit(per_page).all()
    return items, total, page, per_page

@app.route("/")
def index():
    q = apply_sort(build_filters(Event.query))
    items, total, page, per_page = pagination(q)
    args = request.args.to_dict(flat=True); args.pop("page", None)
    return render_template("events.html", events=items, total=total, page=page, per_page=per_page,
                           base_qs=urlencode(args), args=request.args)

@app.route("/event/<int:event_id>")
def event_detail(event_id):
    ev = Event.query.get_or_404(event_id)
    return render_template("event_detail.html", ev=ev)

def reviewer_required(): return current_user.is_authenticated and (current_user.is_reviewer or current_user.is_admin)
def admin_required(): return current_user.is_authenticated and current_user.is_admin

@app.route("/export.csv")
def export_csv():
    if app.config["EXPORT_REQUIRES_LOGIN"] and not reviewer_required(): abort(403)
    q = apply_sort(build_filters(Event.query))
    rows = q.all()
    def gen():
        header = ["id","received_at","host","facility","severity","app_name","procid","msgid","message","protocol","source_ip","source_port"]
        yield ",".join(header)+"\n"
        for ev in rows:
            vals = [ev.id, ev.received_at.isoformat(sep=" ", timespec="seconds"), ev.host or "",
                    ev.facility if ev.facility is not None else "", ev.severity if ev.severity is not None else "",
                    ev.app_name or "", ev.procid or "", ev.msgid or "",
                    (ev.message or "").replace("\n"," ").replace("\r"," "), ev.protocol or "", ev.source_ip or "", ev.source_port or ""]
            out=[]; 
            for v in vals:
                s=str(v); out.append(("\""+s.replace("\"","\"\"")+"\"") if any(c in s for c in [",","\"","\n"]) else s)
            yield ",".join(out)+"\n"
    return Response(gen(), mimetype="text/csv", headers={"Content-Disposition":"attachment; filename=events_export.csv"})

@app.route("/api/events/recent")
def api_events_recent():
    try:
        limit = int(request.args.get("limit", 20))
    except Exception:
        limit = 20
    limit = max(1, min(limit, 200))
    since_id = request.args.get("since_id")
    q = Event.query
    if since_id and since_id.isdigit():
        q = q.filter(Event.id > int(since_id))
    q = q.order_by(Event.id.desc()).limit(limit)
    items = list(reversed(q.all()))
    def ser(ev):
        return {
            "id": ev.id,
            "received_at": ev.received_at.isoformat(sep=" ", timespec="seconds") if ev.received_at else None,
            "host": ev.host,
            "facility": ev.facility,
            "severity": ev.severity,
            "app_name": ev.app_name,
            "protocol": ev.protocol,
            "source_ip": ev.source_ip,
            "source_port": ev.source_port,
            "message": ev.message,
        }
    return jsonify({"events": [ser(e) for e in items]})

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        u = request.form.get("username","").strip()
        p = request.form.get("password","")
        user = User.query.filter_by(username=u).first()
        if user and user.check_password(p):
            login_user(user, remember=True); flash("Logged in.","success")
            return redirect(url_for("manage"))
        flash("Invalid credentials.","danger")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user(); flash("Logged out.","info")
    return redirect(url_for("index"))

@app.route("/manage")
@login_required
def manage():
    if not reviewer_required():
        flash("Reviewer or admin access required.","danger")
        return redirect(url_for("index"))
    total = Event.query.count()
    latest = Event.query.order_by(Event.received_at.desc()).first()
    hosts = [h[0] for h in db.session.query(Event.host).distinct().all() if h[0]]
    retention_days = get_setting('retention_days', '')
    retention_last = get_setting('retention_last', None)
    return render_template("manage.html", total=total, latest=latest, hosts=hosts, retention_days=retention_days, retention_last=retention_last)

@app.route("/manage/delete-older", methods=["POST"])
@login_required
def delete_older():
    if not admin_required():
        flash("Admin access required.","danger")
        return redirect(url_for("manage"))
    days = request.form.get("days","").strip()
    try:
        days = int(days)
        cutoff = datetime.utcnow() - timedelta(days=days)
        deleted = Event.query.filter(Event.received_at < cutoff).delete(synchronize_session=False)
        db.session.commit(); flash(f"Deleted {deleted} events older than {days} day(s).","success")
    except Exception as e:
        db.session.rollback(); flash(f"Delete failed: {e}","danger")
    return redirect(url_for("manage"))

@app.route("/manage/delete-all", methods=["POST"])
@login_required
def delete_all():
    if not admin_required():
        flash("Admin access required.","danger")
        return redirect(url_for("manage"))
    try:
        deleted = db.session.query(Event).delete()
        db.session.commit(); flash(f"Deleted all events ({deleted}).","success")
    except Exception as e:
        db.session.rollback(); flash(f"Delete failed: {e}","danger")
    return redirect(url_for("manage"))

# --- User management (admin only) ---
def _admin_count():
    return User.query.filter_by(is_admin=True).count()

@app.route("/manage/users")
@login_required
def manage_users():
    if not admin_required():
        flash("Admin access required.", "danger")
        return redirect(url_for("manage"))
    users = User.query.order_by(User.username.asc()).all()
    return render_template("users.html", users=users)

@app.route("/manage/users/create", methods=["POST"])
@login_required
def manage_users_create():
    if not admin_required():
        flash("Admin access required.", "danger")
        return redirect(url_for("manage_users"))
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()
    role = (request.form.get("role") or "user").strip()
    if not username or not password:
        flash("Username and password are required.", "danger")
        return redirect(url_for("manage_users"))
    existing = User.query.filter_by(username=username).first()
    if existing:
        flash("User already exists.", "warning")
        return redirect(url_for("manage_users"))
    user = User(username=username)
    user.set_password(password)
    user.is_admin = (role == "admin")
    user.is_reviewer = (role in ("admin","reviewer"))
    db.session.add(user)
    db.session.commit()
    flash(f"User '{username}' created with role={role}.", "success")
    return redirect(url_for("manage_users"))

@app.route("/manage/users/<int:uid>/reset", methods=["POST"])
@login_required
def manage_users_reset(uid):
    if not admin_required():
        flash("Admin access required.", "danger")
        return redirect(url_for("manage_users"))
    user = User.query.get_or_404(uid)
    newpw = (request.form.get("new_password") or "").strip()
    role = (request.form.get("role") or "").strip()
    if newpw:
        user.set_password(newpw)
    if role in ("admin","reviewer","user"):
        user.is_admin = (role == "admin")
        user.is_reviewer = (role in ("admin","reviewer"))
    db.session.commit()
    flash(f"Updated user '{user.username}'.", "success")
    return redirect(url_for("manage_users"))

@app.route("/manage/users/<int:uid>/delete", methods=["POST"])
@login_required
def manage_users_delete(uid):
    if not admin_required():
        flash("Admin access required.", "danger")
        return redirect(url_for("manage_users"))
    user = User.query.get_or_404(uid)
    if user.id == current_user.id:
        flash("You cannot delete your own account while logged in.", "warning")
        return redirect(url_for("manage_users"))
    if user.is_admin and _admin_count() <= 1:
        flash("Cannot delete the last admin user.", "warning")
        return redirect(url_for("manage_users"))
    db.session.delete(user)
    db.session.commit()
    flash(f"Deleted user '{user.username}'.", "success")
    return redirect(url_for("manage_users"))

# --- Retention (auto-purge) ---
def retention_purge(days:int)->int:
    if days is None or days <= 0:
        return 0
    cutoff = datetime.utcnow() - timedelta(days=days)
    deleted = Event.query.filter(Event.received_at < cutoff).delete(synchronize_session=False)
    db.session.commit()
    set_setting('retention_last', datetime.utcnow().isoformat(sep=' ', timespec='seconds'))
    return deleted

@app.route("/manage/set-retention", methods=["POST"])
@login_required
def set_retention():
    if not admin_required():
        flash("Admin access required.", "danger")
        return redirect(url_for("manage"))
    days_str = (request.form.get("retention_days") or "").strip()
    if days_str in ("", "0"):
        set_setting("retention_days", "")
        flash("Auto-purge disabled.", "success")
        return redirect(url_for("manage"))
    try:
        days = int(days_str)
        if days < 1 or days > 36500:
            raise ValueError("Days out of range")
        set_setting("retention_days", str(days))
        deleted = retention_purge(days)
        flash(f"Retention set to {days} day(s). Purged {deleted} old events.", "success")
    except Exception:
        flash("Invalid days value. Enter a positive integer.", "danger")
    return redirect(url_for("manage"))

def retention_worker(app):
    check_seconds = int(os.environ.get("RETENTION_CHECK_SECONDS", "3600"))
    with app.app_context():
        while not _shutdown.is_set():
            try:
                val = get_setting("retention_days", "")
                if val and str(val).isdigit():
                    days = int(val)
                    if days > 0:
                        cutoff = datetime.utcnow() - timedelta(days=days)
                        deleted = Event.query.filter(Event.received_at < cutoff).delete(synchronize_session=False)
                        db.session.commit()
                        if deleted:
                            set_setting('retention_last', datetime.utcnow().isoformat(sep=' ', timespec='seconds'))
            except Exception:
                db.session.rollback()
            _shutdown.wait(check_seconds)

# --- CLI ---
@app.cli.command("init-db")
def init_db_cmd():
    db.create_all(); print("Database initialized.")

@app.cli.command("create-user")
@click.argument("username")
@click.argument("password")
@click.option("--role", type=click.Choice(["admin","reviewer","user"]), default="admin", help="User role")
def create_user_cmd(username, password, role):
    """Create or update a user with a role."""
    db.create_all()
    user = User.query.filter_by(username=username).first()
    if not user:
        user = User(username=username)
    user.is_admin = (role == "admin")
    user.is_reviewer = (role in ("admin","reviewer"))
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    print(f"User '{username}' created/updated with role={role}")

def ensure_default_admin():
    if os.environ.get("CREATE_DEFAULT_ADMIN", "1") in ("0", "false", "False"):
        return
    username = "meraki"
    password = "merakimiles"
    user = User.query.filter_by(username=username).first()
    if not user:
        user = User(username=username)
    user.is_admin = True
    user.is_reviewer = True
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

def main():
    with app.app_context():
        db.create_all()
        ensure_default_admin()
    servers = start_servers(app)
    threading.Thread(target=retention_worker, args=(app,), daemon=True).start()
    print(f"[syslog:udp] {app.config['SYSLOG_HOST']}:{app.config['SYSLOG_PORT']}" if app.config['SYSLOG_ENABLE_UDP'] else "[syslog:udp] disabled")
    print(f"[syslog:tcp] {app.config['SYSLOG_HOST']}:{app.config['SYSLOG_TCP_PORT']}" if app.config['SYSLOG_ENABLE_TCP'] else "[syslog:tcp] disabled")
    try:
        app.run(host="0.0.0.0", port=int(os.environ.get("PORT","8000")))
    finally:
        for s in servers:
            try: s.shutdown()
            except Exception: pass

if __name__ == "__main__":
    main()
