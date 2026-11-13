#!/usr/bin/env python3
"""xui-reseller: چندادمینه (نماینده‌فروشی) برای پنل ثنایی (3x-ui) از طریق API."""
import os, re, json, time, uuid, hmac, hashlib, secrets, sqlite3, asyncio, threading, logging
from contextlib import asynccontextmanager
from typing import Optional, List
from urllib.parse import quote

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from itsdangerous import TimestampSigner, BadSignature

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("reseller")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PANEL_URL = os.environ.get("PANEL_URL", "").rstrip("/")
PANEL_USER = os.environ.get("PANEL_USER", "")
PANEL_PASS = os.environ.get("PANEL_PASS", "")
SUDO_USER = os.environ.get("SUDO_USER", "owner")
SUDO_PASS = os.environ.get("SUDO_PASS", "")
SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
SUB_URL_BASE = os.environ.get("SUB_URL_BASE", "")
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE_DIR, "data.db"))
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "0") == "1"
SYNC_INTERVAL = 300
GB = 1024 ** 3
SUPPORTED = ("vless", "vmess", "trojan")

# ---------------------------------------------------------------- database
SCHEMA = """
CREATE TABLE IF NOT EXISTS admins(
 id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, pw TEXT NOT NULL,
 max_users INTEGER NOT NULL DEFAULT 0, max_gb REAL NOT NULL DEFAULT 0,
 expire_ts INTEGER NOT NULL DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1,
 suspended INTEGER NOT NULL DEFAULT 0, allowed_inbounds TEXT NOT NULL DEFAULT '',
 created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT, admin_id INTEGER NOT NULL, name TEXT NOT NULL,
 email TEXT UNIQUE NOT NULL, inbound_id INTEGER NOT NULL, sub_id TEXT NOT NULL,
 gb REAL NOT NULL DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1, created INTEGER NOT NULL);
"""
db_lock = threading.Lock()


def _conn():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with db_lock:
        c = _conn()
        c.executescript(SCHEMA)
        c.commit()
        c.close()


def q(sql, args=(), one=False):
    with db_lock:
        c = _conn()
        try:
            rows = c.execute(sql, args).fetchall()
            c.commit()
        finally:
            c.close()
    if one:
        return rows[0] if rows else None
    return rows


def ex(sql, args=()):
    with db_lock:
        c = _conn()
        try:
            cur = c.execute(sql, args)
            c.commit()
            return cur.lastrowid
        finally:
            c.close()


def hash_pw(pw, salt=None):
    salt = salt or secrets.token_hex(8)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200_000).hex()
    return f"{salt}${h}"


def check_pw(pw, stored):
    salt, _, _ = stored.partition("$")
    return hmac.compare_digest(hash_pw(pw, salt), stored)


# ---------------------------------------------------------------- panel client
class Panel:
    def __init__(self):
        self.client = httpx.AsyncClient(timeout=20, verify=False)
        self.lock = asyncio.Lock()
        self.logged = False

    async def login(self):
        async with self.lock:
            try:
                r = await self.client.post(PANEL_URL + "/login",
                                           data={"username": PANEL_USER, "password": PANEL_PASS})
                ok = r.json().get("success")
            except Exception:
                ok = False
            if not ok:
                raise HTTPException(502, "ورود به پنل ثنایی ناموفق بود؛ آدرس/یوزر/پسورد را بررسی کنید")
            self.logged = True

    async def call(self, method, path, **kw):
        if not self.logged:
            await self.login()
        for attempt in range(2):
            try:
                r = await self.client.request(method, PANEL_URL + path, **kw)
            except httpx.HTTPError:
                raise HTTPException(502, "اتصال به پنل ثنایی برقرار نشد")
            data = None
            if r.status_code == 200:
                try:
                    data = r.json()
                except Exception:
                    data = None
            if data is None:
                if attempt == 0:
                    await self.login()
                    continue
                raise HTTPException(502, "پاسخ نامعتبر از پنل ثنایی")
            if not data.get("success"):
                raise HTTPException(502, "پنل: " + str(data.get("msg")))
            return data.get("obj")

    async def inbounds(self):
        return await self.call("GET", "/panel/api/inbounds/list") or []

    async def inbound(self, iid):
        return await self.call("GET", f"/panel/api/inbounds/get/{iid}")

    async def add_client(self, iid, c):
        await self.call("POST", "/panel/api/inbounds/addClient",
                        data={"id": iid, "settings": json.dumps({"clients": [c]})})

    async def update_client(self, iid, key, c):
        await self.call("POST", f"/panel/api/inbounds/updateClient/{quote(str(key), safe='')}",
                        data={"id": iid, "settings": json.dumps({"clients": [c]})})

    async def del_client(self, iid, key):
        await self.call("POST", f"/panel/api/inbounds/{iid}/delClient/{quote(str(key), safe='')}")

    async def reset(self, iid, email):
        await self.call("POST", f"/panel/api/inbounds/{iid}/resetClientTraffic/{quote(email, safe='')}")


panel = Panel()
create_lock = asyncio.Lock()


def client_key(proto, c):
    if proto in ("vless", "vmess"):
        return c.get("id")
    if proto == "trojan":
        return c.get("password")
    return c.get("email")


def make_client(proto, email, total, expiry, sub_id, flow=""):
    c = {"email": email, "limitIp": 0, "totalGB": total, "expiryTime": expiry,
         "enable": True, "tgId": "", "subId": sub_id, "comment": "", "reset": 0}
    if proto in ("vless", "vmess"):
        c["id"] = str(uuid.uuid4())
        if proto == "vless":
            c["flow"] = flow
    else:
        c["password"] = secrets.token_urlsafe(10)
    return c


async def find_client(u):
    ib = await panel.inbound(u["inbound_id"])
    proto = ib["protocol"]
    for c in json.loads(ib["settings"]).get("clients", []):
        if c.get("email") == u["email"]:
            return proto, c
    return proto, None


async def stats_map():
    m = {}
    for ib in await panel.inbounds():
        for s in ib.get("clientStats") or []:
            m[s["email"]] = s
    return m


# ---------------------------------------------------------------- helpers
def admin_active(a):
    return bool(a["enabled"]) and not (a["expire_ts"] and a["expire_ts"] < time.time())


def allowed_list(a):
    return [int(x) for x in a["allowed_inbounds"].split(",") if x.strip().isdigit()]


def usage(admin_id, exclude=None):
    rows = [r for r in q("SELECT id, gb FROM users WHERE admin_id=?", (admin_id,)) if r["id"] != exclude]
    return len(rows), sum(r["gb"] for r in rows)


def check_quota(a, gb, exclude=None, new_user=False):
    cnt, alloc = usage(a["id"], exclude)
    if new_user and a["max_users"] and cnt + 1 > a["max_users"]:
        raise HTTPException(400, "سقف تعداد کاربر پر شده است")
    if a["max_gb"]:
        if gb <= 0:
            raise HTTPException(400, "ساخت کاربر نامحدود برای این ادمین مجاز نیست")
        left = a["max_gb"] - alloc
        if gb > left + 1e-9:
            raise HTTPException(400, f"حجم باقی‌مانده ادمین فقط {max(left, 0):.2f} گیگابایت است")


def expiry_ms(days):
    return int((time.time() + days * 86400) * 1000) if days > 0 else 0


def user_view(u, stats, names):
    s = stats.get(u["email"], {})
    used = (s.get("up", 0) or 0) + (s.get("down", 0) or 0)
    exp = s.get("expiryTime", 0) or 0
    if not u["enabled"]:
        status = "disabled"
    elif u["gb"] > 0 and used >= u["gb"] * GB:
        status = "limited"
    elif exp > 0 and exp < time.time() * 1000:
        status = "expired"
    else:
        status = "active"
    return {"id": u["id"], "name": u["name"], "email": u["email"], "admin_id": u["admin_id"],
            "admin": names.get(u["admin_id"], "?"), "gb": u["gb"], "used": used, "expiry": exp,
            "enabled": bool(u["enabled"]), "status": status, "inbound_id": u["inbound_id"],
            "sub": (SUB_URL_BASE + u["sub_id"]) if SUB_URL_BASE else ""}


# ---------------------------------------------------------------- auth
signer = TimestampSigner(SECRET_KEY)
fails = {}


def rate_check(ip):
    now = time.time()
    lst = [t for t in fails.get(ip, []) if now - t < 600]
    fails[ip] = lst
    if len(lst) >= 10:
        raise HTTPException(429, "تلاش ناموفق زیاد؛ چند دقیقه بعد دوباره امتحان کنید")


def get_auth(request: Request):
    tok = request.cookies.get("rs")
    if not tok:
        raise HTTPException(401, "نیاز به ورود")
    try:
        v = signer.unsign(tok, max_age=7 * 86400).decode()
    except BadSignature:
        raise HTTPException(401, "نیاز به ورود")
    role, _, ident = v.partition(":")
    if role == "sudo":
        return {"role": "sudo", "admin": None}
    a = q("SELECT * FROM admins WHERE id=?", (int(ident or 0),), one=True)
    if not a:
        raise HTTPException(401, "نیاز به ورود")
    return {"role": "admin", "admin": a}


def need_sudo(request):
    auth = get_auth(request)
    if auth["role"] != "sudo":
        raise HTTPException(403, "فقط مالک دسترسی دارد")
    return auth


# ---------------------------------------------------------------- sync
async def sync_admin(a):
    active = admin_active(a)
    if active == (not a["suspended"]):
        return
    ok = True
    for u in q("SELECT * FROM users WHERE admin_id=?", (a["id"],)):
        want = active and bool(u["enabled"])
        try:
            proto, c = await find_client(u)
            if c is None or bool(c.get("enable", True)) == want:
                continue
            c["enable"] = want
            await panel.update_client(u["inbound_id"], client_key(proto, c), c)
        except Exception as e:
            ok = False
            log.warning("sync user %s failed: %s", u["email"], e)
    if ok:
        ex("UPDATE admins SET suspended=? WHERE id=?", (0 if active else 1, a["id"]))


async def sync_loop():
    while True:
        try:
            for a in q("SELECT * FROM admins"):
                await sync_admin(a)
        except Exception as e:
            log.warning("sync loop: %s", e)
        await asyncio.sleep(SYNC_INTERVAL)


@asynccontextmanager
async def lifespan(app):
    if not PANEL_URL or not SUDO_PASS:
        raise SystemExit("PANEL_URL و SUDO_PASS باید تنظیم شوند")
    init_db()
    task = asyncio.create_task(sync_loop())
    yield
    task.cancel()


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
with open(os.path.join(BASE_DIR, "static", "index.html"), encoding="utf-8") as f:
    INDEX = f.read()


@app.get("/", response_class=HTMLResponse)
async def index():
    return INDEX


# ---------------------------------------------------------------- session routes
class LoginIn(BaseModel):
    username: str
    password: str


@app.post("/api/login")
async def login(body: LoginIn, request: Request, response: Response):
    ip = request.client.host if request.client else "?"
    rate_check(ip)
    role = ident = None
    if hmac.compare_digest(body.username, SUDO_USER) and hmac.compare_digest(body.password, SUDO_PASS):
        role, ident = "sudo", 0
    else:
        a = q("SELECT * FROM admins WHERE username=?", (body.username,), one=True)
        if a and check_pw(body.password, a["pw"]):
            role, ident = "admin", a["id"]
    if not role:
        fails.setdefault(ip, []).append(time.time())
        raise HTTPException(401, "یوزرنیم یا پسورد اشتباه است")
    response.set_cookie("rs", signer.sign(f"{role}:{ident}").decode(), max_age=7 * 86400,
                        httponly=True, samesite="lax", secure=COOKIE_SECURE)
    return {"ok": True}


@app.post("/api/logout")
async def logout(response: Response):
    response.delete_cookie("rs")
    return {"ok": True}


@app.get("/api/me")
async def me(request: Request):
    auth = get_auth(request)
    if auth["role"] == "sudo":
        return {"role": "sudo", "username": SUDO_USER}
    a = auth["admin"]
    cnt, alloc = usage(a["id"])
    return {"role": "admin", "username": a["username"], "max_users": a["max_users"],
            "max_gb": a["max_gb"], "expire_ts": a["expire_ts"], "active": admin_active(a),
            "count": cnt, "allocated": alloc}


@app.get("/api/inbounds")
async def list_inbounds(request: Request):
    auth = get_auth(request)
    allowed = allowed_list(auth["admin"]) if auth["role"] == "admin" else []
    out = []
    for ib in await panel.inbounds():
        if ib["protocol"] not in SUPPORTED:
            continue
        if allowed and ib["id"] not in allowed:
            continue
        out.append({"id": ib["id"], "remark": ib.get("remark", ""), "protocol": ib["protocol"],
                    "port": ib.get("port")})
    return out


# ---------------------------------------------------------------- admins (sudo)
class AdminIn(BaseModel):
    username: str
    password: str
    max_users: int = 0
    max_gb: float = 0
    days: int = 0
    allowed_inbounds: List[int] = []


class AdminUp(BaseModel):
    password: Optional[str] = None
    max_users: Optional[int] = None
    max_gb: Optional[float] = None
    days: Optional[int] = None
    enabled: Optional[bool] = None
    allowed_inbounds: Optional[List[int]] = None


@app.get("/api/admins")
async def list_admins(request: Request):
    need_sudo(request)
    stats = await stats_map()
    out = []
    for a in q("SELECT * FROM admins ORDER BY id"):
        us = q("SELECT * FROM users WHERE admin_id=?", (a["id"],))
        used = sum((stats.get(u["email"], {}).get("up", 0) or 0) + (stats.get(u["email"], {}).get("down", 0) or 0)
                   for u in us)
        out.append({"id": a["id"], "username": a["username"], "max_users": a["max_users"],
                    "max_gb": a["max_gb"], "expire_ts": a["expire_ts"], "enabled": bool(a["enabled"]),
                    "active": admin_active(a), "count": len(us), "allocated": sum(u["gb"] for u in us),
                    "used": used, "allowed_inbounds": allowed_list(a)})
    return out


@app.post("/api/admins")
async def create_admin(body: AdminIn, request: Request):
    need_sudo(request)
    if not re.fullmatch(r"[A-Za-z0-9_]{3,20}", body.username) or body.username == SUDO_USER:
        raise HTTPException(400, "یوزرنیم باید ۳ تا ۲۰ حرف انگلیسی/عدد/آندرلاین باشد")
    if len(body.password) < 6:
        raise HTTPException(400, "پسورد حداقل ۶ کاراکتر باشد")
    if q("SELECT id FROM admins WHERE username=?", (body.username,), one=True):
        raise HTTPException(400, "این یوزرنیم قبلاً وجود دارد")
    aid = ex("INSERT INTO admins(username,pw,max_users,max_gb,expire_ts,allowed_inbounds,created) VALUES(?,?,?,?,?,?,?)",
             (body.username, hash_pw(body.password), max(body.max_users, 0), max(body.max_gb, 0),
              int(time.time() + body.days * 86400) if body.days > 0 else 0,
              ",".join(map(str, body.allowed_inbounds)), int(time.time())))
    return {"id": aid}


@app.put("/api/admins/{aid}")
async def update_admin(aid: int, body: AdminUp, request: Request):
    need_sudo(request)
    a = q("SELECT * FROM admins WHERE id=?", (aid,), one=True)
    if not a:
        raise HTTPException(404, "ادمین یافت نشد")
    sets, args = [], []
    if body.password:
        if len(body.password) < 6:
            raise HTTPException(400, "پسورد حداقل ۶ کاراکتر باشد")
        sets.append("pw=?"); args.append(hash_pw(body.password))
    if body.max_users is not None:
        sets.append("max_users=?"); args.append(max(body.max_users, 0))
    if body.max_gb is not None:
        sets.append("max_gb=?"); args.append(max(body.max_gb, 0))
    if body.days is not None:
        sets.append("expire_ts=?"); args.append(int(time.time() + body.days * 86400) if body.days > 0 else 0)
    if body.enabled is not None:
        sets.append("enabled=?"); args.append(1 if body.enabled else 0)
    if body.allowed_inbounds is not None:
        sets.append("allowed_inbounds=?"); args.append(",".join(map(str, body.allowed_inbounds)))
    if sets:
        ex(f"UPDATE admins SET {','.join(sets)} WHERE id=?", (*args, aid))
    await sync_admin(q("SELECT * FROM admins WHERE id=?", (aid,), one=True))
    return {"ok": True}


@app.delete("/api/admins/{aid}")
async def delete_admin(aid: int, request: Request):
    need_sudo(request)
    for u in q("SELECT * FROM users WHERE admin_id=?", (aid,)):
        try:
            proto, c = await find_client(u)
            if c is not None:
                await panel.del_client(u["inbound_id"], client_key(proto, c))
        except Exception as e:
            log.warning("delete user %s: %s", u["email"], e)
    ex("DELETE FROM users WHERE admin_id=?", (aid,))
    ex("DELETE FROM admins WHERE id=?", (aid,))
    return {"ok": True}


# ---------------------------------------------------------------- users
class UserIn(BaseModel):
    name: str
    gb: float = 0
    days: int = 0
    inbound_id: int


class UserUp(BaseModel):
    gb: Optional[float] = None
    days: Optional[int] = None
    enabled: Optional[bool] = None


def user_for(auth, uid):
    u = q("SELECT * FROM users WHERE id=?", (uid,), one=True)
    if not u or (auth["role"] == "admin" and u["admin_id"] != auth["admin"]["id"]):
        raise HTTPException(404, "کاربر یافت نشد")
    return u, q("SELECT * FROM admins WHERE id=?", (u["admin_id"],), one=True)


@app.get("/api/users")
async def list_users(request: Request, admin_id: Optional[int] = None):
    auth = get_auth(request)
    if auth["role"] == "admin":
        rows = q("SELECT * FROM users WHERE admin_id=? ORDER BY id DESC", (auth["admin"]["id"],))
    elif admin_id:
        rows = q("SELECT * FROM users WHERE admin_id=? ORDER BY id DESC", (admin_id,))
    else:
        rows = q("SELECT * FROM users ORDER BY id DESC")
    stats = await stats_map()
    names = {r["id"]: r["username"] for r in q("SELECT id, username FROM admins")}
    return [user_view(u, stats, names) for u in rows]


@app.post("/api/users")
async def create_user(body: UserIn, request: Request):
    auth = get_auth(request)
    if auth["role"] != "admin":
        raise HTTPException(403, "ساخت کاربر فقط توسط ادمین‌ها انجام می‌شود")
    a = auth["admin"]
    if not admin_active(a):
        raise HTTPException(403, "حساب ادمین غیرفعال یا منقضی است")
    if not re.fullmatch(r"[A-Za-z0-9_]{2,24}", body.name):
        raise HTTPException(400, "نام کاربر باید ۲ تا ۲۴ حرف انگلیسی/عدد/آندرلاین باشد")
    if body.gb < 0 or body.days < 0:
        raise HTTPException(400, "مقدار نامعتبر")
    allowed = allowed_list(a)
    if allowed and body.inbound_id not in allowed:
        raise HTTPException(403, "دسترسی به این اینباند ندارید")
    async with create_lock:
        check_quota(a, body.gb, new_user=True)
        email = f"{a['username']}_{body.name}"
        if q("SELECT id FROM users WHERE email=?", (email,), one=True):
            raise HTTPException(400, "این نام کاربر قبلاً وجود دارد")
        ib = await panel.inbound(body.inbound_id)
        proto = ib["protocol"]
        if proto not in SUPPORTED:
            raise HTTPException(400, "پروتکل این اینباند پشتیبانی نمی‌شود")
        flow = ""
        if proto == "vless":
            for c in json.loads(ib["settings"]).get("clients", []):
                if c.get("flow"):
                    flow = c["flow"]
                    break
        sub_id = secrets.token_hex(8)
        client = make_client(proto, email, int(body.gb * GB), expiry_ms(body.days), sub_id, flow)
        await panel.add_client(body.inbound_id, client)
        uid = ex("INSERT INTO users(admin_id,name,email,inbound_id,sub_id,gb,created) VALUES(?,?,?,?,?,?,?)",
                 (a["id"], body.name, email, body.inbound_id, sub_id, body.gb, int(time.time())))
    return {"id": uid}


@app.put("/api/users/{uid}")
async def update_user(uid: int, body: UserUp, request: Request):
    auth = get_auth(request)
    u, a = user_for(auth, uid)
    if auth["role"] == "admin" and not admin_active(a):
        raise HTTPException(403, "حساب ادمین غیرفعال یا منقضی است")
    if body.gb is not None:
        if body.gb < 0:
            raise HTTPException(400, "مقدار نامعتبر")
        check_quota(a, body.gb, exclude=uid)
    proto, c = await find_client(u)
    if c is None:
        raise HTTPException(404, "کاربر در پنل ثنایی یافت نشد")
    key = client_key(proto, c)
    if body.gb is not None:
        c["totalGB"] = int(body.gb * GB)
    if body.days is not None:
        c["expiryTime"] = expiry_ms(max(body.days, 0))
    new_enabled = bool(u["enabled"]) if body.enabled is None else body.enabled
    c["enable"] = new_enabled and admin_active(a)
    await panel.update_client(u["inbound_id"], key, c)
    ex("UPDATE users SET gb=?, enabled=? WHERE id=?",
       (u["gb"] if body.gb is None else body.gb, 1 if new_enabled else 0, uid))
    return {"ok": True}


@app.post("/api/users/{uid}/reset")
async def reset_user(uid: int, request: Request):
    auth = get_auth(request)
    u, a = user_for(auth, uid)
    if auth["role"] == "admin" and not admin_active(a):
        raise HTTPException(403, "حساب ادمین غیرفعال یا منقضی است")
    await panel.reset(u["inbound_id"], u["email"])
    return {"ok": True}


@app.delete("/api/users/{uid}")
async def delete_user(uid: int, request: Request):
    auth = get_auth(request)
    u, _ = user_for(auth, uid)
    proto, c = await find_client(u)
    if c is not None:
        await panel.del_client(u["inbound_id"], client_key(proto, c))
    ex("DELETE FROM users WHERE id=?", (uid,))
    return {"ok": True}
