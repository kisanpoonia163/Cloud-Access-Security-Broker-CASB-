#!/usr/bin/env python3
"""
CASB Prototype — Advanced (single-file)

Updated: pastel/light color theme (soothing & modern)
- Only UI/theme changes (many light colors), no feature changes.
- Single-file runnable FastAPI app.

Run:
    python casb_prototype_advanced.py
Open http://127.0.0.1:8000/
"""
import os
import sys
import json
import re
import time
import argparse
import asyncio
import hashlib
import math
import base64
import csv
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timedelta

from fastapi import (
    FastAPI,
    Request,
    HTTPException,
    Depends,
    Response,
    BackgroundTasks,
    Query,
    WebSocket,
    status,
    File,
    UploadFile,
)
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse, PlainTextResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import bcrypt
from jose import jwt, JWTError
from cryptography.fernet import Fernet, InvalidToken
import httpx
import uvicorn
import aiofiles
import threading
import io
import zipfile

# -------------------------
# Config & paths (CLI overrides below)
# -------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
AUDIT_DIR = os.path.join(DATA_DIR, "audit")
SECRETS_FILE = os.path.join(DATA_DIR, "secrets.json.enc")
USERS_FILE = os.path.join(DATA_DIR, "users.json.enc")
POLICIES_FILE = os.path.join(DATA_DIR, "policies.json.enc")
DLP_FILE = os.path.join(DATA_DIR, "dlp_rules.json.enc")
AUDIT_LOG = os.path.join(AUDIT_DIR, "events.log.enc")  # encrypted audit log
METRICS_FILE = os.path.join(DATA_DIR, "metrics.json.enc")
TEMPLATES_FILE = os.path.join(DATA_DIR, "templates.json.enc")

os.makedirs(AUDIT_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

# -------------------------
# Atomic helpers
# -------------------------
def atomic_write(path: str, data: str):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)

def atomic_bytes_write(path: str, data: bytes):
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)

# -------------------------
# Encrypted JSON store helper
# -------------------------
class EncryptedJsonStore:
    def __init__(self, path: str, key: bytes, default: Any):
        self.path = path
        self.key = key
        self.fernet = Fernet(key)
        self.default = default
        self._lock = threading.Lock()
        # Ensure file exists
        if not os.path.exists(self.path):
            try:
                self.save(default)
            except Exception:
                # if save fails, fall back to plaintext write (best-effort)
                atomic_write(self.path, json.dumps(default, indent=2))

    def load(self):
        if not os.path.exists(self.path):
            return self.default
        with open(self.path, "rb") as f:
            data = f.read()
        try:
            plain = self.fernet.decrypt(data)
            return json.loads(plain.decode("utf-8"))
        except (InvalidToken, ValueError, Exception):
            # attempt to read plaintext (fallback)
            try:
                return json.loads(data.decode("utf-8"))
            except Exception:
                return self.default

    def save(self, obj: Any):
        with self._lock:
            b = json.dumps(obj, indent=2, ensure_ascii=False).encode("utf-8")
            enc = self.fernet.encrypt(b)
            atomic_bytes_write(self.path, enc)

# -------------------------
# Secrets manager
# -------------------------
class SecretsManager:
    """
    Stores a single encrypted secrets file containing FERNET_KEY and JWT_SECRET.
    For the demo, if file doesn't exist we create a simple container with a master
    and blob encrypted with the master. This keeps the original pattern but robust.
    """
    def __init__(self, path: str):
        self.path = path
        self._plain = {}
        self.master_key = None
        # Create default secrets if not present
        if not os.path.exists(self.path):
            # create a master and a blob encrypted by the master for demo
            master = Fernet.generate_key()  # bytes
            f_master = Fernet(master)
            plain = {
                "FERNET_KEY": Fernet.generate_key().decode("utf-8"),
                "JWT_SECRET": Fernet.generate_key().decode("utf-8"),
            }
            blob = f_master.encrypt(json.dumps(plain).encode()).decode("utf-8")
            container = {"master_b64": master.decode("utf-8"), "blob": blob}
            atomic_write(self.path, json.dumps(container, indent=2))
            self._plain = plain
            self.master_key = master
            return
        # load existing
        with open(self.path, "r", encoding="utf-8") as f:
            try:
                container = json.load(f)
            except Exception:
                container = {}
        if "master_b64" in container and "blob" in container:
            try:
                master = container["master_b64"].encode("utf-8")
                f_master = Fernet(master)
                blob = f_master.decrypt(container["blob"].encode("utf-8"))
                self._plain = json.loads(blob.decode("utf-8"))
                self.master_key = master
            except Exception:
                # fallback: maybe file stored plaintext secrets
                try:
                    self._plain = container
                    self.master_key = None
                except Exception:
                    self._plain = {}
                    self.master_key = None
        else:
            # treat file contents as plaintext secrets
            self._plain = container
            self.master_key = None

    def get(self, k: str):
        return self._plain.get(k)

secrets = SecretsManager(SECRETS_FILE)
FERNET_KEY = secrets.get("FERNET_KEY")
JWT_SECRET = secrets.get("JWT_SECRET")

if not FERNET_KEY or not JWT_SECRET:
    print("Unable to initialize secrets (FERNET_KEY or JWT_SECRET missing). Exiting.")
    sys.exit(1)

FERNET_KEY_BYTES = FERNET_KEY.encode("utf-8")
fernet = Fernet(FERNET_KEY_BYTES)

# Encrypted stores
users_store = EncryptedJsonStore(USERS_FILE, FERNET_KEY_BYTES, default=[])
policies_store = EncryptedJsonStore(POLICIES_FILE, FERNET_KEY_BYTES, default=[])
dlp_store = EncryptedJsonStore(DLP_FILE, FERNET_KEY_BYTES, default=[])
metrics_store = EncryptedJsonStore(METRICS_FILE, FERNET_KEY_BYTES, default={"blocked":0,"allowed":0,"dlp_alerts":0,"dlp_blocks":0,"dlp_redacts":0,"history":[]})
templates_store = EncryptedJsonStore(TEMPLATES_FILE, FERNET_KEY_BYTES, default=[])

# -------------------------
# Seed admin user if none
# -------------------------
def ensure_seeded_users():
    u = users_store.load() or []
    if not u:
        pw = b"password123"
        salt = bcrypt.gensalt()
        ph = bcrypt.hashpw(pw, salt).decode("utf-8")
        admin = {
            "id": "u-admin",
            "email": "admin@example.com",
            "role": "admin",
            "password_hash": ph,
            "created_at": datetime.utcnow().isoformat(),
        }
        users_store.save([admin])

ensure_seeded_users()

# -------------------------
# AuthManager
# -------------------------
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 1 day default

class AuthManager:
    def __init__(self, jwt_secret: str):
        self.jwt_secret = jwt_secret

    def create_access_token(self, data: dict, expires_delta: Optional[timedelta] = None):
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        # JWT 'exp' must be numeric timestamp
        to_encode.update({"exp": int(expire.timestamp())})
        return jwt.encode(to_encode, self.jwt_secret, algorithm=ALGORITHM)

    def decode_token(self, token: str) -> dict:
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=[ALGORITHM])
            return payload
        except JWTError as e:
            # re-raise for callers to handle
            raise

auth = AuthManager(JWT_SECRET)

def verify_password(plain_password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False

def get_user_by_email(email: str) -> Optional[dict]:
    users = users_store.load() or []
    for u in users:
        if u.get("email","").lower() == email.lower():
            return u
    return None

def get_user_by_id(uid: str) -> Optional[dict]:
    users = users_store.load() or []
    for u in users:
        if u.get("id") == uid:
            return u
    return None

# -------------------------
# Policy engine (mini-DSL)
# -------------------------
def match_condition(cond: dict, req_meta: dict) -> bool:
    if not isinstance(cond, dict):
        return False
    if "any" in cond:
        for c in cond["any"]:
            if match_condition(c, req_meta):
                return True
        return False
    if "all" in cond:
        for c in cond["all"]:
            if not match_condition(c, req_meta):
                return False
        return True
    if "not" in cond:
        return not match_condition(cond["not"], req_meta)

    for k, v in cond.items():
        if k == "http_method":
            if req_meta.get("method","").upper() != v.upper():
                return False
        elif k == "path_regex":
            try:
                if not re.search(v, req_meta.get("path","")):
                    return False
            except re.error:
                return False
        elif k == "header_contains":
            ok = False
            for hname, frag in v.items():
                hv = req_meta.get("headers",{}).get(hname.lower())
                if hv and frag in hv:
                    ok = True
                    break
            if not ok:
                return False
        elif k == "file_ext":
            ext = req_meta.get("file_ext")
            if not ext or ext.lower().lstrip(".") not in [e.lower().lstrip(".") for e in v]:
                return False
        elif k == "jwt_claims":
            claims = req_meta.get("jwt_claims",{})
            for claim_k, claim_v in v.items():
                if claims.get(claim_k) != claim_v:
                    return False
        elif k == "body_regex":
            try:
                if not re.search(v, req_meta.get("body","") or "", flags=re.IGNORECASE):
                    return False
            except re.error:
                return False
        else:
            # unknown condition -> fail closed
            return False
    return True

class PolicyEngine:
    def __init__(self, store: EncryptedJsonStore):
        self.store = store

    def evaluate(self, req_meta: dict) -> Optional[dict]:
        policies = self.store.load() or []
        policies_sorted = sorted(policies, key=lambda p: p.get("priority",0), reverse=True)
        for p in policies_sorted:
            cond = p.get("conditions", {})
            if match_condition(cond, req_meta):
                return p
        return None

policy_engine = PolicyEngine(policies_store)

# -------------------------
# DLP Engine
# -------------------------
class DlpEngine:
    def __init__(self, store: EncryptedJsonStore):
        self.store = store

    def _compile(self, pattern: str):
        try:
            return re.compile(pattern, re.IGNORECASE)
        except re.error:
            return None

    def run_on_text(self, text: str) -> List[dict]:
        matches = []
        rules = self.store.load() or []
        for r in rules:
            pat = self._compile(r.get("pattern",""))
            if not pat:
                continue
            for m in pat.finditer(text or ""):
                matches.append({
                    "rule_id": r.get("id"),
                    "rule_name": r.get("name"),
                    "match": m.group(0),
                    "action": r.get("action","alert"),
                    "severity": r.get("severity","medium")
                })
        return matches

    def redact_text(self, text: str) -> str:
        rules = self.store.load() or []
        out = text
        for r in rules:
            if r.get("action") == "redact":
                try:
                    out = re.sub(r.get("pattern",""), "[REDACTED]", out, flags=re.IGNORECASE)
                except re.error:
                    continue
        return out

    def ai_detect_sensitive(self, text: str) -> Optional[List[dict]]:
        matches = []
        if not text:
            return matches
        if re.search(r"[A-Za-z0-9-_]{40,}", text):
            matches.append({"rule_id":"ai-1","rule_name":"ai_token_like","match":"<long-token>","action":"alert","severity":"high"})
        if len(re.findall(r"\b(?:\d[ -]*?){13,19}\b", text)) >= 1:
            matches.append({"rule_id":"ai-2","rule_name":"ai_cc_like","match":"<cc-number-like>","action":"alert","severity":"high"})
        return matches

dlp_engine = DlpEngine(dlp_store)

# -------------------------
# Audit Manager (encrypted append-only JSONL)
# -------------------------
audit_queue: asyncio.Queue = asyncio.Queue()

class AuditManager:
    def __init__(self, audit_path: str, fernet_key: bytes):
        self.audit_path = audit_path
        self.fernet = Fernet(fernet_key)
        # Ensure file exists: encrypted empty content
        if not os.path.exists(self.audit_path):
            try:
                atomic_bytes_write(self.audit_path, self.fernet.encrypt(b""))
            except Exception:
                # fallback plaintext
                atomic_write(self.audit_path, "")
        self._file_lock = threading.Lock()

    def _append_plain(self, line: str):
        with self._file_lock:
            # read existing (if encrypted), decrypt -> append -> re-encrypt
            try:
                with open(self.audit_path, "rb") as f:
                    enc = f.read()
            except Exception:
                enc = b""
            try:
                if enc:
                    plain = self.fernet.decrypt(enc)
                else:
                    plain = b""
            except Exception:
                # file not encrypted or invalid; try to treat as plaintext
                try:
                    plain = enc
                except Exception:
                    plain = b""
            new_plain = plain + (line + "\n").encode("utf-8")
            try:
                new_enc = self.fernet.encrypt(new_plain)
                atomic_bytes_write(self.audit_path, new_enc)
            except Exception:
                # last-resort plaintext append
                try:
                    with open(self.audit_path, "ab") as f:
                        f.write((line + "\n").encode("utf-8"))
                except Exception:
                    pass

    def log(self, entry: dict):
        entry["timestamp"] = datetime.utcnow().isoformat()
        line = json.dumps(entry, ensure_ascii=False)
        # append to encrypted audit log
        try:
            self._append_plain(line)
        except Exception:
            pass
        # push to in-memory queue for SSE
        try:
            audit_queue.put_nowait(line)
        except Exception:
            pass

    def stream_generator(self, request: Request, filter_action: Optional[str] = None, only_user: Optional[str] = None):
        async def gen():
            # send occasional keep-alive comment
            while True:
                if await request.is_disconnected():
                    break
                try:
                    line = await asyncio.wait_for(audit_queue.get(), timeout=0.5)
                    if filter_action and filter_action not in line:
                        continue
                    if only_user:
                        try:
                            obj = json.loads(line)
                            if obj.get("user") != only_user:
                                continue
                        except Exception:
                            pass
                    yield f"data: {line}\n\n"
                except asyncio.TimeoutError:
                    # keep-alive comment to keep connection alive
                    yield ":\n\n"
                except Exception:
                    break
        return gen()

    def search(self, q: str, limit:int=100):
        try:
            with open(self.audit_path, "rb") as f:
                enc = f.read()
        except Exception:
            return []
        try:
            plain = self.fernet.decrypt(enc).decode("utf-8")
        except Exception:
            try:
                plain = enc.decode("utf-8")
            except Exception:
                return []
        res = []
        for line in reversed(plain.splitlines()):
            if q.lower() in line.lower():
                try:
                    res.append(json.loads(line))
                except Exception:
                    continue
                if len(res) >= limit:
                    break
        return res

    def export_lines(self, limit:int=1000):
        try:
            with open(self.audit_path, "rb") as f:
                enc = f.read()
        except Exception:
            return []
        try:
            plain = self.fernet.decrypt(enc).decode("utf-8")
        except Exception:
            try:
                plain = enc.decode("utf-8")
            except Exception:
                return []
        out = []
        for line in plain.splitlines()[-limit:]:
            try:
                out.append(json.loads(line))
            except Exception:
                continue
        return out

audit_manager = AuditManager(AUDIT_LOG, FERNET_KEY_BYTES)

# -------------------------
# Simple per-user rate limiter (token bucket)
# -------------------------
class RateLimiter:
    def __init__(self, rate: float, capacity: float):
        self.rate = rate
        self.capacity = capacity
        self.buckets = {}  # user_email -> (tokens, last_ts)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            tokens, last = self.buckets.get(key, (self.capacity, now))
            elapsed = max(0.0, now - last)
            tokens = min(self.capacity, tokens + elapsed * self.rate)
            if tokens < 1.0:
                self.buckets[key] = (tokens, now)
                return False
            tokens -= 1.0
            self.buckets[key] = (tokens, now)
            return True

    def config(self, rate: float, capacity: float):
        with self._lock:
            self.rate = rate
            self.capacity = capacity
            self.buckets = {}

    def snapshot(self):
        with self._lock:
            return {"rate": self.rate, "capacity": self.capacity, "buckets": {k: {"tokens": v[0], "last": v[1]} for k,v in self.buckets.items()}}

rate_limiter = RateLimiter(rate=1.0, capacity=5.0)

# -------------------------
# Proxy Service
# -------------------------
class ProxyService:
    def __init__(self, allowed_targets: Optional[List[str]] = None, allowed_origins: Optional[List[str]] = None):
        self.allowed_targets = allowed_targets or []
        self.allowed_origins = allowed_origins or []

    def is_target_allowed(self, target: str) -> bool:
        if not self.allowed_targets:
            return True
        for t in self.allowed_targets:
            if target.startswith(t):
                return True
        return False

    @staticmethod
    def sanitize_headers(headers: dict) -> dict:
        out = {}
        for k,v in headers.items():
            kl = k.lower()
            if kl in ("host","content-length","transfer-encoding","connection"):
                continue
            out[k] = v
        return out

proxy_service = ProxyService(allowed_targets=[])

# -------------------------
# FastAPI app setup
# -------------------------
app = FastAPI(title="CASB Prototype")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------
# Pydantic models for API
# -------------------------
class LoginIn(BaseModel):
    email: str
    password: str

class PolicyIn(BaseModel):
    name: str
    priority: int = 0
    conditions: dict
    action: dict
    id: Optional[str] = None

class DLPIn(BaseModel):
    name: str
    pattern: str
    action: str  # alert|redact|block
    severity: Optional[str] = "medium"
    id: Optional[str] = None

class UserIn(BaseModel):
    email: str
    password: str
    role: Optional[str] = "analyst"

class ProxyConfigIn(BaseModel):
    allowed_targets: List[str]

class RateConfigIn(BaseModel):
    rate: float
    capacity: float

class TemplateIn(BaseModel):
    id: Optional[str]
    name: str
    type: str
    content: dict

# -------------------------
# Auth dependency
# -------------------------
async def get_current_user(request: Request):
    auth_header = request.headers.get("Authorization")
    token = None
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ",1)[1]
    else:
        token = request.query_params.get("token")
    if not token:
        raise HTTPException(status_code=401, detail="Missing token")
    try:
        payload = auth.decode_token(token)
        # token decode returns payload; ensure expiration check handled by jwt.decode
        email = payload.get("email")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        user = get_user_by_email(email)
        if not user:
            raise HTTPException(status_code=401, detail="Unknown user")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

# -------------------------
# API: Auth
# -------------------------
@app.post("/api/auth/login")
async def login(data: LoginIn):
    user = get_user_by_email(data.email)
    if not user:
        raise HTTPException(status_code=400, detail="Invalid credentials")
    if not verify_password(data.password, user["password_hash"]):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    token = auth.create_access_token({"email": user["email"], "role": user["role"]})
    audit_manager.log({"action":"login","user":user["email"], "meta":{"ip":"local"}})
    return {"access_token": token, "token_type": "bearer", "user": {"email": user["email"], "role": user["role"]}}

# -------------------------
# API: User management
# -------------------------
@app.get("/api/users")
async def list_users(current=Depends(get_current_user)):
    if current["role"] not in ("admin","analyst"):
        raise HTTPException(status_code=403, detail="admin/analyst only")
    users = users_store.load() or []
    out = [{k:v for k,v in u.items() if k!="password_hash"} for u in users]
    return out

@app.post("/api/users")
async def create_user(u: UserIn, current=Depends(get_current_user)):
    if current["role"] != "admin":
        raise HTTPException(status_code=403, detail="admin only")
    users = users_store.load() or []
    if get_user_by_email(u.email):
        raise HTTPException(status_code=400, detail="user exists")
    ph = bcrypt.hashpw(u.password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    obj = {"id":"u-"+hashlib.sha1((u.email+str(time.time())).encode()).hexdigest()[:12], "email":u.email, "role":u.role, "password_hash":ph, "created_at": datetime.utcnow().isoformat()}
    users.append(obj)
    users_store.save(users)
    audit_manager.log({"action":"user_created","user":current["email"],"meta":{"new_user":u.email}})
    return {k:v for k,v in obj.items() if k!="password_hash"}

@app.delete("/api/users/{user_id}")
async def delete_user(user_id: str, current=Depends(get_current_user)):
    if current["role"] != "admin":
        raise HTTPException(status_code=403, detail="admin only")
    users = users_store.load() or []
    users = [u for u in users if u.get("id") != user_id]
    users_store.save(users)
    audit_manager.log({"action":"user_deleted","user":current["email"],"meta":{"deleted_user_id":user_id}})
    return {"deleted": user_id}

# -------------------------
# API: Policies
# -------------------------
@app.get("/api/policies")
async def list_policies(current=Depends(get_current_user)):
    return policies_store.load() or []

@app.post("/api/policies")
async def create_policy(p: PolicyIn, current=Depends(get_current_user)):
    if current["role"] != "admin":
        raise HTTPException(status_code=403, detail="admin only")
    policies = policies_store.load() or []
    obj = p.dict()
    if not obj.get("id"):
        obj["id"] = "pol-" + hashlib.sha1(str(time.time()).encode()).hexdigest()[:12]
    policies = [x for x in policies if x.get("id") != obj["id"]]
    policies.append(obj)
    policies_store.save(policies)
    audit_manager.log({"action":"policy_upsert","user":current["email"],"policy_id":obj["id"],"meta":obj})
    return obj

@app.delete("/api/policies/{policy_id}")
async def delete_policy(policy_id: str, current=Depends(get_current_user)):
    if current["role"] != "admin":
        raise HTTPException(status_code=403, detail="admin only")
    policies = policies_store.load() or []
    policies = [p for p in policies if p.get("id") != policy_id]
    policies_store.save(policies)
    audit_manager.log({"action":"policy_delete","user":current["email"],"policy_id":policy_id})
    return {"deleted": policy_id}

# -------------------------
# API: DLP rules
# -------------------------
@app.get("/api/dlp")
async def get_dlp(current=Depends(get_current_user)):
    return dlp_store.load() or []

@app.post("/api/dlp")
async def add_dlp(rule: DLPIn, current=Depends(get_current_user)):
    if current["role"] not in ("admin","analyst"):
        raise HTTPException(status_code=403, detail="admin/analyst only")
    rules = dlp_store.load() or []
    obj = rule.dict()
    if not obj.get("id"):
        obj["id"] = "dlp-" + hashlib.sha1(str(time.time()).encode()).hexdigest()[:12]
    rules = [r for r in rules if r.get("id") != obj["id"]]
    rules.append(obj)
    dlp_store.save(rules)
    audit_manager.log({"action":"dlp_upsert","user":current["email"],"rule":obj})
    return obj

@app.delete("/api/dlp/{rule_id}")
async def delete_dlp(rule_id: str, current=Depends(get_current_user)):
    if current["role"] not in ("admin","analyst"):
        raise HTTPException(status_code=403, detail="admin/analyst only")
    rules = dlp_store.load() or []
    rules = [r for r in rules if r.get("id") != rule_id]
    dlp_store.save(rules)
    audit_manager.log({"action":"dlp_delete","user":current["email"],"rule_id":rule_id})
    return {"deleted": rule_id}

# -------------------------
# API: Templates
# -------------------------
@app.get("/api/templates")
async def list_templates(current=Depends(get_current_user)):
    return templates_store.load() or []

@app.post("/api/templates")
async def add_template(t: TemplateIn, current=Depends(get_current_user)):
    if current["role"] not in ("admin","analyst"):
        raise HTTPException(status_code=403, detail="admin/analyst only")
    ts = templates_store.load() or []
    obj = {"id": t.id or "tpl-" + hashlib.sha1((t.name+str(time.time())).encode()).hexdigest()[:10], "name": t.name, "type": t.type, "content": t.content}
    ts = [x for x in ts if x.get("id") != obj["id"]]
    ts.append(obj)
    templates_store.save(ts)
    audit_manager.log({"action":"template_upsert","user":current["email"],"template":obj})
    return obj

@app.delete("/api/templates/{tpl_id}")
async def delete_template(tpl_id: str, current=Depends(get_current_user)):
    if current["role"] not in ("admin","analyst"):
        raise HTTPException(status_code=403, detail="admin/analyst only")
    ts = templates_store.load() or []
    ts = [t for t in ts if t.get("id") != tpl_id]
    templates_store.save(ts)
    audit_manager.log({"action":"template_delete","user":current["email"],"template_id":tpl_id})
    return {"deleted": tpl_id}

# -------------------------
# API: Audit SSE + search + csv export
# -------------------------
@app.get("/api/audit/stream")
async def stream_audit(request: Request, token: Optional[str] = Query(None), filter_action: Optional[str] = Query(None), only_user: Optional[str] = Query(None)):
    if token is None:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ",1)[1]
    if not token:
        raise HTTPException(status_code=401, detail="Missing token")
    try:
        payload = auth.decode_token(token)
        email = payload.get("email")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    generator = audit_manager.stream_generator(request, filter_action=filter_action, only_user=only_user)
    return StreamingResponse(generator, media_type="text/event-stream")

@app.get("/api/audit/search")
async def audit_search(q: str = Query(..., min_length=1), current=Depends(get_current_user), limit: int = Query(200, ge=1, le=5000)):
    res = audit_manager.search(q, limit=limit)
    return res

@app.get("/api/audit/export")
async def audit_export(q: Optional[str] = Query(None), current=Depends(get_current_user)):
    if current["role"] not in ("admin","analyst"):
        raise HTTPException(status_code=403, detail="admin/analyst only")
    if q:
        rows = audit_manager.search(q, limit=5000)
    else:
        rows = audit_manager.export_lines(limit=5000)
    buff = io.StringIO()
    writer = None
    for r in rows:
        if writer is None:
            writer = csv.DictWriter(buff, fieldnames=sorted(r.keys()))
            writer.writeheader()
        writer.writerow(r)
    buff.seek(0)
    return PlainTextResponse(buff.read(), media_type="text/csv", headers={"Content-Disposition":"attachment; filename=audit_export.csv"})

# -------------------------
# API: Metrics (history + snapshot)
# -------------------------
@app.get("/api/metrics")
async def get_metrics(current=Depends(get_current_user)):
    m = metrics_store.load() or {}
    now = datetime.utcnow().isoformat()
    snapshot = {
        "time": now,
        "blocked": m.get("blocked",0),
        "allowed": m.get("allowed",0),
        "dlp_alerts": m.get("dlp_alerts",0),
        "dlp_blocks": m.get("dlp_blocks",0),
        "dlp_redacts": m.get("dlp_redacts",0),
    }
    history = m.get("history", [])
    history.append(snapshot)
    history = history[-200:]
    m["history"] = history
    metrics_store.save(m)
    return m

# -------------------------
# API: Export / Import (new)
# -------------------------
@app.get("/api/export")
async def export_data(current=Depends(get_current_user)):
    if current["role"] != "admin":
        raise HTTPException(status_code=403, detail="admin only")
    data = {
        "users": users_store.load() or [],
        "policies": policies_store.load() or [],
        "dlp": dlp_store.load() or [],
        "metrics": metrics_store.load() or {},
        "templates": templates_store.load() or [],
        "audit_preview": audit_manager.export_lines(limit=200)
    }
    s = json.dumps(data, indent=2, ensure_ascii=False)
    return PlainTextResponse(s, media_type="application/json", headers={"Content-Disposition":"attachment; filename=casb_export.json"})

@app.post("/api/import")
async def import_data(payload: dict, current=Depends(get_current_user)):
    if current["role"] != "admin":
        raise HTTPException(status_code=403, detail="admin only")
    if "users" in payload:
        users_store.save(payload["users"])
    if "policies" in payload:
        policies_store.save(payload["policies"])
    if "dlp" in payload:
        dlp_store.save(payload["dlp"])
    if "metrics" in payload:
        metrics_store.save(payload["metrics"])
    if "templates" in payload:
        templates_store.save(payload["templates"])
    audit_manager.log({"action":"import","user":current["email"],"meta":{"keys":list(payload.keys())}})
    return {"imported": list(payload.keys())}

# -------------------------
# Helper to read body safely
# -------------------------
async def read_body_text(request: Request) -> str:
    try:
        body_bytes = await request.body()
        if not body_bytes:
            return ""
        return body_bytes.decode(errors="ignore")
    except Exception:
        return ""

# -------------------------
# Proxy endpoint (main)
# -------------------------
@app.api_route("/proxy", methods=["GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD"])
async def proxy(request: Request, target: Optional[str] = None, current=Depends(get_current_user)):
    if not target:
        raise HTTPException(status_code=400, detail="missing target query param")

    if not rate_limiter.allow(current["email"]):
        audit_manager.log({"action":"rate_limited","user":current["email"],"meta":{"target":target}})
        raise HTTPException(status_code=429, detail="rate limit exceeded")

    if not proxy_service.is_target_allowed(target):
        audit_manager.log({"action":"deny_target_unallowed","user":current["email"],"meta":{"target":target}})
        raise HTTPException(status_code=403, detail="target not allowed")

    method = request.method
    headers = {k.lower(): v for k,v in request.headers.items()}
    file_ext = None
    content_type = headers.get("content-type","")
    if "multipart/form-data" in content_type:
        file_ext = None
    else:
        parsed = request.url.path
        if "." in parsed:
            file_ext = parsed.split(".")[-1]
    jwt_claims = {}
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        tok = auth_header.split(" ",1)[1]
        try:
            jwt_claims = auth.decode_token(tok)
        except Exception:
            jwt_claims = {}

    body_text = await read_body_text(request)
    req_meta = {
        "method": method,
        "path": str(request.url.path),
        "headers": headers,
        "file_ext": file_ext,
        "jwt_claims": jwt_claims,
        "body": body_text,
    }

    matched_policy = policy_engine.evaluate(req_meta)
    decision = {"status":"allow","policy":None}
    if matched_policy:
        decision["policy"] = matched_policy
        act = matched_policy.get("action",{})
        typ = act.get("type","allow")
        if typ == "deny":
            audit_manager.log({"action":"deny_by_policy","user":current["email"],"policy_id":matched_policy.get("id"),"meta":{"method":method,"path":str(request.url)}})
            m = metrics_store.load(); m["blocked"] = m.get("blocked",0)+1; metrics_store.save(m)
            return JSONResponse({"detail":"blocked by policy"}, status_code=403)
        elif typ == "monitor":
            decision["status"] = "monitor"
        elif typ == "allow":
            decision["status"] = "allow"

    dlp_matches = []
    if body_text:
        dlp_matches = dlp_engine.run_on_text(body_text)
        ai_matches = dlp_engine.ai_detect_sensitive(body_text)
        if ai_matches:
            dlp_matches.extend(ai_matches)
    blocked_by_dlp = False
    redacted_body = body_text
    for m in dlp_matches:
        act = m.get("action")
        if act == "block":
            blocked_by_dlp = True
            audit_manager.log({"action":"dlp_block","user":current["email"],"match":m,"meta":{"method":method,"path":str(request.url)}})
            mm = metrics_store.load(); mm["dlp_blocks"] = mm.get("dlp_blocks",0)+1; metrics_store.save(mm)
        elif act == "alert":
            audit_manager.log({"action":"dlp_alert","user":current["email"],"match":m,"meta":{"method":method,"path":str(request.url)}})
            mm = metrics_store.load(); mm["dlp_alerts"] = mm.get("dlp_alerts",0)+1; metrics_store.save(mm)
        elif act == "redact":
            redacted_body = dlp_engine.redact_text(redacted_body)
            audit_manager.log({"action":"dlp_redact","user":current["email"],"match":m,"meta":{"method":method,"path":str(request.url)}})
            mm = metrics_store.load(); mm["dlp_redacts"] = mm.get("dlp_redacts",0)+1; metrics_store.save(mm)

    if blocked_by_dlp:
        return JSONResponse({"detail":"blocked by DLP rule"}, status_code=403)

    # forward request
    async with httpx.AsyncClient(timeout=30.0, verify=True) as client:
        req_headers = proxy_service.sanitize_headers({k:v for k,v in request.headers.items()})
        if redacted_body != body_text:
            body_bytes = redacted_body.encode("utf-8")
        else:
            body_bytes = await request.body()
        # convert query params to simple dict (exclude 'target' param)
        params = dict(request.query_params)
        params.pop("target", None)
        try:
            resp = await client.request(method, target, headers=req_headers, content=body_bytes, params=params)
        except httpx.RequestError as e:
            audit_manager.log({"action":"proxy_error","user":current["email"],"error":str(e),"meta":{"target":target}})
            raise HTTPException(status_code=502, detail=str(e))

    text_resp = ""
    try:
        text_resp = resp.text
    except Exception:
        text_resp = ""
    resp_dlp_matches = dlp_engine.run_on_text(text_resp) if text_resp else []
    resp_text_redacted = text_resp
    for m in resp_dlp_matches:
        act = m.get("action")
        if act == "block":
            audit_manager.log({"action":"dlp_block_response","user":current["email"],"match":m,"meta":{"target":target}})
            mm = metrics_store.load(); mm["dlp_blocks"] = mm.get("dlp_blocks",0)+1; metrics_store.save(mm)
            return JSONResponse({"detail":"response blocked by DLP"}, status_code=502)
        elif act == "redact":
            resp_text_redacted = dlp_engine.redact_text(resp_text_redacted)
            audit_manager.log({"action":"dlp_redact_response","user":current["email"],"match":m,"meta":{"target":target}})
            mm = metrics_store.load(); mm["dlp_redacts"] = mm.get("dlp_redacts",0)+1; metrics_store.save(mm)
        elif act == "alert":
            audit_manager.log({"action":"dlp_alert_response","user":current["email"],"match":m,"meta":{"target":target}})
            mm = metrics_store.load(); mm["dlp_alerts"] = mm.get("dlp_alerts",0)+1; metrics_store.save(mm)

    audit_manager.log({
        "action":"proxy_forward",
        "user":current["email"],
        "target":target,
        "method":method,
        "policy_id": matched_policy.get("id") if matched_policy else None,
        "dlp_matches_req": dlp_matches,
        "dlp_matches_resp": resp_dlp_matches
    })
    mm = metrics_store.load(); mm["allowed"] = mm.get("allowed",0)+1; metrics_store.save(mm)

    headers_to_send = {k: v for k,v in resp.headers.items() if k.lower() not in ("content-encoding","transfer-encoding","content-length")}
    content_type = resp.headers.get("content-type")
    return Response(content=resp_text_redacted.encode("utf-8"), status_code=resp.status_code, headers=headers_to_send, media_type=content_type)

# -------------------------
# Proxy config endpoints
# -------------------------
@app.get("/api/proxy/config")
async def get_proxy_config(current=Depends(get_current_user)):
    if current["role"] not in ("admin","analyst"):
        raise HTTPException(status_code=403, detail="admin/analyst only")
    return {"allowed_targets": proxy_service.allowed_targets}

@app.post("/api/proxy/config")
async def set_proxy_config(cfg: ProxyConfigIn, current=Depends(get_current_user)):
    if current["role"] != "admin":
        raise HTTPException(status_code=403, detail="admin only")
    proxy_service.allowed_targets = cfg.allowed_targets
    audit_manager.log({"action":"proxy_config_set","user":current["email"],"meta":{"allowed_targets":cfg.allowed_targets}})
    return {"allowed_targets": proxy_service.allowed_targets}

# -------------------------
# Rate limiter endpoints
# -------------------------
@app.get("/api/rate")
async def get_rate(current=Depends(get_current_user)):
    if current["role"] not in ("admin","analyst"):
        raise HTTPException(status_code=403, detail="admin/analyst only")
    return rate_limiter.snapshot()

@app.post("/api/rate")
async def set_rate(cfg: RateConfigIn, current=Depends(get_current_user)):
    if current["role"] != "admin":
        raise HTTPException(status_code=403, detail="admin only")
    rate_limiter.config(cfg.rate, cfg.capacity)
    audit_manager.log({"action":"rate_config_set","user":current["email"],"meta":{"rate":cfg.rate,"capacity":cfg.capacity}})
    return {"rate":cfg.rate,"capacity":cfg.capacity}

# -------------------------
# Policy Simulator
# -------------------------
@app.post("/api/policy/simulate")
async def simulate_policy(req_meta: dict, current=Depends(get_current_user)):
    if current["role"] not in ("admin","analyst"):
        raise HTTPException(status_code=403, detail="admin/analyst only")
    matched = policy_engine.evaluate(req_meta)
    decision = {"status":"allow","policy":matched}
    if matched:
        typ = matched.get("action",{}).get("type","allow")
        if typ == "deny":
            decision["status"] = "deny"
        elif typ == "monitor":
            decision["status"] = "monitor"
        else:
            decision["status"] = "allow"
    return decision

# -------------------------
# UI: Single-file SPA (pastel / many light colors)
# -------------------------
INDEX_HTML = r"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>CASB Prototype</title>
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://cdn.jsdelivr.net/npm/daisyui@2.51.6/dist/full.css" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/codemirror@5.65.13/lib/codemirror.js"></script>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/codemirror@5.65.13/lib/codemirror.css">
  <script src="https://cdn.jsdelivr.net/npm/codemirror@5.65.13/mode/javascript/javascript.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
  <style>
    /* Pastel-rich, light color scheme — many soft accents */
    :root{
      --bg: linear-gradient(180deg, #fbfbff 0%, #f7fbff 30%, #fcfdf7 60%); /* soft multi-stop */
      --page-bg: #f7fafc;  /* light gray-blue */
      --card: linear-gradient(180deg, rgba(255,255,255,0.9), rgba(255,255,255,0.95));
      --muted: #6b7280;
      --dark: #0f172a;
      --accent-indigo: #5b6ef6;   /* main */
      --accent-sky: #7dd3fc;      /* sky blue */
      --accent-mint: #a7f3d0;     /* light mint */
      --accent-pink: #ffd6e0;     /* baby pink */
      --accent-lavender: #e9d5ff; /* lavender */
      --accent-peach: #fff1d6;    /* peachy */
      --border: rgba(15,23,42,0.06);
      --glass: rgba(255,255,255,0.7);
      --soft-shadow: 0 8px 24px rgba(16,24,40,0.06);
    }
    html,body { height:100%; }
    body {
      margin:0;
      background: var(--page-bg);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial;
      -webkit-font-smoothing:antialiased;
      -moz-osx-font-smoothing:grayscale;
      color: var(--dark);
      line-height:1.45;
    }
    .container { max-width:1200px; margin:auto; padding:28px; }
    .card {
      background: var(--card);
      border-radius: 14px;
      box-shadow: var(--soft-shadow);
      border: 1px solid var(--border);
      padding: 16px;
    }
    h1 { font-size:30px; font-weight:700; margin-bottom:10px; color:var(--dark); }
    .accent { font-weight:700; color:var(--accent-indigo); }
    /* Buttons — pastel gradients */
    .btn-accent {
      background: linear-gradient(90deg,var(--accent-indigo), #8ea7ff 60%);
      color: #fff;
      border: none;
      padding: 9px 14px;
      border-radius: 10px;
      cursor: pointer;
      font-weight:700;
      box-shadow: 0 6px 18px rgba(91,110,246,0.14);
    }
    .btn-accent:active { transform: translateY(1px); }
    .btn {
      background: linear-gradient(180deg, rgba(255,255,255,0.85), rgba(255,255,255,0.95));
      border: 1px solid var(--border);
      padding:8px 12px;
      border-radius:10px;
      cursor:pointer;
      box-shadow: 0 6px 18px rgba(16,24,40,0.02);
    }
    .btn:hover { transform: translateY(-1px); }
    .btn-small { padding:6px 8px; border-radius:8px; }
    /* inputs and textareas -> white + subtle pastel focus ring */
    input.input, textarea, .input, input[type="text"], input[type="email"], input[type="password"], textarea.input, select, .select {
      background: #fff !important;
      color: var(--dark) !important;
      border: 1px solid var(--border) !important;
      box-shadow: none !important;
      padding: 10px;
      border-radius: 10px;
      font-size: 14px;
      transition: box-shadow .18s ease, border-color .18s ease;
    }
    input:focus, textarea:focus, select:focus {
      outline: none;
      border-color: rgba(91,110,246,0.6);
      box-shadow: 0 6px 18px rgba(91,110,246,0.08), 0 0 0 6px rgba(123,99,255,0.06);
    }
    input::placeholder, textarea::placeholder {
      color: rgba(15,23,42,0.45) !important;
    }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, "Roboto Mono", monospace; }
    .small { font-size: 0.85rem; color: var(--muted); }
    .log-item.allow { color: #065f46; }
    .log-item.monitor { color: #92400e; }
    .log-item.deny { color: #991b1b; }
    textarea { resize: vertical; }
    .CodeMirror {
      background: #fff !important;
      color: var(--dark) !important;
      border-radius: 8px;
      height: auto;
      border: 1px solid var(--border);
      padding: 8px;
    }
    /* layout */
    .grid { display:grid; gap:16px; grid-template-columns: 300px 1fr; align-items:start; }
    .left-col .card { margin-bottom:16px; }
    .menu a { display:block; padding:12px; border-radius:8px; color:var(--dark); text-decoration:none; margin-bottom:6px; }
    .menu a.active, .menu a:hover { background: linear-gradient(90deg, rgba(123,99,255,0.06), rgba(125,211,252,0.04)); color:var(--accent-indigo); box-shadow: 0 6px 18px rgba(91,110,246,0.04); }
    .pill { display:inline-block; padding:6px 10px; border-radius:999px; background: linear-gradient(90deg,var(--accent-pink),var(--accent-peach)); color:var(--dark); font-weight:600; }
    /* responsive */
    @media (max-width: 920px) {
      .grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>CASB Prototype<span class="accent"></span></h1>

    <div id="auth" class="card p-4 mb-4">
      <h2 class="text-lg font-semibold">Login</h2>
      <div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap;">
        <input id="email" class="input" placeholder="admin@example.com" value="admin@example.com" style="min-width:220px;" />
        <input id="password" class="input" placeholder="password" value="password123" style="min-width:160px;" />
        <button id="loginBtn" class="btn-accent">Login</button>
      </div>
      <div id="loginMsg" class="text-sm" style="margin-top:8px;color:#b91c1c"></div>
    </div>

    <div id="main" style="display:none">
      <div class="grid">
        <div class="left-col">
          <div class="card">
            <h3 style="margin:0 0 8px 0;font-weight:700">Navigation</h3>
            <div class="menu" style="background:transparent;border-radius:8px;padding:8px;">
              <a href="#" id="nav-policies" class="active">Policies</a>
              <a href="#" id="nav-dlp">DLP Rules</a>
              <a href="#" id="nav-proxy">Proxy Test</a>
              <a href="#" id="nav-logs">Live Logs</a>
              <a href="#" id="nav-metrics">Metrics</a>
              <a href="#" id="nav-templates">Templates</a>
              <a href="#" id="nav-users">Users</a>
              <a href="#" id="nav-config">Config</a>
              <a href="#" id="nav-simulate">Policy Sim</a>
            </div>
          </div>

          <div class="card">
            <h3 style="margin:0 0 8px 0;font-weight:700">Quick Actions</h3>
            <div style="display:flex;flex-direction:column;gap:10px;margin-top:10px;">
              <button id="btn-new-policy" class="btn">New Policy</button>
              <button id="btn-new-dlp" class="btn">New DLP Rule</button>
              <button id="btn-refresh" class="btn-accent">Refresh All</button>
              <button id="btn-export" class="btn">Export Data</button>
              <button id="btn-import" class="btn">Import Data</button>
            </div>
          </div>
        </div>

        <div>
          <div id="section-policies" class="card mb-4">
            <h3 style="margin:0 0 8px 0;font-weight:700">Policy Editor</h3>
            <textarea id="policyJson" class="mono" style="width:100%;height:220px;padding:12px;border-radius:8px;border:1px solid var(--border);"></textarea>
            <div style="display:flex;gap:12px;margin-top:12px;">
              <button id="savePolicy" class="btn-accent">Save Policy</button>
              <button id="listPolicies" class="btn">Refresh</button>
            </div>
            <div class="small" style="margin-top:10px;">Policy model: {name, priority, conditions, action}. Use <code>all</code>/<code>any</code>/<code>not</code> to compose.</div>
          </div>

          <div id="section-dlp" class="card mb-4" style="display:none;">
            <h3 style="margin:0 0 8px 0;font-weight:700">DLP Rules</h3>
            <textarea id="dlpJson" class="mono" style="width:100%;height:140px;padding:12px;border-radius:8px;border:1px solid var(--border);"></textarea>
            <div style="display:flex;gap:12px;margin-top:12px;">
              <button id="saveDlp" class="btn-accent">Save DLP Rule</button>
              <button id="listDlp" class="btn">Refresh</button>
            </div>
            <div class="small" style="margin-top:10px;">Example: {"name":"API key","pattern":"[A-Z0-9\\-]{8,}","action":"redact"}</div>
          </div>

          <div id="section-proxy" class="card mb-4" style="display:none;">
            <h3 style="margin:0 0 8px 0;font-weight:700">Proxy Test / Request Simulator</h3>
            <div style="display:grid;grid-template-columns:1fr 120px;gap:10px;">
              <input id="proxyTarget" value="https://httpbin.org/post" class="input" />
              <button id="sendProxy" class="btn-accent">Send</button>
            </div>
            <textarea id="proxyBody" rows="6" class="mono" style="width:100%;margin-top:10px;padding:12px;border-radius:8px;border:1px solid var(--border);">{ "msg":"my secret-api-key: ABCD-1234-SECRET" }</textarea>
            <pre id="proxyResp" class="mono" style="background:#fff;border:1px solid var(--border);padding:12px;border-radius:8px;margin-top:10px;max-height:220px;overflow:auto;"></pre>
          </div>

          <div id="section-logs" class="card mb-4" style="display:none;">
            <h3 style="margin:0 0 8px 0;font-weight:700">Live Logs (SSE)</h3>
            <div style="display:flex;gap:8px;flex-wrap:wrap;">
              <input id="auditFilter" placeholder="filter action substring..." class="input" />
              <input id="auditUser" placeholder="only user (optional)" class="input" style="width:200px;" />
              <button id="btn-pause-sse" class="btn">Pause</button>
              <button id="btn-resume-sse" class="btn">Resume</button>
            </div>
            <div id="logs" class="mono" style="margin-top:10px;background:#fff;border:1px solid var(--border);border-radius:8px;padding:8px;max-height:240px;overflow:auto;font-size:13px;"></div>
            <div style="margin-top:10px;display:flex;gap:8px;">
              <input id="auditSearch" placeholder="Search audit..." class="input" style="flex:1;" />
              <button id="btnSearchAudit" class="btn">Search</button>
              <button id="btnExportAudit" class="btn">Export CSV</button>
            </div>
          </div>

          <div id="section-metrics" class="card mb-4" style="display:none;">
            <h3 style="margin:0 0 8px 0;font-weight:700">Metrics</h3>
            <canvas id="metricsChart" width="800" height="200"></canvas>
            <div id="metricsData" style="margin-top:8px;font-family:monospace;"></div>
          </div>

          <div id="section-templates" class="card mb-4" style="display:none;">
            <h3 style="margin:0 0 8px 0;font-weight:700">Templates</h3>
            <div style="display:flex;gap:8px;">
              <button id="tpl-block-exe" class="btn">Block .exe Uploads</button>
              <button id="tpl-redact-api" class="btn">Redact API Keys</button>
              <button id="tpl-save" class="btn-accent">Save Current as Template</button>
            </div>
            <div id="templatesList" style="margin-top:10px;"></div>
          </div>

          <div id="section-users" class="card mb-4" style="display:none;">
            <h3 style="margin:0 0 8px 0;font-weight:700">Users (admin)</h3>
            <div style="display:flex;gap:8px;flex-wrap:wrap;">
              <input id="newUserEmail" class="input" placeholder="email" />
              <input id="newUserPassword" class="input" placeholder="password" />
              <select id="newUserRole" class="select">
                <option value="analyst">analyst</option>
                <option value="admin">admin</option>
              </select>
              <button id="createUserBtn" class="btn-accent">Create</button>
            </div>
            <div id="usersList" style="margin-top:12px;"></div>
          </div>

          <div id="section-config" class="card mb-4" style="display:none;">
            <h3 style="margin:0 0 8px 0;font-weight:700">Config</h3>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
              <div>
                <h4 style="margin:0 0 6px 0;">Allowed Proxy Targets</h4>
                <textarea id="allowedTargets" class="mono" style="width:100%;height:120px;padding:10px;border-radius:8px;border:1px solid var(--border);"></textarea>
                <div style="display:flex;gap:8px;margin-top:8px;">
                  <button id="saveTargets" class="btn">Save</button>
                  <button id="loadTargets" class="btn">Reload</button>
                </div>
              </div>
              <div>
                <h4 style="margin:0 0 6px 0;">Rate Limiter</h4>
                <div style="display:flex;gap:8px;">
                  <input id="rateValue" class="input" placeholder="rate (tokens/sec)" />
                  <input id="capacityValue" class="input" placeholder="capacity (tokens)" />
                  <button id="saveRate" class="btn">Save</button>
                </div>
                <div class="small" id="rateSnapshot" style="margin-top:10px;"></div>
              </div>
            </div>
          </div>

          <div id="section-simulate" class="card mb-4" style="display:none;">
            <h3 style="margin:0 0 8px 0;font-weight:700">Policy Simulator</h3>
            <textarea id="simRequest" class="mono" style="width:100%;height:160px;padding:12px;border-radius:8px;border:1px solid var(--border);"></textarea>
            <div style="display:flex;gap:8px;margin-top:8px;">
              <button id="runSim" class="btn-accent">Run Simulation</button>
              <button id="loadExampleSim" class="btn">Load Example</button>
            </div>
            <pre id="simResult" style="background:#fff;border:1px solid var(--border);padding:12px;border-radius:8px;margin-top:10px;max-height:120px;overflow:auto;"></pre>
          </div>

        </div>
      </div>
    </div>

    <div style="margin-top:18px;color:var(--muted);font-size:13px;">Tip: demo admin — admin@example.com / password123</div>
  </div>

<script>
let token = null;
let sse = null;
let ssePaused = false;
function notify(msg){ try { alert(msg); } catch(e){} }
function showSection(id){
  document.querySelectorAll('[id^="section-"]').forEach(el=>{
    el.style.display = 'none';
  });
  const el = document.getElementById(id);
  if (el) el.style.display = 'block';
  // nav highlight
  document.querySelectorAll('.menu a').forEach(a=>a.classList.remove('active'));
  const navMap = {
    'section-policies':'nav-policies','section-dlp':'nav-dlp','section-proxy':'nav-proxy','section-logs':'nav-logs',
    'section-metrics':'nav-metrics','section-templates':'nav-templates','section-users':'nav-users','section-config':'nav-config',
    'section-simulate':'nav-simulate'
  };
  const navId = navMap[id];
  if (navId) {
    const navEl = document.getElementById(navId);
    if (navEl) navEl.classList.add('active');
  }
}
// nav handlers
document.getElementById('nav-policies').addEventListener('click',()=>{ showSection('section-policies');});
document.getElementById('nav-dlp').addEventListener('click',()=>{ showSection('section-dlp');});
document.getElementById('nav-proxy').addEventListener('click',()=>{ showSection('section-proxy');});
document.getElementById('nav-logs').addEventListener('click',()=>{ showSection('section-logs');});
document.getElementById('nav-metrics').addEventListener('click',()=>{ showSection('section-metrics');});
document.getElementById('nav-templates').addEventListener('click',()=>{ showSection('section-templates'); loadTemplates();});
document.getElementById('nav-users').addEventListener('click',()=>{ showSection('section-users'); loadUsers();});
document.getElementById('nav-config').addEventListener('click',()=>{ showSection('section-config'); loadProxyConfig(); loadRate();});
document.getElementById('nav-simulate').addEventListener('click',()=>{ showSection('section-simulate');});

// login
document.getElementById("loginBtn").addEventListener("click", async () => {
  const email = document.getElementById("email").value;
  const password = document.getElementById("password").value;
  const res = await fetch("/api/auth/login", {
    method:"POST", headers:{"Content-Type":"application/json"},
    body: JSON.stringify({email,password})
  });
  if (!res.ok) {
    const j = await res.json().catch(()=>({detail:"error"}));
    document.getElementById("loginMsg").innerText = j.detail || "login failed";
    return;
  }
  const j = await res.json();
  token = j.access_token;
  document.getElementById("auth").style.display = "none";
  document.getElementById("main").style.display = "block";
  startSSE();
  listPolicies();
  listDlp();
  fetchMetrics();
  loadTemplates();
  loadUsers();
  loadProxyConfig();
  loadRate();
});

// policies
async function listPolicies(){
  const res = await fetch("/api/policies", {headers:{"Authorization":"Bearer "+token}});
  const j = await res.json();
  document.getElementById("policyJson").value = JSON.stringify(j, null, 2);
}
document.getElementById("listPolicies").addEventListener("click", listPolicies);

document.getElementById("savePolicy").addEventListener("click", async ()=>{ try {
    const p = JSON.parse(document.getElementById("policyJson").value);
    const res = await fetch("/api/policies", { method:"POST", headers:{"Content-Type":"application/json","Authorization":"Bearer "+token}, body: JSON.stringify(p) });
    const j = await res.json();
    notify("Saved: " + (j.id || "ok"));
    listPolicies();
  } catch(e){ notify("Invalid JSON"); } });

// dlp
async function listDlp(){
  const res = await fetch("/api/dlp", {headers:{"Authorization":"Bearer "+token}});
  const j = await res.json();
  document.getElementById("dlpJson").value = JSON.stringify(j, null, 2);
}
document.getElementById("listDlp").addEventListener("click", listDlp);

document.getElementById("saveDlp").addEventListener("click", async ()=>{ try {
  const r = JSON.parse(document.getElementById("dlpJson").value);
  if (Array.isArray(r)) {
    for (const item of r) {
      await fetch("/api/dlp", {method:"POST", headers:{"Authorization":"Bearer "+token,"Content-Type":"application/json"}, body: JSON.stringify(item)});
    }
  } else {
    await fetch("/api/dlp", {method:"POST", headers:{"Authorization":"Bearer "+token,"Content-Type":"application/json"}, body: JSON.stringify(r)});
  }
  listDlp();
  notify("DLP saved");
} catch(e){ notify("Invalid JSON"); } });

// proxy send
document.getElementById("sendProxy").addEventListener("click", async ()=> {
  const target = document.getElementById("proxyTarget").value;
  const body = document.getElementById("proxyBody").value;
  try {
    const res = await fetch("/proxy?target="+encodeURIComponent(target), {
      method:"POST", headers:{"Content-Type":"application/json","Authorization":"Bearer "+token}, body: body
    });
    const text = await res.text();
    document.getElementById("proxyResp").innerText = "HTTP "+res.status + "\n\n" + text;
  } catch(e){ document.getElementById("proxyResp").innerText = "Error: "+String(e); }
});

// SSE
function startSSE(){
  const filter = encodeURIComponent(document.getElementById('auditFilter').value || '');
  const onlyUser = encodeURIComponent(document.getElementById('auditUser').value || '');
  const params = [];
  if (filter) params.push("filter_action="+filter);
  if (onlyUser) params.push("only_user="+onlyUser);
  params.push("token="+encodeURIComponent(token));
  const url = "/api/audit/stream?" + params.join("&");
  if (sse) { try { sse.close(); } catch(e){} }
  sse = new EventSource(url);
  const out = document.getElementById("logs");
  sse.onmessage = (ev)=>{
    if (ssePaused) return;
    try {
      const obj = JSON.parse(ev.data);
      const t = new Date(obj.timestamp).toLocaleTimeString();
      const cls = obj.action && (obj.action.includes('deny')||obj.action.includes('block')) ? 'deny' : (obj.action && obj.action.includes('monitor') ? 'monitor' : 'allow');
      const div = document.createElement("div");
      div.className = "log-item " + cls;
      div.innerText = `${t} ${obj.action||''} ${obj.user||''} ${JSON.stringify(obj.meta||obj)}`;
      out.prepend(div);
    } catch(e){}
  };
  sse.onerror = ()=>{ console.warn("SSE error"); };
}
document.getElementById('btn-pause-sse').addEventListener('click', ()=>{ ssePaused = true; notify('SSE paused');});
document.getElementById('btn-resume-sse').addEventListener('click', ()=>{ ssePaused = false; notify('SSE resumed');});

// audit search
document.getElementById("btnSearchAudit").addEventListener("click", async ()=>{
  const q = document.getElementById("auditSearch").value;
  if (!q) return;
  const res = await fetch("/api/audit/search?q="+encodeURIComponent(q), {headers:{"Authorization":"Bearer "+token}});
  const j = await res.json();
  const out = document.getElementById("logs");
  out.innerHTML = "";
  j.forEach(obj=>{
    const t = new Date(obj.timestamp).toLocaleTimeString();
    const div = document.createElement("div");
    div.innerText = `${t} ${obj.action||''} ${obj.user||''} ${JSON.stringify(obj.meta||obj)}`;
    out.appendChild(div);
  });
});

// export audit csv
document.getElementById("btnExportAudit").addEventListener("click", async ()=>{
  const q = document.getElementById("auditSearch").value;
  const url = q ? "/api/audit/export?q="+encodeURIComponent(q) : "/api/audit/export";
  const res = await fetch(url, {headers:{"Authorization":"Bearer "+token}});
  if (!res.ok) { notify("export failed"); return; }
  const txt = await res.text();
  const blob = new Blob([txt], {type:"text/csv"});
  const u = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = u; a.download = "audit_export.csv"; a.click();
  URL.revokeObjectURL(u);
});

// templates quick
document.getElementById("tpl-block-exe").addEventListener("click", ()=>{
  const example = {
    "name":"Block .exe uploads",
    "priority":100,
    "conditions":{"file_ext":["exe"]},
    "action":{"type":"deny","reason":"disallow exe"}
  };
  document.getElementById("policyJson").value = JSON.stringify(example, null, 2);
});
document.getElementById("tpl-redact-api").addEventListener("click", ()=>{
  const example = {"name":"API key redact","pattern":"[A-Z0-9\\-]{8,}","action":"redact","severity":"medium"};
  document.getElementById("dlpJson").value = JSON.stringify(example, null, 2);
});

document.getElementById("tpl-save").addEventListener("click", async ()=>{
  try {
    const content = {policy: JSON.parse(document.getElementById("policyJson").value || "[]"), dlp: JSON.parse(document.getElementById("dlpJson").value || "[]")};
    const payload = {name: "Saved Template "+(new Date()).toISOString(), type:"mixed", content};
    const res = await fetch("/api/templates", {method:"POST", headers:{"Authorization":"Bearer "+token,"Content-Type":"application/json"}, body: JSON.stringify(payload)});
    const j = await res.json(); notify("template saved: "+j.id); loadTemplates();
  } catch(e){ notify("failed to save template"); }
});

async function loadTemplates(){
  const res = await fetch("/api/templates", {headers:{"Authorization":"Bearer "+token}});
  const j = await res.json();
  const el = document.getElementById("templatesList"); el.innerHTML = "";
  j.forEach(t=>{
    const div = document.createElement("div");
    div.style.padding = "8px";
    div.style.borderBottom = "1px solid var(--border)";
    div.innerText = t.name + " ("+t.type+")";
    const btn = document.createElement("button");
    btn.className = "btn";
    btn.style.marginLeft = "8px";
    btn.innerText = "Apply";
    btn.addEventListener('click', ()=> {
      if (t.content.policy) document.getElementById("policyJson").value = JSON.stringify(t.content.policy, null, 2);
      if (t.content.dlp) document.getElementById("dlpJson").value = JSON.stringify(t.content.dlp, null, 2);
    });
    div.appendChild(btn);
    el.appendChild(div);
  });
}

// users
document.getElementById("createUserBtn").addEventListener("click", async ()=>{
  const email = document.getElementById("newUserEmail").value;
  const pw = document.getElementById("newUserPassword").value;
  const role = document.getElementById("newUserRole").value;
  if (!email || !pw) { notify("email/password required"); return; }
  const res = await fetch("/api/users", {method:"POST", headers:{"Authorization":"Bearer "+token,"Content-Type":"application/json"}, body: JSON.stringify({email,password:pw,role})});
  if (!res.ok) { const j = await res.json().catch(()=>({detail:"error"})); notify("create failed: "+(j.detail||"")); return; }
  notify("user created");
  loadUsers();
});

async function loadUsers(){
  const res = await fetch("/api/users", {headers:{"Authorization":"Bearer "+token}});
  const j = await res.json();
  const el = document.getElementById("usersList"); el.innerHTML = "";
  j.forEach(u=>{
    const div = document.createElement("div");
    div.style.display = "flex";
    div.style.justifyContent = "space-between";
    div.style.padding = "8px 0";
    div.style.borderBottom = "1px solid var(--border)";
    div.innerHTML = `<div>${u.email} <span style="color:var(--muted);font-size:13px;">(${u.role})</span></div>`;
    const btn = document.createElement("button");
    btn.className = "btn";
    btn.innerText = "Delete";
    btn.addEventListener('click', async ()=> {
      if (!confirm("Delete user "+u.email+"?")) return;
      const res = await fetch("/api/users/"+encodeURIComponent(u.id), {method:"DELETE", headers:{"Authorization":"Bearer "+token}});
      if (res.ok) { notify("deleted"); loadUsers(); } else { notify("delete failed"); }
    });
    div.appendChild(btn);
    el.appendChild(div);
  });
}

// proxy config + rate
async function loadProxyConfig(){
  const res = await fetch("/api/proxy/config", {headers:{"Authorization":"Bearer "+token}});
  if (!res.ok) return;
  const j = await res.json();
  document.getElementById("allowedTargets").value = (j.allowed_targets || []).join("\n");
}
document.getElementById("loadTargets").addEventListener("click", loadProxyConfig);
document.getElementById("saveTargets").addEventListener("click", async ()=>{
  const txt = document.getElementById("allowedTargets").value || "";
  const arr = txt.split(/\n+/).map(s=>s.trim()).filter(Boolean);
  const res = await fetch("/api/proxy/config", {method:"POST", headers:{"Authorization":"Bearer "+token,"Content-Type":"application/json"}, body: JSON.stringify({allowed_targets:arr})});
  if (res.ok) notify("saved"); else notify("save failed");
});

async function loadRate(){
  const res = await fetch("/api/rate", {headers:{"Authorization":"Bearer "+token}});
  if (!res.ok) return;
  const j = await res.json();
  document.getElementById("rateSnapshot").innerText = "rate: "+j.rate+"  capacity: "+j.capacity;
  document.getElementById("rateValue").value = j.rate;
  document.getElementById("capacityValue").value = j.capacity;
}
document.getElementById("saveRate").addEventListener("click", async ()=>{
  const rate = parseFloat(document.getElementById("rateValue").value || "1");
  const capacity = parseFloat(document.getElementById("capacityValue").value || "5");
  const res = await fetch("/api/rate", {method:"POST", headers:{"Authorization":"Bearer "+token,"Content-Type":"application/json"}, body: JSON.stringify({rate,capacity})});
  if (res.ok) { notify("rate updated"); loadRate(); } else notify("rate update failed");
});

// policy simulate
document.getElementById("runSim").addEventListener("click", async ()=>{
  try {
    const req = JSON.parse(document.getElementById("simRequest").value || "{}");
    const res = await fetch("/api/policy/simulate", {method:"POST", headers:{"Authorization":"Bearer "+token,"Content-Type":"application/json"}, body: JSON.stringify(req)});
    const j = await res.json();
    document.getElementById("simResult").innerText = JSON.stringify(j, null, 2);
  } catch(e){ notify("invalid JSON"); }
});
document.getElementById("loadExampleSim").addEventListener("click", ()=> {
  const example = {"method":"POST","path":"/upload.exe","file_ext":"exe","headers":{}};
  document.getElementById("simRequest").value = JSON.stringify(example, null, 2);
});

// metrics fetch & draw
async function fetchMetrics(){
  const res = await fetch("/api/metrics", {headers:{"Authorization":"Bearer "+token}});
  if (!res.ok) return;
  const j = await res.json();
  document.getElementById("metricsData").innerText = "blocked: "+j.blocked+"  allowed: "+j.allowed+"  dlp_alerts: "+j.dlp_alerts;
  // draw simple chart if available
  try {
    const ctx = document.getElementById("metricsChart").getContext("2d");
    if (window.metricsChart) { window.metricsChart.destroy(); }
    window.metricsChart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: ['blocked','allowed','dlp_alerts','dlp_blocks','dlp_redacts'],
        datasets: [{ label: 'counts', data: [j.blocked,j.allowed,j.dlp_alerts,j.dlp_blocks,j.dlp_redacts] }]
      },
      options: { responsive:true, maintainAspectRatio:false }
    });
  } catch(e){}
}

// refresh button
document.getElementById("btn-refresh").addEventListener("click", ()=>{
  listPolicies(); listDlp(); loadUsers(); fetchMetrics(); loadProxyConfig(); loadRate();
});

// export/import
document.getElementById("btn-export").addEventListener("click", async ()=>{
  const res = await fetch("/api/export", {headers:{"Authorization":"Bearer "+token}});
  if (!res.ok) { notify("export failed"); return; }
  const txt = await res.text();
  const blob = new Blob([txt], {type:"application/json"});
  const u = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = u; a.download = "casb_export.json"; a.click();
  URL.revokeObjectURL(u);
});
document.getElementById("btn-import").addEventListener("click", async ()=>{
  const body = prompt("Paste JSON to import (keys: users, policies, dlp, metrics, templates)");
  if (!body) return;
  try {
    const payload = JSON.parse(body);
    const res = await fetch("/api/import", {method:"POST", headers:{"Authorization":"Bearer "+token,"Content-Type":"application/json"}, body: JSON.stringify(payload)});
    if (res.ok) { notify("imported"); } else { notify("import failed"); }
  } catch(e){ notify("invalid json"); }
});

// small helpers: automatically show policies at start of UI
document.addEventListener("DOMContentLoaded", ()=> {
  // nothing to do until login
});
</script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse(INDEX_HTML)

# -------------------------
# Run server
# -------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CASB Prototype — Advanced (single-file)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8000, type=int)
    args = parser.parse_args()
    print("Starting CASB Prototype on http://%s:%s" % (args.host, args.port))
    uvicorn.run("casb_prototype_advanced:app", host=args.host, port=args.port, log_level="info", reload=False)