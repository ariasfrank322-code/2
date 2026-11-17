import base64, hashlib, hmac, json, os, secrets, time
from pathlib import Path
import requests
from flask import Flask, jsonify, request

# ---- config ---------------------------------------------------------------
PACKAGE_ID = os.environ.get("CP_PACKAGE", "com.DefaultCompany.IDRK")      # FILL
SECRET     = os.environ["CP_SECRET"].encode()
META_TOKEN = f"OC|{os.environ.get('META_APP_ID','')}|{os.environ.get('META_APP_SECRET','')}"
PF_TITLE   = os.environ.get("PLAYFAB_TITLE_ID", "")
PF_SECRET  = os.environ.get("PLAYFAB_SECRET", "")
BUILDS     = Path("builds")           # builds/<version>/base.apk, main.obb (optional), build.json {"buildGuid": "..."}
CERTS = {"5bf2ed5c1cccd32554106a9bbbc36645f22a0f9d7f4b2921ce39b9714421b201"}# FILL: signing cert sha256, lowercase hex (empty/placeholder = everything denied)
INSTALLER_OK = set()                  # FILL: empty = don't enforce
MIN_SDK    = 25                       # FILL
DEVICE_OK  = {"Basic", "Advanced"}    # FILL: only "NotTrusted" seen in docs
APP_OK     = {"StoreRecognized"}      # FILL: only "NotEvaluated" seen in docs
ON = dict(meta=True, custom=True, build=True, sig=True, frida=True, root=True, lib=True, os=True, repack=True)
CH_TTL, SESS_TTL = 60, 3600

app = Flask(__name__)
CH: dict[str, dict] = {}              # single worker; redis if you scale

# ---- helpers --------------------------------------------------------------
def b64u(b: bytes) -> str: return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def b64d(s: str) -> bytes: return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def jwt_enc(claims: dict) -> str:
    h = b64u(b'{"alg":"HS256","typ":"JWT"}'); p = b64u(json.dumps(claims).encode())
    s = b64u(hmac.new(SECRET, f"{h}.{p}".encode(), hashlib.sha256).digest())
    return f"{h}.{p}.{s}"

def jwt_dec(tok: str):
    try:
        h, p, s = tok.split(".")
        good = b64u(hmac.new(SECRET, f"{h}.{p}".encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(s, good): return None
        c = json.loads(b64d(p))
        return c if c.get("exp", 0) > time.time() else None
    except Exception:
        return None

def sha_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while chunk := f.read(1 << 20): h.update(chunk)
    return h.hexdigest()

def load_builds():
    out = {}
    for d in BUILDS.glob("*"):
        if not d.is_dir(): continue
        files = {k: d / n for k, n in (("apk", "base.apk"), ("obb", "main.obb")) if (d / n).exists()}
        info = json.loads((d / "build.json").read_text()) if (d / "build.json").exists() else {}
        out[d.name] = {"guid": info.get("buildGuid"), "files": files, "sha": {k: sha_file(p) for k, p in files.items()}}
    return out

B = load_builds()                     # restart the server after adding a build

def proof(nonce: str, b: dict, ranges: list) -> str:
    h = hashlib.sha256(nonce.encode())
    for r in ranges:
        with open(b["files"][r["file"]], "rb") as f:
            f.seek(r["off"]); h.update(f.read(r["len"]))
    return h.hexdigest()

# ---- endpoints ------------------------------------------------------------
@app.get("/challenge")
def challenge():
    now = time.time()
    for k in [k for k, v in CH.items() if v["exp"] < now]: CH.pop(k, None)
    v = request.args.get("v", ""); b = B.get(v); ranges = []
    if b:
        for _ in range(4):
            k = secrets.choice(list(b["files"]))
            size = b["files"][k].stat().st_size
            ln = min(65536, size)
            ranges.append({"file": k, "off": secrets.randbelow(max(size - ln, 1)), "len": ln})
    nonce = b64u(secrets.token_bytes(32))
    CH[nonce] = {"exp": now + CH_TTL, "v": v, "ranges": ranges}
    return jsonify(nonce=nonce, ranges=ranges)

@app.post("/verify")
def verify():
    d = request.get_json(force=True)
    ch = CH.pop(d.get("nonce", ""), None)                 # single use
    if not ch or ch["exp"] < time.time():
        return jsonify(allow=False, flags=["bad_nonce"], session="", uid="")

    flags: list[tuple[str, bool]] = []                    # (name, hard)
    def bad(n, hard=True): flags.append((n, hard))

    b = B.get(d.get("version", ""))
    if not b: bad("unknown_version")
    dev = {}

    if ON["meta"]:
        try:
            c = requests.post("https://graph.oculus.com/platform_integrity/verify",   # FILL: confirm method
                              params={"token": d.get("token", ""), "access_token": META_TOKEN}, timeout=5).json()
            a, dev = c.get("app_state", {}), c.get("device_state", {})
            if c.get("request_details", {}).get("challenge_nonce") != d["nonce"]: bad("meta_nonce")   # FILL: field name
            if dev.get("device_integrity_state") not in DEVICE_OK: bad("meta_device")
            if a.get("app_integrity_state") not in APP_OK: bad("meta_app")
            if a.get("package_id") != PACKAGE_ID: bad("meta_package")
            if not CERTS & set(a.get("package_cert_sha256_digest", [])): bad("meta_cert")
        except Exception:
            bad("meta_unreachable")

    if ON["custom"] and b and d.get("proof") != proof(d["nonce"], b, ch["ranges"]): bad("custom_proof")

    if ON["build"] and b:
        if d.get("apkSha") != b["sha"].get("apk"): bad("apk_hash")
        if "obb" in b["sha"] and d.get("obbSha") != b["sha"]["obb"]: bad("obb_hash")

    if ON["sig"] and d.get("sigSha") not in CERTS: bad("sig")

    if ON["repack"]:
        if d.get("debugBuild"): bad("debug_build")
        if b and b["guid"] and d.get("buildGuid") != b["guid"]: bad("build_guid")
        if INSTALLER_OK and d.get("installer") not in INSTALLER_OK: bad("installer", False)

    if ON["os"]:
        fp = d.get("fingerprint", "").lower()
        if d.get("sdk", 0) < MIN_SDK: bad("os_old")
        if d.get("manufacturer", "").lower() not in {"oculus", "meta"}: bad("os_mfr")
        if "quest" not in d.get("model", "").lower(): bad("os_model")                 # FILL: check real model strings
        if any(x in fp for x in ("generic", "goldfish", "ranchu", "emulator", "sdk_gphone")): bad("os_emulator")

    if ON["frida"]:
        if d.get("frida"):  bad("frida:" + d.get("fridaWhy", ""))
        if d.get("tracer"): bad("tracer")
    if ON["root"] and d.get("root"): bad("root:" + d.get("rootWhy", ""), False)
    if ON["lib"] and d.get("libs"):  bad("libs:" + ",".join(d["libs"]), False)

    allow = not any(h for _, h in flags)
    uid = dev.get("unique_id") or secrets.token_hex(8)
    sess = jwt_enc({"uid": uid, "v": d.get("version"), "exp": time.time() + SESS_TTL}) if allow else ""
    return jsonify(allow=allow, flags=[n for n, _ in flags], session=sess, uid=uid)

# custom auth: your game server calls this
@app.post("/session/check")
def session_check():
    c = jwt_dec((request.get_json(silent=True) or {}).get("session", ""))
    return (jsonify(ok=True, uid=c["uid"], v=c["v"]), 200) if c else (jsonify(ok=False), 401)

# photon auth: set this URL in the Photon dashboard (Custom Authentication)
@app.route("/photon/auth", methods=["GET", "POST"])
def photon_auth():
    tok = request.values.get("session") or (request.get_json(silent=True) or {}).get("session", "")
    c = jwt_dec(tok)
    if not c: return jsonify(ResultCode=3, Message="denied")
    return jsonify(ResultCode=1, UserId=c["uid"], Message="ok")

# playfab auth
@app.post("/playfab/login")
def pf_login():
    c = jwt_dec((request.get_json(silent=True) or {}).get("session", ""))
    if not c: return jsonify(ok=False), 401
    r = requests.post(f"https://{PF_TITLE}.playfabapi.com/Server/LoginWithServerCustomId",
                      headers={"X-SecretKey": PF_SECRET},
                      json={"ServerCustomId": c["uid"], "CreateAccount": True}, timeout=5)
    j = (r.json() or {}).get("data") or {}
    if not j.get("SessionTicket"): return jsonify(ok=False), 502
    return jsonify(ok=True, ticket=j["SessionTicket"], playFabId=j["PlayFabId"])

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))