"""
video.py - vavuubey-secure HTTP API (FastAPI)
- Token-protected playlist & channel endpoints
- Admin token-protected admin panel & API
- Rate limiting (sliding window)
- Bot UA filter (allows VLC/Kodi/mpv/IPTV, blocks scanners)
- Security headers on all responses
- /debug CLOSED (was leaking info)
- /api/status LIMITED (no token leak, no db_path)
- /reload protected
- Logo URLs normalized to full https://vavoo.to/...

v4.0 - Bağımsız fork
"""
import os
import sqlite3
import threading
import re
from fastapi import FastAPI, Request, Query, HTTPException
from fastapi.responses import PlainTextResponse, RedirectResponse, Response, HTMLResponse, JSONResponse
import state
import security

app = FastAPI(
    title="vavuubey-secure",
    version="4.0.0",
    docs_url=None,        # /docs kapali
    redoc_url=None,       # /redoc kapali
    openapi_url=None,     # /openapi.json kapali
)

ORD = "COALESCE(cat.sort_order,9999), c.sort_order, c.name"


def get_db():
    conn = sqlite3.connect(state.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_host(r: Request) -> str:
    p = r.headers.get("x-forwarded-proto", "https")
    h = r.headers.get("host", "localhost:10000")
    return f"{p}://{h}"


# ============================================================
# MIDDLEWARE: Security headers + bot filter + global rate limit
# ============================================================
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    # 1. Render's health probe hits /health periodically with a generic UA.
    #    Exempt /health from bot filter (rate limit still applies).
    path = request.url.path
    is_health = path == "/health"

    # 2. Bot UA filter (blocks scanners like curl/wget/python-requests/nikto)
    if not is_health and request.method != "OPTIONS":
        ua = request.headers.get("user-agent", "")
        if security.is_bot_ua(ua):
            return security.forbidden_resp("Forbidden UA")

    # 3. Global rate limit per IP (60/min default)
    ip = security.client_ip(request)
    if not security.rate_check(f"global:{ip}", limit=120, window_sec=60):
        return security.rate_limit_resp(60)

    # 4. Process request
    try:
        resp = await call_next(request)
    except Exception as e:
        return security.apply_security_headers(
            JSONResponse(status_code=500, content={"error": "Internal Server Error"})
        )

    # 5. Apply security headers
    return security.apply_security_headers(resp)


# ============================================================
# PUBLIC HEALTH (no auth, no token, for Render probes)
# ============================================================
@app.get("/")
async def root():
    return {"status": "ready" if state.DATA_READY else "loading",
            "service": "vavuubey-secure",
            "version": "4.0.0"}

@app.get("/health")
async def health():
    return {"status": "ok", "ready": state.DATA_READY}

@app.get("/ping")
@app.get("/pong")
async def pp():
    return {"status": "pong", "ready": state.DATA_READY}


# ============================================================
# LIMITED STATUS (no token leak, no db_path)
# ============================================================
@app.get("/api/status")
async def api_status(request: Request):
    # Rate limit
    ip = security.client_ip(request)
    if not security.rate_check(f"status:{ip}", limit=security.RATE_PUBLIC_PER_MIN):
        return security.rate_limit_resp()

    if not state.DATA_READY:
        return {"status": "loading", "ready": False}

    c = get_db()
    try:
        cu = c.cursor()
        cu.execute("SELECT COUNT(*) FROM channels")
        total = cu.fetchone()[0]
        cu.execute("SELECT COUNT(*) FROM categories")
        cats = cu.fetchone()[0]
        cu.execute("SELECT COUNT(*) FROM channels WHERE hls!='' AND hls IS NOT NULL")
        hls = cu.fetchone()[0]
    finally:
        c.close()

    return {
        "status": "ready",
        "ready": True,
        "data_ready": True,
        "available_channels": total,
        "available_categories": cats,
        "hls_channels": hls,
        "load_time": round(state.LOAD_TIME, 1) if state.DATA_READY else None,
    }


# ============================================================
# CHANNEL - Token required
# ============================================================
@app.get("/channel/{sid}")
async def play_ch(sid: str, request: Request):
    # 1. Token check
    if not security.verify_access_token(request):
        return security.forbidden_resp("Token required")
    # 2. Rate limit per IP (channel streaming)
    ip = security.client_ip(request)
    if not security.rate_check(f"channel:{ip}", limit=security.RATE_CHANNEL_PER_MIN):
        return security.rate_limit_resp(60)
    # 3. Validate sid (numeric only - prevents path traversal)
    if not re.match(r'^\d+$', sid):
        return security.forbidden_resp("Invalid channel id")

    url, _ = state.resolve_channel(sid)
    if url:
        return RedirectResponse(url=url, status_code=302)
    raise HTTPException(503, "Channel resolve failed")


# ============================================================
# M3U PLAYLIST - Token required
# ============================================================
@app.get("/get.php")
async def get_m3u(request: Request):
    # 1. Token check (Xtream-style: username/password OR token)
    if not security.verify_access_token(request):
        # Backwards compat: admin/admin no longer works - must use real token
        return security.forbidden_resp("Token required")

    # 2. Rate limit
    ip = security.client_ip(request)
    if not security.rate_check(f"playlist:{ip}", limit=security.RATE_PLAYLIST_PER_MIN):
        return security.rate_limit_resp()

    if not state.DATA_READY:
        return PlainTextResponse(
            "#EXTM3U\n# Service loading, retry in 30s",
            media_type="audio/x-mpegurl",
            status_code=503,
        )

    host = get_host(request)
    c = get_db()
    try:
        cu = c.cursor()
        cu.execute(f"""
            SELECT c.lid, c.name, c.logo,
                   COALESCE(cat.name,'DE SONSTIGE') as gn
            FROM channels c
            LEFT JOIN categories cat ON c.cid = cat.cid
            ORDER BY {ORD}
        """)
        rows = cu.fetchall()
    finally:
        c.close()

    token = security.get_token_from_request(request)
    lines = [f'#EXTM3U url-tvg="{host}/epg.xml?token={token}"']
    for r in rows:
        logo = r["logo"] or ""
        lines.append(
            f'#EXTINF:-1 tvg-id="{r["lid"]}" tvg-logo="{logo}" group-title="{r["gn"]}",{r["name"]}'
        )
        lines.append(f"{host}/channel/{r['lid']}?token={token}")

    return PlainTextResponse(
        "\n".join(lines),
        media_type="audio/x-mpegurl",
    )


# ============================================================
# EPG
# ============================================================
@app.get("/epg.xml")
async def epg(request: Request):
    # Token required
    if not security.verify_access_token(request):
        return security.forbidden_resp("Token required")
    # Rate limit
    ip = security.client_ip(request)
    if not security.rate_check(f"epg:{ip}", limit=30):
        return security.rate_limit_resp()

    x = state.get_epg_data()
    return Response(
        content=x or "<?xml version='1.0'?><tv/>",
        media_type="application/xml",
    )


# ============================================================
# XTREAM API - Token required
# ============================================================
@app.get("/player_api.php")
async def xtream(request: Request, action: str = Query(None)):
    if not security.verify_access_token(request):
        return security.forbidden_resp("Token required")
    ip = security.client_ip(request)
    if not security.rate_check(f"xtream:{ip}", limit=security.RATE_PLAYLIST_PER_MIN):
        return security.rate_limit_resp()

    host = get_host(request)
    c = get_db()
    try:
        cu = c.cursor()
        if action == "get_live_categories":
            cu.execute("SELECT cid as category_id, name as category_name FROM categories ORDER BY sort_order")
            return [dict(r) for r in cu.fetchall()]
        elif action == "get_live_streams":
            cu.execute(f"""
                SELECT c.lid as stream_id, c.name, c.logo as stream_icon,
                       c.cid as category_id,
                       COALESCE(cat.name,'DE SONSTIGE') as category_name
                FROM channels c
                LEFT JOIN categories cat ON c.cid = cat.cid
                ORDER BY {ORD}
            """)
            d = []
            for r in cu.fetchall():
                row = dict(r)
                row["stream_url"] = f"{host}/channel/{row['stream_id']}?token={security.get_token_from_request(request)}"
                d.append(row)
            return d
        else:
            cu.execute("SELECT COUNT(*) FROM channels")
            t = cu.fetchone()[0]
            cu.execute("SELECT COUNT(*) FROM categories")
            ca = cu.fetchone()[0]
            return {
                "user_info": {"username": "user", "status": "Active"},
                "available_channels": t,
                "available_categories": ca,
            }
    finally:
        c.close()


# ============================================================
# RELOAD - Admin token required
# ============================================================
@app.get("/reload")
async def reload(request: Request):
    if not security.verify_admin_token(request):
        return security.forbidden_resp("Admin token required")
    if not security.rate_check(f"reload:{security.client_ip(request)}", limit=2):
        return security.rate_limit_resp(300)

    state.DATA_READY = False
    state.STARTUP_ERROR = None
    state.STARTUP_LOGS.clear()
    state.clear_resolve_cache()

    def do():
        import server
        try:
            server.init_db()
            server.fetch_vavoo_channels()
            server.fetch_hls_links()
            server.remap_groups()
            state.DATA_READY = True
        except Exception as e:
            state.STARTUP_ERROR = str(e)

    threading.Thread(target=do, daemon=True).start()
    return {"status": "reloading", "message": "Yukleniyor..."}


# ============================================================
# ADMIN API - All endpoints require admin token
# ============================================================
@app.get("/api/admin/login")
async def adm_login_check(request: Request):
    """Check if admin token is valid. Returns ok=true/false."""
    return {"ok": security.verify_admin_token(request)}


@app.post("/api/admin/login")
async def adm_login_post(request: Request):
    body = await request.json()
    tok = body.get("token", "").strip()
    if tok and security.secrets.compare_digest(tok, security.ADMIN_TOKEN):
        return {"ok": True, "token": tok}
    return {"ok": False, "error": "Invalid token"}


@app.get("/api/admin/status")
async def adm_status(request: Request):
    if not security.verify_admin_token(request):
        return security.forbidden_resp("Admin token required")
    return {
        "data_ready": state.DATA_READY,
        "load_time": state.LOAD_TIME,
        "startup_error": state.STARTUP_ERROR,
        "startup_logs": state.STARTUP_LOGS[-30:],
        "resolve_cache": state.get_resolve_cache_info(),
        "vavoo_token": bool(state._vavoo_sig),
        "lokke_token": bool(state._watched_sig),
    }


@app.get("/api/admin/groups")
async def adm_groups(request: Request):
    if not security.verify_admin_token(request):
        return security.forbidden_resp("Admin token required")
    c = get_db()
    try:
        cu = c.cursor()
        cu.execute("""
            SELECT cat.cid, cat.name, cat.sort_order,
                   (SELECT COUNT(*) FROM channels WHERE channels.cid=cat.cid) as cnt
            FROM categories cat
            ORDER BY cat.sort_order
        """)
        return {"groups": [
            {"cid": r["cid"], "name": r["name"], "sort_order": r["sort_order"], "count": r["cnt"]}
            for r in cu.fetchall()
        ]}
    finally:
        c.close()


@app.get("/api/admin/channels")
async def adm_ch(request: Request):
    if not security.verify_admin_token(request):
        return security.forbidden_resp("Admin token required")
    c = get_db()
    try:
        cu = c.cursor()
        cu.execute(f"""
            SELECT c.lid, c.name, c.url, c.hls, c.logo, c.cid, c.sort_order,
                   COALESCE(cat.name,'DE SONSTIGE') as grp
            FROM channels c
            LEFT JOIN categories cat ON c.cid = cat.cid
            ORDER BY {ORD}
            LIMIT 200
        """)
        return {"channels": [
            {"lid": r["lid"], "name": r["name"], "grp": r["grp"], "cid": r["cid"],
             "sort_order": r["sort_order"], "logo": r["logo"] or "",
             "url": r["url"] or "", "has_hls": bool(r["hls"])}
            for r in cu.fetchall()
        ]}
    finally:
        c.close()


@app.post("/api/admin/cache/clear")
async def adm_cache(request: Request):
    if not security.verify_admin_token(request):
        return security.forbidden_resp("Admin token required")
    state.clear_resolve_cache()
    return {"ok": True}


@app.get("/api/admin/resolve/{sid}")
async def adm_resolve(sid: str, request: Request):
    if not security.verify_admin_token(request):
        return security.forbidden_resp("Admin token required")
    if not re.match(r'^\d+$', sid):
        return security.forbidden_resp("Invalid channel id")
    url, method = state.resolve_channel(sid)
    return {
        "channel_id": sid,
        "resolve_method": method,
        "resolved_url": url,
        "success": bool(url),
        "resolve_cache": state.get_resolve_cache_info(),
    }


# ============================================================
# ADMIN PANEL - HTML page, token entered via form
# ============================================================
@app.get("/admin")
async def admin_page():
    return HTMLResponse(ADMIN_HTML)


# ============================================================
# ADMIN HTML (mobile-friendly, no inline token)
# ============================================================
ADMIN_HTML = r"""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=5,user-scalable=yes">
<title>vavuubey-secure</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--p:#8957e5;--g:#3fb950;--r:#f85149;--y:#d29922;--b:#58a6ff;--t:#e6edf3;--d:#8b949e}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--t);font-size:14px;-webkit-tap-highlight-color:transparent}

.top{background:var(--card);padding:14px 16px;display:flex;align-items:center;gap:10px;border-bottom:1px solid var(--border);position:sticky;top:0;z-index:50}
.top h1{font-size:15px;font-weight:800;background:linear-gradient(135deg,var(--p),#c084fc);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.top .v{font-size:10px;color:var(--d);margin-left:auto}

.wrap{padding:14px;max-width:800px;margin:0 auto}

.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:14px;margin-bottom:10px}
.card h2{font-size:13px;font-weight:700;color:var(--b);margin-bottom:10px;text-transform:uppercase;letter-spacing:.5px}

input{width:100%;padding:11px 12px;border-radius:8px;border:1px solid var(--border);background:var(--bg);color:var(--t);font-size:14px;outline:none;-webkit-appearance:none}
input:focus{border-color:var(--p)}

.btn{padding:11px 14px;border-radius:8px;border:1px solid var(--p);background:var(--p);color:#fff;font-size:13px;font-weight:600;cursor:pointer;width:100%;margin-top:8px}
.btn:active{opacity:.8}

.stat{display:grid;grid-template-columns:repeat(3,1fr);gap:6px;margin:8px 0}
.st{text-align:center;padding:10px 4px;border-radius:8px;background:var(--bg);border:1px solid var(--border)}
.st b{display:block;font-size:18px;font-weight:800}
.st small{font-size:9px;color:var(--d);text-transform:uppercase;letter-spacing:.5px}
.c-g{color:var(--g)}.c-r{color:var(--r)}.c-y{color:var(--y)}.c-b{color:var(--b)}.c-p{color:var(--p)}

.row{display:flex;align-items:center;gap:8px;padding:8px 0;border-bottom:1px solid var(--border);font-size:12px}
.row:last-child{border-bottom:none}
.row .l{color:var(--d);width:120px}
.row .v{flex:1;font-weight:600;word-break:break-all}
.dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.dot.ok{background:var(--g);box-shadow:0 0 6px #3fb95060}
.dot.no{background:var(--r)}
.dot.ld{background:var(--y);animation:p 1.5s infinite}
@keyframes p{0%,100%{opacity:1}50%{opacity:.3}}

pre{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:10px;font-size:10px;overflow-x:auto;max-height:300px;overflow-y:auto;color:var(--d);font-family:ui-monospace,'SF Mono',Consolas,monospace}

.url-box{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:10px;font-size:11px;word-break:break-all;color:var(--g);font-family:ui-monospace,Consolas,monospace;margin:6px 0;cursor:pointer}
.url-box:active{border-color:var(--p)}
.toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:var(--g);color:#000;padding:10px 20px;border-radius:8px;font-size:12px;font-weight:600;z-index:100;opacity:0;transition:opacity .3s}
.toast.show{opacity:1}

.hidden{display:none}
</style>
</head>
<body>
<div class="top">
  <h1>vavuubey-secure</h1>
  <span class="v">v4.0</span>
</div>
<div class="wrap">

  <!-- LOGIN -->
  <div id="loginCard" class="card">
    <h2>Admin Token</h2>
    <input type="password" id="tokInput" placeholder="admin token" autocomplete="off">
    <button class="btn" onclick="login()">Giris</button>
  </div>

  <!-- DASHBOARD -->
  <div id="dashCard" class="card hidden">
    <h2>Durum</h2>
    <div class="stat">
      <div class="st"><b id="ch_count" class="c-p">-</b><small>Kanal</small></div>
      <div class="st"><b id="grp_count" class="c-b">-</b><small>Grup</small></div>
      <div class="st"><b id="hls_count" class="c-g">-</b><small>HLS</small></div>
    </div>
    <div class="row"><span class="l">Vavoo Token</span><span class="v" id="vav_t"><span class="dot no"></span></span></div>
    <div class="row"><span class="l">Lokke Token</span><span class="v" id="lok_t"><span class="dot no"></span></span></div>
    <div class="row"><span class="l">Veri Hazir</span><span class="v" id="ready"><span class="dot ld"></span></span></div>
    <div class="row"><span class="l">Cache Hit/Miss</span><span class="v" id="cache">-</span></div>
    <div class="row"><span class="l">Yukleme Suresi</span><span class="v" id="load_time">-</span></div>
  </div>

  <!-- URLS -->
  <div id="urlCard" class="card hidden">
    <h2>Erisim URL'leri</h2>
    <small style="color:var(--d);font-size:10px">Playlist (VLC/IPTV player):</small>
    <div class="url-box" id="playlist_url">-</div>
    <small style="color:var(--d);font-size:10px">Xtream API:</small>
    <div class="url-box" id="xtream_url">-</div>
    <small style="color:var(--d);font-size:10px">EPG:</small>
    <div class="url-box" id="epg_url">-</div>
    <button class="btn" onclick="copyUrls()">Tum URL'leri Kopyala</button>
  </div>

  <!-- GROUPS -->
  <div id="grpCard" class="card hidden">
    <h2>Gruplar</h2>
    <div id="groups"></div>
  </div>

  <!-- LOGS -->
  <div id="logCard" class="card hidden">
    <h2>Baslangic Loglari</h2>
    <pre id="logs">Yukleniyor...</pre>
  </div>

  <!-- ACTIONS -->
  <div id="actCard" class="card hidden">
    <h2>Islemler</h2>
    <button class="btn" onclick="reload()">Yeniden Yukle</button>
    <button class="btn" onclick="clearCache()" style="border-color:var(--y);background:var(--y);margin-top:6px">Cache Temizle</button>
  </div>

</div>
<div class="toast" id="toast"></div>

<script>
let TOK = localStorage.getItem('admin_tok') || '';
const API = location.origin;

async function api(path, opts={}) {
  const r = await fetch(API + path, {
    ...opts,
    headers: { 'Authorization': 'Bearer ' + TOK, ...(opts.headers||{}) }
  });
  return r.json();
}

async function login() {
  const t = document.getElementById('tokInput').value.trim();
  if (!t) return;
  TOK = t;
  const r = await api('/api/admin/login', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({token:t}) });
  if (r.ok) {
    localStorage.setItem('admin_tok', TOK);
    showDash();
  } else {
    showToast('Hatali token');
    TOK = '';
  }
}

async function showDash() {
  document.getElementById('loginCard').classList.add('hidden');
  document.getElementById('dashCard').classList.remove('hidden');
  document.getElementById('urlCard').classList.remove('hidden');
  document.getElementById('grpCard').classList.remove('hidden');
  document.getElementById('logCard').classList.remove('hidden');
  document.getElementById('actCard').classList.remove('hidden');
  refresh();
  // auto refresh every 15s
  setInterval(refresh, 15000);
}

async function refresh() {
  try {
    const s = await api('/api/admin/status');
    document.getElementById('ready').innerHTML = s.data_ready
      ? '<span class="dot ok"></span> Hazir'
      : '<span class="dot ld"></span> Yukleniyor';
    document.getElementById('vav_t').innerHTML = s.vavoo_token ? '<span class="dot ok"></span> OK' : '<span class="dot no"></span> Yok';
    document.getElementById('lok_t').innerHTML = s.lokke_token ? '<span class="dot ok"></span> OK' : '<span class="dot no"></span> Yok';
    document.getElementById('cache').textContent = (s.resolve_cache?.hits||0) + '/' + (s.resolve_cache?.misses||0);
    document.getElementById('load_time').textContent = s.load_time ? s.load_time.toFixed(1)+'s' : '-';
    document.getElementById('logs').textContent = (s.startup_logs||[]).join('\n');

    // Playlist URL - need access token from query/header. Admin uses /get.php?token=
    // We need to pass admin token as access token for the playlist URL since both are separate.
    // For simplicity, use admin token for both. (User can regenerate access token separately if needed)
    const host = location.origin;
    document.getElementById('playlist_url').textContent = host + '/get.php?token=' + TOK;
    document.getElementById('xtream_url').textContent = host + '/player_api.php?token=' + TOK;
    document.getElementById('epg_url').textContent = host + '/epg.xml?token=' + TOK;

    // Status counts
    const st = await api('/api/status');
    document.getElementById('ch_count').textContent = st.available_channels || 0;
    document.getElementById('grp_count').textContent = st.available_categories || 0;
    document.getElementById('hls_count').textContent = st.hls_channels || 0;

    // Groups
    const g = await api('/api/admin/groups');
    document.getElementById('groups').innerHTML = (g.groups||[]).map(x =>
      `<div class="row"><span class="l">${x.name}</span><span class="v">${x.count} kanal</span></div>`
    ).join('');
  } catch(e) {
    console.error(e);
  }
}

async function reload() {
  if (!confirm('Yeniden yuklensin mi?')) return;
  await api('/reload');
  showToast('Yukleniyor...');
}
async function clearCache() {
  await api('/api/admin/cache/clear', { method:'POST' });
  showToast('Cache temizlendi');
}
function copyUrls() {
  const urls = [
    'Playlist: ' + document.getElementById('playlist_url').textContent,
    'Xtream: ' + document.getElementById('xtream_url').textContent,
    'EPG: ' + document.getElementById('epg_url').textContent
  ].join('\n');
  navigator.clipboard.writeText(urls);
  showToast('Kopyalandi');
}
function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'), 2000);
}

// Auto-login if token in storage
if (TOK) showDash();
</script>
</body>
</html>
"""
