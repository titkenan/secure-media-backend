"""
security.py - Guvenlik katmani
- ACCESS_TOKEN: playlist & channel erisimi (URL ?token=xxx)
- ADMIN_TOKEN: admin panel & API
- Rate limiting (slowapi)
- Security headers
- Bot UA filter
- CORS restriction
"""
import os
import re
import time
import secrets
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse

# ============================================================
# TOKENS - Environment variables
# ============================================================
ACCESS_TOKEN = os.environ.get("ACCESS_TOKEN", "").strip()
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "").strip()

# Auto-generate access token if missing (will be logged once)
if not ACCESS_TOKEN:
    ACCESS_TOKEN = "auto_" + secrets.token_urlsafe(24)
    print(f"[SECURITY] WARNING: ACCESS_TOKEN not set, auto-generated: {ACCESS_TOKEN}")

if not ADMIN_TOKEN:
    ADMIN_TOKEN = "auto_" + secrets.token_urlsafe(24)
    print(f"[SECURITY] WARNING: ADMIN_TOKEN not set, auto-generated: {ADMIN_TOKEN}")


# ============================================================
# RATE LIMIT CONFIG
# ============================================================
RATE_PLAYLIST_PER_MIN = 30      # /get.php, /player_api.php
RATE_CHANNEL_PER_MIN = 600      # /channel/{sid} (VLC reloads segments fast)
RATE_ADMIN_PER_MIN = 20         # /api/admin/*, /admin
RATE_PUBLIC_PER_MIN = 60        # /, /ping, /health


# ============================================================
# BOT / SCANNER UA FILTER (block known bots, allow VLC/Kodi/mpv/IPTV)
# ============================================================
BOT_UA_PATTERNS = [
    r"bot", r"crawler", r"spider", r"scanner", r"curl", r"wget",
    r"python-requests", r"httpx", r"axios", r"node-fetch",
    r"nikto", r"sqlmap", r"nmap", r"masscan", r"zgrab",
    r"go-http-client", r"java/", r"okhttp/(?![0-9])",  # okhttp numeric = legit
]

ALLOWED_PLAYER_UA = [
    r"vlc", r"kodi", r"mpv", r"ffmpeg", r"lavf/",  # players
    r"iptv", r"perfect", r"player", r"tivimate", r"setiptv",
    r"siptv", r"gse", r"ottplayer", r"ss iptv",
    r"netflix", r"disney", r"exoplayer", r"mediaplayer",
    r"hls", r"m3u8", r"mozilla", r"safari", r"chrome",  # browsers
]

BOT_RE = re.compile("|".join(BOT_UA_PATTERNS), re.IGNORECASE)
PLAYER_RE = re.compile("|".join(ALLOWED_PLAYER_UA), re.IGNORECASE)


def is_bot_ua(ua: str) -> bool:
    """True if UA looks like a scanner/bot. Allows players and browsers."""
    if not ua or len(ua) < 5:
        return True
    if BOT_RE.search(ua):
        # Could be a real browser embedding "bot" string? Double-check.
        if PLAYER_RE.search(ua):
            return False
        return True
    return False


# ============================================================
# TOKEN VERIFICATION HELPERS
# ============================================================
def get_token_from_request(r: Request) -> str:
    """Extract access token from query (?token=) or header (Authorization: Bearer)."""
    # 1. Query string
    tok = r.query_params.get("token")
    if tok:
        return tok.strip()
    # 2. Basic auth (username:password format used by Xtream players)
    auth = r.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    # 3. Cookie
    ck = r.cookies.get("access_token")
    if ck:
        return ck
    return ""


def verify_access_token(r: Request) -> bool:
    """For playlist + channel endpoints. Token can be in ?token= OR basic auth."""
    tok = get_token_from_request(r)
    if not tok:
        return False
    # Constant-time compare
    return secrets.compare_digest(tok, ACCESS_TOKEN)


def verify_admin_token(r: Request) -> bool:
    """For admin API. Token in Authorization header or ?admin_token=."""
    # 1. Header
    auth = r.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        tok = auth[7:].strip()
        if secrets.compare_digest(tok, ADMIN_TOKEN):
            return True
    # 2. Query
    tok = r.query_params.get("admin_token", "").strip()
    if tok and secrets.compare_digest(tok, ADMIN_TOKEN):
        return True
    # 3. X-Admin-Token header
    tok = r.headers.get("x-admin-token", "").strip()
    if tok and secrets.compare_digest(tok, ADMIN_TOKEN):
        return True
    return False


# ============================================================
# SECURITY HEADERS
# ============================================================
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store, no-cache, must-revalidate",
    "Server": "vavuubey-secure",
}


def apply_security_headers(resp):
    """Attach security headers to any response."""
    for k, v in SECURITY_HEADERS.items():
        resp.headers[k] = v
    return resp


# ============================================================
# ERROR RESPONSES
# ============================================================
def forbidden_resp(message: str = "Forbidden"):
    return JSONResponse(
        status_code=403,
        content={"error": message, "code": 403},
        headers=SECURITY_HEADERS,
    )


def rate_limit_resp(retry_after: int = 60):
    return JSONResponse(
        status_code=429,
        content={"error": "Too Many Requests", "retry_after": retry_after},
        headers={**SECURITY_HEADERS, "Retry-After": str(retry_after)},
    )


def not_found_resp():
    return JSONResponse(
        status_code=404,
        content={"error": "Not Found"},
        headers=SECURITY_HEADERS,
    )


# ============================================================
# IN-MEMORY RATE LIMITER (simple sliding window)
# Used as backup if slowapi fails
# ============================================================
_rate_buckets = {}  # {key: [(timestamp, ...), ...]}
_rate_lock = __import__("threading").Lock()


def rate_check(key: str, limit: int, window_sec: int = 60) -> bool:
    """Returns True if allowed, False if rate-limited. Sliding window."""
    now = time.time()
    cutoff = now - window_sec
    with _rate_lock:
        bucket = _rate_buckets.get(key, [])
        # Drop old entries
        bucket = [t for t in bucket if t > cutoff]
        if len(bucket) >= limit:
            _rate_buckets[key] = bucket
            return False
        bucket.append(now)
        _rate_buckets[key] = bucket
        return True


def client_ip(r: Request) -> str:
    """Get real client IP (behind Render proxy)."""
    xf = r.headers.get("x-forwarded-for", "")
    if xf:
        return xf.split(",")[0].strip()
    xr = r.headers.get("x-real-ip", "")
    if xr:
        return xr.strip()
    return r.client.host if r.client else "unknown"


# ============================================================
# TOKEN PUBLIC EXPORT (for server start logging)
# ============================================================
def get_tokens_for_log():
    return {
        "access_token": ACCESS_TOKEN,
        "admin_token": ADMIN_TOKEN,
        "access_token_preview": ACCESS_TOKEN[:8] + "..." + ACCESS_TOKEN[-4:] if len(ACCESS_TOKEN) > 12 else ACCESS_TOKEN,
        "admin_token_preview": ADMIN_TOKEN[:8] + "..." + ADMIN_TOKEN[-4:] if len(ADMIN_TOKEN) > 12 else ADMIN_TOKEN,
    }
