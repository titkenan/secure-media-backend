"""
state.py - Ortak state modulu (vavuubey-secure fork)
- Token yonetimi (vavoo + lokke)
- HLS resolve (multi-tier fallback)
- Catalog fetch
- EPG data
- Grup siralama ve kurallari (DE SONSTIGE azaltmak icin genisletildi)

v4.0 - Bağımsız fork, güvenlik katmanı entegre
"""
import os
import random
import time
import json
import sqlite3
import requests
import urllib3
import threading

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ============================================================
# CONFIG
# ============================================================
CONFIG = {
    "PING_URLS": [
        "https://www.vavoo.tv/api/app/ping",
        "https://www.lokke.app/api/app/ping",
    ],
    "BASE_URLS": [
        "https://vavoo.to",
        "https://kool.to",
        "https://oha.to",
    ],
    "PING2_URLS": [
        "https://www.vavoo.tv/api/box/ping2",
    ],
    "LIVE2_URLS": [
        "https://www.vavoo.to/live2/index?output=json",
        "https://kool.to/live2/index?output=json",
        "https://oha.to/live2/index?output=json",
    ],
    "LOGO_BASE_URLS": [
        "https://www.vavoo.to",
        "https://vavoo.to",
    ],
    "SIG_CACHE_TTL": 8 * 60,
    "SIG_FAIL_TTL": 3 * 60,
    "RESOLVE_CACHE_TTL": 45 * 60,
    "RESOLVE_TIMEOUT": 15,
    "CDN_USER_AGENT": "VAVOO/2.6",
    "API_USER_AGENT": "MediaHubMX/2",
    "APP_VERSION": "3.0.2",
}


# ============================================================
# PAYLASILAN STATE
# ============================================================
DATA_READY = False
STARTUP_ERROR = None
LOAD_TIME = 0
STARTUP_LOGS = []

DB_PATH = os.environ.get("DB_PATH", "/tmp/vxparser.db")
M3U_PATH = os.environ.get("M3U_PATH", "/tmp/playlist.m3u")
# Defensive: PORT env might be set to wrong value (e.g. path string). Fall back to 10000.
try:
    _port_raw = os.environ.get("PORT", "10000")
    PORT = int(_port_raw) if str(_port_raw).isdigit() else 10000
except (ValueError, TypeError):
    PORT = 10000

_vavoo_sig = None
_vavoo_sig_time = 0
_vavoo_sig_failed = False
_watched_sig = None
_watched_sig_time = 0
_watched_sig_failed = False

_resolve_cache = {}
_resolve_cache_lock = threading.Lock()
_resolve_stats = {"hits": 0, "misses": 0, "expired": 0, "errors": 0}

_last_force_sig_time = 0
FORCE_SIG_MIN_INTERVAL = 30


def get_resolve_cache_info():
    now = time.time()
    active = expired = 0
    with _resolve_cache_lock:
        for entry in _resolve_cache.values():
            if (now - entry["time"]) < CONFIG["RESOLVE_CACHE_TTL"]:
                active += 1
            else:
                expired += 1
    return {"total": len(_resolve_cache), "active": active, "expired": expired,
            "hits": _resolve_stats["hits"], "misses": _resolve_stats["misses"]}


def clear_resolve_cache():
    with _resolve_cache_lock:
        _resolve_cache.clear()
        _resolve_stats["hits"] = _resolve_stats["misses"] = _resolve_stats["expired"] = _resolve_stats["errors"] = 0


def slog(msg):
    ts = time.strftime("%H:%M:%S")
    entry = f"[{ts}] {msg}"
    STARTUP_LOGS.append(entry)
    print(entry)


# ============================================================
# 1. VAVOO TOKEN (ping2)
# ============================================================
def get_auth_signature():
    global _vavoo_sig, _vavoo_sig_time, _vavoo_sig_failed
    if _vavoo_sig and (time.time() - _vavoo_sig_time) < CONFIG["SIG_CACHE_TTL"]:
        return _vavoo_sig
    if _vavoo_sig_failed and (time.time() - _vavoo_sig_time) < CONFIG["SIG_FAIL_TTL"]:
        return None

    slog("Vavoo Token (ping2) aliniyor...")
    headers = {"User-Agent": CONFIG["CDN_USER_AGENT"], "Accept": "application/json", "Content-Type": "application/json"}
    try:
        vec_req = requests.get("http://mastaaa1987.github.io/repo/veclist.json", headers=headers, timeout=10, verify=False)
        veclist = vec_req.json()["value"]
        slog(f"  veclist: {len(veclist)} vec")
        sig = None
        for ping_url in CONFIG["PING2_URLS"]:
            if sig:
                break
            for _ in range(5):
                vec = {"vec": random.choice(veclist)}
                try:
                    req = requests.post(ping_url, json=vec, headers=headers, timeout=10, verify=False).json()
                    signed = req.get("response", {}).get("signed") or req.get("signed")
                    if signed:
                        sig = signed
                        slog(f"  Token alindi: {ping_url}")
                        break
                except Exception:
                    continue
        _vavoo_sig_time = time.time()
        if sig:
            _vavoo_sig = sig
            _vavoo_sig_failed = False
            slog("Vavoo Token alindi!")
            return sig
        else:
            _vavoo_sig = None
            _vavoo_sig_failed = True
            slog(f"Vavoo Token ALINAMADI ({CONFIG['SIG_FAIL_TTL']}s bekleyecek)")
    except Exception as e:
        _vavoo_sig = None
        _vavoo_sig_failed = True
        _vavoo_sig_time = time.time()
        slog(f"Vavoo Token HATASI: {e}")
    return None


# ============================================================
# 2. ADDONSIG (app/ping)
# ============================================================
def get_watchedsig(force=False):
    global _watched_sig, _watched_sig_time, _watched_sig_failed, _last_force_sig_time

    if force:
        now = time.time()
        elapsed = now - _last_force_sig_time
        if elapsed < FORCE_SIG_MIN_INTERVAL:
            if _watched_sig:
                return _watched_sig
            return None
        _last_force_sig_time = now

    if not force and _watched_sig and (time.time() - _watched_sig_time) < CONFIG["SIG_CACHE_TTL"]:
        return _watched_sig
    if not force and _watched_sig_failed and (time.time() - _watched_sig_time) < CONFIG["SIG_FAIL_TTL"]:
        return None

    tag = " (FORCE)" if force else ""
    slog(f"addonSig aliniyor{tag}...")
    headers = {"user-agent": "okhttp/4.11.0", "accept": "application/json", "content-type": "application/json; charset=utf-8"}
    data = {
        "token": "", "reason": "boot", "locale": "de", "theme": "dark",
        "metadata": {
            "device": {"type": "desktop", "uniqueId": ""},
            "os": {"name": "linux", "version": "Ubuntu 22.04", "abis": ["x64"], "host": "RENDER"},
            "app": {"platform": "electron"},
            "version": {"package": "app.lokke.main", "binary": "1.0.19", "js": "1.0.19"},
        },
        "appFocusTime": 173, "playerActive": False, "playDuration": 0,
        "devMode": True, "hasAddon": True, "castConnected": False,
        "package": "app.lokke.main", "version": "1.0.19", "process": "app",
        "firstAppStart": int(time.time() * 1000) - 10000,
        "lastAppStart": int(time.time() * 1000) - 10000,
        "ipLocation": 0, "adblockEnabled": True,
        "proxy": {"supported": ["ss"], "engine": "cu", "enabled": False, "autoServer": True, "id": 0},
        "iap": {"supported": False},
    }
    for ping_url in CONFIG["PING_URLS"]:
        try:
            resp = requests.post(ping_url, json=data, headers=headers, timeout=15, verify=False)
            result = resp.json()
            sig = result.get("addonSig")
            if sig:
                _watched_sig = sig
                _watched_sig_time = time.time()
                _watched_sig_failed = False
                slog(f"  addonSig alindi{tag}: {ping_url}")
                return sig
        except Exception:
            continue
    _watched_sig = None
    _watched_sig_failed = True
    _watched_sig_time = time.time()
    slog(f"addonSig ALINAMADI ({CONFIG['SIG_FAIL_TTL']}s bekleyecek)")
    return None


# ============================================================
# 3. HLS RESOLVE
# ============================================================
def resolve_hls_link(link, force_sig=False):
    sig = get_watchedsig(force=force_sig)
    if not sig:
        slog("  Resolve: addonSig yok")
        return None

    headers = {
        "user-agent": "MediaHubMX/2",
        "accept": "application/json",
        "content-type": "application/json; charset=utf-8",
        "accept-encoding": "gzip",
        "mediahubmx-signature": sig,
    }
    data = {"language": "de", "region": "AT", "url": link, "clientVersion": CONFIG["APP_VERSION"]}

    last_error = ""
    for base in CONFIG["BASE_URLS"]:
        try:
            url = f"{base}/mediahubmx-resolve.json"
            r = requests.post(url, data=json.dumps(data), headers=headers, timeout=CONFIG["RESOLVE_TIMEOUT"], verify=False)
            if r.status_code != 200:
                last_error = f"{r.status_code}: {r.text[:100]}"
                continue
            result = r.json()
            if result and isinstance(result, list) and len(result) > 0:
                resolved = result[0].get("url")
                if resolved:
                    return resolved
            elif isinstance(result, dict):
                last_error = result.get("error", "empty dict")
            else:
                last_error = f"unexpected: {str(result)[:80]}"
        except Exception as e:
            last_error = str(e)[:100]
            continue
    if last_error and not force_sig:
        slog(f"  Resolve HATA: {last_error[:120]}")
    return None


# ============================================================
# 4. CHANNEL RESOLVE
# ============================================================
def resolve_channel(lid):
    now = time.time()
    with _resolve_cache_lock:
        if lid in _resolve_cache:
            entry = _resolve_cache[lid]
            if (now - entry["time"]) < CONFIG["RESOLVE_CACHE_TTL"]:
                _resolve_stats["hits"] += 1
                return entry["url"], f"CACHE ({entry['method']}): {entry['name']}"
            else:
                _resolve_stats["expired"] += 1

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM channels WHERE lid=?", (lid,))
    ch = c.fetchone()
    conn.close()
    if not ch:
        return None, "Kanal bulunamadi"

    name = ch["name"]
    url = ch["url"]
    hls = ch["hls"]

    if hls:
        resolved = resolve_hls_link(hls)
        if not resolved:
            resolved = resolve_hls_link(hls, force_sig=True)
        if resolved:
            _cache_resolve(lid, resolved, "Y1-HLS", name)
            return resolved, f"Y1-HLS: {name}"

    if hls and hls.startswith("http"):
        return hls, f"Y0-Direct: {name}"

    if url:
        sig = get_auth_signature()
        if sig:
            sep = "&" if "?" in url else "?"
            final = url + sep + "n=1&b=5&vavoo_auth=" + sig
            _cache_resolve(lid, final, "Y2-Auth", name)
            return final, f"Y2-Auth: {name}"

    if url:
        resolved = resolve_hls_link(url)
        if not resolved:
            resolved = resolve_hls_link(url, force_sig=True)
        if resolved:
            _cache_resolve(lid, resolved, "Y3-Resolve", name)
            return resolved, f"Y3-Resolve: {name}"

    if url:
        _resolve_stats["errors"] += 1
        return url, f"Y4-Direct: {name}"

    return None, "URL/HLS yok"


def _cache_resolve(lid, url, method, name):
    with _resolve_cache_lock:
        _resolve_cache[lid] = {"url": url, "method": method, "name": name, "time": time.time()}
        if len(_resolve_cache) > 5000:
            oldest = min(_resolve_cache, key=lambda k: _resolve_cache[k]["time"])
            del _resolve_cache[oldest]


# ============================================================
# 5. CATALOG FETCH
# ============================================================
def fetch_catalog(sig, group_name):
    headers = {
        "accept-encoding": "gzip",
        "user-agent": "MediaHubMX/2",
        "accept": "application/json",
        "content-type": "application/json; charset=utf-8",
        "mediahubmx-signature": sig,
    }
    data = {
        "language": "de", "region": "AT",
        "catalogId": "iptv", "id": "iptv",
        "adult": False, "search": "", "sort": "name",
        "filter": {"group": group_name},
        "cursor": 0,
        "clientVersion": CONFIG["APP_VERSION"],
    }

    all_items = []
    for base in CONFIG["BASE_URLS"]:
        if all_items:
            break
        try:
            url = f"{base}/mediahubmx-catalog.json"
            resp = requests.post(url, data=json.dumps(data), headers=headers, timeout=20, verify=False)
            if resp.status_code != 200:
                slog(f"  Catalog {resp.status_code} ({base}): {resp.text[:150]}")
                continue
            catalog_data = resp.json()
            items = catalog_data.get("items", [])
            if items:
                all_items.extend(items)
                slog(f"  Catalog OK: {base} ({len(items)} kayit)")
                next_cursor = catalog_data.get("nextCursor")
                page = 1
                while next_cursor:
                    page += 1
                    data["cursor"] = next_cursor
                    try:
                        resp2 = requests.post(url, data=json.dumps(data), headers=headers, timeout=20, verify=False)
                        cd2 = resp2.json()
                        items2 = cd2.get("items", [])
                        if items2:
                            all_items.extend(items2)
                            slog(f"  Catalog sayfa {page}: +{len(items2)} kayit")
                        next_cursor = cd2.get("nextCursor")
                    except Exception as e:
                        slog(f"  Catalog sayfa {page} HATA: {str(e)[:60]}")
                        break
                break
            else:
                err_msg = catalog_data.get("error", "")
                slog(f"  Catalog bos ({base}): {err_msg}")
        except Exception as e:
            slog(f"  Catalog HATA ({base}): {str(e)[:80]}")

    return all_items


# ============================================================
# 6. EPG DATA (XMLTV) - minimal
# ============================================================
def get_epg_data():
    from datetime import datetime, timedelta
    import xml.etree.ElementTree as ET
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT lid, name, grp FROM channels ORDER BY lid")
        channels = c.fetchall()
        conn.close()
        tv = ET.Element("tv")
        tv.set("generator-info-name", "vavuubey-secure")
        now = datetime.utcnow()
        for ch in channels:
            ch_el = ET.SubElement(tv, "channel")
            ch_el.set("id", str(ch["lid"]))
            ET.SubElement(ch_el, "display-name").text = ch["name"]
            prog = ET.SubElement(tv, "programme")
            prog.set("start", now.strftime("%Y%m%d%H%M%S") + " +0000")
            prog.set("stop", (now + timedelta(hours=6)).strftime("%Y%m%d%H%M%S") + " +0000")
            prog.set("channel", str(ch["lid"]))
            ET.SubElement(prog, "title").text = ch["name"]
            ET.SubElement(prog, "desc").text = f"{ch['name']} - Live"
        return ET.tostring(tv, encoding="unicode", xml_declaration=True)
    except Exception as e:
        slog(f"EPG HATASI: {e}")
        return None


# ============================================================
# LOGO URL DÜZELTME - vavuubey_secure eklenti
# ============================================================
def normalize_logo_url(logo: str) -> str:
    """Convert /live2/logo/... path to full https URL. Empty stays empty."""
    if not logo:
        return ""
    # Already full URL?
    if logo.startswith("http://") or logo.startswith("https://"):
        return logo
    # Relative path - prefix with vavoo.to
    if logo.startswith("/"):
        return CONFIG["LOGO_BASE_URLS"][0] + logo
    # Bare filename - assume live2/logo/
    return CONFIG["LOGO_BASE_URLS"][0] + "/live2/logo/" + logo


# ============================================================
# GRUP SIRALAMASI - VPS reisomer yapısı birebir (44 grup)
# VPS'deki custom_groups tablosundan çekildi (sort_order ile)
# ============================================================
GROUP_ORDER = [
    # TR grupları (sort_order 0-23)
    "Ulusal", "BeinSport", "Sinema", "Haber", "Belgesel",
    "Spor", "Çocuk", "Avrupa", "Dini", "Diğer",
    "Magenta", "Müzik", "TR YEREL",
    # DE grupları (sort_order 8-27)
    "DE FILM", "DE DOKU", "DE SPORT", "DE AUTO MOTOR", "DE KINDER",
    "DE LIFESTYLE", "DE NACHRICHTEN", "DE REGIONAL", "DE SONSTIGE",
    "DE VOLLPROGRAMM", "DE SERIEN", "DE EINKAUF", "DE MUSIK", "DE PARLAMENT",
    # VPS'de ek gruplar (boş ama yapı korunsun)
    "TR ULUSAL", "BEIN VOD", "TR SPOR", "TR SINEMA", "TR SINEMA VOD",
    "TR DIZI", "TR 7/24 DIZI", "TR BELGESEL", "TR COCUK", "TR MUZIK",
    "TR HABER", "TR DINI", "TR RADYO", "TR 4K", "TR 8K", "TR RAW",
    "Ulusal 4K",
]

# VPS reisomer yapısı ile uyumlu grup kuralları
# Kanal isimlerindeki keyword'lere göre grup atama
# VPS'deki custom_grp alanındaki isimler kullanılır
GROUP_RULES = {
    # ===== TÜRKIYE GRUPLARI (VPS yapısı) =====
    "Ulusal": [
        "TRT 1","Show TV","Star TV","ATV","Kanal D","FOX TV","TV8","Tele1","Beyaz TV",
        "TV 8.5","A2","TRT 4K","Tabii","Gain","TV 100","Flash TV","Kanal 7","TGRT",
        "TLC","D MAX","ERT","TVNET","24 TV","360","360 TV","Ekoturk","Bloomberg HT",
        "Ekol TV","Kanal 24","Tele 1","UcanKus","TVem","NOW TV","NOW","Halk TV","ULKE TV",
        "Ulusal Kanal","TV 41","TV 52","TV 4","TV 5","TV 6","Kanal 23","Kanal 26",
        "Kanal 32","Kanal 33","Kanal 34","Kanal 38","Kanal 58","Kanal 68","Kanal 78",
        "Vavoo TV","Mavi Karadeniz","DHA","Gunaydin TV","Kanal 16","Kanal 26","Kanal T",
        "TV 100","Show Max","Show Turk","Ciftci TV","Damla TV","Ekin TV","Ege TV",
        "4K TR: TRT 1","4K TR: SHOW","4K TR: STAR","4K TR: ATV","4K TR: KANAL D",
        "4K TR: FOX","4K TR: TV8","4K TR: BEYAZ","4K TR: TELE 1","4K TR: TV 100",
    ],
    "BeinSport": [
        "beIN Sports","beIN SPORT","beIN","beIN 4K","beIN MAX","Bein Sports","BEIN SPORTS",
        "BeIN","BEIN","beINSP","beIN 1","beIN 2","beIN 3","beIN 4","beIN 5",
        "BEIN SPORTS 4K","BEIN SPORTS 1","BEIN SPORTS 2","BEIN SPORTS 3","BEIN SPORTS 4",
    ],
    "Sinema": [
        "Film","Sinema","Cinema","Movie","Movies","DigiMAX","FilmBox","Magic Box",
        "Yesilcam","Dream TV","MovieSmart","MovieMax","Movie Gold","Movie Platinum",
        "Sinema TV","Sinema 2","Sinema 1001","Sinema Aile","Sinema Aksiyon","Sinema Komedi",
        "Sinema TV 1","Sinema TV 2","Salon","FX","FX Life","beIN Movies","beIN Movies Premiere",
        "beIN Movies Stars","beIN Movies Turk","beIN Movies Action","beIN Movies Family",
        "beIN Movies Festival","beIN Premier","beIN Stars","beIN Action","beIN Comedy",
        "beIN Drama","beIN Family","beIN Festival","beIN Hemen","beIN Movies 2","beIN Series",
        "beIN Series Comedy","beIN Series Drama","beIN Series Sci-Fi","beIN Series Vice",
        "beIN Series Walker","beIN Gurme","Tivibu Sinema","Tivibu Sinema 1","Tivibu Sinema 2",
        "Tivibu Sinema 3","Tivibu Vizyon","D-Smart Smart Sinema","Dizi","Teve2","Televizyon",
        "PROTURK","SALON","REAL BOX","SMART BOX","MAX","DREAM BOX","ARENA BOX","CINE",
        "MOVIESMART","MOVIE","DIZI","LOCA","VIZYON","ORJINAL","WESTERN","KEMAL SUNAL",
        "YESILCAM","GERILIM","KORKU","MACERA","FANTASTIC","BILIM KURGU","YEŞILÇAM",
    ],
    "Haber": [
        "Haber","CNN Turk","HABER","NTV","TRT Haber","Bloomberg","A Haber","Benguturk",
        "Haber Global","Ulusal Kanal","Sky Turk","TGRT Haber","Haber Turk","UHABER","A News",
        "TRT World","TRT Araba","TRT Avaz","Ekoturk","24 Haber","Halk TV","KRT","TVnet",
        "TV 24","Ulke TV","Ulkeler","Bengu Turk","Ulke TV","Haberturk","Tgrt Haber","Tele1",
        "Halkin TV","Haber65","Haber61","Haber 61","Marmara TV","BloombergHT","Mesaj TV",
        "On 4 TV","TV 5 Haber","Yaban TV Haber","Oncu TV","Arti 1","A HABER","A NEWS",
        "TRT WORLD","CNN TURK","BLOOMBERG","HABER GLOBAL","HABERTURK","TGRT HABER",
        "HALK TV","ULKE TV","BENGUTURK","EKOTURK","TVNET","KRT TV","ULUSAL KANAL",
        "SKY TURK","24 HABER","ONCU TV","ARTI 1","TV24","HABER 61","HABER 65",
    ],
    "Belgesel": [
        "Belgesel","Nat Geo","Discovery","Animal","History","Yaban TV","BBC Earth",
        "TRT Belgesel","DMAX","Da Vinci","TLC","Anima","Beast","BBC","Smithsonian",
        "NatGeo","Nat Geo Wild","Nat Geo People","Discovery Science","Discovery Turbo",
        "Investigation","ID Xtra","Science","Science Channel","Travel Channel","Travel",
        "TGRT Belgesel","Yaban","DigiMAX Hype","DigiMAX Vizyon","DigiMAX Yesilcam",
        "DOCU SCREEN","DOCUSCREEN","BELGESEL","NAT GEO","DISCOVERY","ANIMAL PLANET",
        "HISTORY","BBC","DA VINCI","TLC","SMITHSONIAN","TRT BELGESEL","TGRT BELGESEL",
    ],
    "Spor": [
        "Spor","A Spor","TRT Spor","TJK","S Sport","GS TV","FB TV","BJK TV","Fenerbahce",
        "Galatasaray","Besiktas","TRT SPOR","TAY TV","S Sport 1","S Sport 2","Tivibu Spor",
        "Spor 1","Spor 2","EXXEN","Exxen Bundesliga","TFF","Fenerbahce TV","Galatasaray TV",
        "Besiktas TV","Fb TV","Gs Tv","Sportstv","Sports TV","FENERBAHCE","GALATASARAY",
        "A SPOR","TRT SPOR","TJK","S SPORT","GS TV","FB TV","BJK TV","TAY TV","TIVIBU SPOR",
        "EXXEN BUNDESLIGA","TFF","SPORTSTV","SPORTS TV","FENERBAHCE TV","GALATASARAY TV",
        "BESIKTAS TV","EKOL SPOR","EURO STAR","S-SPORT","BEIN SPORTS","SALON",
    ],
    "Cocuk": [
        "Cocuk","Cartoon","Disney","Nick","Minika","Baby TV","Pepee","TRT Cocuk","Cocuk",
        "Cartoon Network","Disney Channel","Disney Junior","Disney XD","Nick Jr","Nickelodeon",
        "Nicktoons","BabyFirst","Baby TV","Minika Go","Minika Cocuk","TRT Cocuk","Smile TV",
        "Kidz","Kidz Bop","Kids","Blok","Cizgi","Oyun","Ceebie","Cbeebies","Boomerang",
        "COCUK","CARTOON","DISNEY","NICK","MINIKA","BABY TV","PEPEE","TRT COCUK","SMILE TV",
        "NICKTOONS","NICK JR","NICK JR.","DISNEY CHANNEL","DISNEY JUNIOR","DISNEY XD",
        "BABYFIRST","MINIKA GO","MINIKA COCUK","KIDZ","BLOK","CIZGI","OYUN","BOOMERANG",
    ],
    "Avrupa": [
        "Avrupa","Euro Star","EuroStar","Euronews","TRT Avaz","TRT World","Show Turk",
        "Show Max","ShowTurk","Kanal 7 Avrupa","TV 8 Avrupa","Star Avrupa","ATV Avrupa",
        "Kanal D Avrupa","TRT Avrupa","Tele1 Avrupa","Euro D","EuroStar","EURO STAR",
        "EURONEWS","TRT AVAZ","TRT WORLD","SHOW TURK","SHOW MAX","KANAL 7 AVRUPA",
        "TV 8 AVRUPA","STAR AVRUPA","ATV AVRUPA","KANAL D AVRUPA","EURO D","ANADOLU DERNEK",
        "ANAKKALE BOGAZ","AVRUPA","KIBRIS","KIBRIS ADA","KIBRIS TV","AS TV","AVRUPA 7",
        "MERCAN TV","DUGUN TV","KACKAR TV","ESS","TV EM","VUSLAT","MERCAN","YOL TV",
    ],
    "Dini": [
        "Dini","Din","Diyanet","Semerkand","Hilal","Lalegul","Lalegul","Yasin","Dua",
        "Merkit","Meltem","Hilal TV","Semerkand TV","Lalegul TV","Diyanet TV","Dini TV",
        "Yasin TV","Quran","Kuran","Kur'an","Hidayet","Mesaj TV","Dost TV","Esra TV",
        "Rehber TV","Tevhid TV","Yurd TV","Kabe","Medine","Mekke","Hicaz","Cami",
        "DINI","DIYANET","SEMERKAND","HILAL","LALEGUL","YASIN","DUA","MERKIT","MELTEM",
        "SEMERKAND TV","LALEGUL TV","DIYANET TV","YASIN TV","QURAN","KURAN","HIDAYET",
        "MESAJ TV","DOST TV","ESRA TV","REHBER TV","TEVHID TV","YURD TV","KABE","MEDINE",
        "MEKKE","HICAZ","CAMI","HZ MERYEM","HZ OMER","HZ YUSUF","IBRAHIM ERKAL",
        "IBRAHIM TATLISES","MAHSUN KIRMIZIGUL","CENGIZ KURTOGLU","FERDI TAYFUR",
        "DURSUN AL ERZINCANLI","HASAN VE HUSEYIN","AHMET KAYA","MUSLUM GURSES",
        "SEZEN AKSU","TARKAN","SELDA BAGCAN","YILDIZ TILBE","SONER ARICA","BAHA",
        "ASHABI KEHF","MAM EBU HANIFE","TEMPO TV","ILKE TV","TYT TURK",
    ],
    "Diger": [
        # Diğer - bu gruba özel kanallar düşer, keyword match az
        # Bu gruba özel ekleme yok, fallback grubu
    ],
    "Magenta": [
        "Magenta","Magenta Sport","MagentaSport","Telekom Sport","MAGENTA","MAGENTA SPORT",
        "TELEKOM SPORT",
    ],
    "Muzik": [
        "Muzik","Kral TV","Kral Pop","Power TV","Power Turk","Number One","NR1","Music",
        "Dream TV","Dream Turk","Muzik","TRT Muzik","VIVA","MTV","VH1","MTV Live","MTV Hits",
        "MTV Rocks","MTV Classic","MTV 90s","MTV 80s","MTV Unplugged","Power Turk","Power",
        "Kral","Kral World","Kral FM TV","Lalegul TV","Music Box","Muzik","Number One TV",
        "MUZIK","KRAL TV","KRAL POP","POWER TV","POWER TURK","NUMBER ONE","NR1","MUSIC",
        "DREAM TV","DREAM TURK","TRT MUZIK","VIVA","MTV","VH1","POWER","KRAL","KRAL WORLD",
        "DREAM BOX","ARENA BOX","NUMBER ONE TV","AHMET KAYA","SEZEN AKSU","TARKAN",
        "SELDA BAGCAN","YILDIZ TILBE","SONER ARICA","CENGIZ KURTOGLU","FERDI TAYFUR",
        "MAHSUN KIRMIZIGUL","IBRAHIM ERKAL","IBRAHIM TATLISES","MUSLUM GURSES",
        "DURSUN AL ERZINCANLI","SIFIR TV","YOL TV",
    ],
    "TR YEREL": [
        "Yerel","TV 41","TV 52","TV 4","TV 5","TV 6","Kanal 23","Kanal 26","Kanal 32",
        "Kanal 33","Kanal 34","Kanal 38","Kanal 58","Kanal 68","Kanal 78","Cay TV",
        "Bursa TV","BRT","BRT 1","BRT 2","Beykent TV","Benguturk","Karadeniz TV","Mavi",
        "Vuslat","Vuslat TV","Mercan","Mercan TV","SUN TV","Sun TV","Super TV","Vizyon",
        "TV 8 Kayseri","TV 8 Izmir","TV 100","TV100","Show Max","Show Turk","Showturk",
        "Ciftci TV","Ciftci","Tarim","Damla TV","Ekin TV","Ekoturk","BloombergHT","Ege TV",
        "KACKAR","VUSLAT","MERCAN","SUN TV","SUPER TV","BRT","BRT 1","BRT 2","BEYKENT",
        "BENGUTURK","KARADENIZ","MAVI","BENGA","TV 41","TV 52","KANAL 23","KANAL 26",
        "KANAL 32","KANAL 33","KANAL 34","KANAL 38","KANAL 58","CAY TV","BURSA TV",
        "EKIN TV","DAMLA TV","CIFTCI TV","TARIM","EGE TV","KARADENIZ TV","MAVI KARADENIZ",
        "DENIZLI TV","KONYA TV","GTV","GUNEY TV","TV 41","TV 52","MERCAN TV","VUSLAT TV",
    ],
    # ===== ALMANCA GRUPLAR (VPS yapısı) =====
    "DE FILM": [
        "Sky Cinema","Sky Cinema Premier","Sky Cinema Special","Sky Cinema Family","Sky Cinema Action",
        "Sky Cinema Comedy","Sky Cinema Classics","Sky Cinema Fun","Sky Cinema Best","Sky Cinema Hits",
        "Sky Cinema Premiere","Sky Cinema Premiere 1","Sky Cinema Premiere 2","Sky Cinema Premiere 3",
        "Sky Cinema Premiere 4","Sky Cinema Premiere 5","Sky Cinema Thriller","Sky Cinema Disney",
        "Sky Cinema Mystery","Sky Cinema Animation","Sky Cinema Toon","Sky Cinema Filmpalast",
        "RTL+","13th Street","13th Street HD","AXN","AXN HD","TNT Serie","TNT Film","TNT Serie HD",
        "TNT Film HD","TNT Comedy","TNT Comedy HD","TNT Series","RTL Passion","RTL Passion HD",
        "RTL Living","RTL Crime","RTL Crime HD","Romance TV","Romance","Universal TV","Syfy","SYFY",
        "MGM","MGM HD","Sonnenklar","Sony Channel","Sony Channel HD","Silverline","Silverline Movie",
        "Kinowelt","Kinowelt TV","KinoweltTV","Filmtangente","Polyband","Divadrome","Lokal TV",
        "Cinema","Cinema 1","Cinema 2","Cinema 3","Cinema 4","Cinema 5","Cinema 6","Cinema 7",
        "Cinema 8","Cinema 9","Cinema 10","Cinema 11","Cinema 12","Cinema 13","Cinema 14","Cinema 15",
        "Cinema 16","Cinema 17","Cinema 18","Cinema 19","Cinema 20","Cinema 21","Cinema 22","Cinema 23",
        "Filmpalast","Filme","Film","Film 1","Film 2","Film 3","Film 4","Film 5","Movie","Movie 1",
        "Movie 2","Movie 3","Movie 4","Movie 5","Movies","Movies 1","Movies 2","Movies 3","Movies 4",
        "Movies 5","Movies 6","Movies 7","Movies 8","Movies 9","Movies 10","Filmdose","Filmdose 1",
        "Filmdose 2","Filmdose 3","Filmdose 4","Filmdose 5","Filmdose 6","Filmdose 7","Filmdose 8",
    ],
    "DE DOKU": [
        "Doku","Docu","D-MAX","N24 Doku","Spiegel TV","Spiegel Geschichte","Spiegel TV Wissen",
        "Spiegel","Discovery","Discovery Channel","Discovery Science","Discovery Turbo Xtra",
        "NatGeo","Nat Geo","Nat Geo Wild","Nat Geo People","National Geographic","National Geo",
        "Animal Planet","Animal","History","History Channel","Planet","Planet Info","Planet Comedy",
        "Planet Cinema","Planet Sport","Planet Wissen","Science","Science Channel","Smithsonian",
        "Smithsonian Channel","TLC","DMAX","D-Max","DMAX HD","Dmax","Geo","Geo TV","Geo HD",
        "ServusTV","Servus","Phoenix","Phoenix HD","Phoenix Info","ZDFinfo","ZDFinfo HD",
        "Tagesschau24","tagesschau24","N24","N-TV","NTV","WELT","Welt der Wunder",
    ],
    "DE SPORT": [
        "Sky Sport","Sky Bundesliga","Eurosport","DAZN","Sport1","Sky Sport 1","Sky Sport 2",
        "Sky Sport Austria","Sky Sport News","Sky Bundesliga 1","Sky Bundesliga 2",
        "Sky Bundesliga 3","Sky Bundesliga 4","Sky Bundesliga 5","Sky Bundesliga 6",
        "Sky Bundesliga 7","Sky Bundesliga 8","Sky Bundesliga 9","Sky Bundesliga 10",
        "Sky Sport Bundesliga","DAZN 1","DAZN 2","DAZN 3","Eurosport 1","Eurosport 2",
        "Eurosport 360","Sport1+","Sport 1+","Sport1 US","Sportdigital","DAZN Bundesliga",
        "Sport ","Sport 1","Sport1","Racing","Bike","Bundesliga","Champions League",
        "Formel 1","Formel","MotoGP","NBA","NFL","NHL","MLB","Tennis","Golf","Snooker","Darts",
        "Wrestling","Boxen","Boxing","Poker","Esports","eSports","E-Sports","WWE","AEW","ROH",
    ],
    "DE AUTO MOTOR": [
        "Auto Motor","Auto Motor Sport","Motorvision","Auto","Motor","Sportauto","Sport Auto",
        "AUTO MOTOR","MOTORVISION","AUTO","MOTOR",
    ],
    "DE KINDER": [
        "Kind","Kids","Toggo","KiKA","Kika","KIKA","Nick","Nick Jr","Nickelodeon","Nicktoons",
        "Disney","Disney Channel","Disney Junior","Disney XD","Cartoon","Cartoon Network","Boomerang",
        "Baby","Baby TV","BabyFirst","Junior","Junior HD","Fix & Foxi","Fix and Foxi","Folx",
        "RiC","RiC HD","RiC TV","Kinderkanal","TOGGO plus","Toggo","TOGGO","ZDFtivi","ZDF tivi",
        "ZDF tivi HD","Super RTL","Super RTL HD","Super RTL Disney","Kika HD","KIKA HD","Junior TV",
    ],
    "DE LIFESTYLE": [
        "Lifestyle","TLC","Romance TV","Living","Fashion","Beauty TV","Health TV","Family TV",
        "Folx","Fix & Foxi","Fix and Foxi","Heimatkanal","LIFESTYLE","TLC","ROMANCE TV",
        "LIVING","FASHION","BEAUTY TV","HEALTH TV","FAMILY TV","FOLX","FIX & FOXI",
    ],
    "DE NACHRICHTEN": [
        "News","Tagesschau","Tagesschau HD","N-TV","ntv","N24","N24 Doku","WELT","WELT TV","Welt",
        "Welt HD","Welt News","Welt Nachrichten","Bild","Bild TV","Bild News","Bild.de","Bild de",
        "Focus","Focus TV","Focus Gesundheit","Spiegel","Spiegel TV","Spiegel TV HD",
        "Spiegel TV Wissen","Spiegel Geschichte","Phoenix","Phoenix HD","Phoenix Info","ZDFinfo",
        "ZDFinfo HD","Tagesschau24","tagesschau24","ARD Alpha","BR Alpha","BR Fernsehen",
        "hr-fernsehen","HR Fernsehen","MDR Fernsehen","NDR Fernsehen","RBB Fernsehen",
        "SR Fernsehen","SWR Fernsehen","WDR Fernsehen","Deutsche Welle","DW","DW Deutsch",
        "DW English","DW News","DW Espanol","Euronews","Euronews HD","BBC World","BBC World News",
        "CNN","CNBC","Bloomberg","Bloomberg TV","Sky News","Al Jazeera","TRT World",
        "NACHRICHTEN","NEWS","TAGESSCHAU","N-TV","NTV","N24","WELT","WELT TV","PHOENIX",
        "ZDFINFO","DEUTSCHE WELLE","DW","EURONEWS","BBC WORLD","CNN","CNBC","BLOOMBERG",
        "SKY NEWS","AL JAZEERA","TRT WORLD","BILD","FOCUS","SPIEGEL",
    ],
    "DE REGIONAL": [
        "Regional","TV Berlin","TV Munchen","TV Mainfranken","TV Mittelrhein","TV Oberfranken",
        "TV Westfalen","TVA Ostbayern","TVO","Wochenblitz TV","RFO","RNF","LT1","LT1-OOE",
        "LT1 Salzburg","LT1 Carinthia","LT1 Tirol","LT1 Vorarlberg","LT1 Upper Austria",
        "LT1 Steiermark","Hamburg 1","Munchen TV","Berlin TV","Frankfurt TV","RFO","RNF",
        "REGIONAL","TV BERLIN","TV MUNCHEN","TV MAINFRANKEN","LT1","HAMBURG 1","RFO","RNF",
    ],
    "DE VOLLPROGRAMM": [
        "ARD","ZDF","Das Erste","WDR","NDR","BR","SWR","HR","MDR","RBB","Phoenix",
        "3sat","KiKA","ONE","Arte","tagesschau24","zdfinfo","zdfneo","BR Fernsehen",
        "WDR Fernsehen","NDR Fernsehen","SWR Fernsehen","HR Fernsehen","MDR Fernsehen",
        "RBB Fernsehen","SR Fernsehen","Deutsche Welle","DW","SRF Info","ServusTV",
        "ATV","ATV 2","Puls 4","Puls 8","ProSieben","Pro 7","Pro7","Sat.1","Sat 1","SAT1",
        "RTL","RTLup","RTL II","RTL2","VOX","kabel eins","Kabel 1","Kabel1","Sixx","SIXX",
        "TELE 5","Tele5","Nitro","RTL Nitro","Super RTL","Comedy Central","DMAX",
        "Anixe","Anixe HD","Anixe+","Anixe SD","Romance TV","RTL Passion","RTL Crime",
        "RTL Living","Sat.1 emotions","Sat.1 Gold","Sat1 Gold","Sat.1 Comedy","ProSieben Fun",
        "ProSieben Maxx","Pro7 Fun","Pro7 Maxx","Sixx","Sky Cinema","Voxup","WELT","WELT TV",
        "ZDF","ZDFneo","ZDFinfo","ZWEI","Zwei","Welt der Wunder","eoTV","Zee One","Warner TV",
    ],
    "DE SERIEN": [
        "Serie","RTL","Sat.1","ProSieben","VOX","kabel eins","RTL2","Super RTL","Sixx","TELE 5",
        "Pro7","Pro 7","Sat1","Sat 1","RTL II","RTL2","RTL up","RTLup","RTL Passion","RTL Living",
        "RTL Crime","Sat.1 emotions","Sat.1 Gold","Sat.1 Comedy","ProSieben Fun","ProSieben Maxx",
        "Pro7 Fun","Pro7 Maxx","kabel eins Doku","kabel eins classics","kabel eins Docu","Kabel 1",
        "Kabel1","Kabel Eins","Kabel Eins HD","Kabel 1 HD","Kabel 1 Classics","Kabel 1 Docu",
        "Universal TV","SYFY","Syfy","13th Street","13th Street HD","AXN","AXN HD","TNT Serie",
        "TNT Film","TNT Serie HD","TNT Comedy","TNT Comedy HD","TNT Series","E! Entertainment",
        "E!","Comedy Central","VIVA","VoxUp","Sixx","SIXX","Sony Channel","Sony Channel HD",
        "Warner TV","Warner TV Comedy","Warner TV Film","Warner TV Serie","Warner TV HD","Silverline",
        "Silverline Serie","Silverline Movies","Silverline Sports","Silverline Music","Silverline News",
    ],
    "DE EINKAUF": [
        "Shop","Einkauf","QVC","HSE","HSE24","HSE Extra","1-2-3.tv","123tv","1-2-3 TV",
        "Channel 21","Channel21","Astro TV","Beauty TV","EINKAUF","SHOP","QVC","HSE","HSE24",
        "1-2-3.TV","CHANNEL 21","CHANNEL21",
    ],
    "DE MUSIK": [
        "Musik","VIVA","Deluxe Music","MTV","MTV Live","MTV Hits","MTV Rocks","MTV Classic",
        "MTV 80s","MTV 90s","MTV Unplugged","VH1","VH1 Classic","VIVA HD","MTV HD","Deluxe Music HD",
        "Folx","Folx TV","Kronehit","Kronehit TV","Kronehit HD","gotv","gotv HD","goTV","gotv",
        "XITE","XITE HD","XITE TV","Sunshine Live","Sunshine Live HD","Sunshine Live TV",
        "MUSIK","VIVA","DELUXE MUSIC","MTV","MTV LIVE","MTV HITS","MTV ROCKS","MTV CLASSIC",
        "FOLX","FOLX TV","KRONEHIT","GOTV","XITE","SUNSHINE LIVE",
    ],
    "DE PARLAMENT": [
        "Parlament","Phoenix","Phoenix HD","Phoenix Info","Bundestag","Landtag","PARLAMENT",
        "PHOENIX","BUNDESTAG","LANDTAG","Oberfranken TV",
    ],
    "DE SONSTIGE": [
        # Fallback grup - diğer kurallara uymayan tüm DE kanalları buraya düşer
        # Buraya özel keyword eklenmez, sadece fallback olarak kullanılır
    ],
}
