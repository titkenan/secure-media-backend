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
PORT = int(os.environ.get("PORT", 10000))

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
# GRUP SIRALAMASI - DE SONSTIGE minimize edildi
# ============================================================
GROUP_ORDER = [
    "TR ULUSAL", "TR HABER", "TR BEIN SPORTS", "TR SPOR", "TR BELGESEL",
    "TR SINEMA UHD", "TR SINEMA", "TR MUZIK", "TR COCUK", "TR YEREL",
    "TR DINI", "TR RADYO",
    "DE DEUTSCHLAND", "DE VIP SPORTS", "DE VIP SPORTS 2", "DE SPORT",
    "DE AUSTRIA", "DE SCHWEIZ", "DE FILM", "DE SERIEN", "DE KINO",
    "DE DOKU", "DE KIDS", "DE MUSIK", "DE INFOTAINMENT", "DE NEWS",
    "DE THEMEN", "DE SONSTIGE",
]

# Daha genis kurallar - DE SONSTIGE'deki 1154 kanali azaltmak icin
GROUP_RULES = {
    "TR ULUSAL": [
        "TRT 1","Show TV","Star TV","ATV","Kanal D","FOX TV","TV8","Tele1","Beyaz TV",
        "TV 8.5","A2","TRT 4K","Tabii","Gain","TV 100","Flash TV","Kanal 7","TGRT",
        "TLC","D MAX","ERT","TVNET","24 TV","360","360 TV","Ekoturk","Bloomberg HT",
        "Ekol TV","Kanal 24","Tele 1","UcanKus","TVem","Kanal 3","Kanal 5","Kanal 6",
        "Kanal 12","Vavoo TV","Mavi Karadeniz","DHA","Gunaydin TV","Kanal 16","Kanal 26",
        "Kanal 38","Kanal 58","Kanal T","Kanal V","TV 41","TV 52","TV 4","TV 5","TV 6",
    ],
    "TR HABER": [
        "Haber","CNN Turk","HABER","NTV","TRT Haber","Bloomberg","A Haber","Benguturk",
        "Haber Global","Ulusal Kanal","Sky Turk","TGRT Haber","Haber Turk","UHABER","A News",
        "TRT World","TRT Araba","TRT Avaz","Ekoturk","24 Haber","Halk TV","KRT","TVnet",
        "TV 24","Ulke TV","Ulkeler","Bengü Türk","Ülke TV","Habertürk","Tgrt Haber","Tele1",
        "Halkın TV","Haber65","Haber61","Haber 61","Marmara TV","BloombergHT","Mesaj TV",
        "On 4 TV","TV 5 Haber","Yaban TV Haber","Öncü TV","Artı 1",
    ],
    "TR BEIN SPORTS": [
        "beIN Sports","beIN SPORT","beIN","beIN 4K","beIN MAX","Bein Sports","BEIN SPORTS",
        "BeIN","BEIN","beINSP","beIN 1","beIN 2","beIN 3","beIN 4","beIN 5",
    ],
    "TR SPOR": [
        "Spor","A Spor","TRT Spor","TJK","S Sport","GS TV","FB TV","BJK TV","Fenerbahce",
        "Galatasaray","Besiktas","TRT SPOR","TAY TV","S Sport 1","S Sport 2","Tivibu Spor",
        "Spor 1","Spor 2","EXXEN","Exxen Bundesliga","TFF","Fenerbahçe TV","Galatasaray TV",
        "Beşiktaş TV","Fb TV","Gs TV","Sportstv","Sports TV","FENERBAHÇE","GALATASARAY",
    ],
    "TR BELGESEL": [
        "Belgesel","Nat Geo","Discovery","Animal","History","Yaban TV","BBC Earth",
        "TRT Belgesel","DMAX","Da Vinci","TLC","Anima","Beast","BBC","Smithsonian",
        "NatGeo","Nat Geo Wild","Nat Geo People","Discovery Science","Discovery Turbo",
        "Investigation","ID Xtra","Science","Science Channel","Travel Channel","Travel",
        "TGRT Belgesel","Yaban","DigiMAX Hype","DigiMAX Vizyon","DigiMAX Yeşilçam",
    ],
    "TR SINEMA UHD": ["4K","UHD","HDR","DOLBY"],
    "TR SINEMA": [
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
    ],
    "TR MUZIK": [
        "Muzik","Kral TV","Kral Pop","Power TV","Power Turk","Number One","NR1","Music",
        "Dream TV","Dream Turk","Müzik","TRT Müzik","VIVA","MTV","VH1","MTV Live","MTV Hits",
        "MTV Rocks","MTV Classic","MTV 90s","MTV 80s","MTV Unplugged","Power Türk","Power",
        "Kral","Kral World","Kral FM TV","Lalegül TV","Music Box","Müzik","Number One TV",
    ],
    "TR COCUK": [
        "Cocuk","Cartoon","Disney","Nick","Minika","Baby TV","Pepee","TRT Cocuk","Çocuk",
        "Cartoon Network","Disney Channel","Disney Junior","Disney XD","Nick Jr","Nickelodeon",
        "Nicktoons","BabyFirst","Baby TV","Minika Go","Minika Cocuk","TRT Çocuk","Smile TV",
        "Kidz","Kidz Bop","Kids","Blok","Çizgi","Oyun","Ceebie","Cbeebies","Boomerang",
    ],
    "TR YEREL": [
        "Yerel","TV 41","TV 52","TV 4","TV 5","TV 6","Kanal 23","Kanal 26","Kanal 32",
        "Kanal 33","Kanal 34","Kanal 38","Kanal 58","Kanal 68","Kanal 78","Çay TV",
        "Bursa TV","BRT","BRT 1","BRT 2","Beykent TV","Benguturk","Karadeniz TV","Mavi",
        "Vuslat","Vuslat TV","Mercan","Mercan TV","SUN TV","Sun TV","Süper TV","Vizyon",
        "TV 8 Kayseri","TV 8 İzmir","TV 100","TV100","Show Max","Show Türk","Showtürk",
        "Ciftci TV","Çiftçi","Tarim","Damla TV","Ekin TV","Ekoturk","BloombergHT","Ege TV",
    ],
    "TR DINI": [
        "Dini","Din","Diyanet","Semerkand","Hilal","Lalegul","Lalegül","Yasin","Dua",
        "Merkit","Meltem","Hilal TV","Semerkand TV","Lalegül TV","Diyanet TV","Dini TV",
        "Yasin TV","Quran","Kuran","Kur'an","Hidayet","Mesaj TV","Dost TV","Esra TV",
        "Rehber TV","Tevhid TV","Yurd TV","Kabe","Medine","Mekke","Hicaz","Cami",
    ],
    "TR RADYO": [
        "Radyo","Radio","FM","Best FM","Power Türk FM","Radyo D","Radyo Viva","Kral FM",
        "Radyo Spor","TRT FM","Radyo 1","Radyo 2","Radyo 3","Radyo 4","Alem FM","Show Radyo",
        "Radyo Eksen","Radyo FIRTINA","Radyo Mydonose","Radyo Süper","Metro FM","Joy FM",
        "Joy Türk","Kral FM","Lig Radyo","Radyo ODTÜ","Radyo Eksen","Radyo Hacettepe",
        "Radyo Ege","Radyo İmrenden","CNN Türk Radyo","Bloomberg HT Radyo","NTV Radyo",
    ],
    "DE DEUTSCHLAND": [
        "ARD","ZDF","Das Erste","WDR","NDR","BR","SWR","HR","MDR","RBB","Phoenix",
        "3sat","KiKA","ONE","Arte","tagesschau24","zdfinfo","zdfneo","BR Fernsehen",
        "WDR Fernsehen","NDR Fernsehen","SWR Fernsehen","HR Fernsehen","MDR Fernsehen",
        "RBB Fernsehen","SR Fernsehen","Deutsche Welle","DW","KiKA","SRF Info","ServusTV",
        "ATV","ATV 2","Puls 4","Puls 8","ProSieben","Pro 7","Pro7","Sat.1","Sat 1","SAT1",
        "RTL","RTLup","RTL II","RTL2","VOX","kabel eins","Kabel 1","Kabel1","Sixx","SIXX",
        "TELE 5","Tele5","Nitro","RTL Nitro","Super RTL","Comedy Central","DMAX",
        "Sport1","Sport 1","Sportdigital","Eurosport 1","Eurosport 2","Anixe","Anixe HD",
        "Anixe+","Anixe SD","Bibel TV","BibelTV","CBS Reality","CN","Cartoon Network",
        "Disney Channel","Disney Junior","Disney XD","Dox.","E! Entertainment","Eurosport",
        "Family TV","Fix & Foxi","Folx","Kabel eins Doku","KinoweltTV","Motorvision",
        "MTV","N24 Doku","N-TV","Nitro","ntv","ORF 1","ORF 2","ORF 3","ORF III","ORF Sport",
        "ORF SPORT","ProSieben Fun","ProSieben Maxx","Pro7 Fun","Pro7 Maxx","Romance TV",
        "RTL Passion","RTL Crime","RTL Living","RTL Passion","Sat.1 emotions","Sat.1 Gold",
        "Sat1 Gold","Sat.1 Comedy","Sixx","Sky Cinema","Sky Sport","Sky Bundesliga",
        "Sky Sport News","Sky Sport 1","Sky Sport 2","Sky Sport Austria","Spiegel TV",
        "Spiegel Geschichte","Spiegel TV Wissen","Sport 1+","Sport1 US","SRF 1","SRF 2",
        "SRF zwei","Super RTL","Syfy","TLC","TNT Comic","TNT Film","TNT Serie","TNT Series",
        "TOGGO plus","Universal TV","VIVA","Voxup","WDR","WELT","WELT TV","ZDF","ZDFneo",
        "ZDFinfo","ZWEI","Zwei","Welt der Wunder","eoTV","Health TV","HSE","HSE24","HSE Extra",
        "QVC","QVC2","QVC Plus","RFO","RNF","RiC","San-Shi","SciX","Sport1+","Tagesschau24",
        "Toggo","TOGGO","Toggo Plus","Travel Channel","TV Berlin","TV Mainfranken","TV München",
        "TV Mittelrhein","TV Nugels","TV Oberfranken","TV Westfalen","TVA Ostbayern","TVO",
        "Wild TV","Wochenblitz TV","WMH TV","XXP","YFE TV","ZDFkultur","ZDFtivi","Zee One",
    ],
    "DE VIP SPORTS": [
        "Sky Sport","Sky Bundesliga","Eurosport","DAZN","Sport1","Sky Sport 1","Sky Sport 2",
        "Sky Sport Austria","Sky Sport News","Sky Bundesliga 1","Sky Bundesliga 2",
        "Sky Bundesliga 3","Sky Bundesliga 4","Sky Bundesliga 5","Sky Bundesliga 6",
        "Sky Bundesliga 7","Sky Bundesliga 8","Sky Bundesliga 9","Sky Bundesliga 10",
        "Sky Sport Bundesliga","DAZN 1","DAZN 2","DAZN 3","Eurosport 1","Eurosport 2",
        "Eurosport 360","Sport1+","Sport 1+","Sport1 US","Sportdigital","DAZN Bundesliga",
    ],
    "DE VIP SPORTS 2": [
        "Telekom Sport","Magenta Sport","MagentaSport","P7","P7 Maxx","P7 One","P7 Maxx 2",
        "P7 Maxx One","P7 Sport 1","P7 Sport 2","P7 Sport 3","P7 Sport 4","P7 Sport 5",
        "P7 Maxx Sport","P7 Sport 6","P7 Sport 7","P7 Sport 8","C&CTP","C&T","RCTP","RCTP Sport",
        "Blue Sport","Blue Maxx","MySports","My Sports","MySports One","MySports 1","MySports 2",
    ],
    "DE SPORT": [
        "Sport ","Eurosport","Sportdigital","Motorvision","Auto Motor","Auto Motor Sport",
        "Channel 21","Channel21","Sport 1","Sport1","Racing","Bike","Bundesliga","Champions League",
        "Formel 1","Formel","MotoGP","NBA","NFL","NHL","MLB","Tennis","Golf","Snooker","Darts",
        " Wrestling","Boxen","Boxing","Poker","Esports","eSports","E-Sports","WWE","AEW","ROH",
    ],
    "DE AUSTRIA": [
        "ORF","ORF 1","ORF 2","ORF 3","ORF III","ORF Sport","ORF SPORT","Puls 4","Puls 8",
        "Servus","ServusTV","ATV","ATV 2","oe24","oe24TV","gotv","gotv HD","Kronen TV",
        "Krone TV","Austria","Austria TV","Austrian TV","W24","W24 TV","Salzburg TV","Tirol TV",
        "Steiermark TV","Upper Austria TV","LT1","LT1 Carinthia","LT1 Salzburg","Okto","Okto TV",
        "FS1","FS1 Salzburg","Dorf TV","dorfTV","RTS Salzburg","RTS","TCM Austria","SF1",
        "SF2","SF1 Austria","SF2 Austria","SF Doku","SF Info","SF zwei","SRF 1","SRF zwei",
        "SRF Info","SRF Austria","Teletext","Hitradio","Hitradio Ö3","Ö3","OE3",
    ],
    "DE SCHWEIZ": [
        "SRF","SRF 1","SRF zwei","SRF Info","SRF Austria","SF 1","SF 2","SF1","SF2","SF Doku",
        "SF Info","SF zwei","SRF zwei","Tele Züri","Tele Zuerich","TeleBärn","TeleBärn HD",
        "Tele 1","Tele 1 HD","TVO","TVO HD","TVO Ostschweiz","TeleTop","TeleTop HD","Tele M1",
        "Tele M1 HD","Telebasel","Telebasel HD","Tele D","TVOstschweiz","Canale Alpha","Alpha",
        "Alpha TV","Swiss","Switzerland","Schweiz","ZVV","Teleclub","TeleClub","Tele Club",
        "TC Sport","TC Cinema","TC Sport 1","TC Sport 2","TC Cinema 1","TC Cinema 2","TC Action",
        "TC Emotion","TC Comedy","TC Disc","TC Flash","TC Zushi","TC Premium","TC Select",
        "TC Select 1","TC Select 2","TC Select 3","TC Select 4","TC Select 5","MySports One",
        "MySports 1","MySports 2","MySports 3","MySports 4","MySports 5","MySports 6","MySports 7",
        "MySports 8","MySports 9","MySports 10","MySports Surf","Blue Maxx","Blue Sport",
        "Blue Sport 1","Blue Sport 2","Blue Sport 3","Blue Sport 4","Blue Sport 5","Blue Sport 6",
        "Blue Sport 7","Blue Sport 8","Blue Sport 9","Blue Sport 10","TVO 1","TVO 2","TVO 3",
    ],
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
    "DE KINO": [
        "Kino","Kinowelt","Kinowelt TV","KinoweltTV","Kinowelt HD","MGM","MGM HD","TNT Film",
        "TNT Film HD","Silverline Movies","Cinema","Cinema 1","Cinema 2","Cinema 3","Cinema 4",
        "Cinema 5","Cinema 6","Cinema 7","Cinema 8","Cinema 9","Cinema 10","Cinema 11","Cinema 12",
        "Cinema 13","Cinema 14","Cinema 15","Cinema 16","Cinema 17","Cinema 18","Cinema 19","Cinema 20",
        "Cinema 21","Cinema 22","Cinema 23","Sky Cinema","Sky Cinema Premier","Sky Cinema Hits",
        "Sky Cinema Action","Sky Cinema Comedy","Sky Cinema Family","Sky Cinema Classics","Sky Cinema Fun",
        "Sky Cinema Best","Sky Cinema Premiere","Sky Cinema Thriller","Sky Cinema Disney",
        "Sky Cinema Mystery","Sky Cinema Animation","Sky Cinema Toon","Sky Cinema Filmpalast",
        "Sky Cinema Special","Polyband","Filmtangente","Filmdose","Filmdose 1","Filmdose 2","Filmdose 3",
        "Filmdose 4","Filmdose 5","Filmdose 6","Filmdose 7","Filmdose 8","Movie","Movies","Movie 1","Movie 2",
    ],
    "DE DOKU": [
        "Doku","Docu","D-MAX","N24 Doku","Spiegel TV","Spiegel Geschichte","Spiegel TV Wissen",
        "Spiegel","Discovery","Discovery Channel","Discovery Science","Discovery Turbo Xtra",
        "NatGeo","Nat Geo","Nat Geo Wild","Nat Geo People","National Geographic","National Geo",
        "Animal Planet","Animal","History","History Channel","Planet","Planet Info","Planet Comedy",
        "Planet Cinema","Planet Sport","Planet Wissen","Science","Science Channel","Smithsonian",
        "Smithsonian Channel","TLC","DMAX","D-Max","DMAX HD","Dmax","Geo","Geo TV","Geo HD",
        "ServusTV","Servus","Phönix","Phoenix","Phoenix HD","Phoenix Info","ZDFinfo","ZDFinfo HD",
        "Tagesschau24","tagesschau24","N24","N24 Doku","N-TV","NTV","WELT","Welt der Wunder",
        "Welt der Wunder TV","Bibel TV","BibelTV","Motorvision","Auto Motor","Auto Motor Sport",
        "Auto","Motor","Sportauto","Sport Auto","Travel","Travel Channel","Travel Channel HD",
        "E! Entertainment","E!","Fix & Foxi","Fix and Foxi","Folx","Heimatkanal","Romance TV",
        "Silverline Movies","Silverline","Lokal TV","Channel 21","Channel21","QVC","QVC2","HSE24",
        "HSE","HSE Extra","1-2-3.tv","123tv","1-2-3 TV","Astro TV","Beauty TV","Bibel TV",
        "BibelTV","Brava HD","CBS Reality","CN","Cartoon Network","Disney Channel","Disney Junior",
        "Disney XD","Dox.","Eurosport","Family TV","Fix & Foxi","Folx","Health TV","HSE24","HSE24 Extra",
        "HSE Extra","KinoweltTV","LT1","LT1-OOE","LT1 Salzburg","LT1 Carinthia","LT1 Tirol","LT1 Vorarlberg",
        "LT1 Upper Austria","LT1 Salzburg","LT1 Steiermark","MTV","Motorvision","N24 Doku","N-TV",
        "Nitro","ntv","ORF 1","ORF 2","ORF 3","ORF III","ORF Sport","ORF SPORT","ORF SPORT +",
        "ProSieben Fun","ProSieben Maxx","Pro7 Fun","Pro7 Maxx","QVC","QVC2","QVC Plus","RFO","RNF","RiC",
        "San-Shi","SciX","Sport1+","Sport1 US","SRF 1","SRF 2","SRF zwei","Super RTL","Syfy","TLC","TNT Comic",
        "TNT Film","TNT Serie","TNT Series","TOGGO plus","Universal TV","VIVA","Voxup","WDR","WELT","WELT TV",
        "ZDF","ZDFneo","ZDFinfo","ZWEI","Zwei","Welt der Wunder","eoTV","Health TV","HSE","HSE24","HSE Extra",
        "QVC","QVC2","QVC Plus","RFO","RNF","RiC","San-Shi","SciX","Sport1+","Sport1 US","SRF 1","SRF 2",
        "SRF zwei","Super RTL","Syfy","TLC","TNT Comic","TNT Film","TNT Serie","TNT Series","TOGGO plus",
        "Universal TV","VIVA","Voxup","WDR","WELT","WELT TV","ZDF","ZDFneo","ZDFinfo","ZWEI","Zwei",
        "Welt der Wunder","eoTV","Health TV","HSE","HSE24","HSE Extra","QVC","QVC2","QVC Plus","RFO","RNF",
        "RiC","San-Shi","SciX","Sport1+","Sport1 US","SRF 1","SRF 2","SRF zwei","Super RTL","Syfy","TLC",
        "TNT Comic","TNT Film","TNT Serie","TNT Series","TOGGO plus","Universal TV","VIVA","Voxup","WDR",
    ],
    "DE KIDS": [
        "Kind","Kids","Toggo","KiKA","Kika","KIKA","Nick","Nick Jr","Nickelodeon","Nicktoons",
        "Disney","Disney Channel","Disney Junior","Disney XD","Cartoon","Cartoon Network","Boomerang",
        "Baby","Baby TV","BabyFirst","Junior","Junior HD","Fix & Foxi","Fix and Foxi","Folx",
        "RiC","RiC HD","RiC TV","Kinderkanal","TOGGO plus","Toggo","TOGGO","ZDFtivi","ZDF tivi",
        "ZDF tivi HD","Super RTL","Super RTL HD","Super RTL Disney","ORF 1 Kids","ORF Kids","Toggo Plus",
        "TOGGO Plus HD","Kika HD","KIKA HD","Junior TV","Junior TV HD","Junior HD","Junior Xtra","Junior 1",
        "Junior 2","Junior 3","Junior 4","Junior 5","Junior 6","Junior 7","Junior 8","Junior 9","Junior 10",
    ],
    "DE MUSIK": [
        "Musik","VIVA","Deluxe Music","MTV","MTV Live","MTV Hits","MTV Rocks","MTV Classic",
        "MTV 80s","MTV 90s","MTV Unplugged","VH1","VH1 Classic","VIVA HD","MTV HD","Deluxe Music HD",
        "Deluxe Music","Folx","Folx TV","Kronehit","Kronehit TV","Kronehit HD","Gotv","gotv HD","goTV",
        "gotv","XITE","XITE HD","XITE TV","Sunshine Live","Sunshine Live HD","Sunshine Live TV",
        "Sunshine Live 1","Sunshine Live 2","Sunshine Live 3","Sunshine Live 4","Sunshine Live 5",
        "Sunshine Live 6","Sunshine Live 7","Sunshine Live 8","Sunshine Live 9","Sunshine Live 10",
        "Power Türk","Power Turk","Number One","NR1","Music","Music 1","Music 2","Music 3","Music 4",
        "Music 5","Music 6","Music 7","Music 8","Music 9","Music 10","Power TV","Power","Hitradio",
        "Hitradio Ö3","Ö3","OE3","Hitradio RTL","Hitradio Antenne","Antenne","Antenne 1","Antenne 2",
        "Antenne Bayern","Antenne Niedersachsen","Antenne Thüringen","Antenne 1","Antenne Vorarlberg",
        "SWR1","SWR2","SWR3","SWR4","SWR Info","SR 1","SR 2","SR 3","HR 1","HR 2","HR 3","HR Info",
        "Bayern 1","Bayern 2","Bayern 3","Bayern 4","Bremen 1","Bremen 2","Bremen 3","Bremen 4","RBB 1",
        "RBB 2","RBB 3","RBB 4","WDR 1","WDR 2","WDR 3","WDR 4","WDR 5","MDR 1","MDR 2","MDR 3","MDR 4",
    ],
    "DE INFOTAINMENT": [
        "Info","N24","WELT","n-tv","BBC World","France 24","CNN","Euronews","CNBC","Bloomberg",
        "Sky News","RT","RT Deutsch","RT English","Al Jazeera","Al Jazeera English","Deutsche Welle",
        "DW","DW News","DW Deutsch","DW English","TRT World","TRT","TRT Haber","TRT World HD","Euronews HD",
        "TV5 Monde","TV5Monde","RAI","RAI 1","RAI 2","RAI 3","RAI News","RAI News 24","RAI News 24 HD",
        "TVE","TVE 1","TVE 2","TVE 24","TVE 24h","TVE 24 Hora","TVE Internacional","TVE Intl","Antena 3",
        "Antena 3 HD","Antena 3 España","Telecinco","Telecinco HD","Telecinco España","Cuatro","Cuatro HD",
        "La Sexta","La Sexta HD","La Sexta España","La 1","La 1 HD","La 2","La 2 HD","La 2 España","24h",
        "24 horas","Canal 24 Horas","Canal 24h","Canal Sur","Canal Sur HD","Canal Sur Andalucía","Telemadrid",
        "Telemadrid HD","Canal Extremadura","TV3","TV3 HD","TV3 Catalunya","Canal Català","Canal Catala",
    ],
    "DE NEWS": [
        "News","Tagesschau","Tagesschau HD","N-TV","ntv","N24","N24 Doku","WELT","WELT TV","Welt",
        "Welt HD","Welt News","Welt Nachrichten","Bild","Bild TV","Bild News","Bild.de","Bild de",
        "Focus","Focus TV","Focus Gesundheit","Focus Gesundheit HD","Spiegel","Spiegel TV","Spiegel TV HD",
        "Spiegel TV Wissen","Spiegel Geschichte","Phönix","Phoenix","Phoenix HD","Phoenix Info","ZDFinfo",
        "ZDFinfo HD","Tagesschau24","tagesschau24","ARD Alpha","BR Alpha","BR Fernsehen","hr-fernsehen",
        "HR Fernsehen","MDR Fernsehen","NDR Fernsehen","RBB Fernsehen","SR Fernsehen","SWR Fernsehen",
        "WDR Fernsehen","Deutsche Welle","DW","DW Deutsch","DW English","DW News","DW Español","Euronews",
        "Euronews HD","BBC World","BBC World News","BBC World HD","BBC World News HD","CNN International",
        "CNN","CNBC","CNBC HD","Bloomberg","Bloomberg TV","Bloomberg TV HD","Sky News","Sky News HD",
        "Sky News UK","Sky News International","RT","RT Deutsch","RT English","RT HD","RT Deutsch HD",
        "Al Jazeera","Al Jazeera English","Al Jazeera HD","Al Jazeera English HD","TRT World","TRT World HD",
        "TV5 Monde","TV5Monde","RAI News","RAI News 24","RAI News 24 HD","TVE 24","TVE 24h","TVE 24 Hora",
        "Antena 3 Noticias","Antena 3","Telecinco","Cuatro","La Sexta","La 1","La 2","France 24","France 24 HD",
        "France 24 English","France 24 Français","France 24 Español","France 24 Arabic","France 24 HD",
    ],
    "DE THEMEN": [
        "Shop","QVC","HSE","Bibel TV","Sonstig","Regional","Channel 21","Channel21","1-2-3.tv","123tv",
        "1-2-3 TV","Astro TV","Beauty TV","Bibel TV","BibelTV","Brava HD","CBS Reality","CN","Cartoon Network",
        "Disney Channel","Disney Junior","Disney XD","Dox.","Eurosport","Family TV","Fix & Foxi","Folx","Health TV",
        "HSE24","HSE24 Extra","HSE Extra","KinoweltTV","LT1","LT1-OOE","LT1 Salzburg","LT1 Carinthia","LT1 Tirol",
        "LT1 Vorarlberg","LT1 Upper Austria","LT1 Steiermark","MTV","Motorvision","N24 Doku","N-TV","Nitro","ntv",
        "ORF 1","ORF 2","ORF 3","ORF III","ORF Sport","ORF SPORT","ORF SPORT +","ProSieben Fun","ProSieben Maxx",
        "Pro7 Fun","Pro7 Maxx","QVC","QVC2","QVC Plus","RFO","RNF","RiC","San-Shi","SciX","Sport1+","Sport1 US",
        "SRF 1","SRF 2","SRF zwei","Super RTL","Syfy","TLC","TNT Comic","TNT Film","TNT Serie","TNT Series",
        "TOGGO plus","Universal TV","VIVA","Voxup","WDR","WELT","WELT TV","ZDF","ZDFneo","ZDFinfo","ZWEI","Zwei",
        "Welt der Wunder","eoTV","Health TV","HSE","HSE24","HSE Extra","QVC","QVC2","QVC Plus","RFO","RNF","RiC",
    ],
}
