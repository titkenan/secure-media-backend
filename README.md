# vavuubey-secure

Bağımsız IPTV proxy fork (vavuubey → vavuubey-secure v4.0).

## Güvenlik
- Token-based access (URL ?token=xxx)
- Admin token (panel + API)
- Rate limiting (sliding window per IP)
- Bot UA filter (VLC/Kodi/mpv allowed, scanners blocked)
- Security headers (X-Frame-Options, X-Content-Type-Options, etc.)
- /docs /redoc /openapi.json kapalı
- /debug kapalı (was leaking db_path, token status)
- /reload admin token ile korunmuş
- Xtream `admin/admin` kaldırıldı — gerçek token zorunlu

## Logo düzeltmesi
- `/live2/logo/...` path-only logolar `https://vavoo.to/live2/logo/...` URL'sine çevrildi
- Boş logolar boş bırakılır

## Gelişmiş gruplama
- 28 grup (TR + DE)
- Genişletilmiş keyword kuralları — DE SONSTIGE minimize edildi

## Deploy (Render)
1. Repo'yu GitHub'a push
2. Render.com → New → Web Service → Connect repo
3. Environment variables:
   - `ACCESS_TOKEN` — playlist/channel için
   - `ADMIN_TOKEN` — admin panel için
4. Build: `pip install -r requirements.txt`
5. Start: `python server.py`

## Endpoint'ler
- `GET /get.php?token=TOKEN` — M3U playlist
- `GET /player_api.php?token=TOKEN` — Xtream API
- `GET /channel/{sid}?token=TOKEN` — Channel stream (302 redirect)
- `GET /epg.xml?token=TOKEN` — EPG (XMLTV)
- `GET /admin` — Admin panel (HTML)
- `GET /api/admin/login` — Admin token verify
- `GET /api/admin/status` — Detailed status (admin only)
- `GET /api/admin/groups` — Groups list (admin only)
- `GET /health` — Render health probe (no auth)
- `GET /reload?admin_token=TOKEN` — Reload data
