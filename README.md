# secure-media-backend

Lightweight Python backend with token-based access control, sliding-window rate limiting, and user-agent-based bot filtering.

## Features

- Token-based authentication (URL query + admin)
- Sliding-window rate limiting per IP
- User-agent allow-list for media clients (scanners blocked)
- Security headers (X-Frame-Options, X-Content-Type-Options, CSP, etc.)
- Admin panel with status endpoint
- Content metadata endpoint (XMLTV-compatible)

## Tech Stack

- Python 3.11+
- FastAPI / Starlette
- Uvicorn

## Deploy (Render)

1. Push repo to GitHub
2. Render.com → New → Web Service → Connect repo
3. Environment variables:
   - `ACCESS_TOKEN` — content access
   - `ADMIN_TOKEN` — admin panel
4. Build: `pip install -r requirements.txt`
5. Start: `python server.py`

## Configuration

All runtime config is via env vars. See `.env.example`.

## License

MIT — see [LICENSE](LICENSE).
