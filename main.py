"""
main.py - Render entry point

Render's default Python runtime runs:  uvicorn main:app
This file exposes the FastAPI app AND triggers the startup sequence
(channel fetch, HLS resolve, group remap) so everything works out of the box.
"""

import os
import threading

# Read PORT/paths before anything else
import state
state.PORT = int(os.environ.get("PORT", 10000))
state.DB_PATH = os.environ.get("DB_PATH", "/tmp/vxparser.db")
state.M3U_PATH = os.environ.get("M3U_PATH", "/tmp/playlist.m3u")

from video import app  # noqa: E402 — app must be importable by uvicorn


# ============================================================
# Startup: runs once in a background thread after first import
# ============================================================
def _boot():
    import server
    server.startup_sequence()


if not state.DATA_READY and not state.STARTUP_ERROR:
    t = threading.Thread(target=_boot, daemon=True)
    t.start()

__all__ = ["app"]
