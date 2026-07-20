"""Secure Delete — an honest, per-device secure-deletion primitive + CLI.

Crypto-erase-first; overwrite is an HDD-only supplement; never a bare "unrecoverable".
Destructive operations run only via engine.execute*() behind guards + an exact-match
confirmation gate. See README.md / SAFETY.md.
"""
from . import detect, engine, guards, methods
from .result import Media, Method, ScopedResult

__all__ = ["ScopedResult", "Media", "Method", "detect", "engine", "guards", "methods"]
__version__ = "0.1.0"
