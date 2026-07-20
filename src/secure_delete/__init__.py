"""secure-delete — secure-deletion primitive (SCAFFOLD; no destructive code).

Crypto-erase-first, honest per-device claims. See README.md / SAFETY.md.
"""
from . import detect, engine, methods
from .result import Media, Method, ScopedResult

__all__ = ["ScopedResult", "Media", "Method", "detect", "engine", "methods"]
__version__ = "0.0.0-scaffold"
