
"""Read-only exact SHA-256 signature database loader."""
import json
import os
import sys

def _database_path():
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(base, "database", "known_hashes.json")

def load_hash_database():
    path = _database_path()
    try:
        with open(path, "r", encoding="utf-8") as stream:
            data = json.load(stream)
        entries = data.get("entries", []) if isinstance(data, dict) else []
        return [entry for entry in entries if isinstance(entry, dict) and entry.get("verified") is True]
    except Exception:
        return []

def match_sha256(sha256, entries=None):
    if not sha256:
        return None
    for entry in (entries if entries is not None else load_hash_database()):
        expected = str(entry.get("sha256", "")).lower()
        if len(expected) == 64 and expected == str(sha256).lower():
            return {
                "sha256": expected,
                "label": entry.get("label", "Verified signature"),
                "family": entry.get("family", "unknown"),
                "source": entry.get("source", "local reviewed database"),
                "verified": True,
            }
    return None
