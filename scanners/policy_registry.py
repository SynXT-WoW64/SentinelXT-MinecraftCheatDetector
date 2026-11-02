
"""Local, server-specific policy registry loader for SentinelXT."""
import json
import os
import re
import sys
import unicodedata

DEFAULT_SOURCE = "RUStrengthSMP-2026-10-22"
_CACHE = None

def _registry_path():
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(base, "database", "policy_registry.json")

def load_policy_registry():
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    try:
        with open(_registry_path(), "r", encoding="utf-8") as stream:
            data = json.load(stream)
        if not isinstance(data, dict):
            raise ValueError("registry root is not an object")
        _CACHE = data
    except Exception:
        _CACHE = {
            "schema_version": 1, "registry_id": DEFAULT_SOURCE,
            "prohibited_clients": [], "ambiguous_client_names": [],
            "prohibited_feature_families": {}, "exact_prohibited_mod_ids": [],
            "context_dependent_tools": [], "trace_cleanup_tools": [],
            "allowed_mods": [], "gray_zone": [], "launchers": [],
        }
    return _CACHE

_LOOKALIKE_TRANSLATION = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "у": "y", "к": "k", "м": "m", "т": "t", "в": "b", "н": "h",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ԛ": "q",
    "Α": "a", "Β": "b", "Ε": "e", "Ζ": "z", "Η": "h", "Ι": "i",
    "Κ": "k", "Μ": "m", "Ν": "n", "Ο": "o", "Ρ": "p", "Τ": "t",
    "Υ": "y", "Χ": "x",
})

def normalize_policy_text(value):
    text = unicodedata.normalize("NFKC", str(value or "")).casefold()
    text = text.translate(_LOOKALIKE_TRANSLATION)
    text = "".join(char for char in text if not unicodedata.category(char).startswith("C"))
    return text

def normalize_identifier(value):
    return re.sub(r"[^a-z0-9]+", "", normalize_policy_text(value))

def ambiguous_client_identifiers():
    """Return normalized names that are too generic for an automatic identity match."""
    return set(normalize_identifier(name) for name in load_policy_registry().get("ambiguous_client_names", []))

def _token_pattern(value):
    parts = re.findall(r"[a-z0-9]+", normalize_policy_text(value))
    if not parts:
        return None
    return re.compile(r"(?<![a-z0-9])" + r"[^a-z0-9]+".join(re.escape(part) for part in parts) + r"(?![a-z0-9])", re.I)

def client_identifier_map():
    registry = load_policy_registry()
    result = {}
    for name in registry.get("prohibited_clients", []):
        key = normalize_identifier(name)
        if key:
            result[key] = name
    return result

def client_markers_in_text(value, include_ambiguous=False):
    text = normalize_policy_text(value)
    registry = load_policy_registry()
    ambiguous = set(normalize_identifier(x) for x in registry.get("ambiguous_client_names", []))
    results = []
    for name in registry.get("prohibited_clients", []):
        key = normalize_identifier(name)
        if not key or (not include_ambiguous and key in ambiguous):
            continue
        pattern = _token_pattern(name)
        if pattern and pattern.search(text):
            results.append({"marker": name, "name": name, "source": "RUStrengthSMP policy registry"})
    return results

def exact_policy_mod_matches(values):
    """Match exact mod ID/display values only; filenames and generic strings are not identity."""
    registry = load_policy_registry()
    banned = set(normalize_identifier(x) for x in registry.get("exact_prohibited_mod_ids", []))

    for name in registry.get("prohibited_clients", []):
        banned.add(normalize_identifier(name))
    output = []
    seen = set()
    for field, value in values:
        normalized = normalize_identifier(value)
        if normalized and normalized in banned and normalized not in seen:
            seen.add(normalized)
            output.append({
                "marker": normalized,
                "name": str(value),
                "source": "exact_server_policy_metadata",
                "field": field,
                "value": str(value),
                "policy_registry": registry.get("registry_id", DEFAULT_SOURCE),
            })
    return output

def policy_feature_markers(text):
    registry = load_policy_registry()
    output = []
    for family, names in registry.get("prohibited_feature_families", {}).items():
        for name in names:
            pattern = _token_pattern(name)
            if pattern and pattern.search(str(text or "")):
                output.append({"name": name, "family": family})
    return output

def context_tool_matches(text):
    registry = load_policy_registry()
    output = []
    for name in registry.get("context_dependent_tools", []):
        pattern = _token_pattern(name)
        if pattern and pattern.search(str(text or "")):
            output.append(name)
    return output

def cleanup_tool_matches(text):
    registry = load_policy_registry()
    output = []
    for name in registry.get("trace_cleanup_tools", []):
        pattern = _token_pattern(name)
        if pattern and pattern.search(str(text or "")):
            output.append(name)
    return output

def launcher_identifier_map():
    registry = load_policy_registry()
    return {normalize_identifier(name): name for name in registry.get("launchers", []) if normalize_identifier(name)}

def allowed_policy_mod_matches(values):
    """Recognize exact allow-listed mod identifiers to explain legitimate matches."""
    registry = load_policy_registry()
    allowed = set()
    for name in registry.get("allowed_mods", []):

        canonical = re.sub(r"\s*\([^)]*\)\s*", "", str(name)).strip()
        allowed.add(normalize_identifier(canonical))
    output = []
    seen = set()
    for field, value in values:
        normalized = normalize_identifier(value)
        if normalized and normalized in allowed and normalized not in seen:
            seen.add(normalized)
            output.append({"name": str(value), "field": field, "source": "RUStrengthSMP allow-list"})
    return output

def gray_zone_mod_matches(values):
    registry = load_policy_registry()
    gray = set(normalize_identifier(x) for x in registry.get("gray_zone", []))
    output = []
    for field, value in values:
        normalized = normalize_identifier(value)
        if normalized and normalized in gray:
            output.append({"name": str(value), "field": field, "source": "RUStrengthSMP gray zone"})
    return output
