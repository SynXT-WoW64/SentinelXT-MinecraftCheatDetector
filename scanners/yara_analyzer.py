
"""Optional YARA scanner. Rules are local, reviewed and read-only."""
import os
import sys

try:
    import yara
except Exception:
    yara = None

_RULES = None
_RULES_ERROR = None

def _rules_path():
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(base, "database", "rules", "sentinelxt.yar")

def yara_available():
    return yara is not None

def _load_rules():
    global _RULES, _RULES_ERROR
    if _RULES is not None or _RULES_ERROR is not None:
        return _RULES
    if yara is None:
        _RULES_ERROR = "Модуль yara-python не установлен."
        return None
    path = _rules_path()
    if not os.path.isfile(path):
        _RULES_ERROR = "Файл локальных YARA-правил не найден."
        return None
    try:
        _RULES = yara.compile(filepath=path)
    except Exception as exc:
        _RULES_ERROR = "Не удалось загрузить YARA-правила: {}".format(type(exc).__name__)
    return _RULES

def _format_matches(matches):
    output = []
    for match in matches:
        output.append({
            "rule": str(getattr(match, "rule", "unknown")),
            "tags": list(getattr(match, "tags", []) or []),
            "meta": dict(getattr(match, "meta", {}) or {}),
        })
    return output

def analyze_with_yara(path, timeout=20):
    """Return YARA rule matches; never executes the scanned file."""
    rules = _load_rules()
    if rules is None:
        return {"available": False, "matches": [], "message": _RULES_ERROR or "YARA недоступен."}
    try:
        matches = rules.match(path=path, timeout=timeout)
        output = _format_matches(matches)
        return {"available": True, "matches": output, "message": "YARA: {} совпадений.".format(len(output))}
    except Exception as exc:
        return {"available": True, "matches": [], "message": "Ошибка YARA: {}".format(type(exc).__name__)}

def analyze_bytes_with_yara(data, timeout=10):
    """Scan extracted archive-entry bytes so compressed JAR entries are visible."""
    rules = _load_rules()
    if rules is None:
        return {"available": False, "matches": [], "message": _RULES_ERROR or "YARA недоступен."}
    try:
        output = _format_matches(rules.match(data=bytes(data), timeout=timeout))
        return {"available": True, "matches": output, "message": "YARA в содержимом: {} совпадений.".format(len(output))}
    except Exception as exc:
        return {"available": True, "matches": [], "message": "Ошибка YARA в содержимом: {}".format(type(exc).__name__)}
