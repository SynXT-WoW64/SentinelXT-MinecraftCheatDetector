
"""SentinelXT interface localization.

Source strings in the code are Russian; ``tr(text)`` returns the text in the current
interface language (English by default). Strings with ``{}`` placeholders are also matched
against already-formatted text, so messages produced by the scanners are translated for
display only - reports and scanner logic stay untouched.
"""
import re

from core.translations import CATALOG

LANGUAGES = (("en", "English"), ("ru", "Русский"), ("uk", "Українська"))
DEFAULT_LANGUAGE = "en"
SOURCE_LANGUAGE = "ru"

_current = DEFAULT_LANGUAGE
_patterns = None
_reverse = None
_cache = {}


def available_codes():
    return [code for code, _name in LANGUAGES]


def get_language():
    return _current


def set_language(code):
    global _current
    _current = code if code in available_codes() else DEFAULT_LANGUAGE
    _cache.clear()
    return _current


def _build_patterns():
    global _patterns
    if _patterns is None:
        found = []
        for key, entry in CATALOG.items():
            if "{}" not in key:
                continue
            regex = re.escape(key).replace(re.escape("{}"), "(.*?)")
            found.append((len(key), re.compile("^" + regex + "$", re.DOTALL), entry))
        found.sort(key=lambda item: -item[0])
        _patterns = [(rx, entry) for _length, rx, entry in found]
    return _patterns


def _entry_text(entry, key):
    return entry.get(_current) or entry.get("en") or key


def _translate_group(text):
    translated = tr(text)
    if translated != text or ", " not in text:
        return translated
    parts = text.split(", ")
    converted = [tr(part) for part in parts]
    return ", ".join(converted) if converted != parts else text


def tr(text):
    """Translate a Russian source string (or a formatted message built from one)."""
    if not isinstance(text, str) or not text or _current == SOURCE_LANGUAGE:
        return text
    cached = _cache.get(text)
    if cached is not None:
        return cached
    result = text
    entry = CATALOG.get(text)
    if entry is not None:
        result = _entry_text(entry, text)
    else:
        for rx, entry in _build_patterns():
            match = rx.match(text)
            if match:
                try:
                    result = _entry_text(entry, text).format(*[_translate_group(g) for g in match.groups()])
                except (IndexError, KeyError, ValueError):
                    result = text
                break
    if len(_cache) < 4000:
        _cache[text] = result
    return result


def localize(value):
    """Translate every string value inside nested dict/list data (keys are left alone)."""
    if isinstance(value, str):
        return tr(value)
    if isinstance(value, dict):
        return {key: localize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [localize(item) for item in value]
    return value


def _build_reverse():
    global _reverse
    if _reverse is None:
        reverse = {}
        for key, entry in CATALOG.items():
            if "{}" in key:
                continue
            for text in [key] + [entry[code] for code in entry]:
                if reverse.get(text, key) != key:
                    reverse[text] = None
                else:
                    reverse[text] = key
        _reverse = reverse
    return _reverse


def source_of(text):
    """Return the Russian source string for an already translated widget text, or None."""
    return _build_reverse().get(text)
