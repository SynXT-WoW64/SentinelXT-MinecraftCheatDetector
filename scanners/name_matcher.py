
"""Tolerant matching of X-Ray style names and similar character combinations.

Handles case, separators, digits, zero-width/invisible characters, look-alike
(Cyrillic/Greek/fullwidth) letters, leet substitutions and single-character typos
(xray, x-ray, x_ray, X Ray, xray123, xr4y, xrау, xrya, xrray, x.r.a.y).
Names of unrelated network software (Xray-core, V2Ray, Xray VPN) are excluded unless the
caller already knows the file is a Minecraft resource pack. A name match is only a lead.
"""
import re
import unicodedata

CONFUSABLES = {
    "\u0445": "x", "\u0443": "y", "\u0440": "p", "\u0430": "a", "\u0435": "e",
    "\u043e": "o", "\u0441": "c", "\u0456": "i", "\u0433": "r", "\u0433": "r",
    "\u03c7": "x", "\u03b1": "a", "\u03c1": "p", "\u03c5": "y", "\u03b3": "y",
    "\u0445": "x", "\u04b3": "x", "\u0443": "y", "\u04af": "y",
}
LEET = {"4": "a", "@": "a", "3": "e", "0": "o", "1": "i", "5": "s", "7": "t", "$": "s", "!": "i"}
INVISIBLE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\u00ad]")

XRAY_FORMS = ("xray", "xr4y")
OREFINDER_FORMS = ("orefinder", "orefind", "oreesp", "orehighlight", "orehack", "oresight",
                   "oreseeker", "oredetector")
CAVEFINDER_FORMS = ("cavefinder", "cavefind", "cavehack", "tunnelfinder", "caveesp")

NETWORK_SOFTWARE_TERMS = (
    "vpn", "v2ray", "v2rayn", "v2rayng", "xraycore", "xrayr", "xrayui", "3xui", "xui",
    "vless", "vmess", "trojan", "shadowsocks", "nekoray", "nekobox", "clash", "proxy",
    "reality", "xtls", "hiddify", "marzban", "singbox",
)

def _fold(text, leet=False):
    value = unicodedata.normalize("NFKC", str(text or ""))
    value = INVISIBLE.sub("", value)
    value = "".join(CONFUSABLES.get(ch, CONFUSABLES.get(ch.lower(), ch)) for ch in value)
    value = re.sub(r"([a-z])([A-Z])", r"\1 \2", value)
    value = value.lower()
    if leet:
        value = "".join(LEET.get(ch, ch) for ch in value)
    return value

def compact_name(text, leet=False):
    """Letters/digits only: 'X_Ray-1.8 (final)' -> 'xray18final'."""
    return re.sub(r"[^a-z0-9]+", "", _fold(text, leet))

def _distance(a, b):
    """Damerau-Levenshtein distance (adjacent transposition counts as one edit)."""
    if a == b:
        return 0
    rows = len(a) + 1
    cols = len(b) + 1
    table = [[0] * cols for _ in range(rows)]
    for i in range(rows):
        table[i][0] = i
    for j in range(cols):
        table[0][j] = j
    for i in range(1, rows):
        for j in range(1, cols):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            table[i][j] = min(table[i - 1][j] + 1, table[i][j - 1] + 1, table[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                table[i][j] = min(table[i][j], table[i - 2][j - 2] + 1)
    return table[-1][-1]

def _tokens(text):
    folded = _fold(text, leet=True)
    return [token for token in re.split(r"[^a-z0-9]+", folded) if token]

def _fuzzy_xray_token(token):
    """One-edit variants of 'xray' that still look like it: starts with x, has r near the start."""
    token = token.rstrip("0123456789")
    if not 4 <= len(token) <= 6 or token[0] != "x" or "r" not in token[1:3]:
        return False
    return _distance(token, "xray") <= 1

def _is_network_software(compact):
    return any(term in compact for term in NETWORK_SOFTWARE_TERMS)

def xray_name_hints(text, exclude_network_software=True):
    """Return canonical hint names found in ``text`` or an empty list."""
    compact = compact_name(text)
    compact_leet = compact_name(text, leet=True)
    if not compact:
        return []
    hints = []
    exact = any(form in compact for form in XRAY_FORMS) or "xray" in compact_leet
    if not exact:
        tokens = _tokens(text)
        exact = any(_fuzzy_xray_token(token) for token in tokens)
        if not exact:
            for left, right in zip(tokens, tokens[1:]):
                if _fuzzy_xray_token(left + right) and len(left) <= 2:
                    exact = True
                    break
    if exact and not (exclude_network_software and _is_network_software(compact)):
        hints.append("xray")
    if any(form in compact for form in OREFINDER_FORMS):
        hints.append("ore finder")
    if any(form in compact for form in CAVEFINDER_FORMS):
        hints.append("cave finder")
    return hints

def has_xray_name_hint(text, exclude_network_software=True):
    return bool(xray_name_hints(text, exclude_network_software))
