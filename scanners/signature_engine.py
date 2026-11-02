
"""Reviewed Minecraft client identities and feature families."""
import re
from functools import lru_cache

from scanners.policy_registry import client_identifier_map, launcher_identifier_map, load_policy_registry

KNOWN_CLIENT_IDENTIFIERS = {
    "wurst": "Wurst Client", "meteor-client": "Meteor Client", "meteorclient": "Meteor Client",
    "liquidbounce": "LiquidBounce", "bleachhack": "BleachHack", "aristois": "Aristois",
    "rusherhack": "RusherHack", "inertia": "Inertia Client", "future-client": "Future Client",
    "vape": "Vape Client", "rise-client": "Rise Client", "riseclient": "Rise Client",
    "raven-bplus": "Raven B+", "ravenbplus": "Raven B+", "fdpclient": "FDP Client",
    "thunderhack": "ThunderHack", "mathax": "MatHax", "doomsday": "Doomsday Client",
    "novoline": "Novoline", "tenacity": "Tenacity", "vestige": "Vestige",
    "exhibition": "Exhibition", "zeroday": "ZeroDay", "jigsaw": "Jigsaw Client",
    "impact-client": "Impact Client", "sigma-client": "Sigma Client", "phobos": "Phobos",
    "konas": "Konas", "pyro-client": "Pyro Client", "salhack": "SalHack",
    "kamiblue": "Kami Blue", "kami-blue": "Kami Blue", "xulu": "Xulu",
    "gamesense": "GameSense", "raven-b3": "Raven B3", "ravenb3": "Raven B3",
    "horion": "Horion", "zephyr-client": "Zephyr Client", "moon-client": "Moon Client",
    "myau": "Myau", "slinky-client": "Slinky Client", "drip-client": "Drip Client",
    "augustus-client": "Augustus Client", "astolfo": "Astolfo", "flux-client": "Flux Client",
}

for _key, _display in client_identifier_map().items():
    KNOWN_CLIENT_IDENTIFIERS.setdefault(_key, _display)

KNOWN_PACKAGE_PREFIXES = {
    "net/wurstclient/": "Wurst Client",
    "meteordevelopment/meteorclient/": "Meteor Client",
    "net/ccbluex/liquidbounce/": "LiquidBounce",
    "bleachhack/": "BleachHack",
}

FEATURE_FAMILIES = {
    "combat": ("killaura", "aimassist", "aim-assist", "aimbot", "triggerbot", "autoclicker", "autoclick", "hitboxes", "reach", "critical", "silentaim", "bowaima bot".replace(" ", "")),
    "movement": ("scaffold", "flight", "flyhack", "speedhack", "longjump", "noslow", "no-slow", "step", "bhop", "waterwalk", "spider", "wallclimb", "nofall", "invmove", "guimove"),
    "render": ("xray", "x-ray", "tracers", "entityesp", "blockesp", "nametags", "freecam", "chams", "radar", "soundesp", "chestesp", "storageesp", "seedcracker", "cavefinder"),
    "network": ("packetfly", "disabler", "blink", "antiknockback", "anti-knockback", "velocity", "backtrack", "fakelag", "pingspoof", "tickbase"),
    "player": ("cheststealer", "inventorystealer", "autototem", "autocrystal", "surround", "autoarmor", "autoeat", "autolog", "autofarm", "autofish", "baritone", "fabritone"),
    "automation": ("autotrade", "autolibrarian", "litematicaprinter", "schematicaprinter", "easyplaceprotocol", "elytraswap", "hotbarswap", "autoclicker", "keyran", "botmek"),
}

_POLICY = load_policy_registry()
_FAMILY_MAP = {
    "combat": "combat", "crystal_anchor": "player", "combat_survival": "player",
    "network": "network", "movement": "movement", "visual_information": "render",
    "automation": "automation", "macro_clicker": "automation", "resource_pack": "render",
}
for _family, _terms in _POLICY.get("prohibited_feature_families", {}).items():
    _target = _FAMILY_MAP.get(_family, "player")
    _existing = list(FEATURE_FAMILIES.get(_target, ()))
    for _term in _terms:
        _existing.append(str(_term).lower())
    FEATURE_FAMILIES[_target] = tuple(sorted(set(_existing)))

KNOWN_CLIENT_MARKERS = dict(KNOWN_CLIENT_IDENTIFIERS)
FEATURE_MARKERS = tuple(sorted(set(term for values in FEATURE_FAMILIES.values() for term in values)))

LAUNCHER_IDENTIFIERS = {
    "minecraft launcher": "Minecraft Launcher", "minecraftlauncher": "Minecraft Launcher",
    "tlauncher": "TLauncher", "tl legacy": "TL Legacy", "legacy launcher": "Legacy Launcher",
    "sklauncher": "SKlauncher", "prism launcher": "Prism Launcher", "prismlauncher": "Prism Launcher",
    "multimc": "MultiMC", "polymc": "PolyMC", "ultimmc": "UltimMC", "atlauncher": "ATLauncher",
    "modrinth": "Modrinth App", "curseforge": "CurseForge", "gdlauncher": "GDLauncher",
    "ftb app": "FTB App", "technic launcher": "Technic Launcher", "techniclauncher": "Technic Launcher",
    "lunar client": "Lunar Client", "lunarclient": "Lunar Client", "badlion": "Badlion Client",
    "feather client": "Feather Client", "feather": "Feather Client", "labymod": "LabyMod",
    "hmcl": "HMCL", "hello minecraft launcher": "HMCL", "plain craft launcher": "PCL",
    "pcl": "PCL", "xmcl": "X Minecraft Launcher", "x minecraft launcher": "X Minecraft Launcher",
    "bakaxl": "BakaXL", "cheatbreaker": "CheatBreaker", "salwyrr": "Salwyrr Client",
    "pvplounge": "PvPLounge", "cosmic client": "Cosmic Client", "pojavlauncher": "PojavLauncher",
    "voidlauncher": "VoidLauncher",
}
for _key, _display in launcher_identifier_map().items():
    LAUNCHER_IDENTIFIERS.setdefault(_key, _display)

def normalize_text(value):
    value = str(value or "").lower().replace("_", "-").replace(" ", "-")
    return re.sub(r"[^a-z0-9.-]+", "", value)

@lru_cache(maxsize=8192)
def _compiled_token_pattern(token):
    needle = str(token or "").lower()
    if not needle:
        return None
    pattern = r"(?<![a-z0-9]){}(?![a-z0-9])".format(re.escape(needle))
    return re.compile(pattern)

def _has_token(text, token):
    haystack = str(text or "").lower()
    pattern = _compiled_token_pattern(str(token or "").lower())
    return bool(pattern and pattern.search(haystack))

def find_known_client_markers(text):
    """Return whole-token names as low-strength leads; metadata identity is checked elsewhere."""
    matches = []
    ambiguous = set(re.sub(r"[^a-z0-9]+", "", x.lower()) for x in _POLICY.get("ambiguous_client_names", []))
    for marker, display in KNOWN_CLIENT_IDENTIFIERS.items():
        normalized = re.sub(r"[^a-z0-9]+", "", marker.lower())
        if normalized in ambiguous:
            continue
        variants = (marker, marker.replace("-", "_"), marker.replace("-", " "))
        if any(_has_token(text, variant) for variant in variants):
            matches.append({"marker": marker, "name": display})
    return matches

def find_feature_markers(text):
    matches = []
    for marker in FEATURE_MARKERS:
        variants = (marker, marker.replace("-", ""), marker.replace("-", " "))
        if any(_has_token(text, variant) for variant in variants):
            matches.append(marker)
    return matches

def feature_families_for(markers):
    marker_set = set(markers or [])
    return sorted(family for family, terms in FEATURE_FAMILIES.items() if marker_set.intersection(terms))

def launcher_name_from_text(text):
    low = str(text or "").lower()
    normalized = normalize_text(low)

    for marker, display in LAUNCHER_IDENTIFIERS.items():
        marker_normalized = normalize_text(marker)
        if marker in ("pcl", "hmcl", "xmcl"):
            if _has_token(low, marker):
                return display
            continue
        if marker in low or (marker_normalized and marker_normalized in normalized):
            return display
    return None
