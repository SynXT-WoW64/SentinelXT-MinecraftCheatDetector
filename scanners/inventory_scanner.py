
"""SentinelXT broad Minecraft inventory and static forensic scanner.

The scanner inventories launchers and game directories, checks candidate JAR/ZIP
archives, looks for known project markers, and optionally walks all fixed local
volumes. It never executes, modifies, deletes, or uploads discovered files.
"""
import datetime
import os
import re
import sys
import time
import zipfile

from scanners.archive_analyzer import analyze_archive
from core.version import PRODUCT_VERSION, BUILD_NUMBER, VERSION_LABEL
from scanners.pe_analyzer import analyze_pe_file
from scanners.yara_analyzer import analyze_with_yara, yara_available
from scanners.runtime_config_analyzer import analyze_runtime_configs
from core.hash_database import load_hash_database, match_sha256
from scanners.signature_engine import (
    LAUNCHER_IDENTIFIERS, find_known_client_markers, launcher_name_from_text,
    normalize_text, find_feature_markers,
)
from scanners.policy_registry import (
    load_policy_registry, context_tool_matches, cleanup_tool_matches,
)
from scanners.name_matcher import has_xray_name_hint
from scanners.trace_scanner import run_trace_scan
from scanners.texture_analyzer import analyze_resource_pack
from scanners.script_analyzer import SCRIPT_EXTENSIONS, MAX_SCRIPT_FILES, analyze_script_candidates
from integrations.everything_scanner import scan_with_everything

try:
    import winreg
except ImportError:
    winreg = None

MAX_FILES_PER_CATEGORY = 300
MAX_MOD_ARCHIVES_PER_INSTALLATION = 40
MAX_VERSION_ARCHIVES_PER_INSTALLATION = 8
MAX_PACK_ARCHIVES_PER_INSTALLATION = 10
MAX_GLOBAL_JARS = 60
MAX_GLOBAL_ZIPS = 30
MAX_GLOBAL_PES = 60
MAX_EXTERNAL_PACK_DISCOVERY_DIRS = 1800
MAX_EXTERNAL_PACK_CANDIDATES = 32
MAX_PRIORITY_PES = 45
MAX_GENERAL_PES = 15
MAX_YARA_PE_FILES = 4
MAX_YARA_ARCHIVES = 4
MAX_ROOT_DEPTH = 6
MAX_FULL_SCAN_DIRECTORIES = 6000
MAX_QUICK_SCAN_DIRECTORIES = 1000
MAX_FULL_SCAN_FILES = 80000
MAX_QUICK_SCAN_FILES = 16000
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_PE_BYTES = 96 * 1024 * 1024

class ScanBudget(object):
    """Hard wall-clock budget; a timed-out run still produces an explicitly partial report."""
    def __init__(self, full_scan=False):
        self.seconds = 120 if full_scan else 60
        self.started = time.time()
        self.deadline = self.started + self.seconds

    def expired(self):
        return time.time() >= self.deadline

    def elapsed(self):
        return max(0.0, time.time() - self.started)

IGNORED_DIRS = set((
    "$recycle.bin", "system volume information", "windows", "winsxs", "recovery",
    "config.msi", "temporary internet files", "$windows.~bt", "$windows.~ws",
    "system32", "syswow64", "programdata", "perflogs", "installer", "windowsapps",
    "default", "default user", "node_modules", ".git", "__pycache__", ".venv", "venv",
))
CACHE_DIRS = set((
    "temp", "cache", "caches", ".cache", "code cache", "gpucache",
    "shadercache", "crashdumps", "crash-reports", "logs", "log", "thumbnails",
))
GAME_HEAVY_DIRS = set(("assets", "libraries", "logs", "cache", "crash-reports", "natives", "screenshots"))
ARCHIVE_SUFFIXES = (".jar", ".zip", ".mrpack")
EXECUTABLE_SUFFIXES = (".exe", ".dll", ".bat", ".cmd", ".ps1", ".jar", ".ahk", ".py", ".vbs", ".js", ".lua")

SCANNABLE_SUFFIXES = set((
    ".jar", ".zip", ".mrpack", ".exe", ".dll", ".bat", ".cmd", ".ps1",
    ".ahk", ".py", ".vbs", ".js", ".lua", ".json", ".toml", ".cfg",
    ".ini", ".properties", ".xml", ".yml", ".yaml", ".mf",
))
IGNORED_EXTENSIONS = set((
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".ico", ".tif", ".tiff",
    ".mp3", ".wav", ".flac", ".ogg", ".m4a", ".aac", ".wma", ".mp4", ".mkv",
    ".avi", ".mov", ".wmv", ".webm", ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".ppt", ".pptx", ".psd", ".blend", ".obj", ".fbx", ".iso", ".vhd", ".vhdx",
))
SAFE_TOP_LEVEL_DIRS = set(("games", "minecraft", "launchers", "portableapps", "downloads", "documents", "mods", "clients", "software"))
CHEAT_FILE_TERMS = (
    "wurst", "meteor-client", "meteorclient", "liquidbounce", "bleachhack",
    "inertia-client", "aristois", "rusherhack", "future-client", "futureclient",
    "vape", "rise-client", "riseclient", "raven-bplus", "ravenbplus", "fdpclient",
    "thunderhack", "mathax", "doomsday", "novoline", "tenacity", "vestige",
    "exhibition", "zeroday", "jigsaw-client", "sigma-client",
)
LAUNCHER_EXE_TERMS = (
    "minecraftlauncher", "minecraft launcher", "tlauncher", "tl.exe", "prismlauncher",
    "multimc", "polymc", "ultimmc", "atlauncher", "modrinth", "curseforge",
    "gdlauncher", "ftbapp", "techniclauncher", "lunarclient", "badlion",
    "feather", "labymod", "hmcl", "pcl", "xmcl", "bakaxl", "sklauncher",
    "legacylauncher", "cheatbreaker", "salwyrr", "pvplounge",
)

def _emit(callback, message):
    if callback:
        callback(message)

def _safe_walk_error(_error):

    return

def _walk_dir_priority(name):
    """Visit likely user/game locations before broad application directories."""
    low = str(name or "").lower()
    if low in (
        "users", "documents and settings", "games", "minecraft", ".minecraft",
        "desktop", "downloads", "documents", "appdata", "roaming", "instances",
        "programs", "launchers", "clients", "tlauncher", "prismlauncher", "lunarclient",
    ):
        return (0, low)
    if low in ("program files", "program files (x86)"):
        return (1, low)
    return (2, low)

def _norm_path(path):
    try:
        return os.path.normcase(os.path.abspath(path))
    except Exception:
        return str(path).lower()

def _candidate_directories():
    appdata = os.environ.get("APPDATA", "")
    local = os.environ.get("LOCALAPPDATA", "")
    program_files = os.environ.get("PROGRAMFILES", r"C:\Program Files")
    program_files_x86 = os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")
    home = os.path.expanduser("~")
    candidates = [
        ("Minecraft Java (.minecraft)", os.path.join(appdata, ".minecraft")),
        ("Minecraft Java (.minecraft)", os.path.join(home, ".minecraft")),
        ("Minecraft Launcher", os.path.join(local, "Packages", "Microsoft.4297127D64EC6_8wekyb3d8bbwe", "LocalState", "games", "com.mojang")),
        ("TLauncher", os.path.join(appdata, ".tlauncher")),
        ("TLauncher", os.path.join(appdata, "TLauncher")),
        ("TL Legacy", os.path.join(appdata, ".tlauncher")),
        ("Prism Launcher", os.path.join(appdata, "PrismLauncher")),
        ("Prism Launcher", os.path.join(local, "Programs", "PrismLauncher")),
        ("Prism Launcher", os.path.join(program_files, "Prism Launcher")),
        ("MultiMC", os.path.join(appdata, "MultiMC")),
        ("MultiMC", os.path.join(local, "Programs", "MultiMC")),
        ("PolyMC", os.path.join(appdata, "PolyMC")),
        ("UltimMC", os.path.join(appdata, "UltimMC")),
        ("ATLauncher", os.path.join(appdata, "ATLauncher")),
        ("ATLauncher", os.path.join(local, "Programs", "ATLauncher")),
        ("Modrinth App", os.path.join(local, "Programs", "Modrinth App")),
        ("Modrinth App", os.path.join(appdata, "com.modrinth.theseus")),
        ("CurseForge", os.path.join(local, "Programs", "CurseForge")),
        ("CurseForge", os.path.join(appdata, "CurseForge")),
        ("GDLauncher", os.path.join(appdata, "gdlauncher")),
        ("GDLauncher", os.path.join(local, "Programs", "GDLauncher")),
        ("Lunar Client", os.path.join(home, ".lunarclient")),
        ("Lunar Client", os.path.join(local, "Programs", "Lunar Client")),
        ("Badlion Client", os.path.join(local, "Badlion Client")),
        ("Badlion Client", os.path.join(local, "Programs", "Badlion Client")),
        ("Feather Client", os.path.join(appdata, "Feather")),
        ("Feather Client", os.path.join(local, "Programs", "Feather")),
        ("LabyMod", os.path.join(appdata, "LabyMod")),
        ("HMCL", os.path.join(appdata, "Hello Minecraft Launcher")),
        ("PCL", os.path.join(appdata, "Plain Craft Launcher")),
        ("Minecraft Launcher", os.path.join(program_files, "Minecraft Launcher")),
        ("Minecraft Launcher", os.path.join(program_files_x86, "Minecraft Launcher")),
        ("Minecraft custom installations", os.path.join(home, "Games")),
        ("Minecraft custom installations", os.path.join(home, "Documents", "Minecraft")),
        ("Minecraft custom installations", os.path.join(home, "Desktop")),
        ("Minecraft custom installations", os.path.join(home, "Downloads")),
    ]
    return [(label, path) for label, path in candidates if path]

def _existing_directories(candidates):
    found = []
    seen = set()
    for label, path in candidates:
        expanded = os.path.abspath(os.path.expandvars(path))
        key = _norm_path(expanded)
        if key not in seen and os.path.isdir(expanded):
            seen.add(key)
            found.append({"name": label, "path": expanded})
    return found

def _fixed_drives():
    drives = []
    if sys.platform == "win32":
        try:
            import ctypes
            mask = ctypes.windll.kernel32.GetLogicalDrives()
            for index in range(26):
                if mask & (1 << index):
                    drive = "{}:\\".format(chr(ord("A") + index))
                    try:
                        drive_type = ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(drive))
                    except Exception:
                        drive_type = 3
                    if drive_type in (2, 3) and os.path.isdir(drive):
                        drives.append(drive)
        except Exception:
            pass
    if not drives:
        for letter in "CDEFGHIJKLMNOPQRSTUVWXYZ":
            drive = "{}:\\".format(letter)
            if os.path.isdir(drive):
                drives.append(drive)
    return drives

def _launcher_label(path_or_name):
    label = launcher_name_from_text(path_or_name)
    if label:
        return label
    return None

def _looks_like_game_root(path, dir_names):
    low_name = os.path.basename(path).lower()
    lower_dirs = set(name.lower() for name in dir_names)
    if low_name == ".minecraft":
        return True
    markers = ("versions", "mods", "resourcepacks", "shaderpacks")
    return len(lower_dirs.intersection(markers)) >= 2 or ("versions" in lower_dirs and "mods" in lower_dirs)

def _registry_launcher_entries():
    if winreg is None:
        return []
    roots = []
    for hive, hive_name in ((winreg.HKEY_CURRENT_USER, "HKCU"), (winreg.HKEY_LOCAL_MACHINE, "HKLM")):
        for subkey in (
            r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
            r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ):
            try:
                base = winreg.OpenKey(hive, subkey)
            except OSError:
                continue
            try:
                count = winreg.QueryInfoKey(base)[0]
                for index in range(count):
                    try:
                        child_name = winreg.EnumKey(base, index)
                        child = winreg.OpenKey(base, child_name)
                        try:
                            values = {}
                            for value_name in ("DisplayName", "InstallLocation", "DisplayIcon", "UninstallString"):
                                try:
                                    values[value_name] = winreg.QueryValueEx(child, value_name)[0]
                                except OSError:
                                    pass
                        finally:
                            winreg.CloseKey(child)
                        display = str(values.get("DisplayName", ""))
                        install_location = str(values.get("InstallLocation", ""))
                        display_icon = str(values.get("DisplayIcon", ""))
                        probe = display + " " + install_location + " " + display_icon
                        label = _launcher_label(probe)
                        client_matches = find_known_client_markers(probe)
                        if label or client_matches:
                            roots.append({
                                "name": label or client_matches[0].get("name", "Known Minecraft client"),
                                "display_name": display,
                                "install_location": install_location,
                                "display_icon": display_icon,
                                "client_marker_matches": client_matches,
                                "match_type": "launcher" if label else "known_client_name",
                                "registry_hive": hive_name,
                                "registry_key": subkey + "\\" + child_name,
                            })
                    except OSError:
                        continue
            finally:
                winreg.CloseKey(base)
    return roots

def _start_menu_shortcuts():

    roots = [os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows", "Start Menu", "Programs")]
    results = []
    for start_root in roots:
        if not os.path.isdir(start_root):
            continue
        for current, dirs, files in os.walk(start_root, onerror=_safe_walk_error):
            depth = current[len(start_root):].count(os.sep)
            if depth >= 6:
                dirs[:] = []
            for filename in files:
                if not filename.lower().endswith(".lnk"):
                    continue
                label = _launcher_label(filename)
                if label:
                    results.append({"name": label, "shortcut": filename, "path": os.path.join(current, filename)})
    return results

def _is_excluded_scan_path(path):
    """Never enter Windows/system/cache trees; explicit game roots remain separately known."""
    try:
        parts = [part.lower() for part in os.path.abspath(path).replace("/", "\\").split("\\") if part]
    except Exception:
        parts = []
    blocked = IGNORED_DIRS.union(CACHE_DIRS)
    return any(part in blocked for part in parts)

def _is_scannable_file(path):
    suffix = os.path.splitext(str(path))[1].lower()
    return suffix in SCANNABLE_SUFFIXES and suffix not in IGNORED_EXTENSIONS

def _append_scan_root(output, seen, path, label):
    if not path:
        return
    expanded = os.path.abspath(os.path.expandvars(path))
    key = _norm_path(expanded)
    if key in seen or not os.path.isdir(expanded) or _is_excluded_scan_path(expanded):
        return

    for existing in output:
        parent = _norm_path(existing.get("path", ""))
        try:
            if os.path.commonpath([key, parent]) == parent:
                return
        except Exception:
            if key.startswith(parent.rstrip("\\") + "\\"):
                return

    children = []
    for existing in output:
        child = _norm_path(existing.get("path", ""))
        try:
            if os.path.commonpath([key, child]) == key:
                children.append(existing)
        except Exception:
            if child.startswith(key.rstrip("\\") + "\\"):
                children.append(existing)
    for existing in children:
        output.remove(existing)
        seen.discard(_norm_path(existing.get("path", "")))
    seen.add(key)
    output.append({"path": expanded, "name": label, "discovery": "scan_scope"})

def _discover_appdata_launcher_roots(base_path, max_directories=900, max_depth=2):
    """Discover named portable/unknown launchers in AppData without walking all of it."""
    results = []
    if not base_path or not os.path.isdir(base_path) or _is_excluded_scan_path(base_path):
        return results
    visited = 0
    for current, dirs, _files in os.walk(base_path, topdown=True, onerror=_safe_walk_error):
        visited += 1
        depth = current[len(base_path):].count(os.sep)
        dirs[:] = [name for name in dirs if name.lower() not in IGNORED_DIRS and name.lower() not in CACHE_DIRS]
        dirs.sort(key=_walk_dir_priority)
        if depth >= max_depth or visited >= max_directories:
            dirs[:] = []
        label = _launcher_label(current)
        client_matches = find_known_client_markers(current)
        child_names = list(dirs)
        if label or client_matches or _looks_like_game_root(current, child_names):
            results.append({
                "path": current,
                "name": label or (client_matches[0].get("name") if client_matches else "Обнаруженная Minecraft-папка"),
                "discovery": "AppData shallow launcher/client discovery",
            })
        if visited >= max_directories:
            break
    return results

def _scan_roots(full_scan, drives, registry_entries=None):
    """Fast mode scans user/game roots. Extended mode also scans non-system disks and user profiles."""
    output = []
    seen = set()
    home = os.path.abspath(os.path.expanduser("~"))
    appdata = os.environ.get("APPDATA", os.path.join(home, "AppData", "Roaming"))
    local = os.environ.get("LOCALAPPDATA", os.path.join(home, "AppData", "Local"))

    if full_scan:
        users_root = None
        for drive in drives:
            system_drive = os.environ.get("SystemDrive", "C:").rstrip("\\/").lower()
            if drive.rstrip("\\/").lower() == system_drive:
                candidate = os.path.join(drive, "Users")
                if os.path.isdir(candidate):
                    users_root = candidate
                    break
        if users_root:
            _append_scan_root(output, seen, users_root, "User profiles")
        for drive in drives:
            if drive.rstrip("\\/").lower() == os.environ.get("SystemDrive", "C:").rstrip("\\/").lower():

                try:
                    names = os.listdir(drive)
                except OSError:
                    names = []
                for name in names:
                    if name.lower() in SAFE_TOP_LEVEL_DIRS:
                        _append_scan_root(output, seen, os.path.join(drive, name), name)

                for pf_name in ("Program Files", "Program Files (x86)"):
                    pf = os.path.join(drive, pf_name)
                    try:
                        children = os.listdir(pf)
                    except OSError:
                        children = []
                    for child in children:
                        if _launcher_label(child) or any(t in child.lower() for t in ("minecraft", "launcher", "lunar", "badlion", "feather", "modrinth", "curseforge")):
                            _append_scan_root(output, seen, os.path.join(pf, child), child)
            else:

                _append_scan_root(output, seen, drive, "Additional local drive")
    else:
        for child in ("Desktop", "Downloads", "Documents", "Games"):
            _append_scan_root(output, seen, os.path.join(home, child), child)

        for base in (appdata, local):
            for discovered in _discover_appdata_launcher_roots(base):
                _append_scan_root(output, seen, discovered.get("path"), discovered.get("name"))

    for program_root in (
        os.environ.get("PROGRAMFILES", r"C:\Program Files"),
        os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"),
    ):
        try:
            program_children = os.listdir(program_root)
        except OSError:
            program_children = []
        for child in program_children:
            child_path = os.path.join(program_root, child)
            if _launcher_label(child) or find_known_client_markers(child) or any(
                token in child.lower() for token in ("minecraft", "launcher", "lunar", "badlion", "feather", "modrinth", "curseforge")
            ):
                _append_scan_root(output, seen, child_path, child)

    for label, path in _candidate_directories():
        _append_scan_root(output, seen, path, label)
    for entry in registry_entries or []:
        location = entry.get("install_location")
        if location:
            _append_scan_root(output, seen, location, entry.get("name", "Installed launcher"))
    return output

def _discover_external_resource_pack_archives(drives, budget=None, max_seconds=6.0):
    results = []
    seen = set()
    visited = 0
    started = time.time()
    target_names = set(("resourcepacks", "resource-packs", "resource packs", "texturepacks", "texture-packs", "texture packs"))
    system_drive = os.environ.get("SystemDrive", "C:").rstrip("\\/").lower()
    priority_names = set(("legacy", "games", "game", "minecraft", "instances", "launchers", "mods"))
    for drive in drives:
        if drive.rstrip("\\/").lower() == system_drive:
            continue
        if not os.path.isdir(drive):
            continue
        for current, dirs, _files in os.walk(drive, topdown=True, onerror=_safe_walk_error):
            if time.time() - started >= max_seconds or (budget is not None and budget.expired()):
                return results
            visited += 1
            depth = current[len(drive):].count(os.sep)
            dirs[:] = [name for name in dirs if name.lower() not in IGNORED_DIRS and name.lower() not in CACHE_DIRS]
            dirs.sort(key=lambda name: (0 if name.lower() in priority_names else 1, name.lower()))
            if depth >= 7 or visited >= MAX_EXTERNAL_PACK_DISCOVERY_DIRS:
                dirs[:] = []
            if os.path.basename(current).lower() not in target_names:
                continue
            try:
                entries = os.scandir(current)
            except OSError:
                dirs[:] = []
                continue
            with entries:
                for entry in entries:
                    if time.time() - started >= max_seconds or (budget is not None and budget.expired()):
                        return results
                    try:
                        if not entry.is_file(follow_symlinks=False):
                            continue
                        if not entry.name.lower().endswith((".zip", ".mrpack")):
                            continue
                        size = entry.stat(follow_symlinks=False).st_size
                        if size > MAX_ARCHIVE_BYTES:
                            continue
                        key = _norm_path(entry.path)
                        if key in seen:
                            continue
                        seen.add(key)
                        results.append({
                            "path": entry.path,
                            "name": entry.name,
                            "kind": "global_resource_pack",
                            "resource_pack_directory": current,
                            "size_bytes": size,
                        })
                        if len(results) >= MAX_EXTERNAL_PACK_CANDIDATES:
                            return results
                    except OSError:
                        continue
            dirs[:] = []
    return results

def _discover_drive_artifacts(progress_callback=None, full_scan=False, registry_entries=None, budget=None):
    """Search scoped user/game roots only; Windows and cache/system trees are excluded."""
    drives = _fixed_drives()
    scan_roots = _scan_roots(full_scan, drives, registry_entries)
    launcher_dirs = []
    game_roots = []
    launcher_files = []
    script_candidates = []
    filename_markers = []
    client_directory_markers = []
    external_pack_candidates = _discover_external_resource_pack_archives(drives, budget=budget, max_seconds=6.0)
    global_archive_candidates = list(external_pack_candidates)
    global_jar_count = 0
    global_zip_count = 0
    priority_pe_candidates = []
    general_pe_candidates = []
    visited_dirs = 0
    visited_files = 0
    skipped_dirs = 0
    candidate_files_seen = 0
    seen_paths = set(_norm_path(item.get("path", "")) for item in external_pack_candidates)
    max_dirs = MAX_FULL_SCAN_DIRECTORIES if full_scan else MAX_QUICK_SCAN_DIRECTORIES
    max_files = MAX_FULL_SCAN_FILES if full_scan else MAX_QUICK_SCAN_FILES

    for scan_root in scan_roots:
        root_path = scan_root.get("path", "")
        if not os.path.isdir(root_path) or _is_excluded_scan_path(root_path):
            continue
        _emit(progress_callback, "Поиск игровых файлов: {}".format(root_path))
        for current, dirs, files in os.walk(root_path, topdown=True, onerror=_safe_walk_error):
            if budget is not None and budget.expired():
                _emit(progress_callback, "Достигнут лимит времени быстрого поиска; формируется частичный отчёт.")
                break
            visited_dirs += 1
            depth = current[len(root_path):].count(os.sep)
            retained = []
            for name in dirs:
                low = name.lower()
                if low in IGNORED_DIRS or low in CACHE_DIRS:
                    skipped_dirs += 1
                    continue
                if current.rstrip("\\/") == root_path.rstrip("\\/") and low in ("program files", "program files (x86)"):
                    skipped_dirs += 1
                    continue
                if low in GAME_HEAVY_DIRS:
                    skipped_dirs += 1
                    continue

                if low in ("google", "mozilla", "microsoftedge", "edge", "firefox", "opera software") and "appdata" in current.lower():
                    skipped_dirs += 1
                    continue
                retained.append(name)
            dirs[:] = retained
            dirs.sort(key=_walk_dir_priority)
            if depth >= MAX_ROOT_DEPTH:
                skipped_dirs += len(dirs)
                dirs[:] = []
            if visited_dirs >= max_dirs or candidate_files_seen >= max_files:
                dirs[:] = []
                break

            current_label = _launcher_label(current)
            folder_client_markers = find_known_client_markers(os.path.basename(current))
            if folder_client_markers:
                client_directory_markers.append({
                    "path": current, "name": os.path.basename(current),
                    "client_markers": folder_client_markers, "discovery": "directory_name",
                })
            if current_label:
                key = _norm_path(current)
                if key not in seen_paths:
                    seen_paths.add(key)
                    launcher_dirs.append({"name": current_label, "path": current, "discovery": "scoped_path"})

            if _looks_like_game_root(current, dirs):
                key = _norm_path(current)
                if key not in seen_paths:
                    seen_paths.add(key)
                    game_roots.append({"name": current_label or "Обнаруженная Minecraft-папка", "path": current, "discovery": "drive_markers"})

            for filename in files:
                visited_files += 1
                if not _is_scannable_file(filename):
                    continue
                full_path = os.path.join(current, filename)
                if _is_excluded_scan_path(full_path):
                    continue
                lower = filename.lower()
                ext = os.path.splitext(lower)[1]
                candidate_files_seen += 1

                if ext in (".exe", ".dll") and _launcher_label(filename):
                    launcher_files.append({"name": filename, "path": full_path, "launcher": _launcher_label(filename)})

                path_parts = [part.lower() for part in full_path.replace("/", "\\").split("\\") if part]
                inside_minecraft_root = ".minecraft" in path_parts or ("instances" in path_parts and "minecraft" in path_parts)
                game_context = any(token in full_path.lower() for token in ("minecraft", "\\mods\\", "\\clients\\", "\\launchers\\", "\\instances\\"))
                filename_client_match = bool(find_known_client_markers(filename))
                if ext == ".jar" and global_jar_count < MAX_GLOBAL_JARS:

                    eligible_global_jar = filename_client_match or (not inside_minecraft_root and (game_context or full_scan))
                    if eligible_global_jar:
                        try:
                            size = os.path.getsize(full_path)
                        except OSError:
                            size = MAX_ARCHIVE_BYTES + 1
                        if size <= MAX_ARCHIVE_BYTES:
                            global_archive_candidates.append({"path": full_path, "name": filename, "kind": "global_jar"})
                            global_jar_count += 1
                elif ext in (".zip", ".mrpack") and global_zip_count < MAX_GLOBAL_ZIPS:
                    context = current.lower()
                    relevant_context = any(token in context for token in (
                        "minecraft", "resourcepack", "resource pack", "texturepack", "texture pack",
                        "shaderpack", "modrinth", "curseforge", "tlauncher", "prism", "multimc",
                        "mods", "games", "launchers", "downloads", "desktop", "documents",
                    ))
                    client_name_matches = find_known_client_markers(filename)
                    if client_name_matches or (relevant_context and not inside_minecraft_root):
                        try:
                            size = os.path.getsize(full_path)
                        except OSError:
                            size = MAX_ARCHIVE_BYTES + 1
                        if size <= MAX_ARCHIVE_BYTES:
                            global_archive_candidates.append({"path": full_path, "name": filename, "kind": "global_zip"})
                            global_zip_count += 1

                if ext in SCRIPT_EXTENSIONS and len(script_candidates) < MAX_SCRIPT_FILES:
                    try:
                        script_size = os.path.getsize(full_path)
                    except OSError:
                        script_size = 2 * 1024 * 1024
                    if script_size <= 1024 * 1024:
                        script_candidates.append(full_path)

                if ext in (".exe", ".dll"):
                    try:
                        pe_size = os.path.getsize(full_path)
                    except OSError:
                        pe_size = MAX_PE_BYTES + 1
                    if pe_size <= MAX_PE_BYTES:
                        path_probe = full_path.lower()
                        priority_tokens = (
                            "minecraft", "launcher", "tlauncher", "prism", "multimc", "modrinth",
                            "curseforge", "lunar", "badlion", "feather", "\\desktop\\", "\\downloads\\",
                            "\\documents\\", "\\appdata\\", "\\games\\", "\\launchers\\",
                        )
                        candidate = {"path": full_path, "name": filename, "kind": "global_pe"}
                        if any(token in path_probe for token in priority_tokens):
                            if len(priority_pe_candidates) < MAX_PRIORITY_PES:
                                priority_pe_candidates.append(candidate)
                        elif full_scan and len(general_pe_candidates) < MAX_GENERAL_PES:
                            general_pe_candidates.append(candidate)

                if ext not in (".exe", ".dll"):
                    marker_matches = find_known_client_markers(filename)
                    feature_matches = find_feature_markers(os.path.splitext(filename)[0])
                    marker_matches = marker_matches + [
                        {"marker": item, "name": item, "source": "policy feature in filename"}
                        for item in feature_matches if item not in ("xray", "x-ray", "fly", "speed", "step", "aura", "reach", "timer")
                    ]
                    if marker_matches:
                        filename_markers.append({
                            "name": filename, "path": full_path,
                            "marker": marker_matches[0].get("marker", "unknown"),
                            "matches": marker_matches[:8], "discovery": "filename",
                        })
            if visited_dirs % 250 == 0:
                _emit(progress_callback, "Каталогов: {} · файлов просмотрено: {} · кандидатов: {}".format(visited_dirs, visited_files, candidate_files_seen))
            elif visited_files and visited_files % 5000 == 0:
                _emit(progress_callback, "Файлов просмотрено: {} · каталогов: {} · кандидатов: {}".format(visited_files, visited_dirs, candidate_files_seen))
            if visited_dirs >= max_dirs or candidate_files_seen >= max_files:
                break
        if visited_dirs >= max_dirs or candidate_files_seen >= max_files or (budget is not None and budget.expired()):
            break

    global_pe_candidates = priority_pe_candidates + general_pe_candidates
    return {
        "drives": drives,
        "scan_roots": scan_roots,
        "scan_mode": "extended_user_and_data_drives" if full_scan else "quick_user_and_launcher_roots",
        "launcher_directories": launcher_dirs,
        "game_roots": game_roots,
        "launcher_files": launcher_files,
        "script_candidates": script_candidates,
        "filename_markers": filename_markers,
        "client_directory_markers": client_directory_markers,
        "global_archive_candidates": global_archive_candidates,
        "global_archive_counts": {"jar": global_jar_count, "zip": global_zip_count, "external_resource_packs": len(external_pack_candidates)},
        "global_pe_candidates": global_pe_candidates,
        "global_pe_count": len(global_pe_candidates),
        "archive_candidate_limits": {
            "jar_limit_reached": global_jar_count >= MAX_GLOBAL_JARS,
            "zip_limit_reached": global_zip_count >= MAX_GLOBAL_ZIPS,
        },
        "visited_directories": visited_dirs,
        "visited_files": visited_files,
        "candidate_files_seen": candidate_files_seen,
        "skipped_directories": skipped_dirs,
        "system_directories_excluded": True,
        "non_candidate_extensions_skipped": True,
    }

def _list_child_directories(path, child_name):
    target = os.path.join(path, child_name)
    if not os.path.isdir(target):
        return []
    try:
        return sorted(name for name in os.listdir(target) if os.path.isdir(os.path.join(target, name)))
    except (OSError, IOError):
        return []

def _list_files(path, folder, suffixes, budget=None, max_files=None):
    """Collect relevant archives shallowly and prioritize known client names/recent files."""
    target = os.path.join(path, folder)
    if not os.path.isdir(target):
        return []
    limit = MAX_FILES_PER_CATEGORY if max_files is None else int(max_files)
    if limit <= 0:
        return []
    candidates = []
    child_dirs = []
    max_entries_per_folder = 1200

    def collect_folder(folder_path, entry_limit):
        try:
            entries = os.scandir(folder_path)
        except OSError:
            return
        with entries:
            for index, entry in enumerate(entries):
                if index >= entry_limit or (budget is not None and budget.expired()):
                    break
                name = entry.name
                low = name.lower()
                if low in IGNORED_DIRS or low in CACHE_DIRS:
                    continue
                try:
                    if entry.is_dir(follow_symlinks=False):
                        if folder_path == target and len(child_dirs) < 16:
                            child_dirs.append(entry.path)
                        continue
                    if not low.endswith(suffixes) or not entry.is_file(follow_symlinks=False):
                        continue
                    size = entry.stat(follow_symlinks=False).st_size
                except OSError:
                    continue
                if size > MAX_ARCHIVE_BYTES or _is_excluded_scan_path(entry.path):
                    continue
                try:
                    modified = entry.stat(follow_symlinks=False).st_mtime
                except OSError:
                    modified = 0
                candidates.append({"name": name, "path": entry.path, "size_bytes": size, "modified": modified})

    collect_folder(target, max_entries_per_folder)

    for child_folder in child_dirs:
        if budget is not None and budget.expired():
            break
        collect_folder(child_folder, 250)

    candidates.sort(key=lambda item: (
        0 if find_known_client_markers(item.get("name", "")) else 1,
        -float(item.get("modified", 0)),
        item.get("name", "").lower(),
    ))
    return candidates[:limit]

def _list_resource_pack_items(game_path, budget=None, max_items=None):
    """Find ZIP resource packs and unpacked resource-pack directories.

    Resource packs are commonly distributed as ZIP files; checking only JARs
    misses X-Ray packs. Unpacked folders with pack.mcmeta are supported too.
    """
    target = os.path.join(game_path, "resourcepacks")
    if not os.path.isdir(target):
        return []
    limit = MAX_PACK_ARCHIVES_PER_INSTALLATION if max_items is None else max(0, int(max_items))
    if limit <= 0:
        return []
    candidates = []
    try:
        entries = os.scandir(target)
    except OSError:
        return []
    with entries:
        for index, entry in enumerate(entries):
            if index >= 1600 or (budget is not None and budget.expired()):
                break
            try:
                if entry.is_file(follow_symlinks=False):
                    low = entry.name.lower()
                    if low.endswith((".zip", ".mrpack")):
                        size = entry.stat(follow_symlinks=False).st_size
                        if size <= MAX_ARCHIVE_BYTES and not _is_excluded_scan_path(entry.path):
                            modified = entry.stat(follow_symlinks=False).st_mtime
                            candidates.append({
                                "name": entry.name, "path": entry.path,
                                "size_bytes": size, "modified": modified,
                                "pack_type": "zip",
                            })
                elif entry.is_dir(follow_symlinks=False):
                    pack_root = entry.path
                    marker = os.path.join(pack_root, "pack.mcmeta")
                    assets = os.path.join(pack_root, "assets")
                    if os.path.isfile(marker) or os.path.isdir(assets):
                        try:
                            modified = entry.stat(follow_symlinks=False).st_mtime
                        except OSError:
                            modified = 0
                        candidates.append({
                            "name": entry.name, "path": pack_root,
                            "size_bytes": 0, "modified": modified,
                            "pack_type": "directory",
                        })
            except OSError:
                continue
    candidates.sort(key=lambda item: (
        0 if (has_xray_name_hint(item.get("name", "")) or any(term in item.get("name", "").lower() for term in ("ore", "cave"))) else 1,
        -float(item.get("modified", 0)),
        item.get("name", "").lower(),
    ))
    return candidates[:limit]

def _list_version_archives(game_path, budget=None):
    """Inspect recent version JARs, prioritizing recently modified installations."""
    result = []
    versions_dir = os.path.join(game_path, "versions")
    if not os.path.isdir(versions_dir):
        return result
    try:
        version_names = os.listdir(versions_dir)
    except OSError:
        return result
    version_dirs = []
    for version_name in version_names:
        if budget is not None and budget.expired():
            break
        version_path = os.path.join(versions_dir, version_name)
        if os.path.isdir(version_path):
            try:
                modified = os.path.getmtime(version_path)
            except OSError:
                modified = 0
            version_dirs.append((modified, version_name, version_path))
    version_dirs.sort(reverse=True)
    for _modified, version_name, version_path in version_dirs[:MAX_VERSION_ARCHIVES_PER_INSTALLATION]:
        if budget is not None and budget.expired():
            break
        try:
            file_names = os.listdir(version_path)
        except OSError:
            continue
        for filename in file_names:
            if budget is not None and budget.expired():
                break
            if not filename.lower().endswith(".jar"):
                continue
            path = os.path.join(version_path, filename)
            try:
                size = os.path.getsize(path)
            except OSError:
                continue
            if size > MAX_ARCHIVE_BYTES:
                continue
            result.append({"name": filename, "path": path, "size_bytes": size, "version": version_name})
            if len(result) >= MAX_VERSION_ARCHIVES_PER_INSTALLATION:
                return result
    return result

def _collect_installations(roots, progress_callback=None, hash_entries=None, budget=None):
    """Inspect only high-value Minecraft folders, with strict per-category limits."""
    installations = []
    archive_records = []
    pack_records = []
    seen = set()
    yara_archive_count = 0
    hash_enabled = bool(hash_entries)

    for root_index, root in enumerate(roots):
        if budget is not None and budget.expired():
            _emit(progress_callback, "Лимит времени достигнут перед следующим игровым каталогом.")
            break
        path = root.get("path", "")
        if not os.path.isdir(path):
            continue
        _emit(progress_callback, "Подготовка игрового каталога: {}".format(path))
        root_is_dotminecraft = os.path.basename(path).lower() == ".minecraft"
        game_path = path
        if not root_is_dotminecraft and os.path.isdir(os.path.join(path, ".minecraft")):
            game_path = os.path.join(path, ".minecraft")
            root_is_dotminecraft = True
        key = _norm_path(game_path)
        if key in seen:
            continue
        seen.add(key)

        _emit(progress_callback, "Инвентаризация {}: список версий...".format(game_path))
        versions = _list_child_directories(game_path, "versions")[:80]
        version_archives = _list_version_archives(game_path, budget=budget)
        _emit(progress_callback, "Инвентаризация {}: поиск модов...".format(game_path))
        mods = _list_files(game_path, "mods", ARCHIVE_SUFFIXES, budget=budget, max_files=MAX_MOD_ARCHIVES_PER_INSTALLATION)
        _emit(progress_callback, "Инвентаризация {}: поиск ресурс-паков...".format(game_path))
        resourcepacks = _list_resource_pack_items(game_path, budget=budget, max_items=MAX_PACK_ARCHIVES_PER_INSTALLATION)
        _emit(progress_callback, "Инвентаризация {}: поиск шейдеров...".format(game_path))
        shaderpacks = _list_files(game_path, "shaderpacks", (".zip",), budget=budget, max_files=MAX_PACK_ARCHIVES_PER_INSTALLATION)

        if not (versions or version_archives or mods or resourcepacks or shaderpacks):
            for child in _list_child_directories(path, "instances")[:80]:
                instance_path = os.path.join(path, "instances", child)
                nested = os.path.join(instance_path, ".minecraft")
                candidate = nested if os.path.isdir(nested) else instance_path
                if not os.path.isdir(candidate):
                    continue
                try:
                    candidate_dirs = os.listdir(candidate)
                except OSError:
                    candidate_dirs = []
                if not _looks_like_game_root(candidate, candidate_dirs):
                    continue
                versions.extend(_list_child_directories(candidate, "versions")[:80])
                version_archives.extend(_list_version_archives(candidate, budget=budget)[:max(0, MAX_VERSION_ARCHIVES_PER_INSTALLATION - len(version_archives))])
                mods.extend(_list_files(candidate, "mods", ARCHIVE_SUFFIXES, budget=budget, max_files=max(0, MAX_MOD_ARCHIVES_PER_INSTALLATION - len(mods)))[:max(0, MAX_MOD_ARCHIVES_PER_INSTALLATION - len(mods))])
                resourcepacks.extend(_list_resource_pack_items(candidate, budget=budget, max_items=max(0, MAX_PACK_ARCHIVES_PER_INSTALLATION - len(resourcepacks)))[:max(0, MAX_PACK_ARCHIVES_PER_INSTALLATION - len(resourcepacks))])
                shaderpacks.extend(_list_files(candidate, "shaderpacks", (".zip",), budget=budget, max_files=max(0, MAX_PACK_ARCHIVES_PER_INSTALLATION - len(shaderpacks)))[:max(0, MAX_PACK_ARCHIVES_PER_INSTALLATION - len(shaderpacks))])
                if len(mods) >= MAX_MOD_ARCHIVES_PER_INSTALLATION:
                    break

        if not (root_is_dotminecraft or versions or version_archives or mods or resourcepacks or shaderpacks):
            continue

        work = []
        work.extend((item, "version_client") for item in version_archives)
        work.extend((item, "mod") for item in mods)
        work.extend((item, "resource_pack") for item in resourcepacks)
        work.extend((item, "shader_pack") for item in shaderpacks)
        total_work = len(work)
        for archive_index, (item, kind) in enumerate(work, 1):
            if budget is not None and budget.expired():
                _emit(progress_callback, "Достигнут лимит времени анализа архивов; оставшиеся файлы отмечены как непроверенные.")
                break
            _emit(progress_callback, "Анализ архивов {}/{}: {}".format(archive_index, total_work, item.get("name", "архив")))
            is_pack = kind in ("resource_pack", "shader_pack")

            if not (kind == "resource_pack" and os.path.isdir(item["path"])):
                allow_yara = (not is_pack and yara_archive_count < MAX_YARA_ARCHIVES)
                analysis = analyze_archive(
                    item["path"], kind,
                    enable_yara=allow_yara,
                    include_hash=hash_enabled,
                )
                if analysis.get("yara_attempted"):

                    yara_archive_count += 1
                item["analysis"] = analysis
                archive_records.append(analysis)
            if kind == "resource_pack":
                _emit(progress_callback, "Глубокий анализ текстур ресурс-пака: {}".format(item.get("name", "пак")))
                item["texture_analysis"] = analyze_resource_pack(item["path"])
                pack_records.append(item["texture_analysis"])
            elif kind == "shader_pack":
                pack_records.append({
                    "path": item["path"], "name": item["name"],
                    "assessment": "shader_pack_inventory_only",
                    "notes": ["Шейдерный архив учтён; содержимое шейдеров не оценивается как чит без отдельных правил."]
                })

        limits_reached = (
            len(mods) >= MAX_MOD_ARCHIVES_PER_INSTALLATION
            or len(version_archives) >= MAX_VERSION_ARCHIVES_PER_INSTALLATION
            or len(resourcepacks) >= MAX_PACK_ARCHIVES_PER_INSTALLATION
            or len(shaderpacks) >= MAX_PACK_ARCHIVES_PER_INSTALLATION
        )
        installations.append({
            "scan_limits_reached": bool(limits_reached),
            "name": root.get("name", "Minecraft"),
            "path": path,
            "game_path": game_path,
            "versions": versions,
            "version_archives": version_archives,
            "mods": mods,
            "resource_packs": resourcepacks,
            "shader_packs": shaderpacks,
            "discovery": root.get("discovery", "known_location"),
        })
    return installations, archive_records, pack_records

def _zip_looks_like_resource_pack(path):
    try:
        with zipfile.ZipFile(path, "r") as archive:
            names = [item.filename.replace("\\", "/").lower() for item in archive.infolist()[:6000] if not item.is_dir()]
        has_metadata = any(name.endswith("pack.mcmeta") for name in names)
        texture_names = ("stone.png", "dirt.png", "netherrack.png", "end_stone.png", "deepslate.png", "cobblestone.png", "diamond_ore.png", "iron_ore.png", "gold_ore.png", "coal_ore.png", "deepslate_diamond_ore.png", "ancient_debris.png")
        texture_paths = []
        for name in names:
            normalized = "/" + name.lstrip("/")
            if "/textures/block/" in normalized or "/textures/blocks/" in normalized:
                if normalized.rsplit("/", 1)[-1] in texture_names:
                    texture_paths.append(normalized)
        return bool(has_metadata and texture_paths) or len(set(texture_paths)) >= 2
    except Exception:
        return False

def _analyze_global_resource_packs(candidates, already_analyzed=None, progress_callback=None, budget=None):
    """Find X-Ray-like ZIP packs in user folders such as Downloads, not only installed packs."""
    results = []
    seen = set(already_analyzed or [])
    max_global_packs = 25
    ordered_candidates = sorted(candidates, key=lambda item: (
        0 if has_xray_name_hint(item.get("name", "")) else 1,
        0 if item.get("kind") == "global_resource_pack" else 1,
        str(item.get("name", "")).lower(),
    ))
    for item in ordered_candidates:
        if budget is not None and budget.expired():
            break
        path = item.get("path", "")
        key = _norm_path(path)
        if not path or key in seen or item.get("kind") not in ("global_zip", "global_resource_pack") or not os.path.isfile(path):
            continue
        seen.add(key)
        if item.get("kind") != "global_resource_pack" and not _zip_looks_like_resource_pack(path):
            continue
        _emit(progress_callback, "Проверка ZIP-ресурс-пака вне .minecraft: {}".format(item.get("name", os.path.basename(path))))
        result = analyze_resource_pack(path)
        result["discovery"] = (
            "secondary_drive_resourcepacks_folder"
            if item.get("kind") == "global_resource_pack"
            else "user_folder_zip_candidate"
        )
        results.append(result)
        if len(results) >= max_global_packs:
            break
    return results

def _analyze_global_archives(candidates, already_analyzed, progress_callback=None, hash_entries=None, budget=None):
    analyses = []
    seen = set(already_analyzed)
    for index, item in enumerate(candidates):
        if budget is not None and budget.expired():
            break
        path = item.get("path", "")
        key = _norm_path(path)
        if not path or key in seen or not os.path.isfile(path):
            continue
        if item.get("kind") == "global_resource_pack":
            continue
        seen.add(key)
        if index and index % 100 == 0:
            _emit(progress_callback, "Статическая проверка архивов вне игровых папок: {}".format(index))
        try:
            if os.path.getsize(path) > MAX_ARCHIVE_BYTES:
                continue
        except OSError:
            continue
        analyses.append(analyze_archive(path, item.get("kind", "global_archive"), include_hash=bool(hash_entries)))
    return analyses

def _analyze_global_pes(candidates, already_analyzed=None, hash_entries=None, progress_callback=None, budget=None):
    analyses = []
    seen = set(already_analyzed or [])
    do_hash = bool(hash_entries)
    yara_attempts = 0
    for index, item in enumerate(candidates):
        if budget is not None and budget.expired():
            break
        path = item.get("path", "")
        key = _norm_path(path)
        if not path or key in seen or not os.path.isfile(path):
            continue
        seen.add(key)
        if index and index % 100 == 0:
            _emit(progress_callback, "Анализ PE-метаданных исполняемых файлов: {}".format(index))
        analysis = analyze_pe_file(path, include_hash=do_hash)

        pe_has_lead = bool(analysis.get("known_client_matches") or analysis.get("ambiguous_client_matches") or len(analysis.get("feature_families", [])) >= 2)
        if yara_attempts < MAX_YARA_PE_FILES and pe_has_lead:
            analysis["yara"] = analyze_with_yara(path, timeout=1)
            yara_attempts += 1
        else:
            analysis["yara"] = {"available": False, "matches": [], "message": "YARA не запускался: нет предварительных признаков или исчерпан лимит."}
        for yara_match in analysis["yara"].get("matches", []):
            category = yara_match.get("meta", {}).get("category")
            if category == "known_client_identity":
                analysis["yara_known_client_match"] = yara_match
            elif category == "multi_family_behavior_markers":
                analysis["yara_behavior_match"] = yara_match
        analyses.append(analysis)
    return analyses

def _registry_context_software():
    """Report dual-use tools by uninstall metadata as context, never as proof of cheating."""
    if winreg is None:
        return []
    results = []
    seen = set()
    for hive, hive_name in ((winreg.HKEY_CURRENT_USER, "HKCU"), (winreg.HKEY_LOCAL_MACHINE, "HKLM")):
        for subkey in (
            r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
            r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ):
            try:
                base = winreg.OpenKey(hive, subkey)
            except OSError:
                continue
            try:
                count = winreg.QueryInfoKey(base)[0]
                for index in range(count):
                    try:
                        child = winreg.OpenKey(base, winreg.EnumKey(base, index))
                        try:
                            display = str(winreg.QueryValueEx(child, "DisplayName")[0])
                            publisher = ""
                            try:
                                publisher = str(winreg.QueryValueEx(child, "Publisher")[0])
                            except OSError:
                                pass
                        finally:
                            winreg.CloseKey(child)
                    except OSError:
                        continue
                    context_matches = context_tool_matches(display)
                    cleanup_matches = cleanup_tool_matches(display)
                    if not context_matches and not cleanup_matches:
                        continue
                    key = display.lower()
                    if key in seen:
                        continue
                    seen.add(key)
                    results.append({
                        "display_name": display,
                        "publisher": publisher,
                        "registry_hive": hive_name,
                        "context_dependent_tools": context_matches,
                        "trace_cleanup_tools": cleanup_matches,
                        "interpretation": "Обнаружена запись установленной dual-use/cleanup-программы. Наличие ПО не доказывает запуск, использование макросов или очистку следов перед проверкой.",
                    })
            finally:
                winreg.CloseKey(base)
    return results

def _make_findings(archive_records, pack_records, filename_markers, directory_markers,
                  prefetch_traces, running_processes, pe_records, hash_entries, runtime_configs,
                  policy_software=None, script_records=None, trace_records=None):
    findings = []

    def add(category, title, path, details, evidence=None, sha256=None):
        item = {
            "category": category,
            "title": title,
            "path": path,
            "details": details,
            "evidence": evidence if evidence is not None else {},
        }
        if sha256:
            item["sha256"] = sha256
        findings.append(item)

    for record in archive_records:
        path = record.get("path", "")
        hash_match = match_sha256(record.get("sha256"), hash_entries)
        matches = record.get("known_client_matches", [])
        if record.get("assessment") == "allow_listed_mod":
            matches = []
        if hash_match:
            add("verified_hash_match", "Совпадение с проверенной SHA-256 записью", path,
                "Хеш совпал с локальной проверенной базой. Это идентифицирует файл, но не доказывает его запуск или использование.",
                hash_match, record.get("sha256"))
        elif matches:
            names = ", ".join(sorted(set(item.get("name", "") for item in matches)))
            add("known_client_identity", "Идентификатор известного клиентского проекта", path,
                "Метаданные или несколько независимых классов соответствуют проекту: {}. Проверьте исходный файл и контекст установки; запуск не установлен.".format(names),
                matches, record.get("sha256"))
        elif record.get("ambiguous_client_matches") or record.get("decorated_client_name_matches"):
            add("ambiguous_client_metadata", "Название клиента найдено в метаданных с неоднозначным контекстом", path,
                "Название клиента обнаружено в ID или описании, но оно не идентифицирует весь архив. Проверьте издателя, namespace и соседние классы.",
                {
                    "ambiguous": record.get("ambiguous_client_matches", []),
                    "decorated": record.get("decorated_client_name_matches", []),
                }, record.get("sha256"))
        elif record.get("policy_feature_matches"):
            add("policy_forbidden_mod_identifier", "ID модификации совпал с запрещённой записью правил сервера", path,
                "Точное поле метаданных совпало с реестром RUStrengthSMP. Проверьте содержимое, версию и включённые функции; использование в матче не установлено.",
                record.get("policy_feature_matches"), record.get("sha256"))
        elif record.get("gray_zone_matches"):
            add("gray_zone_mod_identifier", "Модификация отмечена в серой зоне правил сервера", path,
                "Реестр RUStrengthSMP требует ручной проверки функций и конфигурации этой модификации.",
                record.get("gray_zone_matches"), record.get("sha256"))
        elif record.get("assessment") == "multi_family_behavior_markers":
            add("multi_family_behavior_markers", "В классах найдены маркеры нескольких игровых функций", path,
                "Маркеры встречаются в нескольких независимых функциональных группах. Просмотрите классы и контекст; строки сами по себе не подтверждают работу этих функций.",
                {"markers": record.get("feature_markers", []), "families": record.get("feature_families", [])},
                record.get("sha256"))

        if record.get("allowed_mod_matches"):
            add("allow_listed_mod", "Модификация совпала с разрешённым списком сервера", path,
                "Точный ID совпал с белым списком. Дополнительные namespace-ссылки могут относиться к API-интеграции; модифицированные форки всё равно требуют отдельной проверки.",
                {
                    "allowed_mod_matches": record.get("allowed_mod_matches", []),
                    "namespace_references": record.get("namespace_reference_matches", []),
                }, record.get("sha256"))
        elif record.get("namespace_reference_matches") or record.get("yara_namespace_matches"):
            add("namespace_reference", "В архиве есть ссылка на namespace известного клиента", path,
                "Отдельные классы или строки обращаются к пространству имён клиента. Это может быть API-интеграция, совместимый мод или часть клиента; проверьте структуру архива.",
                {
                    "class_namespace_references": record.get("namespace_reference_matches", []),
                    "yara_namespace_references": record.get("yara_namespace_matches", []),
                }, record.get("sha256"))

        if record.get("feature_markers"):
            add("archive_feature_strings", "В архиве найдены строки, похожие на названия игровых функций", path,
                "Строки могут присутствовать в документации, конфигурациях или совместимых модах. Сопоставляйте их с классами и поведением, а не используйте отдельно.",
                {
                    "markers": record.get("feature_markers", []),
                    "families": record.get("feature_families", []),
                    "class_files_examined": record.get("class_files_examined", 0),
                }, record.get("sha256"))

    for record in pe_records:
        path = record.get("path", "")
        hash_match = match_sha256(record.get("sha256"), hash_entries)
        if hash_match:
            add("verified_hash_match", "PE-файл совпал с проверенной SHA-256 записью", path,
                "Хеш совпал с локальной проверенной базой. Наличие файла не доказывает его запуск.", hash_match, record.get("sha256"))
        elif record.get("yara_known_client_match"):
            add("yara_client_signature", "YARA обнаружила сигнатуру клиентского проекта", path,
                "Проверьте совпавшие байты, происхождение и цифровую подпись файла.", record.get("yara_known_client_match"), record.get("sha256"))
        elif record.get("ambiguous_client_matches"):
            add("ambiguous_pe_metadata", "В PE-метаданных найдено неоднозначное название клиента", path,
                "Название продукта совпало с общим маркером. Изучите издателя, подпись и происхождение; имя продукта само по себе не является идентификацией.",
                record.get("ambiguous_client_matches"), record.get("sha256"))
        elif record.get("known_client_matches"):
            add("client_name_in_pe_metadata", "PE-метаданные содержат название клиентского проекта", path,
                "Совпало поле версии PE. Проверьте издателя, цифровую подпись, хеш и происхождение файла.",
                record.get("known_client_matches"), record.get("sha256"))
        elif record.get("yara_behavior_match") or record.get("assessment") == "multi_family_behavior_markers":
            add("pe_feature_families", "В секциях PE найдены строки нескольких групп игровых функций", path,
                "Исследуйте контекст строк и издателя. Это статические признаки, не подтверждение исполнения функций.",
                {"markers": record.get("feature_markers", []), "families": record.get("feature_families", [])},
                record.get("sha256"))
        if record.get("feature_markers"):
            add("pe_feature_strings", "В EXE/DLL найдены строки игровых функций", path,
                "Строки могут быть частью документации или несвязанного ПО. Они приведены для ручной проверки.",
                {"markers": record.get("feature_markers", []), "families": record.get("feature_families", [])},
                record.get("sha256"))
        if record.get("assessment") == "recognized_launcher_metadata":
            add("recognized_launcher", "Обнаружен известный Minecraft-лаунчер", path,
                "Метаданные указывают на известный лаунчер. Это запись инвентаризации.",
                {"launcher_identity": record.get("launcher_identity"), "metadata": record.get("metadata", {})})

    for record in pack_records:
        path = record.get("path")
        assessment = record.get("assessment")
        if assessment == "xray_like_texture_pattern":
            add("xray_texture_pattern", "Текстуры ресурс-пака образуют X-Ray-подобный рисунок", path,
                (record.get("notes") or ["Обычные блоки прозрачны, а текстуры руд остаются видимыми."])[0],
                {
                    "texture_checks": record.get("texture_checks", []),
                    "solid_textures_examined": record.get("solid_textures_examined", 0),
                    "ore_textures_examined": record.get("ore_textures_examined", 0),
                    "transparent_solid_textures": record.get("transparent_solid_textures", 0),
                    "opaque_ore_textures": record.get("opaque_ore_textures", 0),
                    "pack_format": record.get("pack_format"),
                    "metadata_description": record.get("metadata_description", ""),
                })
        elif assessment == "xray_like_model_pattern":
            add("xray_model_pattern", "Модели базовых блоков ресурс-пака пусты (блоки не рисуются)", path,
                (record.get("notes") or ["Модели блоков не содержат элементов."])[0],
                {
                    "blank_block_models": record.get("blank_block_models", []),
                    "models_examined": record.get("models_examined", 0),
                    "pack_format": record.get("pack_format"),
                    "metadata_description": record.get("metadata_description", ""),
                })
        elif assessment == "partial_texture_anomalies":
            add("xray_texture_clues", "В ресурс-паке есть отдельные прозрачные блоки при видимых рудах", path,
                (record.get("notes") or ["Найдены отдельные особенности текстур."])[0],
                record.get("texture_checks", []))
        elif assessment == "pack_name_or_metadata_hint":
            add("resource_pack_name_hint", "Название или описание ресурс-пака содержит X-Ray/ore-термин", path,
                (record.get("notes") or ["Название требует проверки содержимого."])[0],
                {"hints": record.get("metadata_hints", []), "description": record.get("metadata_description", "")})

    known_paths = set(_norm_path(item.get("path", "")) for item in list(filename_markers) + list(directory_markers))
    trace_titles = {
        "file": "Файл с названием, похожим на X-Ray/клиент",
        "directory": "Папка с названием, похожим на X-Ray/клиент",
        "deleted_file": "В корзине найден удалённый файл с подозрительным названием",
        "recent_link": "В недавних файлах есть запись с подозрительным названием",
        "prefetch_record": "В Prefetch есть запись запуска программы с подозрительным названием",
        "disguised_archive": "ZIP-ресурс-пак скрыт под нетипичным именем файла",
    }
    trace_categories = {
        "file": "name_trace_file", "directory": "name_trace_file", "deleted_file": "name_trace_deleted",
        "recent_link": "name_trace_recent", "prefetch_record": "name_trace_execution",
        "disguised_archive": "disguised_archive",
    }
    trace_notes = {
        "file": "Название совпало с шаблоном X-Ray/клиента. Это зацепка по имени; содержимое проверяется отдельно, если файл является архивом.",
        "directory": "Название каталога совпало с шаблоном. Каталог мог быть создан для чего угодно.",
        "deleted_file": "Файл удалён, но запись корзины сохранила исходное имя и путь. Удаление не доказывает использование.",
        "recent_link": "Windows запомнила обращение к файлу с таким именем (открытие через проводник или приложение).",
        "prefetch_record": "Prefetch означает, что программа с таким именем запускалась. Содержимое файла нужно проверять отдельно.",
        "disguised_archive": "Файл имеет ZIP-сигнатуру и структуру ресурс-пака Minecraft, но расширение/имя нейтральное.",
    }
    for record in trace_records or []:
        kind = record.get("kind", "file")
        if kind in ("file", "directory") and _norm_path(record.get("path", "")) in known_paths:
            continue
        add(trace_categories.get(kind, "name_trace_file"), trace_titles.get(kind, "След по названию"),
            record.get("original_path") or record.get("path"), trace_notes.get(kind, "Совпадение по названию."),
            {key: record.get(key) for key in (
                "name", "leads", "path", "original_path", "deleted_at", "modified", "size_bytes", "target_hint", "source",
            ) if record.get(key) is not None})

    for record in filename_markers:
        add("client_filename_match", "Имя файла совпало с названием клиентского проекта", record.get("path"),
            "Совпадение только по имени файла. Содержимое и запуск должны проверяться отдельно.", record)
    for record in directory_markers:
        add("client_directory_match", "Название каталога совпало с названием клиентского проекта", record.get("path"),
            "Название каталога не идентифицирует его содержимое.", record.get("client_markers", []))
    for record in runtime_configs:
        add("java_runtime_config", "В конфигурации Minecraft найден внешний Java agent/runtime аргумент", record.get("path"),
            record.get("interpretation", "Параметр запуска требует изучения."),
            {"flags": record.get("flags", []), "targets": record.get("targets", [])})
    for record in running_processes:
        if record.get("client_markers"):
            add("running_client_process", "В активном процессе найден маркер клиентского проекта",
                record.get("executable") or record.get("name"),
                "Маркер найден в имени/пути или Java command line. Память процесса не анализировалась.",
                record.get("client_markers", []))
        if record.get("java_injection_flags"):
            add("java_runtime_injection", "Minecraft запущен с внешним Java agent/runtime аргументом",
                record.get("executable") or record.get("name"),
                "Изучите указанный путь и подпись файла: такие параметры также применяются профайлерами и некоторыми модификациями.",
                {"pid": record.get("pid"), "flags": record.get("java_injection_flags"), "command_line": record.get("java_command_line", "")})
    for record in prefetch_traces:
        if record.get("client_markers"):
            add("historical_client_trace", "В системной истории обнаружено название клиентского проекта",
                record.get("path"), record.get("interpretation", "Историческая запись требует контекста."),
                record.get("client_markers"))
    for record in (script_records or []):
        if record.get("assessment") == "minecraft_input_automation_script":
            add("minecraft_automation_script", "Скрипт содержит признаки автоматизации ввода для Minecraft", record.get("path"),
                (record.get("notes") or ["Содержимое требует ручной проверки."])[0],
                {
                    "game_context": record.get("game_context_matches", []),
                    "automation_apis": record.get("automation_api_matches", []),
                    "actions": record.get("action_matches", []),
                })
        elif record.get("assessment") == "generic_input_automation_script":
            add("generic_automation_script", "Найден скрипт автоматизации ввода без подтверждённой связи с Minecraft", record.get("path"),
                (record.get("notes") or ["Содержимое требует ручной проверки."])[0], record)
    for record in (policy_software or []):
        add("context_dependent_software", "Обнаружено ПО двойного назначения", record.get("display_name"),
            record.get("interpretation", "Наличие ПО не доказывает его запрещённое использование."), record)

    return findings

def _running_minecraft_processes():
    """List matching process metadata only; do not inspect or alter process memory."""
    try:
        import psutil
    except Exception:
        return []
    results = []
    try:
        for process in psutil.process_iter(attrs=["pid", "name", "exe", "cmdline"]):
            try:
                info = process.info
                process_name = str(info.get("name") or "")
                executable = str(info.get("exe") or "")
                probe = process_name + " " + executable

                java_command = ""
                if process_name.lower() in ("java.exe", "javaw.exe"):
                    java_command = " ".join(info.get("cmdline") or [])
                    probe += " " + java_command
                launcher = _launcher_label(probe)
                client_markers = find_known_client_markers(probe)
                probe_low = probe.lower()
                java_minecraft = process_name.lower() in ("java.exe", "javaw.exe") and any(
                    token in java_command.lower() for token in (
                        "net.minecraft.client", "minecraft.client", "--gamedir", "minecraftforge",
                    )
                )
                java_injection_flags = []
                if java_minecraft:
                    command_low = java_command.lower()
                    for flag in ("-javaagent:", "-agentpath:", "-agentlib:", "-xbootclasspath:", "-xbootclasspath/p:"):
                        if flag in command_low:
                            java_injection_flags.append(flag)
                if launcher or client_markers or "minecraft" in probe_low or java_minecraft:
                    results.append({
                        "pid": info.get("pid"),
                        "name": info.get("name"),
                        "executable": info.get("exe"),
                        "launcher_marker": launcher,
                        "client_markers": client_markers,
                        "java_minecraft_process": bool(java_minecraft),
                        "java_injection_flags": java_injection_flags,
                        "java_command_line": java_command[:4000] if java_minecraft else "",
                        "evidence_type": "process metadata",
                        "interpretation": "Совпадение имени/пути процесса; не является анализом памяти или доказательством читерства.",
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    except Exception:
        return results
    return results

def scan_inventory(progress_callback=None, full_scan=False):
    started = datetime.datetime.now()
    budget = ScanBudget(full_scan=full_scan)
    _emit(progress_callback, "Поиск известных директорий Minecraft и лаунчеров...")
    launcher_dirs = _existing_directories(_candidate_directories())
    launcher_registry = _registry_launcher_entries()
    shortcuts = _start_menu_shortcuts()
    roots = list(launcher_dirs)

    deep_result = {
        "drives": [], "launcher_directories": [], "game_roots": [],
        "launcher_files": [], "script_candidates": [], "filename_markers": [], "client_directory_markers": [],
        "global_archive_candidates": [], "global_archive_counts": {"jar": 0, "zip": 0},
        "global_pe_candidates": [], "global_pe_count": 0,
        "archive_candidate_limits": {"jar_limit_reached": False, "zip_limit_reached": False},
        "visited_directories": 0,
        "visited_files": 0, "skipped_directories": 0, "candidate_files_seen": 0,
        "scan_roots": [], "scan_mode": "quick_user_and_launcher_roots",
        "system_directories_excluded": True, "non_candidate_extensions_skipped": True,
    }
    deep_result = _discover_drive_artifacts(progress_callback, full_scan=full_scan, registry_entries=launcher_registry, budget=budget)
    trace_result = {"traces": [], "pack_candidates": [], "stats": {}, "prefetch_available": False}
    if not budget.expired():
        try:
            trace_result = run_trace_scan(drives=deep_result.get("drives", []), full_scan=full_scan, progress_callback=progress_callback)
        except Exception as exc:
            _emit(progress_callback, "Поиск следов остановлен: {}".format(type(exc).__name__))
    candidate_keys = set(_norm_path(item.get("path", "")) for item in deep_result.get("global_archive_candidates", []))
    for candidate in trace_result.get("pack_candidates", []):
        candidate_key = _norm_path(candidate.get("path", ""))
        if candidate_key not in candidate_keys:
            candidate_keys.add(candidate_key)
            deep_result["global_archive_candidates"].append(candidate)
    global_pack_records = _analyze_global_resource_packs(
        deep_result.get("global_archive_candidates", []),
        already_analyzed=[],
        progress_callback=progress_callback,
        budget=budget,
    )
    launcher_dirs.extend(deep_result["launcher_directories"])
    roots.extend(deep_result["game_roots"])

    if budget.expired():
        everything_result = {"status": "skipped_time_budget", "message": "Пропущен: исчерпан лимит времени проверки.", "paths": []}
    else:
        everything_result = scan_with_everything(progress_callback)
    everything_launcher_paths = []
    everything_markers = []
    everything_directories = []
    for result in everything_result.get("paths", []):
        result_path = result.get("path", "")
        if not result_path or _is_excluded_scan_path(result_path):
            continue
        if os.path.isfile(result_path) and not _is_scannable_file(result_path):
            continue
        if result.get("launcher"):
            candidate_dir = result_path if os.path.isdir(result_path) else os.path.dirname(result_path)
            if os.path.isdir(candidate_dir):
                everything_launcher_paths.append({
                    "name": result.get("launcher"), "path": candidate_dir, "discovery": "Everything index"
                })
        if result.get("client_markers"):
            if os.path.isdir(result_path):
                everything_directories.append({
                    "path": result_path, "name": result.get("name"),
                    "client_markers": result.get("client_markers"), "discovery": "Everything index",
                })
            else:
                everything_markers.append({
                    "path": result_path, "name": result.get("name"),
                    "marker": result.get("client_markers")[0].get("marker"), "discovery": "Everything index",
                })
    launcher_dirs.extend(everything_launcher_paths)
    roots.extend(everything_launcher_paths)
    deep_result["filename_markers"].extend(everything_markers)
    deep_result["client_directory_markers"].extend(everything_directories)

    for entry in launcher_registry:
        location = entry.get("install_location")
        if location and os.path.isdir(location):
            roots.append({"name": entry.get("name", "Launcher"), "path": location, "discovery": "registry"})

    _emit(progress_callback, "Поиск вложенных игровых директорий и portable-клиентов...")
    expanded_roots = []
    root_seen = set()
    for root in roots:
        if budget.expired():
            _emit(progress_callback, "Достигнут общий лимит времени поиска игровых корней.")
            break
        path = root.get("path", "")
        key = _norm_path(path)
        if key not in root_seen:
            root_seen.add(key)
            expanded_roots.append(root)
        if not os.path.isdir(path):
            continue
        visited = 0
        for current, dirs, files in os.walk(path, topdown=True, onerror=_safe_walk_error):
            if budget.expired():
                break
            visited += 1
            depth = current[len(path):].count(os.sep)
            dirs[:] = [name for name in dirs if name.lower() not in GAME_HEAVY_DIRS and name.lower() not in IGNORED_DIRS]
            dirs.sort(key=_walk_dir_priority)
            if depth >= MAX_ROOT_DEPTH or visited >= 2500:
                dirs[:] = []
            if _looks_like_game_root(current, dirs):
                found_key = _norm_path(current)
                if found_key not in root_seen:
                    root_seen.add(found_key)
                    expanded_roots.append({"name": root.get("name", "Minecraft"), "path": current, "discovery": "nested_game_root"})

    hash_entries = load_hash_database()
    installations, archive_records, pack_records = _collect_installations(expanded_roots, progress_callback, hash_entries=hash_entries, budget=budget)
    _emit(progress_callback, "Проверка JVM-аргументов в конфигурациях Minecraft...")
    runtime_configs = analyze_runtime_configs(installations)
    already_analyzed = [_norm_path(item.get("path", "")) for item in archive_records]
    global_archive_records = _analyze_global_archives(
        deep_result.get("global_archive_candidates", []), already_analyzed, progress_callback, hash_entries=hash_entries, budget=budget
    )
    archive_records.extend(global_archive_records)
    pack_paths = set(_norm_path(item.get("path", "")) for item in pack_records)
    for pack_record in global_pack_records:
        pack_key = _norm_path(pack_record.get("path", ""))
        if pack_key not in pack_paths:
            pack_records.append(pack_record)
            pack_paths.add(pack_key)
    _emit(progress_callback, "Анализ метаданных EXE/DLL без запуска файлов...")
    pe_records = _analyze_global_pes(
        deep_result.get("global_pe_candidates", []),
        hash_entries=hash_entries,
        progress_callback=progress_callback,
        budget=budget,
    )
    for pe_record in pe_records:
        launcher_identity = pe_record.get("launcher_identity")
        if launcher_identity:
            launcher_path = pe_record.get("path", "")
            launcher_dir = os.path.dirname(launcher_path)
            deep_result["launcher_files"].append({
                "name": pe_record.get("name"),
                "path": launcher_path,
                "launcher": launcher_identity,
                "discovery": "PE version metadata",
            })
            if os.path.isdir(launcher_dir):
                launcher_dirs.append({
                    "name": launcher_identity,
                    "path": launcher_dir,
                    "discovery": "PE version metadata",
                })
    _emit(progress_callback, "Проверка скриптов автоматизации и активных Minecraft-процессов...")
    script_records = analyze_script_candidates(deep_result.get("script_candidates", []))

    prefetch_traces = []
    policy_software = _registry_context_software()
    running_processes = _running_minecraft_processes()
    findings = _make_findings(
        archive_records, pack_records, deep_result["filename_markers"],
        deep_result["client_directory_markers"], prefetch_traces, running_processes,
        pe_records, hash_entries, runtime_configs, policy_software=policy_software,
        script_records=script_records, trace_records=trace_result.get("traces", []),
    )

    launcher_unique = {}
    for entry in launcher_dirs:
        launcher_unique[_norm_path(entry.get("path", ""))] = entry
    game_count = len(installations)
    versions_total = sum(len(item.get("versions", [])) for item in installations)
    mods_total = sum(len(item.get("mods", [])) for item in installations)
    packs_total = sum(len(item.get("resource_packs", [])) + len(item.get("shader_packs", [])) for item in installations) + len(global_pack_records)
    elapsed = (datetime.datetime.now() - started).total_seconds()
    per_install_limits_reached = any(item.get("scan_limits_reached") for item in installations)
    directory_or_file_budget_reached = (
        deep_result.get("visited_directories", 0) >= (MAX_FULL_SCAN_DIRECTORIES if full_scan else MAX_QUICK_SCAN_DIRECTORIES)
        or deep_result.get("candidate_files_seen", 0) >= (MAX_FULL_SCAN_FILES if full_scan else MAX_QUICK_SCAN_FILES)
    )
    global_candidate_limit_reached = any(deep_result.get("archive_candidate_limits", {}).values()) or deep_result.get("global_pe_count", 0) >= MAX_GLOBAL_PES
    partial_reasons = []
    if budget.expired():
        partial_reasons.append("общий лимит времени")
    if per_install_limits_reached:
        partial_reasons.append("лимит архивов одной игровой установки")
    if directory_or_file_budget_reached:
        partial_reasons.append("лимит обхода каталогов/файлов")
    if global_candidate_limit_reached:
        partial_reasons.append("лимит глобальных кандидатов")
    partial_scan = bool(partial_reasons)

    category_counts = {}
    for finding in findings:
        category = finding.get("category", "other")
        category_counts[category] = category_counts.get(category, 0) + 1
    if findings:
        verdict = "Проверка завершена: обнаружено записей для ручного просмотра — {}".format(len(findings))
    else:
        verdict = "В проверенном объёме зарегистрированных индикаторов не найдено"
    if partial_scan:
        verdict = "ЧАСТИЧНЫЙ РЕЗУЛЬТАТ ({}): {}".format(", ".join(partial_reasons), verdict)

    report = {
        "product": "SentinelXT",
        "version": PRODUCT_VERSION,
        "build": BUILD_NUMBER,
        "build_label": VERSION_LABEL,
        "report_type": "minecraft_forensic_inventory",
        "created_at": datetime.datetime.now().isoformat(),
        "duration_seconds": round(elapsed, 2),
        "partial_scan": partial_scan,
        "partial_reasons": partial_reasons,
        "computer": os.environ.get("COMPUTERNAME", "unknown"),
        "user_profile": os.path.expanduser("~"),
        "scan_scope": {
            "full_local_drive_scan": bool(full_scan),
            "time_budget_seconds": budget.seconds,
            "time_budget_exhausted": budget.expired(),
            "per_install_archive_limits_reached": per_install_limits_reached,
            "directory_or_file_budget_reached": directory_or_file_budget_reached,
            "global_candidate_limit_reached": global_candidate_limit_reached,
            "partial_reasons": partial_reasons,
            "scan_mode": deep_result.get("scan_mode"),
            "scan_roots": deep_result.get("scan_roots", []),
            "drives_detected": deep_result["drives"],
            "visited_directories": deep_result["visited_directories"],
            "visited_files": deep_result["visited_files"],
            "candidate_files_seen": deep_result.get("candidate_files_seen", 0),
            "skipped_directories": deep_result.get("skipped_directories", 0),
            "system_directories_excluded": True,
            "ignored_extensions": sorted(IGNORED_EXTENSIONS),
            "allowed_candidate_extensions": sorted(SCANNABLE_SUFFIXES),
            "appdata_discovery_max_depth": 2,
            "minecraft_library_jars_skipped_by_default": True,
            "archive_entries_limit": 1800,
            "resource_pack_entries_limit": 6000,
            "resource_pack_texture_file_limit": 26,
            "resource_pack_texture_total_read_limit_bytes": 8 * 1024 * 1024,
            "resource_pack_analysis_time_limit_seconds": 3.0,
            "unpacked_resource_pack_support": True,
            "archive_uncompressed_read_limit_bytes": 1 * 1024 * 1024,
            "archive_analysis_time_limit_seconds": 0.35,
            "mod_archives_per_installation_limit": MAX_MOD_ARCHIVES_PER_INSTALLATION,
            "resource_packs_per_installation_limit": MAX_PACK_ARCHIVES_PER_INSTALLATION,
            "global_resource_pack_analysis_limit": 25,
            "global_resource_pack_candidate_contexts": ["Minecraft", "resourcepacks on secondary local drives", "Downloads", "Desktop", "Documents", "launcher/game folders"],
            "version_archives_per_installation_limit": MAX_VERSION_ARCHIVES_PER_INSTALLATION,
            "appdata_discovery_directory_budget_per_root": 900,
            "quick_scan_directory_budget": MAX_QUICK_SCAN_DIRECTORIES,
            "quick_scan_time_budget_seconds": 60,
            "quick_scan_candidate_file_budget": MAX_QUICK_SCAN_FILES,
            "full_scan_directory_budget": MAX_FULL_SCAN_DIRECTORIES,
            "extended_scan_time_budget_seconds": 120,
            "full_scan_candidate_file_budget": MAX_FULL_SCAN_FILES,
            "prefetch_scanned": bool(trace_result.get("prefetch_available")),
            "name_trace_scan": trace_result.get("stats", {}),
            "recycle_bin_scanned": True,
            "global_archives_considered": len(deep_result.get("global_archive_candidates", [])),
            "global_archive_counts": deep_result.get("global_archive_counts", {}),
            "global_pe_candidates": deep_result.get("global_pe_count", 0),
            "pe_candidate_limit": MAX_GLOBAL_PES,
            "yara_archives_shortlist_only": True,
            "pe_priority_candidate_limit": MAX_PRIORITY_PES,
            "pe_general_candidate_limit": MAX_GENERAL_PES,
            "yara_pe_scan_limit": MAX_YARA_PE_FILES,
            "yara_archive_scan_limit": MAX_YARA_ARCHIVES,
            "archive_candidate_limits": deep_result.get("archive_candidate_limits", {}),
            "limitations": [
                "Windows, System32, SysWOW64, System Volume Information, Recovery и системные каталоги не обходятся. Корзина анализируется только по записям $I (исходные имена и пути), Prefetch — только при наличии доступа к C:\\Windows\\Prefetch (нужны права администратора).",
                "В стандартном режиме проверяются игровые каталоги, Desktop/Downloads/Documents/Games и найденные папки лаунчеров; расширенный режим добавляет профили пользователей и другие локальные диски, сохраняя системные исключения.",
                "PNG/JPG/GIF/BMP/WebP, ICO, аудио, видео, PDF, офисные документы, 3D-модели и образы дисков не анализируются.",
                "Сетевые диски и облачные файлы, не загруженные локально, не сканируются этим режимом.",
                "Библиотеки Minecraft (libraries) и assets не обходятся как массив кандидатов; в игровых каталогах анализируются versions, mods, resourcepacks и shaderpacks.",
                "Анализ модов и версий ограничен 1 800 записями, 1 МиБ распакованных данных и 0,35 секунды на архив. Ресурс-паки (ZIP и распакованные каталоги) проверяются отдельным анализатором: до 6 000 записей, 26 целевых текстур, 8 МиБ чтения и 3 секунды на пак; в одной установке проверяется до 10 ресурс-паков и до 10 шейдерных архивов.",
                "Быстрая проверка имеет общий лимит 60 секунд; расширенная — 120 секунд. При достижении временного или файлового лимита отчёт помечается как частичный; это не означает чистый результат.",
                "YARA применяется максимум к 4 архивам и 4 PE-файлам с предварительными признаками; время каждого запуска ограничено 1 секундой.",
                "Глобальный статический анализ ограничен 60 JAR, 30 ZIP и 60 PE-кандидатами (приоритет пользовательским и Minecraft-каталогам); игровые каталоги проверяются отдельно.",
                "PE-анализ читает метаданные и до 2 МиБ секций на файл; YARA запускается максимум для 4 PE-файлов и 4 архивов.",
                "PE-анализ не является полноценным динамическим анализом программы или проверкой цифровой подписи.",
                "Сканирование ограничено бюджетом каталогов/файлов и лимитами кандидатов для защиты от чрезмерно долгого анализа.",
                "Удалённые данные и содержимое оперативной памяти этим режимом не исследуются.",
                "Название клиента или совпадение сигнатуры не доказывает, что игрок запускал его во время игры.",
            ],
        },
        "summary": {
            "launcher_directories": len(launcher_unique),
            "launcher_registry_entries": len(launcher_registry),
            "launcher_shortcuts": len(shortcuts),
            "launcher_executables": len(deep_result["launcher_files"]),
            "game_directories": game_count,
            "versions": versions_total,
            "mod_archives": mods_total,
            "resource_and_shader_packs": packs_total,
            "archive_checks": len(archive_records),
            "pe_checks": len(pe_records),
            "runtime_config_injection_flags": len(runtime_configs),
            "yara_matches": sum(len(item.get("yara", {}).get("matches", [])) for item in pe_records) + sum(len(item.get("yara_matches", [])) for item in archive_records),
            "running_minecraft_processes": len(running_processes),
            "context_dependent_software": len(policy_software),
            "allow_listed_mods": sum(1 for item in archive_records if item.get("assessment") == "allow_listed_mod"),
            "gray_zone_mods": sum(1 for item in archive_records if item.get("assessment") == "gray_zone_mod_identifier"),
            "ambiguous_client_metadata": sum(1 for item in archive_records if item.get("assessment") == "ambiguous_client_metadata"),
            "script_candidates_examined": len(deep_result.get("script_candidates", [])),
            "script_automation_indicators": len(script_records),
            "total_findings": len(findings),
            "finding_category_counts": category_counts,
        },
        "verdict": verdict,
        "integrations": {
            "everything": everything_result,
            "yara": {
                "available": yara_available(),
                "pe_scan_limit": MAX_YARA_PE_FILES,
                "archive_scan_limit": MAX_YARA_ARCHIVES,
            },
        },
        "launcher_directories": list(launcher_unique.values()),
        "launcher_registry": launcher_registry,
        "launcher_shortcuts": shortcuts,
        "launcher_executables": deep_result["launcher_files"],
        "filename_markers": deep_result["filename_markers"],
        "client_directory_markers": deep_result["client_directory_markers"],
        "running_processes": running_processes,
        "installations": installations,
        "archive_analyses": archive_records,
        "pe_analyses": pe_records,
        "runtime_config_analyses": runtime_configs,
        "resource_pack_analyses": pack_records,
        "global_resource_pack_analyses": global_pack_records,
        "prefetch_traces": prefetch_traces,
        "context_dependent_software": policy_software,
        "script_analyses": script_records,
        "policy_registry": {
            "registry_id": load_policy_registry().get("registry_id"),
            "source_url": load_policy_registry().get("source_url"),
            "source_date": load_policy_registry().get("source_date"),
            "prohibited_client_count": len(load_policy_registry().get("prohibited_clients", [])),
            "exact_prohibited_mod_id_count": len(load_policy_registry().get("exact_prohibited_mod_ids", [])),
            "allowed_mod_count": len(load_policy_registry().get("allowed_mods", [])),
            "gray_zone_count": len(load_policy_registry().get("gray_zone", [])),
            "feature_category_count": len(load_policy_registry().get("prohibited_feature_families", {})),
        },
        "findings": findings,
        "interpretation": (
            "SentinelXT 0.1.4 performs bounded user/game discovery, server-policy archive identity checks, PE metadata inspection and resource-pack texture heuristics. "
            "Exact filename matches are weak clues only; generic names such as xray.exe are not classified as cheats. "
            "Resource-pack ZIP files and unpacked pack folders are inspected for X-Ray-like block texture transparency patterns. Legacy resource-pack ZIPs are also discovered in resourcepacks folders on secondary local drives, including packs without pack.mcmeta when legacy block texture paths are present. "
            "Texture anomalies and class-string matches are listed separately in the Results page. "
            "A finding is an investigative lead, not an automatic ban decision. "
            "Findings are not ranked; each record shows the matched data and evidence for administrator review. If partial_scan is true, the report is incomplete and a no-findings result must not be interpreted as clean. "
            "Windows/system/cache directories and common media/document extensions are skipped. No discovered file is executed, changed, deleted, or uploaded."
        ),
    }
    _emit(progress_callback, "Анализ завершён: найдено записей {} · архивов проверено {} · PE-файлов проверено {}.".format(len(findings), len(archive_records), len(pe_records)))
    return report
