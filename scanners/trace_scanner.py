
"""Name-based and structure-based trace search that does not depend on a file being in a game folder.

Sources: user folders and Temp, other local drives, Recycle Bin ($I records keep the original
name of deleted files), Recent-file shortcuts, Prefetch execution records, and ZIP files that
look like resource packs even when renamed. Nothing is executed or modified.
A name or a trace is a lead for the administrator, not proof.
"""
import datetime
import os
import re
import struct
import time
import zipfile
from collections import deque

from scanners.name_matcher import xray_name_hints
from scanners.signature_engine import find_known_client_markers

ARCHIVE_EXTENSIONS = (".zip", ".mrpack", ".jar", ".rar", ".7z", ".tar", ".gz")
LEAD_EXTENSIONS = ARCHIVE_EXTENSIONS + (
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".lnk", ".lua", ".ahk", ".py", ".json", ".txt", "",
)
DISGUISE_EXTENSIONS = (
    "", ".dat", ".bin", ".tmp", ".bak", ".old", ".data", ".res", ".pak", ".cache", ".db",
    ".txt", ".log", ".dll", ".sys", ".tmp", ".temp", ".backup", ".bk",
)
SKIP_DIRS = set((
    "windows", "winsxs", "system32", "syswow64", "$windows.~bt", "$windows.~ws", "system volume information",
    "node_modules", ".git", "__pycache__", ".venv", "venv", "windowsapps", "assembly", "servicing",
    "gpucache", "code cache", "shadercache", "dawncache", "grshadercache", "installer", "$recycle.bin",
    "config.msi", "perflogs", "recovery", "microsoft.net", "inetcache", "crashpad",
))
SKIP_TOP_LEVEL = set(("program files", "program files (x86)"))
ZIP_MAGIC = b"PK\x03\x04"
MAX_ENTRY_NAME = 160
MIN_DISGUISED_BYTES = 20 * 1024
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024

def _iso(timestamp):
    try:
        return datetime.datetime.fromtimestamp(float(timestamp)).isoformat(timespec="seconds")
    except Exception:
        return None

def name_leads(name, is_directory=False):
    """Return lead descriptors for a file/folder name or an empty list."""
    leads = []
    text = str(name or "")
    if not text or len(text) > MAX_ENTRY_NAME:
        return leads
    ext = os.path.splitext(text.lower())[1]
    for hint in xray_name_hints(text):
        leads.append({"type": "xray_name", "hint": hint})
    if is_directory or ext in LEAD_EXTENSIONS:
        for item in find_known_client_markers(text):
            leads.append({"type": "client_name", "hint": item.get("name"), "marker": item.get("marker")})
    return leads

def looks_like_resource_pack_zip(path):
    try:
        with zipfile.ZipFile(path, "r") as archive:
            names = [item.filename.replace("\\", "/").lower() for item in archive.infolist()[:6000] if not item.is_dir()]
    except Exception:
        return False
    has_meta = any(name.endswith("pack.mcmeta") for name in names)
    block_names = ("stone.png", "dirt.png", "netherrack.png", "end_stone.png", "deepslate.png", "cobblestone.png",
                   "diamond_ore.png", "iron_ore.png", "gold_ore.png", "coal_ore.png", "deepslate_diamond_ore.png")
    found = set()
    for name in names:
        normalized = "/" + name.lstrip("/")
        if "/textures/block/" in normalized or "/textures/blocks/" in normalized:
            tail = normalized.rsplit("/", 1)[-1]
            if tail in block_names:
                found.add(tail)
    has_models = any("/models/block/" in "/" + name for name in names)
    return bool((has_meta and (found or has_models)) or len(found) >= 2)

def _is_zip_magic(path):
    try:
        with open(path, "rb") as stream:
            return stream.read(4) == ZIP_MAGIC
    except (IOError, OSError):
        return False

def scan_filesystem_names(roots, seconds=20.0, max_entries=200000, max_depth=7,
                          structural_zip_limit=400, magic_check_limit=300, progress_callback=None):
    """Walk roots breadth-first, matching names and testing ZIP structure."""
    started = time.time()
    traces = []
    pack_candidates = []
    stats = {"entries": 0, "structural_zip_checks": 0, "magic_checks": 0, "truncated": False}
    seen = set()
    candidate_paths = set()
    queue = deque()
    for root in roots:
        if root and os.path.isdir(root):
            queue.append((root, 0, True))
    while queue:
        if time.time() - started > seconds or stats["entries"] >= max_entries:
            stats["truncated"] = True
            break
        current, depth, is_root = queue.popleft()
        key = os.path.normcase(os.path.abspath(current))
        if key in seen:
            continue
        seen.add(key)
        try:
            entries = list(os.scandir(current))
        except (OSError, PermissionError):
            continue
        for entry in entries:
            stats["entries"] += 1
            name = entry.name
            lowered = name.lower()
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
            except OSError:
                continue
            if is_dir:
                if lowered in SKIP_DIRS:
                    continue
                if is_root and depth == 0 and lowered in SKIP_TOP_LEVEL:
                    continue
                leads = name_leads(name, True)
                if leads:
                    traces.append({"kind": "directory", "path": entry.path, "name": name,
                                   "leads": leads, "source": "filesystem", "modified": _iso(_safe_mtime(entry))})
                if depth < max_depth:
                    queue.append((entry.path, depth + 1, False))
                continue
            leads = name_leads(name, False)
            ext = os.path.splitext(lowered)[1]
            size = None
            if leads:
                size = _safe_size(entry)
                traces.append({"kind": "file", "path": entry.path, "name": name, "leads": leads,
                               "size_bytes": size, "source": "filesystem", "modified": _iso(_safe_mtime(entry)),
                               "archive": ext in ARCHIVE_EXTENSIONS})
                if ext in (".zip", ".mrpack") and (size or 0) <= MAX_ARCHIVE_BYTES:
                    candidate_paths.add(entry.path)
                    pack_candidates.append({"path": entry.path, "name": name, "kind": "global_zip", "via": "name_match"})
            if ext in (".zip", ".mrpack") and stats["structural_zip_checks"] < structural_zip_limit:
                if size is None:
                    size = _safe_size(entry)
                if 300 <= (size or 0) <= MAX_ARCHIVE_BYTES and entry.path not in candidate_paths:
                    stats["structural_zip_checks"] += 1
                    if looks_like_resource_pack_zip(entry.path):
                        candidate_paths.add(entry.path)
                        pack_candidates.append({"path": entry.path, "name": name, "kind": "global_zip", "via": "structure"})
            elif ext in DISGUISE_EXTENSIONS and stats["magic_checks"] < magic_check_limit:
                if size is None:
                    size = _safe_size(entry)
                if MIN_DISGUISED_BYTES <= (size or 0) <= MAX_ARCHIVE_BYTES:
                    stats["magic_checks"] += 1
                    if _is_zip_magic(entry.path) and looks_like_resource_pack_zip(entry.path):
                        traces.append({"kind": "disguised_archive", "path": entry.path, "name": name,
                                       "leads": [{"type": "disguised_zip", "hint": "ZIP-структура ресурс-пака"}],
                                       "size_bytes": size, "source": "filesystem",
                                       "modified": _iso(_safe_mtime(entry))})
                        pack_candidates.append({"path": entry.path, "name": name, "kind": "global_resource_pack", "via": "magic"})
        if progress_callback and stats["entries"] % 20000 < len(entries):
            progress_callback("Поиск по названиям: просмотрено {} элементов".format(stats["entries"]))
    return {"traces": traces, "pack_candidates": pack_candidates, "stats": stats}

def _safe_mtime(entry):
    try:
        return entry.stat(follow_symlinks=False).st_mtime
    except OSError:
        return None

def _safe_size(entry):
    try:
        return entry.stat(follow_symlinks=False).st_size
    except OSError:
        return None

def parse_recycle_info(data):
    """Parse a Recycle Bin $I record (version 1 for Win7/8, version 2 for Win10/11)."""
    if not data or len(data) < 28:
        return None
    try:
        version = struct.unpack("<Q", data[:8])[0]
        size = struct.unpack("<Q", data[8:16])[0]
        filetime = struct.unpack("<Q", data[16:24])[0]
        if version == 2:
            length = struct.unpack("<I", data[24:28])[0]
            raw = data[28:28 + length * 2]
        elif version == 1:
            raw = data[24:24 + 520]
        else:
            return None
        original = raw.decode("utf-16-le", "ignore").split("\x00", 1)[0]
    except Exception:
        return None
    deleted = None
    if filetime:
        try:
            deleted = (datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=filetime // 10)).isoformat(timespec="seconds")
        except Exception:
            deleted = None
    return {"original_path": original, "size_bytes": size, "deleted_at": deleted, "version": version}

def scan_recycle_bin(drive_roots):
    traces = []
    for drive in drive_roots:
        bin_root = os.path.join(drive, "$Recycle.Bin")
        try:
            owners = list(os.scandir(bin_root))
        except (OSError, PermissionError):
            continue
        for owner in owners:
            try:
                items = list(os.scandir(owner.path))
            except (OSError, PermissionError):
                continue
            for item in items:
                if not item.name.upper().startswith("$I"):
                    continue
                try:
                    with open(item.path, "rb") as stream:
                        info = parse_recycle_info(stream.read(1200))
                except (IOError, OSError):
                    continue
                if not info or not info.get("original_path"):
                    continue
                original_name = os.path.basename(info["original_path"].replace("\\", "/"))
                leads = name_leads(original_name, False) or name_leads(info["original_path"].replace("\\", " ").replace("/", " "), False)
                if leads:
                    traces.append({"kind": "deleted_file", "path": item.path, "name": original_name, "leads": leads,
                                   "original_path": info["original_path"], "deleted_at": info.get("deleted_at"),
                                   "size_bytes": info.get("size_bytes"), "source": "recycle_bin"})
    return traces

def _lnk_target(path):
    try:
        with open(path, "rb") as stream:
            data = stream.read(65536)
    except (IOError, OSError):
        return None
    for raw in (data.decode("latin-1", "ignore"), data.decode("utf-16-le", "ignore")):
        found = re.search(r"[A-Za-z]:\\[^\x00\r\n\"<>|?*]{3,240}", raw)
        if found:
            return found.group(0)
    return None

def scan_recent_links(recent_dir):
    traces = []
    try:
        entries = list(os.scandir(recent_dir))
    except (OSError, PermissionError, TypeError):
        return traces
    for entry in entries:
        if not entry.name.lower().endswith(".lnk"):
            continue
        base = entry.name[:-4]
        leads = name_leads(base, False)
        if leads:
            traces.append({"kind": "recent_link", "path": entry.path, "name": base, "leads": leads,
                           "target_hint": _lnk_target(entry.path), "source": "recent_files",
                           "modified": _iso(_safe_mtime(entry))})
    return traces

def scan_prefetch(prefetch_dir):
    traces = []
    try:
        entries = list(os.scandir(prefetch_dir))
    except (OSError, PermissionError, TypeError):
        return traces
    for entry in entries:
        if not entry.name.lower().endswith(".pf"):
            continue
        program = entry.name.rsplit("-", 1)[0]
        leads = name_leads(program, False)
        if leads:
            traces.append({"kind": "prefetch_record", "path": entry.path, "name": program, "leads": leads,
                           "source": "prefetch", "modified": _iso(_safe_mtime(entry))})
    return traces

def default_trace_sources(drives, full_scan=False):
    """Locations for the sweep on a normal Windows system."""
    home = os.path.abspath(os.path.expanduser("~"))
    appdata = os.environ.get("APPDATA", os.path.join(home, "AppData", "Roaming"))
    local = os.environ.get("LOCALAPPDATA", os.path.join(home, "AppData", "Local"))
    windir = os.environ.get("WINDIR", r"C:\Windows")
    system_drive = os.environ.get("SystemDrive", "C:").rstrip("\\/").lower()
    roots = []
    for child in ("Desktop", "Downloads", "Documents", "Videos", "Pictures", "Music", "OneDrive", "Games"):
        roots.append(os.path.join(home, child))
    roots.extend([os.path.join(local, "Temp"), appdata, local, os.environ.get("TEMP", ""), home])
    for drive in drives:
        if drive.rstrip("\\/").lower() != system_drive:
            roots.append(drive)
        elif full_scan:
            roots.append(os.path.join(drive, "Users"))
            roots.append(os.path.join(drive, "ProgramData"))
    unique = []
    seen = set()
    for item in roots:
        if not item:
            continue
        key = os.path.normcase(os.path.abspath(item))
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return {
        "roots": unique,
        "recent_dir": os.path.join(appdata, "Microsoft", "Windows", "Recent"),
        "prefetch_dir": os.path.join(windir, "Prefetch"),
        "drives": list(drives),
    }

def run_trace_scan(drives, full_scan=False, progress_callback=None, sources=None, seconds=None):
    sources = sources or default_trace_sources(drives, full_scan)
    seconds = seconds if seconds is not None else (45.0 if full_scan else 22.0)
    emit = progress_callback or (lambda _message: None)
    emit("Поиск следов по названиям, корзине, Recent и Prefetch...")
    sweep = scan_filesystem_names(
        sources["roots"], seconds=seconds, max_entries=400000 if full_scan else 160000,
        progress_callback=progress_callback,
    )
    traces = list(sweep["traces"])
    traces.extend(scan_recycle_bin(sources.get("drives", [])))
    traces.extend(scan_recent_links(sources.get("recent_dir")))
    traces.extend(scan_prefetch(sources.get("prefetch_dir")))
    unique = {}
    for item in traces:
        unique[(item.get("kind"), os.path.normcase(str(item.get("path"))))] = item
    return {
        "traces": list(unique.values()),
        "pack_candidates": sweep["pack_candidates"],
        "stats": sweep["stats"],
        "prefetch_available": os.path.isdir(sources.get("prefetch_dir") or ""),
    }
