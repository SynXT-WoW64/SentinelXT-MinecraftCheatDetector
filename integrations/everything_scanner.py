
"""Optional integration with voidtools Everything through its ES CLI.

Everything and ES must already be installed; Everything must be running. The
integration only queries the index and does not change Everything's settings.
"""
import os
import shutil
import subprocess

from scanners.signature_engine import KNOWN_CLIENT_MARKERS, LAUNCHER_IDENTIFIERS, find_known_client_markers, launcher_name_from_text

def find_es_executable():
    candidates = []
    path_candidate = shutil.which("es.exe") or shutil.which("es")
    if path_candidate:
        candidates.append(path_candidate)
    program_files = os.environ.get("PROGRAMFILES", r"C:\Program Files")
    program_files_x86 = os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")
    local = os.environ.get("LOCALAPPDATA", "")
    candidates.extend([
        os.path.join(program_files, "Everything", "es.exe"),
        os.path.join(program_files_x86, "Everything", "es.exe"),
        os.path.join(local, "Microsoft", "WindowsApps", "es.exe"),
    ])
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return candidate
    return None

def _decode_output(raw):
    for encoding in ("utf-8", "mbcs", "cp1251", "latin-1"):
        try:
            return raw.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", "replace")

def _query(es_path, query, limit=5000, timeout=25):
    command = [es_path, "-match-path", "-n", str(int(limit)), query]
    try:
        raw = subprocess.check_output(command, stderr=subprocess.STDOUT, timeout=timeout)
        return [line.strip() for line in _decode_output(raw).splitlines() if line.strip()], None
    except subprocess.CalledProcessError as exc:
        message = _decode_output(exc.output or b"").strip()
        return [], message or "ES завершился с кодом {}".format(exc.returncode)
    except Exception as exc:
        return [], "{}: {}".format(type(exc).__name__, exc)

def scan_with_everything(progress_callback=None, max_results=5000):
    """Return supplemental indexed path matches; gracefully skip absent Everything."""
    es_path = find_es_executable()
    if not es_path:
        return {"status": "not_installed", "message": "ES.exe не найден; использован собственный поиск." , "paths": []}

    launcher_terms = []
    for marker in LAUNCHER_IDENTIFIERS:
        if marker in ("pcl", "feather", "pcl", "hmcl", "xmcl"):
            continue
        launcher_terms.append('"{}"'.format(marker) if " " in marker else marker)
    cheat_terms = list(KNOWN_CLIENT_MARKERS.keys())
    all_terms = launcher_terms + cheat_terms
    query = "|".join(all_terms)

    if progress_callback:
        progress_callback("Дополнительный поиск по индексу Everything...")
    paths, error = _query(es_path, query, limit=max_results)
    if error:
        lowered = error.lower()
        if "ipc" in lowered or "window was not found" in lowered:
            status = "not_running"
            message = "Everything установлен, но не запущен или ES не смог подключиться. Использован собственный поиск."
        else:
            status = "error"
            message = "Не удалось получить результаты Everything: {}".format(error)
        return {"status": status, "message": message, "paths": []}

    records = []
    seen = set()
    allowed_suffixes = set((
        ".jar", ".zip", ".mrpack", ".exe", ".dll", ".bat", ".cmd", ".ps1",
        ".ahk", ".py", ".vbs", ".js", ".lua", ".json", ".toml", ".cfg",
        ".ini", ".properties", ".xml", ".yml", ".yaml", ".mf",
    ))
    blocked_parts = set(("windows", "system32", "syswow64", "winsxs", "programdata", "$recycle.bin", "system volume information", "recovery", "temp", "tmp", "cache", "caches", "logs"))
    for path in paths:
        path_parts = [part.lower() for part in os.path.abspath(path).replace("/", "\\").split("\\") if part]
        if any(part in blocked_parts for part in path_parts):
            continue
        if os.path.isfile(path) and os.path.splitext(path)[1].lower() not in allowed_suffixes:
            continue
        normalized = os.path.normcase(os.path.abspath(path))
        if normalized in seen:
            continue
        seen.add(normalized)
        name = os.path.basename(path.rstrip("\\/"))
        launcher = launcher_name_from_text(path)
        markers = find_known_client_markers(path)
        record = {"path": path, "name": name, "launcher": launcher, "client_markers": markers}
        records.append(record)
    return {
        "status": "ok",
        "message": "Everything вернул {} дополнительных совпадений.".format(len(records)),
        "paths": records,
        "es_path": es_path,
    }
