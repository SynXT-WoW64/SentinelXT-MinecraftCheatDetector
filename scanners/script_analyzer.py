
"""Bounded static review of user scripts for Minecraft input automation clues."""
import os

MAX_SCRIPT_BYTES = 1024 * 1024
MAX_SCRIPT_FILES = 400
SCRIPT_EXTENSIONS = (".ahk", ".py", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".lua")
GAME_CONTEXT = (
    "minecraft", "net.minecraft", "javaw.exe", "java.exe", "lunarclient", "badlion", "feather client",
)
AUTOMATION_APIS = (
    "pyautogui", "pydirectinput", "pynput", "keyboard.press", "keyboard.send",
    "mouse_event", "sendinput", "postmessage", "ahk_exe javaw.exe", "win32api",
    "ctypes.windll.user32", "mouse.click", "click(", "hotkey(", "send {",
)
ACTION_TERMS = ("click", "press", "hold", "hotkey", "attack", "leftbutton", "rightbutton", "autoclick", "w-tap", "s-tap")

def analyze_script_file(path):
    result = {
        "path": path, "name": os.path.basename(path),
        "assessment": "not_suspicious",
        "game_context_matches": [], "automation_api_matches": [], "action_matches": [],
    }
    if os.path.splitext(path)[1].lower() not in SCRIPT_EXTENSIONS:
        return result
    try:
        size = os.path.getsize(path)
        if size <= 0 or size > MAX_SCRIPT_BYTES:
            result["assessment"] = "skipped_size_limit"
            return result
        with open(path, "rb") as stream:
            text = stream.read(MAX_SCRIPT_BYTES).decode("utf-8", "ignore").lower()
    except (OSError, IOError):
        result["assessment"] = "unreadable"
        return result

    game_hits = [term for term in GAME_CONTEXT if term in text]
    api_hits = [term for term in AUTOMATION_APIS if term in text]
    action_hits = [term for term in ACTION_TERMS if term in text]
    result["game_context_matches"] = game_hits
    result["automation_api_matches"] = api_hits
    result["action_matches"] = action_hits
    if game_hits and api_hits and len(action_hits) >= 2:
        result["assessment"] = "minecraft_input_automation_script"
        result["notes"] = [
            "Скрипт содержит признаки Minecraft/Java-контекста, API эмуляции ввода и несколько действий. "
            "Это требует ручного изучения файла; само по себе не доказывает использование макроса во время игры."
        ]
    elif api_hits and action_hits:
        result["assessment"] = "generic_input_automation_script"
        result["notes"] = ["Обнаружены признаки скрипта автоматизации ввода, но не подтверждена связь с Minecraft."]
    return result

def analyze_script_candidates(paths):
    results = []
    seen = set()
    for path in paths[:MAX_SCRIPT_FILES]:
        key = os.path.normcase(os.path.abspath(path))
        if key in seen:
            continue
        seen.add(key)
        result = analyze_script_file(path)
        if result.get("assessment") not in ("not_suspicious", "skipped_size_limit", "unreadable"):
            results.append(result)
    return results
