
"""Inspect Minecraft launcher/version configs for external Java agents."""
import json
import os
import re

INJECTION_PATTERNS = (
    ("-javaagent", re.compile(r"-javaagent:([^\s\"']+)", re.IGNORECASE)),
    ("-agentpath", re.compile(r"-agentpath:([^\s\"']+)", re.IGNORECASE)),
    ("-agentlib", re.compile(r"-agentlib:([^\s\"']+)", re.IGNORECASE)),
    ("-xbootclasspath", re.compile(r"-xbootclasspath(?:/p)?:([^\s\"']+)", re.IGNORECASE)),
)
MAX_CONFIG_BYTES = 2 * 1024 * 1024
MAX_CONFIG_FILES = 1200

def _candidate_config_files(game_path):
    candidates = []
    for filename in (
        "launcher_profiles.json", "launcher_profiles_microsoft_store.json",
        "mmc-pack.json", "instance.cfg", "launcher.json",
    ):
        path = os.path.join(game_path, filename)
        if os.path.isfile(path):
            candidates.append(path)
    versions_dir = os.path.join(game_path, "versions")
    if os.path.isdir(versions_dir):
        try:
            versions = os.listdir(versions_dir)[:2500]
        except OSError:
            versions = []
        for version in versions:
            folder = os.path.join(versions_dir, version)
            if not os.path.isdir(folder):
                continue
            try:
                files = os.listdir(folder)
            except OSError:
                continue
            for filename in files:
                if filename.lower().endswith(".json"):
                    candidates.append(os.path.join(folder, filename))
                    if len(candidates) >= MAX_CONFIG_FILES:
                        return candidates
    return candidates[:MAX_CONFIG_FILES]

def analyze_runtime_configs(installations):
    results = []
    seen = set()
    for installation in installations:
        game_path = installation.get("game_path", "")
        if not game_path or not os.path.isdir(game_path):
            continue
        for path in _candidate_config_files(game_path):
            key = os.path.normcase(os.path.abspath(path))
            if key in seen:
                continue
            seen.add(key)
            try:
                size = os.path.getsize(path)
                if size > MAX_CONFIG_BYTES:
                    continue
                with open(path, "rb") as stream:
                    raw = stream.read(MAX_CONFIG_BYTES)
                text = raw.decode("utf-8", "ignore")
            except (OSError, IOError):
                continue

            flags = []
            targets = []
            for flag, pattern in INJECTION_PATTERNS:
                for match in pattern.findall(text):
                    flags.append(flag)
                    targets.append(match[:500])
            if not flags:
                continue
            unique_flags = sorted(set(flags))
            unique_targets = sorted(set(targets))
            results.append({
                "path": path,
                "game_path": game_path,
                "flags": unique_flags,
                "targets": unique_targets,
                "assessment": "external_java_runtime_argument",
                "interpretation": (
                    "В конфигурации найден внешний Java agent/runtime argument. Такие параметры могут применяться "
                    "читами, профайлерами или легальными инструментами; проверьте целевой файл, его подпись и хеш."
                ),
            })
    return results
