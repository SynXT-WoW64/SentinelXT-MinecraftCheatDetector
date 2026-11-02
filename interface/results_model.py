
"""Qt-free grouping, filtering and text export of findings for the Results tab."""
import json
import ntpath

RESULT_FILTER_GROUPS = {
    "clients": {
        "verified_hash_match", "known_client_identity", "ambiguous_client_metadata",
        "namespace_reference", "yara_client_signature", "ambiguous_pe_metadata",
        "client_name_in_pe_metadata",
    },
    "mods": {
        "policy_forbidden_mod_identifier", "gray_zone_mod_identifier",
        "allow_listed_mod", "multi_family_behavior_markers", "archive_feature_strings",
    },
    "packs": {"xray_texture_pattern", "xray_texture_clues", "xray_model_pattern", "resource_pack_name_hint", "disguised_archive"},
    "traces": {"name_trace_file", "name_trace_deleted", "name_trace_recent", "name_trace_execution"},
    "runtime": {"java_runtime_config", "running_client_process", "java_runtime_injection", "historical_client_trace"},
    "files": {"client_filename_match", "client_directory_match", "recognized_launcher"},
    "tools": {"minecraft_automation_script", "generic_automation_script", "context_dependent_software", "pe_feature_families", "pe_feature_strings"},
}

GROUP_ORDER = (
    ("packs", "Ресурс-паки и X-Ray"),
    ("clients", "Клиенты и сигнатуры"),
    ("mods", "Моды и функции"),
    ("traces", "Следы по названиям: файлы, корзина, запуск"),
    ("runtime", "Процессы и запуск"),
    ("files", "Файлы и лаунчеры"),
    ("tools", "Скрипты и другое ПО"),
    ("other", "Прочее"),
)

INFORMATIONAL_CATEGORIES = frozenset(("allow_listed_mod", "recognized_launcher"))

def group_of(category):
    for key, categories in RESULT_FILTER_GROUPS.items():
        if category in categories:
            return key
    return "other"

def short_path_parts(path, limit=64):
    """Return (file name, shortened directory) for compact list rows."""
    if not path:
        return "Путь не указан", ""
    normalized = str(path).replace("/", "\\")
    name = ntpath.basename(normalized.rstrip("\\")) or normalized
    folder = ntpath.dirname(normalized.rstrip("\\"))
    if len(folder) > limit:
        folder = folder[:limit // 2 - 1] + "…" + folder[-(limit // 2 - 1):]
    return name, folder

def _search_blob(finding, labels):
    try:
        evidence = json.dumps(finding.get("evidence", {}), ensure_ascii=False)[:4000]
    except Exception:
        evidence = ""
    category = finding.get("category", "")
    return " ".join([
        str(finding.get("title", "")), str(finding.get("path", "")), str(finding.get("details", "")),
        str(labels.get(category, category)), evidence, str(finding.get("sha256", "")),
    ]).lower()

def build_groups(findings, group_filter="all", query="", show_informational=False, labels=None):
    """Return (groups, hidden_informational_count). Findings keep scan order inside a group, sorted by path."""
    labels = labels or {}
    needle = str(query or "").strip().lower()
    buckets = {}
    hidden = 0
    for finding in findings or []:
        category = finding.get("category", "other")
        key = group_of(category)
        if group_filter not in (None, "all") and key != group_filter:
            continue
        if not show_informational and category in INFORMATIONAL_CATEGORIES:
            hidden += 1
            continue
        if needle and needle not in _search_blob(finding, labels):
            continue
        buckets.setdefault(key, []).append(finding)
    groups = []
    for key, label in GROUP_ORDER:
        items = buckets.get(key)
        if items:
            items.sort(key=lambda item: (str(item.get("category", "")), str(item.get("path", "")).lower()))
            groups.append((key, label, items))
    return groups, hidden

def finding_time_hint(finding):
    evidence = finding.get("evidence")
    if isinstance(evidence, dict):
        for key, prefix in (("deleted_at", "удалён"), ("modified", "изменён")):
            if evidence.get(key):
                return "{}: {}".format(prefix, str(evidence[key]).replace("T", " "))
    return ""

def export_text(groups, labels=None, translate=None):
    """Plain-text list for pasting into a ticket: group, category, path, short explanation."""
    labels = labels or {}
    translate = translate or (lambda text: text)
    lines = []
    for _key, label, items in groups:
        lines.append("== {} ({}) ==".format(translate(label), len(items)))
        for finding in items:
            category = finding.get("category", "other")
            lines.append("[{}] {}".format(labels.get(category, category), finding.get("title", "")))
            lines.append(translate("  Путь: {}").format(finding.get("path") or translate("не указан")))
            hint = finding_time_hint(finding)
            if hint:
                prefix, separator, rest = hint.partition(": ")
                if separator:
                    hint = translate(prefix) + separator + rest
                lines.append("  {}".format(hint))
            if finding.get("sha256"):
                lines.append("  SHA-256: {}".format(finding.get("sha256")))
        lines.append("")
    return "\n".join(lines).strip()
