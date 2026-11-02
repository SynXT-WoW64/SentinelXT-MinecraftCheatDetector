
"""Conservative static analysis of JAR/ZIP archives; never executes content."""
import hashlib
import json
import os
import re
import time
import zipfile

from scanners.yara_analyzer import analyze_bytes_with_yara
from scanners.signature_engine import (
    KNOWN_CLIENT_IDENTIFIERS, KNOWN_PACKAGE_PREFIXES,
    feature_families_for, find_feature_markers,
)
from scanners.policy_registry import (
    exact_policy_mod_matches, allowed_policy_mod_matches, gray_zone_mod_matches, load_policy_registry,
    ambiguous_client_identifiers, normalize_identifier, normalize_policy_text,
)

MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_ENTRIES = 1800
MAX_ENTRY_BYTES = 768 * 1024
MAX_TOTAL_READ = 1024 * 1024
MAX_CLASS_FILES = 120
MAX_ARCHIVE_SECONDS = 0.35
MAX_YARA_BUFFER = 512 * 1024
TEXT_EXTENSIONS = (".json", ".toml", ".properties", ".mf", ".cfg", ".txt", ".xml", ".yml", ".yaml")

def sha256_file(path, chunk_size=1024 * 1024):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        while True:
            chunk = stream.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()

def _safe_text(data):
    try:
        return data.decode("utf-8", "ignore")
    except Exception:
        return data.decode("latin-1", "ignore")

def _metadata_values(entry_name, text):
    values = []
    lower_name = entry_name.lower()
    if lower_name.endswith("fabric.mod.json") or lower_name.endswith("mcmod.info"):
        try:
            parsed = json.loads(text)
            nodes = parsed if isinstance(parsed, list) else [parsed]
            for node in nodes:
                if not isinstance(node, dict):
                    continue
                for key in ("id", "modid", "name", "displayname", "slug"):
                    value = node.get(key)
                    if isinstance(value, (str, int, float)):
                        values.append((key, str(value)))
        except Exception:
            pass
    if lower_name.endswith("mods.toml"):
        for key, value in re.findall(r"(?im)^\s*(modId|displayName|name)\s*=\s*['\"]([^'\"]+)['\"]", text):
            values.append((key.lower(), value))
    if lower_name.endswith("manifest.mf"):
        for key, value in re.findall(r"(?im)^(Implementation-Title|Specification-Title|Bundle-Name):\s*(.+)$", text):
            values.append((key.lower(), value.strip()))
    return values

def _identify_metadata_client(metadata_values):
    matches = []
    decorated = []
    for field, value in metadata_values:
        normalized = normalize_identifier(value)
        field_name = str(field).lower()
        for identifier, display in KNOWN_CLIENT_IDENTIFIERS.items():
            expected = normalize_identifier(identifier)
            display_expected = normalize_identifier(display)
            if not expected:
                continue
            if normalized == expected or (display_expected and normalized == display_expected):
                matches.append({"marker": identifier, "name": display, "source": "archive_metadata", "field": field, "value": value})
                continue
            if field_name in ("id", "modid", "name", "displayname", "display_name", "implementation-title", "specification-title", "bundle-name"):
                text = normalize_policy_text(value)
                needle = normalize_policy_text(display)
                compact_text = normalize_identifier(value)
                compact_needle = normalize_identifier(display)
                if len(needle.split()) > 1 and needle:
                    pattern = re.compile(r"(?<![a-z0-9])" + r"[^a-z0-9]+".join(re.escape(part) for part in needle.split()) + r"(?![a-z0-9])")
                    decorated_match = bool(pattern.search(text))
                    if not decorated_match:
                        decorated_match = bool(len(compact_needle) >= 7 and compact_needle in compact_text and compact_needle != normalized)
                else:
                    decorated_match = bool(len(compact_needle) >= 7 and compact_needle in compact_text and compact_needle != normalized)
                if decorated_match:
                    decorated.append({"marker": identifier, "name": display, "source": "decorated_archive_metadata", "field": field, "value": value})
    unique = {}
    for item in matches:
        unique[(item["marker"], item["field"], item["value"])] = item
    decorated_unique = {}
    for item in decorated:
        decorated_unique[(item["marker"], item["field"], item["value"])] = item
    return list(unique.values()), list(decorated_unique.values())

def _identify_package_client(entry_names):
    clusters = []
    references = []
    normalized_entries = [str(entry).replace("\\", "/").lower() for entry in entry_names]
    for prefix, display in KNOWN_PACKAGE_PREFIXES.items():
        matched = [entry for entry in normalized_entries if entry.startswith(prefix) and entry.endswith(".class")]
        if not matched:
            continue
        subpackages = set()
        for entry in matched:
            remainder = entry[len(prefix):]
            parts = remainder.split("/")
            if len(parts) > 1:
                subpackages.add(parts[0])
        record = {
            "marker": prefix.rstrip("/"),
            "name": display,
            "source": "package_namespace",
            "class_count": len(matched),
            "subpackages": sorted(subpackages),
            "entries": matched[:12],
        }
        if len(matched) >= 5 and len(subpackages) >= 2:
            clusters.append(record)
        else:
            record["source"] = "namespace_reference"
            references.append(record)
    return clusters, references

def analyze_archive(path, archive_kind="mod", enable_yara=False, include_hash=True, progress_callback=None):
    result = {
        "path": path,
        "name": os.path.basename(path),
        "kind": archive_kind,
        "size_bytes": None,
        "sha256": None,
        "archive_readable": False,
        "known_client_matches": [],
        "ambiguous_client_matches": [],
        "decorated_client_name_matches": [],
        "namespace_reference_matches": [],
        "policy_feature_matches": [],
        "allowed_mod_matches": [],
        "gray_zone_matches": [],
        "policy_registry": load_policy_registry().get("registry_id", "unknown"),
        "feature_markers": [],
        "feature_families": [],
        "metadata_files": [],
        "metadata_values": [],
        "yara_matches": [],
        "class_files_examined": 0,
        "notes": [],
    }
    started = time.time()
    try:
        size = os.path.getsize(path)
        result["size_bytes"] = size
        if size > MAX_ARCHIVE_BYTES:
            result["notes"].append("Архив превышает лимит 128 МиБ; содержимое не анализировалось.")
            result["assessment"] = "size_limit"
            return result

        if include_hash:
            result["sha256"] = sha256_file(path)
    except (OSError, IOError) as exc:
        result["notes"].append("Не удалось прочитать файл: {}".format(exc))
        return result

    if not zipfile.is_zipfile(path):
        result["notes"].append("Файл не распознан как ZIP/JAR-архив.")
        return result

    metadata = []
    class_entries = []
    all_entries = []
    features = set()
    yara_buffer = bytearray()
    total_read = 0
    truncated = False
    try:
        with zipfile.ZipFile(path, "r") as archive:
            result["archive_readable"] = True
            infos = archive.infolist()
            if len(infos) > MAX_ENTRIES:
                result["notes"].append("Список записей архива ограничен быстрым профилем.")
                infos = infos[:MAX_ENTRIES]
                truncated = True

            for info in infos:
                if not info.is_dir():
                    all_entries.append(info.filename)
            candidates = []
            for info in infos:
                if info.is_dir() or info.file_size > MAX_ENTRY_BYTES:
                    continue
                lower = info.filename.lower()
                is_metadata = lower.endswith(("fabric.mod.json", "mods.toml", "mcmod.info", "manifest.mf", "pack.mcmeta"))
                is_class = lower.endswith(".class")
                is_text = lower.endswith(TEXT_EXTENSIONS)
                if is_metadata:
                    candidates.append((0, info))
                elif archive_kind not in ("resource_pack", "shader_pack") and is_class:
                    candidates.append((1, info))
                elif archive_kind not in ("resource_pack", "shader_pack") and is_text:
                    candidates.append((2, info))
            candidates.sort(key=lambda pair: pair[0])
            class_count = 0
            for _priority, info in candidates:
                if time.time() - started > MAX_ARCHIVE_SECONDS:
                    result["notes"].append("Превышен лимит времени анализа архива; оставшееся содержимое пропущено.")
                    truncated = True
                    break
                if total_read >= MAX_TOTAL_READ:
                    result["notes"].append("Достигнут лимит быстрого анализа содержимого архива.")
                    truncated = True
                    break
                lower = info.filename.lower()
                is_metadata = lower.endswith(("fabric.mod.json", "mods.toml", "mcmod.info", "manifest.mf", "pack.mcmeta"))
                is_class = lower.endswith(".class")
                if is_class and class_count >= MAX_CLASS_FILES:
                    continue
                try:
                    remaining = MAX_TOTAL_READ - total_read
                    with archive.open(info, "r") as member:
                        data = member.read(min(info.file_size, remaining))
                except Exception:
                    continue
                if not data:
                    continue
                total_read += len(data)
                if is_metadata:
                    result["metadata_files"].append(info.filename)
                    metadata.extend(_metadata_values(info.filename, _safe_text(data)))
                elif is_class:
                    class_count += 1
                    class_entries.append(info.filename)
                    text = _safe_text(data)
                    for marker in find_feature_markers(text):
                        features.add(marker)
                    if len(yara_buffer) < MAX_YARA_BUFFER:
                        yara_buffer.extend(data[:MAX_YARA_BUFFER - len(yara_buffer)])
    except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
        result["notes"].append("Ошибка чтения архива: {}".format(exc))

    metadata_matches, decorated_metadata_matches = _identify_metadata_client(metadata)
    ambiguous_names = ambiguous_client_identifiers()
    ambiguous_metadata_matches = [
        item for item in metadata_matches
        if normalize_identifier(item.get("marker")) in ambiguous_names
        or normalize_identifier(item.get("name")) in ambiguous_names
    ]
    metadata_matches = [item for item in metadata_matches if item not in ambiguous_metadata_matches]
    namespace_matches, namespace_references = _identify_package_client(all_entries)
    policy_feature_matches = exact_policy_mod_matches(metadata)
    allowed_mod_matches = allowed_policy_mod_matches(metadata)
    gray_matches = gray_zone_mod_matches(metadata)

    yara_prefilter = bool(metadata_matches or namespace_matches or namespace_references or policy_feature_matches or len(feature_families_for(features)) >= 2)
    yara_attempted = bool(enable_yara and yara_prefilter and yara_buffer and not (truncated and time.time() - started > MAX_ARCHIVE_SECONDS))
    yara_result = analyze_bytes_with_yara(yara_buffer, timeout=1) if yara_attempted else {"available": False, "matches": [], "message": "Не запускался: быстрый предварительный фильтр не нашёл оснований."}
    yara_matches = yara_result.get("matches", [])
    yara_known = [item for item in yara_matches if item.get("meta", {}).get("category") == "known_client_identity"]
    yara_namespace = [item for item in yara_matches if item.get("meta", {}).get("category") == "namespace_reference"]
    yara_behavior = [item for item in yara_matches if item.get("meta", {}).get("category") == "multi_family_behavior_markers"]
    known = metadata_matches + namespace_matches
    for item in yara_known:
        known.append({"marker": item.get("rule", "yara-rule"), "name": "YARA: известный клиент", "source": "yara_rule", "rule": item})
    result["metadata_values"] = [{"field": key, "value": value} for key, value in metadata]
    result["yara_matches"] = yara_matches
    result["yara_namespace_matches"] = yara_namespace
    result["yara_available"] = yara_result.get("available", False)
    result["yara_attempted"] = yara_attempted
    result["class_files_examined"] = len(class_entries)
    result["known_client_matches"] = known
    result["ambiguous_client_matches"] = ambiguous_metadata_matches
    result["decorated_client_name_matches"] = decorated_metadata_matches
    result["namespace_reference_matches"] = namespace_references
    result["policy_feature_matches"] = policy_feature_matches
    result["allowed_mod_matches"] = allowed_mod_matches
    result["gray_zone_matches"] = gray_matches
    result["feature_markers"] = sorted(features)
    result["feature_families"] = feature_families_for(features)
    result["bytes_examined"] = total_read
    result["analysis_truncated"] = truncated
    result["analysis_duration_seconds"] = round(time.time() - started, 3)
    if not include_hash:
        result["hash_status"] = "skipped_no_verified_hash_database"

    if allowed_mod_matches and not metadata_matches and not policy_feature_matches and not yara_known:
        result["assessment"] = "allow_listed_mod"
        result["known_client_matches"] = []
        result["namespace_reference_matches"] = namespace_references + namespace_matches
        result["notes"].append("Идентификатор модификации совпал с точной записью белого списка RUStrengthSMP. Ссылки на namespace другого проекта сохранены как отдельные сведения и не считаются идентичностью клиента.")
    elif known:
        result["assessment"] = "known_client_identity"
        result["notes"].append(
            "Метаданные или несколько независимых классов соответствуют клиентскому проекту. "
            "Это идентифицирует содержимое файла, но не доказывает запуск или использование игроком."
        )
    elif ambiguous_metadata_matches or decorated_metadata_matches:
        result["assessment"] = "ambiguous_client_metadata"
        result["notes"].append("Поле mod ID/имени совпало с общим названием из списка клиента. Из-за неоднозначности совпадение не считается идентификацией; проверьте namespace, издателя и другие независимые признаки.")
    elif namespace_references or yara_namespace:
        result["assessment"] = "namespace_reference_only"
        result["notes"].append("Найдена ссылка на namespace известного клиента. Это может быть API-интеграция или совместимый мод; найденных сведений недостаточно для идентификации целого клиента.")
    elif policy_feature_matches:
        result["assessment"] = "policy_forbidden_mod_identifier"
        result["notes"].append("Точное значение mod ID или имени в метаданных совпало с функцией, запрещённой политикой RUStrengthSMP. Это требует проверки файла и не доказывает использование в матче.")
    elif gray_matches:
        result["assessment"] = "gray_zone_mod_identifier"
        result["notes"].append("Модификация находится в серой зоне правил RUStrengthSMP; нужна ручная проверка её функций и конфигурации.")
    elif (len(result["feature_families"]) >= 3 and len(class_entries) >= 3 and len(features) >= 5
          and (not yara_behavior or len(result["feature_families"]) >= 4)):
        result["assessment"] = "multi_family_behavior_markers"
        result["notes"].append(
            "В нескольких class-файлах обнаружены маркеры из нескольких независимых семейств функций. "
            "Это эвристика; необходима ручная проверка байткода и контекста."
        )
    elif features:
        result["assessment"] = "feature_string_matches"
        result["notes"].append(
            "Найдены отдельные строки, похожие на названия функций. Одной такой строки, включая X-Ray, недостаточно для вывода о читерстве."
        )
    elif allowed_mod_matches:
        result["assessment"] = "allow_listed_mod"
        result["notes"].append("Точное имя модификации совпало с белым списком RUStrengthSMP. Функции внутри мода всё равно могут быть изменены в форке.")
    else:
        result["assessment"] = "no_known_indicators"
    return result
