
"""Read-only PE metadata inspection. File names alone never imply cheating."""
import hashlib
import os
import re

try:
    import pefile
except Exception:
    pefile = None

from scanners.signature_engine import KNOWN_CLIENT_IDENTIFIERS, find_feature_markers, feature_families_for, launcher_name_from_text
from scanners.policy_registry import ambiguous_client_identifiers, normalize_identifier

MAX_PE_SIZE = 128 * 1024 * 1024
MAX_SECTION_SCAN = 2 * 1024 * 1024

def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()

def _decode(value):
    if isinstance(value, bytes):
        for encoding in ("utf-8", "utf-16le", "cp1252", "latin-1"):
            try:
                return value.decode(encoding, "ignore").strip("\x00 \t\r\n")
            except Exception:
                pass
    return str(value or "").strip("\x00 \t\r\n")

def analyze_pe_file(path, include_hash=False):
    result = {
        "path": path,
        "name": os.path.basename(path),
        "size_bytes": None,
        "sha256": None,
        "pe_readable": False,
        "metadata": {},
        "imports": [],
        "known_client_matches": [],
        "ambiguous_client_matches": [],
        "launcher_identity": None,
        "feature_markers": [],
        "feature_families": [],
        "assessment": "not_analyzed",
        "notes": [],
    }
    try:
        size = os.path.getsize(path)
        result["size_bytes"] = size
        if size > MAX_PE_SIZE:
            result["assessment"] = "size_limit"
            result["notes"].append("PE-файл превышает лимит анализа 128 МиБ.")
            return result
        if include_hash:
            result["sha256"] = _sha256(path)
    except OSError as exc:
        result["assessment"] = "read_error"
        result["notes"].append(str(exc))
        return result

    if pefile is None:
        result["assessment"] = "pefile_unavailable"
        result["notes"].append("Для анализа PE-метаданных установите pefile.")
        return result

    try:
        pe = pefile.PE(path, fast_load=True)
        result["pe_readable"] = True
        metadata = {}
        try:
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
            for file_info_block in getattr(pe, "FileInfo", []) or []:
                entries = file_info_block if isinstance(file_info_block, (list, tuple)) else [file_info_block]
                for entry in entries:
                    for table in getattr(entry, "StringTable", []) or []:
                        for key, value in table.entries.items():
                            metadata[_decode(key)] = _decode(value)
        except Exception:
            pass
        result["metadata"] = metadata

        import_names = []
        try:
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
                import_names.append(_decode(entry.dll).lower())
        except Exception:
            pass
        result["imports"] = sorted(set(import_names))[:150]

        identity_fields = ("ProductName", "OriginalFilename", "InternalName", "FileDescription")
        metadata_identity_values = []
        for field_name in identity_fields:
            value = metadata.get(field_name, "")
            if value:
                normalized = re.sub(r"[^a-z0-9]+", "", value.lower())
                metadata_identity_values.append((field_name, value, normalized))
        result["known_client_matches"] = []
        result["ambiguous_client_matches"] = []
        ambiguous_names = ambiguous_client_identifiers()
        for identifier, display in KNOWN_CLIENT_IDENTIFIERS.items():
            aliases = {
                re.sub(r"[^a-z0-9]+", "", identifier.lower()),
                re.sub(r"[^a-z0-9]+", "", display.lower()),
            }
            for field_name, value, normalized in metadata_identity_values:
                if normalized in aliases and normalized:
                    match = {
                        "marker": identifier,
                        "name": display,
                        "source": "exact_pe_version_metadata",
                        "field": field_name,
                        "value": value,
                    }
                    if normalize_identifier(identifier) in ambiguous_names or normalize_identifier(display) in ambiguous_names:
                        result["ambiguous_client_matches"].append(match)
                    else:
                        result["known_client_matches"].append(match)
        product_text = " ".join(metadata.get(key, "") for key in ("ProductName", "FileDescription", "OriginalFilename", "InternalName"))
        result["launcher_identity"] = launcher_name_from_text(product_text)

        feature_set = set()
        scanned = 0
        for section in getattr(pe, "sections", []) or []:
            if scanned >= MAX_SECTION_SCAN:
                break
            try:
                data = section.get_data()[:MAX_SECTION_SCAN - scanned]
            except Exception:
                continue
            scanned += len(data)
            text = data.decode("latin-1", "ignore")
            for marker in find_feature_markers(text):
                feature_set.add(marker)
        result["feature_markers"] = sorted(feature_set)
        result["feature_families"] = feature_families_for(feature_set)

        if result["known_client_matches"]:
            result["assessment"] = "known_client_metadata"
            result["notes"].append("Точное поле метаданных PE совпало с названием известного клиентского проекта; требуется проверка издателя, подписи и происхождения. Запуск не доказан.")
        elif result["ambiguous_client_matches"]:
            result["assessment"] = "ambiguous_client_metadata"
            result["notes"].append("Точное поле PE совпало с общим названием из реестра клиентов; совпадение неоднозначно и не классифицируется как чит без независимых признаков.")
        elif len(result["feature_families"]) >= 4 and len(feature_set) >= 8:
            result["assessment"] = "multi_family_behavior_markers"
            result["notes"].append("В секциях PE найдены маркеры как минимум четырёх семейств функций; это эвристика, а не подтверждение чита.")
        elif feature_set:
            result["assessment"] = "feature_string_matches"
            result["notes"].append("В PE найдены отдельные строки с названиями игровых функций; они могут встречаться в документации и обычном ПО.")
        elif result["launcher_identity"]:
            result["assessment"] = "recognized_launcher_metadata"
            result["notes"].append("Метаданные указывают на известный Minecraft-лаунчер; это не индикатор читерства.")
        else:
            result["assessment"] = "no_minecraft_identity_match"
            result["notes"].append("Одно лишь имя файла не используется для классификации. Например, xray.exe не считается читом по названию.")
        try:
            pe.close()
        except Exception:
            pass
    except Exception as exc:
        result["assessment"] = "not_a_readable_pe"
        result["notes"].append("Не удалось разобрать PE-файл: {}".format(type(exc).__name__))
    return result
