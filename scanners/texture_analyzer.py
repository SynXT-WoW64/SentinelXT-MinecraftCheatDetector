
"""Inspect Minecraft resource-pack ZIPs and unpacked folders for X-Ray-like textures.

Only a small, explicit set of block textures is read. The analyzer never executes
pack content. A texture pattern is an investigative lead, not proof of use.
"""
import json
import os
import re
import time
import zipfile

from scanners.name_matcher import xray_name_hints

try:
    from io import BytesIO
    from PIL import Image
except Exception:
    Image = None
    BytesIO = None

SOLID_BLOCKS = (
    "stone.png", "deepslate.png", "netherrack.png", "end_stone.png",
    "dirt.png", "granite.png", "andesite.png", "diorite.png",
    "tuff.png", "blackstone.png", "basalt.png", "calcite.png",
    "dripstone_block.png", "terracotta.png", "cobblestone.png", "gravel.png",
    "sand.png", "sandstone.png", "red_sand.png", "bedrock.png", "smooth_basalt.png",
    "cobbled_deepslate.png", "magma.png", "soul_sand.png", "soul_soil.png",
)
ORE_BLOCKS = (
    "coal_ore.png", "copper_ore.png", "diamond_ore.png", "deepslate_diamond_ore.png",
    "gold_ore.png", "deepslate_gold_ore.png", "iron_ore.png", "deepslate_iron_ore.png",
    "emerald_ore.png", "lapis_ore.png", "redstone_ore.png", "ancient_debris.png",
    "deepslate_coal_ore.png", "deepslate_copper_ore.png", "deepslate_emerald_ore.png",
    "deepslate_lapis_ore.png", "deepslate_redstone_ore.png", "nether_gold_ore.png",
    "nether_quartz_ore.png", "ancient_debris_side.png", "ancient_debris_top.png",
)
SOLID_MODEL_NAMES = (
    "stone", "deepslate", "netherrack", "end_stone", "dirt", "granite", "andesite",
    "diorite", "tuff", "cobblestone", "gravel", "sand", "bedrock", "cube_all", "cube",
    "cube_column", "cube_bottom_top", "block",
)
MAX_MODEL_BYTES = 64 * 1024
MAX_PACK_ENTRIES = 6000
MAX_TEXTURE_BYTES = 1 * 1024 * 1024
MAX_TOTAL_TEXTURE_BYTES = 8 * 1024 * 1024
MAX_PACK_METADATA_BYTES = 256 * 1024
MAX_PACK_ANALYSIS_SECONDS = 3.0
MAX_DIRECTORY_FILES = 6000
MAX_DIRECTORY_SECONDS = 2.0
PACK_NAME_HINTS = ("xray", "x-ray", "ore finder", "orefinder", "cave finder", "cavefinder")

def _find_texture(names, target):
    matches = []
    for name in names:
        normalized = "/" + name.replace("\\", "/").lower().lstrip("/")
        if normalized.endswith("/" + target) and (
            "/textures/block/" in normalized or "/textures/blocks/" in normalized
        ):
            matches.append(name)
    return sorted(matches)[0] if matches else None

def _texture_alpha(read_bytes, name):
    if Image is None or BytesIO is None:
        return None
    raw = read_bytes(name, MAX_TEXTURE_BYTES)
    if not raw:
        return None
    image = Image.open(BytesIO(raw))
    if image.width > 512 or image.height > 512 or image.width < 1 or image.height < 1:
        return None
    image.load()
    image = image.convert("RGBA")
    histogram = image.getchannel("A").histogram()
    total = float(image.width * image.height)
    transparent = sum(histogram[:128]) / total
    translucent = sum(histogram[128:240]) / total
    opaque = sum(histogram[240:]) / total
    return {
        "transparent_ratio": round(transparent, 3),
        "translucent_ratio": round(translucent, 3),
        "opaque_ratio": round(opaque, 3),
        "size": [image.width, image.height],
        "texture": name,
    }

def _find_model(names, target):
    matches = []
    for name in names:
        normalized = "/" + name.replace("\\", "/").lower().lstrip("/")
        if normalized.endswith("/models/block/" + target + ".json"):
            matches.append(name)
    return sorted(matches)[0] if matches else None

def _blank_model_info(read_bytes, name):
    raw = read_bytes(name, MAX_MODEL_BYTES)
    if not raw:
        return None
    try:
        model = json.loads(raw.decode("utf-8", "ignore"))
    except Exception:
        return None
    if not isinstance(model, dict):
        return None
    elements = model.get("elements")
    blank = isinstance(elements, list) and len(elements) == 0
    return {"model": name, "blank": blank, "has_parent": "parent" in model}

def _collect_zip_pack(path):
    archive = zipfile.ZipFile(path, "r")
    infos = archive.infolist()
    if len(infos) > MAX_PACK_ENTRIES:
        infos = infos[:MAX_PACK_ENTRIES]
    names = [item.filename for item in infos if not item.is_dir()]

    def read_bytes(name, limit):
        try:
            info = archive.getinfo(name)
            if info.file_size > limit:
                return None
            with archive.open(info, "r") as stream:
                return stream.read(limit + 1)[:limit]
        except Exception:
            return None

    return archive, names, read_bytes, len(infos) >= MAX_PACK_ENTRIES

def _collect_directory_pack(path):
    names = []
    started = time.time()
    truncated = False
    for current, dirs, files in os.walk(path, topdown=True):
        dirs[:] = [name for name in dirs if name.lower() not in (
            ".git", "__pycache__", "cache", "caches", "logs", "temp", "tmp"
        )]
        for filename in files:
            full = os.path.join(current, filename)
            try:
                if os.path.islink(full):
                    continue
            except OSError:
                continue
            names.append(os.path.relpath(full, path).replace(os.sep, "/"))
            if len(names) >= MAX_DIRECTORY_FILES or time.time() - started > MAX_DIRECTORY_SECONDS:
                truncated = True
                dirs[:] = []
                break
        if truncated:
            break
    def read_bytes(name, limit):
        full = os.path.join(path, *name.replace("\\", "/").split("/"))
        try:
            if os.path.getsize(full) > limit:
                return None
            with open(full, "rb") as stream:
                return stream.read(limit + 1)[:limit]
        except (IOError, OSError):
            return None
    return None, names, read_bytes, truncated

def analyze_resource_pack(path):
    result = {
        "path": path,
        "name": os.path.basename(os.path.normpath(path)),
        "pack_format": None,
        "texture_checks": [],
        "metadata_description": "",
        "metadata_hints": [],
        "assessment": "not_checked",
        "notes": [],
        "pack_type": "directory" if os.path.isdir(path) else "zip",
        "scan_truncated": False,
    }
    if Image is None:
        result["assessment"] = "texture_analysis_unavailable"
        result["notes"].append("Pillow отсутствует; содержимое архива учтено, но пиксели текстур не анализировались.")
        return result

    container = None
    try:
        if os.path.isdir(path):
            container, names, read_bytes, truncated = _collect_directory_pack(path)
        elif zipfile.is_zipfile(path):
            container, names, read_bytes, truncated = _collect_zip_pack(path)
        else:
            result["assessment"] = "not_a_resource_pack_archive"
            result["notes"].append("Путь не является ZIP-архивом или распакованным каталогом ресурс-пака.")
            return result
        result["scan_truncated"] = bool(truncated)
        if truncated:
            result["notes"].append("Список элементов ресурс-пака ограничен защитным лимитом.")

        read_total = [0]
        def bounded_read(name, limit):
            remaining = MAX_TOTAL_TEXTURE_BYTES - read_total[0]
            if remaining <= 0:
                return None
            data = read_bytes(name, min(limit, remaining))
            if data:
                read_total[0] += len(data)
            return data

        analysis_deadline = time.time() + MAX_PACK_ANALYSIS_SECONDS

        metadata_name = None
        for name in names:
            if name.replace("\\", "/").lower().endswith("pack.mcmeta"):
                metadata_name = name
                break
        if metadata_name:
            raw = bounded_read(metadata_name, MAX_PACK_METADATA_BYTES)
            if raw:
                result["metadata_description"] = raw[:4000].decode("utf-8", "ignore")
                try:
                    metadata = json.loads(raw.decode("utf-8", "ignore"))
                    result["pack_format"] = metadata.get("pack", {}).get("pack_format")
                except Exception:
                    pass

        hint_text = " {} {} ".format(result["name"], result["metadata_description"])
        for hint in xray_name_hints(hint_text, exclude_network_software=False):
            result["metadata_hints"].append(hint)
        if not metadata_name:
            result["notes"].append("Не найден pack.mcmeta; архив может быть не ресурс-паком либо иметь нестандартную структуру.")

        solid = []
        ores = []
        for target in SOLID_BLOCKS:
            if time.time() > analysis_deadline or read_total[0] >= MAX_TOTAL_TEXTURE_BYTES:
                result["scan_truncated"] = True
                break
            name = _find_texture(names, target)
            if not name:
                continue
            try:
                metrics = _texture_alpha(bounded_read, name)
                if metrics is not None:
                    solid.append(metrics)
                    result["texture_checks"].append(metrics)
            except Exception:
                continue
        for target in ORE_BLOCKS:
            if time.time() > analysis_deadline or read_total[0] >= MAX_TOTAL_TEXTURE_BYTES:
                result["scan_truncated"] = True
                break
            name = _find_texture(names, target)
            if not name:
                continue
            try:
                metrics = _texture_alpha(bounded_read, name)
                if metrics is not None:
                    ores.append(metrics)
                    result["texture_checks"].append(metrics)
            except Exception:
                continue

        blank_models = []
        models_examined = 0
        for target in SOLID_MODEL_NAMES:
            if time.time() > analysis_deadline:
                result["scan_truncated"] = True
                break
            model_name = _find_model(names, target)
            if not model_name:
                continue
            info = _blank_model_info(bounded_read, model_name)
            if info is None:
                continue
            models_examined += 1
            if info["blank"]:
                blank_models.append(info)
        result["models_examined"] = models_examined
        result["blank_block_models"] = blank_models

        result["texture_bytes_examined"] = read_total[0]
        if result["scan_truncated"] and "Список элементов ресурс-пака ограничен защитным лимитом." not in result["notes"]:
            result["notes"].append("Анализ текстур остановлен по лимиту времени/объёма; вывод может быть неполным.")
        transparent_solids = [item for item in solid if item["transparent_ratio"] >= 0.45]
        suspicious_solids = [item for item in solid if item["transparent_ratio"] >= 0.15]
        opaque_ores = [item for item in ores if item["opaque_ratio"] >= 0.70]
        result["solid_textures_examined"] = len(solid)
        result["ore_textures_examined"] = len(ores)
        result["transparent_solid_textures"] = len(transparent_solids)
        result["suspicious_solid_textures"] = len(suspicious_solids)
        result["opaque_ore_textures"] = len(opaque_ores)

        if len(blank_models) >= 3:
            result["assessment"] = "xray_like_model_pattern"
            result["notes"].append(
                "Модели не менее трёх базовых блоков не содержат элементов (пустой список elements), поэтому такие блоки не рисуются. "
                "Это описание содержимого пака, а не доказательство его выбора или использования."
            )
        elif len(transparent_solids) >= 3 and len(opaque_ores) >= 1:
            average_solid = sum(item["transparent_ratio"] for item in transparent_solids) / float(len(transparent_solids))
            average_ore = sum(item["opaque_ratio"] for item in opaque_ores) / float(len(opaque_ores))
            result["average_solid_block_transparency"] = round(average_solid, 3)
            result["average_ore_opacity"] = round(average_ore, 3)
            if average_solid >= 0.60 and average_ore >= 0.75:
                result["assessment"] = "xray_like_texture_pattern"
                result["notes"].append(
                    "Не менее трёх обычных блоков преимущественно прозрачны, а текстуры руд сохраняют непрозрачность. "
                    "Комбинация текстур соответствует шаблону X-Ray-паков. Это описание содержимого, а не доказательство выбора или использования пака в матче."
                )
            else:
                result["assessment"] = "partial_texture_anomalies"
                result["notes"].append("Есть прозрачные текстуры обычных блоков при сохранённой видимости руд; сочетание требует просмотра самих изображений.")
        elif len(suspicious_solids) >= 1 and len(opaque_ores) >= 1:
            result["assessment"] = "partial_texture_anomalies"
            result["notes"].append(
                "Есть отдельные полупрозрачные текстуры блоков при непрозрачных рудах. "
                "Прозрачность отдельных блоков встречается и в обычных ресурс-паках; проверьте сопоставленные изображения."
            )
        elif result["metadata_hints"]:
            result["assessment"] = "pack_name_or_metadata_hint"
            result["notes"].append("Название или описание пакета содержит X-Ray/ore/cave-термин; само по себе это не доказывает изменение текстур.")
        elif len(solid) + len(ores) == 0:
            result["assessment"] = "no_target_block_textures"
            result["notes"].append("Не найдены целевые текстуры блоков Minecraft для анализа.")
        else:
            result["assessment"] = "no_xray_pattern_found"
            result["notes"].append("Проверенные текстуры не образуют характерный X-Ray-паттерн. Это не исключает другие способы X-Ray.")
    except Exception as exc:
        result["assessment"] = "read_error"
        result["notes"].append("Ошибка чтения ресурс-пака: {}".format(type(exc).__name__))
    finally:
        if container is not None:
            try:
                container.close()
            except Exception:
                pass
    return result
