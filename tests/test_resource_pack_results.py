
"""Tests for X-Ray resource-pack analysis and the expanded findings feed."""
import io
import json
import os
import sys
import tempfile
import unittest
import zipfile

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

try:
    from PIL import Image
    PIL_AVAILABLE = True
except Exception:
    Image = None
    PIL_AVAILABLE = False

from scanners.texture_analyzer import analyze_resource_pack
from scanners.inventory_scanner import _list_resource_pack_items, _make_findings, _analyze_global_resource_packs, _discover_drive_artifacts, ScanBudget

def _png_bytes(alpha):
    image = Image.new("RGBA", (16, 16), (120, 120, 120, alpha))
    output = io.BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()

@unittest.skipUnless(PIL_AVAILABLE, "Pillow is required for texture tests")
class ResourcePackAnalysisTests(unittest.TestCase):
    def _write_xray_zip(self, path):
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("pack.mcmeta", json.dumps({"pack": {"pack_format": 15, "description": "Test pack"}}))
            for name in ("stone", "deepslate", "netherrack", "dirt"):
                archive.writestr("assets/minecraft/textures/block/{}.png".format(name), _png_bytes(0))
            for name in ("diamond_ore", "iron_ore", "gold_ore"):
                archive.writestr("assets/minecraft/textures/block/{}.png".format(name), _png_bytes(255))

    def _write_legacy_xray_zip(self, path):
        with zipfile.ZipFile(path, "w") as archive:
            for name in ("stone", "dirt", "netherrack", "end_stone"):
                archive.writestr("textures/blocks/{}.png".format(name), _png_bytes(0))
            for name in ("diamond_ore", "iron_ore", "gold_ore"):
                archive.writestr("textures/blocks/{}.png".format(name), _png_bytes(255))

    def test_legacy_18_xray_pack_without_pack_mcmeta_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "MinecraftXray-1.8.zip")
            self._write_legacy_xray_zip(path)
            result = analyze_resource_pack(path)
        self.assertEqual(result["assessment"], "xray_like_texture_pattern")
        self.assertFalse(any("pack.mcmeta" in note for note in result.get("notes", []) if "Не найден" not in note))

    def test_secondary_drive_resourcepacks_folder_is_discovered_before_general_walk(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "legacy", "Minecraft", "game", "resourcepacks")
            os.makedirs(target)
            path = os.path.join(target, "MinecraftXray-1.8.zip")
            self._write_legacy_xray_zip(path)
            module = __import__("scanners.inventory_scanner", fromlist=["_fixed_drives"])
            with mock.patch.object(module, "_fixed_drives", return_value=[tmp]), mock.patch.dict(os.environ, {"SystemDrive": "C:"}, clear=False):
                result = _discover_drive_artifacts(full_scan=False, budget=ScanBudget())
            candidates = [item for item in result.get("global_archive_candidates", []) if item.get("path") == path]
            packs = _analyze_global_resource_packs(candidates, already_analyzed=[])
        self.assertEqual(len(candidates), 1)
        self.assertEqual(len(packs), 1)
        self.assertEqual(packs[0]["assessment"], "xray_like_texture_pattern")
        self.assertEqual(packs[0]["discovery"], "secondary_drive_resourcepacks_folder")

    def test_xray_resource_pack_zip_is_detected_by_texture_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "ordinary-name.zip")
            self._write_xray_zip(path)
            result = analyze_resource_pack(path)
        self.assertEqual(result["assessment"], "xray_like_texture_pattern")
        self.assertGreaterEqual(result["transparent_solid_textures"], 3)
        self.assertGreaterEqual(result["opaque_ore_textures"], 1)

    def test_unpacked_resource_pack_folder_is_supported(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack = os.path.join(tmp, "FolderPack")
            os.makedirs(os.path.join(pack, "assets", "minecraft", "textures", "block"))
            with open(os.path.join(pack, "pack.mcmeta"), "w", encoding="utf-8") as stream:
                stream.write('{"pack":{"pack_format":15,"description":"test"}}')
            base = os.path.join(pack, "assets", "minecraft", "textures", "block")
            for name in ("stone", "deepslate", "netherrack"):
                with open(os.path.join(base, name + ".png"), "wb") as stream:
                    stream.write(_png_bytes(0))
            for name in ("diamond_ore", "iron_ore"):
                with open(os.path.join(base, name + ".png"), "wb") as stream:
                    stream.write(_png_bytes(255))
            result = analyze_resource_pack(pack)
        self.assertEqual(result["pack_type"], "directory")
        self.assertEqual(result["assessment"], "xray_like_texture_pattern")

    def test_xray_name_without_texture_pattern_is_only_name_clue(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "Xray-VPN-Theme.zip")
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("pack.mcmeta", '{"pack":{"pack_format":15,"description":"A normal visual theme"}}')
                archive.writestr("assets/minecraft/textures/block/stone.png", _png_bytes(255))
            result = analyze_resource_pack(path)
        self.assertEqual(result["assessment"], "pack_name_or_metadata_hint")

    def test_resource_pack_discovery_includes_zip_and_unpacked_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            game = os.path.join(tmp, ".minecraft")
            packs = os.path.join(game, "resourcepacks")
            os.makedirs(os.path.join(packs, "FolderPack", "assets"))
            with open(os.path.join(packs, "FolderPack", "pack.mcmeta"), "w", encoding="utf-8") as stream:
                stream.write('{"pack":{"pack_format":15}}')
            with zipfile.ZipFile(os.path.join(packs, "XrayPack.zip"), "w") as archive:
                archive.writestr("pack.mcmeta", '{"pack":{"pack_format":15}}')
            items = _list_resource_pack_items(game)
        names = {item["name"] for item in items}
        self.assertIn("FolderPack", names)
        self.assertIn("XrayPack.zip", names)

    def test_downloads_zip_is_added_to_global_resource_pack_candidates(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            home = os.path.join(tmp, "Users", "Tester")
            downloads = os.path.join(home, "Downloads")
            os.makedirs(downloads)
            path = os.path.join(downloads, "resource-pack.zip")
            self._write_xray_zip(path)
            with mock.patch.object(__import__("scanners.inventory_scanner", fromlist=["_fixed_drives"]), "_fixed_drives", return_value=[tmp]):
                with mock.patch.dict(os.environ, {
                    "HOME": home, "USERPROFILE": home,
                    "APPDATA": os.path.join(home, "AppData", "Roaming"),
                    "LOCALAPPDATA": os.path.join(home, "AppData", "Local"),
                    "PROGRAMFILES": os.path.join(tmp, "Program Files"),
                    "PROGRAMFILES(X86)": os.path.join(tmp, "Program Files (x86)"),
                    "SystemDrive": "C:",
                }, clear=False):
                    result = _discover_drive_artifacts(full_scan=False, budget=ScanBudget())
        candidates = [item.get("path") for item in result.get("global_archive_candidates", [])]
        self.assertIn(path, candidates)

    def test_global_download_zip_candidate_gets_texture_analysis(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "downloaded-pack.zip")
            self._write_xray_zip(path)
            records = _analyze_global_resource_packs(
                [{"path": path, "name": "downloaded-pack.zip", "kind": "global_zip"}],
                already_analyzed=[],
            )
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["assessment"], "xray_like_texture_pattern")
        self.assertEqual(records[0]["discovery"], "user_folder_zip_candidate")

    def test_collection_pipeline_adds_zip_resource_pack_analysis(self):
        with tempfile.TemporaryDirectory() as tmp:
            game = os.path.join(tmp, ".minecraft")
            packs = os.path.join(game, "resourcepacks")
            os.makedirs(packs)
            path = os.path.join(packs, "not-obviously-named.zip")
            self._write_xray_zip(path)
            installations, archive_records, pack_records = __import__(
                "scanners.inventory_scanner", fromlist=["_collect_installations"]
            )._collect_installations([{"path": game, "name": "Minecraft"}], hash_entries=[])
        self.assertEqual(len(installations), 1)
        self.assertTrue(any(item.get("path") == path for item in archive_records))
        self.assertTrue(any(item.get("path") == path and item.get("assessment") == "xray_like_texture_pattern" for item in pack_records))

class FindingsFeedTests(unittest.TestCase):
    def test_class_string_matches_are_visible_as_a_finding(self):
        archive = {
            "path": "C:/Users/Test/.minecraft/mods/unknown.jar",
            "assessment": "feature_string_matches",
            "feature_markers": ["xray"],
            "feature_families": ["visual"],
            "class_files_examined": 1,
        }
        findings = _make_findings([archive], [], [], [], [], [], [], [], [])
        self.assertTrue(any(item["category"] == "archive_feature_strings" for item in findings))
        weak = [item for item in findings if item["category"] == "archive_feature_strings"][0]
        self.assertEqual(weak["path"], archive["path"])
        self.assertNotIn("risk", weak)

    def test_partial_xray_texture_anomaly_is_visible_as_a_finding(self):
        pack = {
            "path": "C:/Users/Test/.minecraft/resourcepacks/pack.zip",
            "assessment": "partial_texture_anomalies",
            "notes": ["One partial texture clue"],
            "texture_checks": [{"texture": "stone.png", "transparent_ratio": 0.2}],
        }
        findings = _make_findings([], [pack], [], [], [], [], [], [], [])
        self.assertTrue(any(item["category"] == "xray_texture_clues" for item in findings))

    def test_xray_pack_pattern_is_visible_without_weighting(self):
        pack = {
            "path": "C:/Users/Test/.minecraft/resourcepacks/pack.zip",
            "assessment": "xray_like_texture_pattern",
            "notes": ["Transparent normal blocks; opaque ores"],
            "texture_checks": [{"texture": "stone.png", "transparent_ratio": 1.0}],
        }
        findings = _make_findings([], [pack], [], [], [], [], [], [], [])
        item = [item for item in findings if item["category"] == "xray_texture_pattern"][0]
        self.assertEqual(item["path"], pack["path"])
        self.assertNotIn("risk", item)

    def test_allowlisted_wi_zoom_is_not_duplicated_as_a_client_identity(self):
        archive = {
            "path": "C:/Users/Test/.minecraft/mods/WI-Zoom.jar",
            "assessment": "allow_listed_mod",
            "known_client_matches": [],
            "allowed_mod_matches": [{"name": "WI Zoom"}],
            "namespace_reference_matches": [{"name": "Wurst Client", "source": "namespace_reference"}],
        }
        findings = _make_findings([archive], [], [], [], [], [], [], [], [])
        categories = [item["category"] for item in findings]
        self.assertIn("allow_listed_mod", categories)
        self.assertNotIn("known_client_identity", categories)

    def test_findings_do_not_assign_severity_or_numeric_weight(self):
        archive = {
            "path": "C:/Users/Test/.minecraft/mods/unknown.jar",
            "assessment": "feature_string_matches",
            "feature_markers": ["xray"],
            "feature_families": ["visual"],
            "class_files_examined": 1,
        }
        findings = _make_findings([archive], [], [], [], [], [], [], [], [])
        self.assertTrue(findings)
        for item in findings:
            self.assertFalse(set(item).intersection(("risk", "confidence", "evidence_strength", "severity_score")))

    def test_allowlisted_mod_appears_as_informational_not_suspicious(self):
        archive = {
            "path": "C:/Users/Test/.minecraft/mods/lithium.jar",
            "assessment": "allow_listed_mod",
            "allowed_mod_matches": [{"name": "Lithium"}],
        }
        findings = _make_findings([archive], [], [], [], [], [], [], [], [])
        item = [item for item in findings if item["category"] == "allow_listed_mod"][0]
        self.assertEqual(item["path"], archive["path"])
        self.assertNotIn("risk", item)

if __name__ == "__main__":
    unittest.main()
