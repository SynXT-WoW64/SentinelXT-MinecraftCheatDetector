
"""Small offline smoke tests for SentinelXT scanners; run: python -m unittest discover -s tests"""
import os
import sys
import tempfile
import unittest
from types import SimpleNamespace
import zipfile
from io import BytesIO
from unittest import mock

from PIL import Image

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from scanners.archive_analyzer import analyze_archive
from scanners.texture_analyzer import analyze_resource_pack
from scanners import inventory_scanner
from scanners.inventory_scanner import scan_inventory

class SentinelXTScannerTests(unittest.TestCase):
    def test_jar_known_client_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = os.path.join(tmp, "renamed.jar")
            with zipfile.ZipFile(jar_path, "w") as archive:
                archive.writestr("fabric.mod.json", '{"id":"meteor-client","name":"Meteor Client"}')
                archive.writestr("example/Feature.class", b"KillAura AimAssist Velocity")
            result = analyze_archive(jar_path, "mod")
            self.assertEqual(result["assessment"], "known_client_identity")
            self.assertTrue(result["sha256"])

    def test_xray_like_texture_pattern(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack_path = os.path.join(tmp, "test-pack.zip")
            with zipfile.ZipFile(pack_path, "w") as archive:
                for name in ("stone", "deepslate", "netherrack"):
                    image = Image.new("RGBA", (16, 16), (100, 100, 100, 0))
                    buffer = BytesIO()
                    image.save(buffer, format="PNG")
                    archive.writestr("assets/minecraft/textures/block/{}.png".format(name), buffer.getvalue())
                image = Image.new("RGBA", (16, 16), (100, 100, 100, 255))
                buffer = BytesIO()
                image.save(buffer, format="PNG")
                archive.writestr("assets/minecraft/textures/block/diamond_ore.png", buffer.getvalue())
            result = analyze_resource_pack(pack_path)
            self.assertEqual(result["assessment"], "xray_like_texture_pattern")

    def test_full_drive_scan_finds_renamed_jar_outside_minecraft_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            downloads = os.path.join(tmp, "Downloads")
            os.makedirs(downloads)
            jar_path = os.path.join(downloads, "ordinary-file.jar")
            with zipfile.ZipFile(jar_path, "w") as archive:
                archive.writestr("fabric.mod.json", '{"id":"liquidbounce","name":"LiquidBounce"}')
                archive.writestr("dev/package/SomeClass.class", b"KillAura")
            original_drive_function = inventory_scanner._fixed_drives
            inventory_scanner._fixed_drives = lambda: [tmp]
            try:

                test_cache_dirs = set(inventory_scanner.CACHE_DIRS) - set(("temp",))
                with mock.patch.object(inventory_scanner, "CACHE_DIRS", test_cache_dirs):
                    result = scan_inventory(full_scan=True)
            finally:
                inventory_scanner._fixed_drives = original_drive_function
            self.assertTrue(any(
                item.get("path") == jar_path
                for item in result.get("archive_analyses", [])
            ))
            self.assertTrue(any(
                finding.get("category") == "known_client_identity"
                and finding.get("path") == jar_path
                for finding in result.get("findings", [])
            ))

    def test_known_minecraft_directory_is_inventoried(self):
        with tempfile.TemporaryDirectory() as tmp:
            appdata = os.path.join(tmp, "Roaming")
            game = os.path.join(appdata, ".minecraft")
            os.makedirs(os.path.join(game, "mods"))
            os.makedirs(os.path.join(game, "versions", "1.20.1"))
            with zipfile.ZipFile(os.path.join(game, "mods", "test.jar"), "w") as archive:
                archive.writestr("fabric.mod.json", '{"id":"wurst"}')
            old_env = {}
            for key, value in {
                "APPDATA": appdata,
                "LOCALAPPDATA": os.path.join(tmp, "Local"),
                "PROGRAMDATA": os.path.join(tmp, "ProgramData"),
                "PROGRAMFILES": os.path.join(tmp, "Program Files"),
                "PROGRAMFILES(X86)": os.path.join(tmp, "Program Files (x86)"),
            }.items():
                old_env[key] = os.environ.get(key)
                os.environ[key] = value
            try:
                test_cache_dirs = set(inventory_scanner.CACHE_DIRS) - set(("temp",))
                with mock.patch.object(inventory_scanner, "CACHE_DIRS", test_cache_dirs):
                    result = scan_inventory(full_scan=False)
            finally:
                for key, value in old_env.items():
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value
            self.assertEqual(result["summary"]["game_directories"], 1)
            self.assertGreaterEqual(result["summary"]["archive_checks"], 1)
            self.assertTrue(any(item["category"] == "known_client_identity" for item in result["findings"]))

    def test_generic_xray_filename_is_not_a_cheat_detection(self):
        from scanners.pe_analyzer import analyze_pe_file
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "xray.exe")
            with open(path, "wb") as stream:
                stream.write(b"This is a placeholder for a VPN executable named Xray.\x00")
            result = analyze_pe_file(path, include_hash=False)
            self.assertNotIn(result.get("assessment"), ("known_client_metadata", "multi_family_behavior_markers"))

    def test_single_xray_marker_is_not_a_client_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "some-mod.jar")
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("example/Feature.class", b"xray")
            result = analyze_archive(path, "mod")
            self.assertEqual(result["assessment"], "feature_string_matches")

    def test_archive_filename_does_not_create_identity_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "meteor-client.jar")
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("fabric.mod.json", '{"id":"example-helper","name":"Example Helper"}')
                archive.writestr("example/Feature.class", b"ordinary code")
            result = analyze_archive(path, "mod")
            self.assertEqual(result["assessment"], "no_known_indicators")
            self.assertEqual(result["known_client_matches"], [])

    def test_java_agent_in_minecraft_version_config_is_recorded(self):
        from scanners.runtime_config_analyzer import analyze_runtime_configs
        with tempfile.TemporaryDirectory() as tmp:
            game = os.path.join(tmp, ".minecraft")
            version_dir = os.path.join(game, "versions", "1.20.1")
            os.makedirs(version_dir)
            config_path = os.path.join(version_dir, "1.20.1.json")
            with open(config_path, "w", encoding="utf-8") as stream:
                stream.write('{"arguments":{"jvm":["-Xmx2G","-javaagent:C:/temp/agent.jar"]}}')
            results = analyze_runtime_configs([{"game_path": game}])
            self.assertEqual(len(results), 1)
            self.assertIn("-javaagent", results[0]["flags"])
            self.assertIn("C:/temp/agent.jar", results[0]["targets"])

    def test_non_exact_client_name_in_pe_metadata_is_not_identity_match(self):
        from unittest import mock
        from scanners import pe_analyzer

        class FakePE(object):
            def __init__(self, path, fast_load=True):
                table = SimpleNamespace(entries={b"ProductName": b"Meteor Client Helper Utility"})
                entry = SimpleNamespace(StringTable=[table])
                self.FileInfo = [[entry]]
                self.sections = []
                self.DIRECTORY_ENTRY_IMPORT = []
            def parse_data_directories(self, directories=None):
                return None
            def close(self):
                return None

        fake_module = SimpleNamespace(
            PE=FakePE,
            DIRECTORY_ENTRY={"IMAGE_DIRECTORY_ENTRY_RESOURCE": 2, "IMAGE_DIRECTORY_ENTRY_IMPORT": 1},
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "helper.exe")
            with open(path, "wb") as stream:
                stream.write(b"MZ-test-file")
            with mock.patch.object(pe_analyzer, "pefile", fake_module):
                result = pe_analyzer.analyze_pe_file(path, include_hash=False)
            self.assertEqual(result["known_client_matches"], [])
            self.assertEqual(result["assessment"], "no_minecraft_identity_match")

    def test_exact_pe_product_name_is_a_manual_review_signal_not_high_verdict(self):
        from unittest import mock
        from scanners import pe_analyzer

        class FakePE(object):
            def __init__(self, path, fast_load=True):
                table = SimpleNamespace(entries={b"ProductName": b"Meteor Client"})
                entry = SimpleNamespace(StringTable=[table])
                self.FileInfo = [[entry]]
                self.sections = []
                self.DIRECTORY_ENTRY_IMPORT = []
            def parse_data_directories(self, directories=None):
                return None
            def close(self):
                return None

        fake_module = SimpleNamespace(
            PE=FakePE,
            DIRECTORY_ENTRY={"IMAGE_DIRECTORY_ENTRY_RESOURCE": 2, "IMAGE_DIRECTORY_ENTRY_IMPORT": 1},
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "client.exe")
            with open(path, "wb") as stream:
                stream.write(b"MZ-test-file")
            with mock.patch.object(pe_analyzer, "pefile", fake_module):
                result = pe_analyzer.analyze_pe_file(path, include_hash=False)
            self.assertEqual(result["assessment"], "known_client_metadata")

    def test_xray_vpn_pe_metadata_is_not_flagged_as_minecraft_cheat(self):
        from unittest import mock
        from scanners import pe_analyzer

        class FakePE(object):
            def __init__(self, path, fast_load=True):
                table = SimpleNamespace(entries={b"ProductName": b"Xray VPN Core", b"FileDescription": b"Network proxy client"})
                entry = SimpleNamespace(StringTable=[table])
                self.FileInfo = [[entry]]
                self.sections = []
                self.DIRECTORY_ENTRY_IMPORT = []
            def parse_data_directories(self, directories=None):
                return None
            def close(self):
                return None

        fake_module = SimpleNamespace(
            PE=FakePE,
            DIRECTORY_ENTRY={"IMAGE_DIRECTORY_ENTRY_RESOURCE": 2, "IMAGE_DIRECTORY_ENTRY_IMPORT": 1},
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "xray.exe")
            with open(path, "wb") as stream:
                stream.write(b"MZ-test-file")
            with mock.patch.object(pe_analyzer, "pefile", fake_module):
                result = pe_analyzer.analyze_pe_file(path, include_hash=False)
            self.assertEqual(result["assessment"], "no_minecraft_identity_match")
            self.assertEqual(result["known_client_matches"], [])
            self.assertIsNone(result["launcher_identity"])

if __name__ == "__main__":
    unittest.main()
