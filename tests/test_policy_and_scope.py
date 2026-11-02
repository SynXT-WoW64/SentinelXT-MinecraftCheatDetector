
"""Regression tests for server policy matching and bounded scan scope."""
import json
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from scanners.archive_analyzer import analyze_archive
from scanners import inventory_scanner
from scanners.inventory_scanner import _discover_drive_artifacts, _scan_roots
from scanners.policy_registry import load_policy_registry

class SentinelXTPolicyAndScopeTests(unittest.TestCase):
    def _make_mod(self, folder, filename, mod_id, display_name=None):
        path = os.path.join(folder, filename)
        metadata = {"schemaVersion": 1, "id": mod_id, "name": display_name or mod_id}
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("fabric.mod.json", json.dumps(metadata))
            archive.writestr("example/Marker.class", b"ordinary class payload")
        return path

    def test_server_registry_contains_large_popular_client_catalog(self):
        registry = load_policy_registry()
        self.assertGreaterEqual(len(registry.get("prohibited_clients", [])), 150)
        names = set(registry.get("prohibited_clients", []))
        self.assertIn("Meteor Client", names)
        self.assertIn("Celestial", names)
        self.assertIn("Vape", names)
        self.assertIn("Raven B++", names)
        self.assertGreaterEqual(len(registry.get("exact_prohibited_mod_ids", [])), 100)

    def test_exact_policy_client_metadata_is_recognized(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._make_mod(tmp, "renamed.jar", "celestial", "Celestial")
            result = analyze_archive(path)
            self.assertEqual(result["assessment"], "known_client_identity")
            self.assertTrue(any(item.get("name") == "Celestial" for item in result["known_client_matches"]))

    def test_generic_client_name_is_ambiguous_not_strong_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._make_mod(tmp, "delta-helper.jar", "delta", "Delta")
            result = analyze_archive(path)
            self.assertEqual(result["assessment"], "ambiguous_client_metadata")
            self.assertEqual(result["known_client_matches"], [])
            self.assertTrue(result["ambiguous_client_matches"])

    def test_forbidden_feature_mod_id_is_manual_review_not_auto_ban(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._make_mod(tmp, "ordinary-helper.jar", "autototem", "Totem Helper")
            result = analyze_archive(path)
            self.assertEqual(result["assessment"], "policy_forbidden_mod_identifier")

    def test_allowed_lithium_mod_is_not_flagged_as_ghost_client(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._make_mod(tmp, "lithium.jar", "lithium", "Lithium")
            result = analyze_archive(path)
            self.assertEqual(result["assessment"], "allow_listed_mod")
            self.assertTrue(result["allowed_mod_matches"])

    def test_replaymod_gray_zone_is_not_auto_banned(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._make_mod(tmp, "replaymod.jar", "replaymod", "ReplayMod")
            result = analyze_archive(path)
            self.assertEqual(result["assessment"], "gray_zone_mod_identifier")

    def test_wi_zoom_is_allowlisted_even_when_it_references_wurst_namespace(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "WI-Zoom-1.3-MC1.17.1.jar")
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("fabric.mod.json", json.dumps({"id": "wi_zoom", "name": "WI Zoom"}))
                for index in range(4):
                    archive.writestr("net/wurstclient/zoom/mixin/Mixin{}.class".format(index), b"ordinary mixin bytecode")
                for index in range(4):
                    archive.writestr("net/wurstclient/gui/ZoomScreen{}.class".format(index), b"ordinary ui bytecode")
            result = analyze_archive(path)
        self.assertEqual(result["assessment"], "allow_listed_mod")
        self.assertEqual(result["known_client_matches"], [])
        self.assertTrue(result["allowed_mod_matches"])
        self.assertTrue(result["namespace_reference_matches"] or result.get("known_client_matches") == [])

    def test_appended_client_name_is_a_review_clue_not_an_identity_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._make_mod(tmp, "renamed.jar", "sample_helper", "WurstClientPlus")
            result = analyze_archive(path)
        self.assertEqual(result["assessment"], "ambiguous_client_metadata")
        self.assertEqual(result["known_client_matches"], [])
        self.assertTrue(result["decorated_client_name_matches"])

    def test_case_punctuation_and_unicode_confusables_do_not_hide_client_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._make_mod(tmp, "renamed.jar", "МЕTЕОR—CLlENT", "Meteor Client")
            result = analyze_archive(path)
        self.assertTrue(result["known_client_matches"])

    def test_analysis_records_do_not_expose_risk_or_confidence_scores(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._make_mod(tmp, "ordinary.jar", "example_helper", "Example Helper")
            result = analyze_archive(path)
        self.assertNotIn("risk", result)
        self.assertNotIn("confidence", result)
        self.assertNotIn("evidence_strength", result)

    def test_generic_pe_product_name_is_ambiguous_not_strong_identity(self):
        from types import SimpleNamespace
        from scanners import pe_analyzer

        class FakePE(object):
            def __init__(self, path, fast_load=True):
                table = SimpleNamespace(entries={b"ProductName": b"Delta"})
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
            path = os.path.join(tmp, "utility.exe")
            with open(path, "wb") as stream:
                stream.write(b"MZ-test-file")
            with mock.patch.object(pe_analyzer, "pefile", fake_module):
                result = pe_analyzer.analyze_pe_file(path, include_hash=False)
            self.assertEqual(result["assessment"], "ambiguous_client_metadata")
            self.assertEqual(result["known_client_matches"], [])
            self.assertTrue(result["ambiguous_client_matches"])

    def test_windows_programdata_and_system_trees_are_not_scan_roots(self):
        with tempfile.TemporaryDirectory() as tmp:
            windows = os.path.join(tmp, "Windows", "System32")
            programdata = os.path.join(tmp, "ProgramData", "Microsoft")
            os.makedirs(windows)
            os.makedirs(programdata)
            test_cache_dirs = set(inventory_scanner.CACHE_DIRS) - set(("temp",))
            with mock.patch.object(inventory_scanner, "CACHE_DIRS", test_cache_dirs), mock.patch.dict(os.environ, {
                "APPDATA": os.path.join(tmp, "Roaming"),
                "LOCALAPPDATA": os.path.join(tmp, "Local"),
                "PROGRAMFILES": os.path.join(tmp, "Program Files"),
                "PROGRAMFILES(X86)": os.path.join(tmp, "Program Files (x86)"),
                "SystemDrive": "C:",
            }, clear=False):
                roots = _scan_roots(True, [tmp], [])
            paths = [os.path.normcase(os.path.abspath(item["path"])) for item in roots]
            self.assertNotIn(os.path.normcase(os.path.abspath(windows)), paths)
            self.assertNotIn(os.path.normcase(os.path.abspath(programdata)), paths)
            self.assertTrue(all("programdata" not in path.lower() and "\\windows\\" not in path.lower() for path in paths))

    def test_windows_system_files_and_media_are_skipped_but_user_jar_is_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "Windows", "System32"))
            user_downloads = os.path.join(tmp, "Users", "Tester", "Downloads")
            os.makedirs(user_downloads)
            with zipfile.ZipFile(os.path.join(tmp, "Windows", "System32", "payload.jar"), "w") as archive:
                archive.writestr("fabric.mod.json", '{"id":"meteor-client","name":"Meteor Client"}')
            user_jar = os.path.join(user_downloads, "renamed.jar")
            with zipfile.ZipFile(user_jar, "w") as archive:
                archive.writestr("fabric.mod.json", '{"id":"wurst","name":"Wurst Client"}')
            for filename in ("cover.png", "song.mp3", "clip.mp4", "photo.jpg"):
                with open(os.path.join(user_downloads, filename), "wb") as stream:
                    stream.write(b"ignored media")
            test_cache_dirs = set(inventory_scanner.CACHE_DIRS) - set(("temp",))
            with mock.patch.object(inventory_scanner, "CACHE_DIRS", test_cache_dirs), mock.patch.object(inventory_scanner, "_fixed_drives", return_value=[tmp]), mock.patch.dict(os.environ, {"SystemDrive": "C:"}, clear=False):
                result = _discover_drive_artifacts(full_scan=True)
            found_paths = [item["path"] for item in result.get("global_archive_candidates", [])]
            self.assertIn(user_jar, found_paths)
            self.assertFalse(any("Windows" in path for path in found_paths))
            self.assertEqual(len(found_paths), 1)
            self.assertTrue(result["system_directories_excluded"])
            self.assertTrue(result["non_candidate_extensions_skipped"])

    def test_minecraft_libraries_are_skipped_but_mods_and_versions_are_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            game = os.path.join(tmp, ".minecraft")
            libraries = os.path.join(game, "libraries", "org", "example")
            mods = os.path.join(game, "mods")
            version = os.path.join(game, "versions", "1.20.1")
            os.makedirs(libraries)
            os.makedirs(mods)
            os.makedirs(version)
            with zipfile.ZipFile(os.path.join(libraries, "large-dependency.jar"), "w") as archive:
                archive.writestr("org/example/Dependency.class", b"ordinary dependency")
            self._make_mod(mods, "test-mod.jar", "example_helper", "Example Helper")
            self._make_mod(version, "1.20.1.jar", "vanilla_test", "Vanilla Test")

            with mock.patch.object(inventory_scanner, "_scan_roots", return_value=[{"path": game, "name": "Minecraft"}]):
                discovery = _discover_drive_artifacts(full_scan=False)
            global_paths = [item.get("path", "") for item in discovery.get("global_archive_candidates", [])]
            self.assertFalse(any(os.sep + "libraries" + os.sep in path for path in global_paths))

            installs, archive_records, _packs = inventory_scanner._collect_installations(
                [{"path": game, "name": "Minecraft"}], hash_entries=[]
            )
            checked_paths = [item.get("path", "") for item in archive_records]
            self.assertTrue(any(os.sep + "mods" + os.sep in path for path in checked_paths))
            self.assertTrue(any(os.sep + "versions" + os.sep in path for path in checked_paths))
            self.assertFalse(any(os.sep + "libraries" + os.sep in path for path in checked_paths))
            self.assertTrue(all(item.get("hash_status") == "skipped_no_verified_hash_database" for item in archive_records))

    def test_product_version_is_frozen_and_build_is_separate(self):
        from core.version import PRODUCT_VERSION, BUILD_NUMBER, VERSION_LABEL
        self.assertEqual(PRODUCT_VERSION, "0.1.4")
        self.assertEqual(BUILD_NUMBER, 6)
        self.assertIn("Build #6", VERSION_LABEL)

    def test_fast_scan_and_archive_limits_are_bounded(self):
        from scanners.inventory_scanner import ScanBudget
        from scanners import archive_analyzer
        self.assertEqual(ScanBudget(full_scan=False).seconds, 60)
        self.assertEqual(ScanBudget(full_scan=True).seconds, 120)
        self.assertEqual(archive_analyzer.MAX_ARCHIVE_SECONDS, 0.35)
        self.assertEqual(archive_analyzer.MAX_TOTAL_READ, 1024 * 1024)
        self.assertLessEqual(inventory_scanner.MAX_MOD_ARCHIVES_PER_INSTALLATION, 40)
        self.assertLessEqual(inventory_scanner.MAX_VERSION_ARCHIVES_PER_INSTALLATION, 8)

    def test_mod_folder_scan_is_shallow_and_respects_zero_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            game = os.path.join(tmp, ".minecraft")
            mod_root = os.path.join(game, "mods")
            one_level = os.path.join(mod_root, "organized")
            deep_level = os.path.join(one_level, "nested")
            os.makedirs(deep_level)
            self._make_mod(mod_root, "root-mod.jar", "root_helper", "Root Helper")
            self._make_mod(one_level, "one-level.jar", "one_level_helper", "One Level Helper")
            self._make_mod(deep_level, "deep-mod.jar", "deep_helper", "Deep Helper")
            found = inventory_scanner._list_files(game, "mods", (".jar",), max_files=40)
            paths = [os.path.normcase(item["path"]) for item in found]
            self.assertIn(os.path.normcase(os.path.join(mod_root, "root-mod.jar")), paths)
            self.assertIn(os.path.normcase(os.path.join(one_level, "one-level.jar")), paths)
            self.assertNotIn(os.path.normcase(os.path.join(deep_level, "deep-mod.jar")), paths)
            self.assertEqual(inventory_scanner._list_files(game, "mods", (".jar",), max_files=0), [])

    def test_known_client_name_is_prioritized_when_mod_limit_is_hit(self):
        with tempfile.TemporaryDirectory() as tmp:
            game = os.path.join(tmp, ".minecraft")
            mods = os.path.join(game, "mods")
            os.makedirs(mods)
            for index in range(45):
                with zipfile.ZipFile(os.path.join(mods, "ordinary-{:02d}.jar".format(index)), "w") as archive:
                    archive.writestr("fabric.mod.json", '{{"id":"ordinary_{:02d}","name":"Ordinary"}}'.format(index))
            with zipfile.ZipFile(os.path.join(mods, "zzz-meteor-client.jar"), "w") as archive:
                archive.writestr("fabric.mod.json", '{"id":"meteor-client","name":"Meteor Client"}')
            found = inventory_scanner._list_files(game, "mods", (".jar",), max_files=40)
            names = [item["name"] for item in found]
            self.assertEqual(len(found), 40)
            self.assertIn("zzz-meteor-client.jar", names)

            installs, records, _packs = inventory_scanner._collect_installations(
                [{"path": game, "name": "Test Minecraft"}], hash_entries=[]
            )
            self.assertEqual(len(records), 40)
            self.assertTrue(installs[0]["scan_limits_reached"])

    def test_appdata_discovery_is_shallow_and_finds_named_portable_client(self):
        with tempfile.TemporaryDirectory() as tmp:
            roaming = os.path.join(tmp, "Roaming")
            client = os.path.join(roaming, "Celestial")
            os.makedirs(os.path.join(client, "mods"))
            os.makedirs(os.path.join(client, "versions"))
            test_cache_dirs = set(inventory_scanner.CACHE_DIRS) - set(("temp",))
            with mock.patch.object(inventory_scanner, "CACHE_DIRS", test_cache_dirs), mock.patch.dict(os.environ, {
                "APPDATA": roaming,
                "LOCALAPPDATA": os.path.join(tmp, "Local"),
                "PROGRAMFILES": os.path.join(tmp, "Program Files"),
                "PROGRAMFILES(X86)": os.path.join(tmp, "Program Files (x86)"),
            }, clear=False):
                roots = _scan_roots(False, [], [])
            paths = [os.path.normcase(os.path.abspath(item["path"])) for item in roots]
            self.assertIn(os.path.normcase(os.path.abspath(client)), paths)
            self.assertNotIn(os.path.normcase(os.path.abspath(roaming)), paths)

if __name__ == "__main__":
    unittest.main()
