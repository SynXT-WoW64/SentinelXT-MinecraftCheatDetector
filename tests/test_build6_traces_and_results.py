
"""Fuzzy names, trace sources, renamed resource packs and Results grouping."""
import json
import os
import struct
import sys
import tempfile
import unittest
import zipfile
from io import BytesIO

from PIL import Image

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from scanners.name_matcher import has_xray_name_hint
from scanners import trace_scanner
from scanners.inventory_scanner import _make_findings
from interface.results_model import build_groups, export_text, short_path_parts

def _png(alpha):
    buffer = BytesIO()
    Image.new("RGBA", (16, 16), (90, 90, 90, alpha)).save(buffer, "PNG")
    return buffer.getvalue()

def _pack(path):
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("pack.mcmeta", json.dumps({"pack": {"pack_format": 15, "description": "d"}}))
        archive.writestr("assets/minecraft/textures/block/stone.png", _png(0))
        archive.writestr("assets/minecraft/textures/block/diamond_ore.png", _png(255))

def _recycle_record(original, version=2):
    raw = original.encode("utf-16-le") + b"\x00\x00"
    if version == 2:
        return struct.pack("<QQQI", 2, 1234, 132000000000000000, len(original) + 1) + raw
    return struct.pack("<QQQ", 1, 1234, 132000000000000000) + raw.ljust(520, b"\x00")

class FuzzyNameTests(unittest.TestCase):
    def test_typos_and_obfuscation(self):
        for name in ("xrya", "xrray", "xr4y", "x.r.a.y", "xr\u200bay", "\uff58\uff52\uff41\uff59", "\u0445ray-final", "xRayUltimate_v2"):
            self.assertTrue(has_xray_name_hint(name), name)

    def test_normal_names_not_matched(self):
        for name in ("Xray VPN", "xray-core", "v2rayN", "faithful-32x", "bare-bones", "xbox", "extra", "xerox", "Xmas", "ray-tracing"):
            self.assertFalse(has_xray_name_hint(name), name)

class TraceScannerTests(unittest.TestCase):
    def test_filesystem_sweep_finds_names_anywhere(self):
        with tempfile.TemporaryDirectory() as tmp:
            deep = os.path.join(tmp, "stuff", "misc")
            os.makedirs(deep)
            _pack(os.path.join(deep, "x_ray123.zip"))
            os.makedirs(os.path.join(tmp, "X-Ray folder"))
            with open(os.path.join(tmp, "readme.txt"), "w") as stream:
                stream.write("hello")
            result = trace_scanner.scan_filesystem_names([tmp], seconds=5)
            names = sorted(item["name"] for item in result["traces"])
            self.assertIn("x_ray123.zip", names)
            self.assertIn("X-Ray folder", names)
            self.assertNotIn("readme.txt", names)
            self.assertTrue(any(c["path"].endswith("x_ray123.zip") for c in result["pack_candidates"]))

    def test_renamed_pack_found_by_structure(self):
        with tempfile.TemporaryDirectory() as tmp:
            _pack(os.path.join(tmp, "holiday.zip"))
            with zipfile.ZipFile(os.path.join(tmp, "plain.zip"), "w") as archive:
                archive.writestr("notes.txt", "x" * 6000)
            result = trace_scanner.scan_filesystem_names([tmp], seconds=5)
            paths = [c["path"] for c in result["pack_candidates"]]
            self.assertTrue(any(p.endswith("holiday.zip") for p in paths))
            self.assertFalse(any(p.endswith("plain.zip") for p in paths))

    def test_disguised_pack_with_wrong_extension(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "cache.dat")
            _pack(target)
            with open(target, "ab") as stream:
                stream.write(b"\x00" * (trace_scanner.MIN_DISGUISED_BYTES + 10))
            result = trace_scanner.scan_filesystem_names([tmp], seconds=5)
            self.assertTrue(any(item["kind"] == "disguised_archive" for item in result["traces"]))

    def test_recycle_info_parsing_both_versions(self):
        for version in (1, 2):
            info = trace_scanner.parse_recycle_info(_recycle_record("D:\\dl\\xray-pack.zip", version))
            self.assertEqual(info["original_path"], "D:\\dl\\xray-pack.zip")
            self.assertEqual(info["size_bytes"], 1234)

    def test_recycle_bin_scan_reports_original_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            owner = os.path.join(tmp, "$Recycle.Bin", "S-1-5-21-1")
            os.makedirs(owner)
            with open(os.path.join(owner, "$IABC123.zip"), "wb") as stream:
                stream.write(_recycle_record("C:\\Users\\a\\Downloads\\X Ray pack.zip"))
            with open(os.path.join(owner, "$IOTHER.txt"), "wb") as stream:
                stream.write(_recycle_record("C:\\Users\\a\\notes.txt"))
            traces = trace_scanner.scan_recycle_bin([tmp])
            self.assertEqual(len(traces), 1)
            self.assertEqual(traces[0]["kind"], "deleted_file")

    def test_recent_and_prefetch(self):
        with tempfile.TemporaryDirectory() as tmp:
            recent = os.path.join(tmp, "Recent")
            prefetch = os.path.join(tmp, "Prefetch")
            os.makedirs(recent)
            os.makedirs(prefetch)
            with open(os.path.join(recent, "xray.zip.lnk"), "wb") as stream:
                stream.write(b"L\x00\x00\x00C:\\Users\\a\\Downloads\\xray.zip\x00")
            with open(os.path.join(recent, "photo.jpg.lnk"), "wb") as stream:
                stream.write(b"x")
            with open(os.path.join(prefetch, "XRAY_INJECTOR.EXE-1A2B3C4D.pf"), "wb") as stream:
                stream.write(b"x")
            with open(os.path.join(prefetch, "NOTEPAD.EXE-AAAA.pf"), "wb") as stream:
                stream.write(b"x")
            recent_traces = trace_scanner.scan_recent_links(recent)
            self.assertEqual(len(recent_traces), 1)
            self.assertIn("xray.zip", recent_traces[0]["target_hint"])
            self.assertEqual(len(trace_scanner.scan_prefetch(prefetch)), 1)

class FindingsAndResultsTests(unittest.TestCase):
    def _findings(self):
        traces = [
            {"kind": "deleted_file", "path": "C:\\$Recycle.Bin\\S\\$IABC", "original_path": "C:\\a\\xray.zip", "name": "xray.zip",
             "leads": [{"type": "xray_name", "hint": "xray"}], "deleted_at": "2026-10-01T10:00:00", "source": "recycle_bin"},
            {"kind": "file", "path": "D:\\x\\xray.zip", "name": "xray.zip", "leads": [{"type": "xray_name", "hint": "xray"}], "source": "filesystem"},
        ]
        return _make_findings([], [], [], [], [], [], [], [], [], trace_records=traces)

    def test_trace_findings_created(self):
        categories = sorted(item["category"] for item in self._findings())
        self.assertEqual(categories, ["name_trace_deleted", "name_trace_file"])

    def test_groups_search_and_informational_hiding(self):
        findings = self._findings() + [
            {"category": "allow_listed_mod", "title": "Разрешённый мод", "path": "C:\\mods\\sodium.jar", "details": "", "evidence": {}},
            {"category": "xray_texture_pattern", "title": "Паттерн", "path": "D:\\p.zip", "details": "", "evidence": {}},
        ]
        groups, hidden = build_groups(findings)
        self.assertEqual(hidden, 1)
        self.assertEqual([g[0] for g in groups], ["packs", "traces"])
        groups, hidden = build_groups(findings, show_informational=True)
        self.assertEqual(hidden, 0)
        self.assertEqual(len(groups), 3)
        groups, _ = build_groups(findings, query="recycle")
        self.assertEqual(sum(len(g[2]) for g in groups), 1)
        text = export_text(build_groups(findings)[0])
        self.assertIn("xray.zip", text)

    def test_short_path_parts(self):
        name, folder = short_path_parts("C:\\Users\\very\\" + "long\\" * 20 + "file.zip")
        self.assertEqual(name, "file.zip")
        self.assertLessEqual(len(folder), 64)

if __name__ == "__main__":
    unittest.main()
