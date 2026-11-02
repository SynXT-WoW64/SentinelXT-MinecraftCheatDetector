
"""Build #5: tolerant X-Ray name matching and blank-model pack detection."""
import json
import os
import sys
import tempfile
import unittest
import zipfile
from io import BytesIO

from PIL import Image

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.version import PRODUCT_VERSION, BUILD_NUMBER
from scanners.name_matcher import xray_name_hints, has_xray_name_hint
from scanners.texture_analyzer import analyze_resource_pack

def _png(alpha):
    buffer = BytesIO()
    Image.new("RGBA", (16, 16), (90, 90, 90, alpha)).save(buffer, "PNG")
    return buffer.getvalue()

class NameMatcherTests(unittest.TestCase):
    def test_variants_match(self):
        for name in ("xray", "XRay.zip", "x-ray", "x_ray", "X Ray Pack", "xray123", "MinecraftXray-1.8", "xr4y_final", "XRayUltimate"):
            self.assertTrue(has_xray_name_hint(name), name)

    def test_cyrillic_confusables_match(self):
        self.assertTrue(has_xray_name_hint("\u0445ray_pack"))

    def test_network_software_not_matched(self):
        for name in ("Xray VPN", "xray-core-1.8.zip", "v2rayN-xray", "3x-ui xray panel", "Xray proxy"):
            self.assertFalse(has_xray_name_hint(name), name)

    def test_confirmed_pack_keeps_name_lead_even_with_vpn_words(self):
        self.assertTrue(has_xray_name_hint("Xray-VPN-Theme", exclude_network_software=False))

    def test_ore_and_cave_finders(self):
        self.assertIn("ore finder", xray_name_hints("Ore_Finder_pack"))
        self.assertIn("cave finder", xray_name_hints("cavefinder2"))

    def test_unrelated_names(self):
        for name in ("faithful-32x", "bare-bones", "ray-tracing-shaders"):
            self.assertFalse(has_xray_name_hint(name), name)

class BlankModelPackTests(unittest.TestCase):
    def _pack(self, tmp, name, blank_models, with_textures=False):
        path = os.path.join(tmp, name)
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("pack.mcmeta", json.dumps({"pack": {"pack_format": 15, "description": "x"}}))
            for model in blank_models:
                archive.writestr("assets/minecraft/models/block/{}.json".format(model), json.dumps({"elements": []}))
            archive.writestr("assets/minecraft/models/block/diamond_ore.json", json.dumps({"parent": "block/cube_all"}))
            if with_textures:
                archive.writestr("assets/minecraft/textures/block/stone.png", _png(255))
        return path

    def test_blank_models_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = analyze_resource_pack(self._pack(tmp, "plain.zip", ["stone", "dirt", "netherrack", "deepslate"]))
            self.assertEqual(result["assessment"], "xray_like_model_pattern")
            self.assertEqual(len(result["blank_block_models"]), 4)

    def test_normal_models_not_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = analyze_resource_pack(self._pack(tmp, "normal.zip", [], with_textures=True))
            self.assertNotEqual(result["assessment"], "xray_like_model_pattern")

    def test_two_blank_models_not_enough(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = analyze_resource_pack(self._pack(tmp, "two.zip", ["stone", "dirt"]))
            self.assertNotEqual(result["assessment"], "xray_like_model_pattern")

    def test_name_hint_variant_in_pack_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = analyze_resource_pack(self._pack(tmp, "x_ray123.zip", [], with_textures=True))
            self.assertTrue(result["metadata_hints"])

class VersionTests(unittest.TestCase):
    def test_version_locked(self):
        self.assertEqual(PRODUCT_VERSION, "0.1.4")
        self.assertEqual(BUILD_NUMBER, 6)

if __name__ == "__main__":
    unittest.main()
