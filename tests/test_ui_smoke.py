
"""GUI construction smoke test; run on Windows with PySide2 installed."""
import os
import sys
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

try:
    from PySide2.QtWidgets import QApplication
    from interface.main_window import MainWindow
    PYSIDE2_AVAILABLE = True
except ImportError:
    PYSIDE2_AVAILABLE = False

@unittest.skipUnless(PYSIDE2_AVAILABLE, "PySide2 is not installed in this environment")
class SentinelXTGuiSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_main_window_can_be_constructed(self):
        def resource_path(relative_path):
            return os.path.join(PROJECT_ROOT, relative_path)

        window = MainWindow(resource_path, language="en")
        self.assertIn("0.1.4", window.windowTitle())
        self.assertIn("Build #6", window.windowTitle())
        self.assertEqual(window.pages.count(), 5)
        self.assertTrue(hasattr(window, "results_list"))
        self.assertEqual(window.nav_buttons[2].text(), "Results")
        window.close()

if __name__ == "__main__":
    unittest.main()
