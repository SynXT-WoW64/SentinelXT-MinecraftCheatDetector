
"""SentinelXT - Minecraft Client Forensic System."""
import os
import sys

from PySide2.QtCore import Qt
from PySide2.QtGui import QIcon
from PySide2.QtWidgets import QApplication

from interface.main_window import MainWindow
from core.version import PRODUCT_VERSION, BUILD_NUMBER, VERSION_LABEL

__version__ = PRODUCT_VERSION
__build__ = BUILD_NUMBER

def resource_path(relative_path):
    """Return a resource path that works both from source and PyInstaller."""
    base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)

def main():
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    app = QApplication(sys.argv)
    app.setApplicationName("SentinelXT")
    app.setOrganizationName("SynXT")
    app.setWindowIcon(QIcon(resource_path(os.path.join("assets", "sentinelxt.ico"))))
    window = MainWindow(resource_path)
    window.show()
    return app.exec_()

if __name__ == "__main__":
    sys.exit(main())
