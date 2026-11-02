
"""Verify SentinelXT's Windows 7 legacy Python environment and local YARA rules."""
import os
import struct
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))

def show(label, value):
    print("{:<22} {}".format(label + ":", value))

def main():
    print("SentinelXT environment check")
    print("=" * 36)
    show("Python", sys.version.replace("\n", " "))
    show("Architecture", "{}-bit".format(struct.calcsize("P") * 8))
    show("Executable", sys.executable)

    checks = [
        ("PySide2", "PySide2"),
        ("psutil", "psutil"),
        ("Pillow", "PIL"),
        ("pefile", "pefile"),
        ("PyInstaller", "PyInstaller"),
        ("yara-python", "yara"),
    ]
    failures = []
    for label, module_name in checks:
        try:
            module = __import__(module_name)
            version = getattr(module, "__version__", getattr(module, "VERSION", "OK"))
            show(label, version)
        except Exception as exc:
            show(label, "MISSING ({})".format(type(exc).__name__))
            failures.append(label)

    try:
        import sqlite3
        show("SQLite", sqlite3.sqlite_version)
    except Exception as exc:
        show("SQLite", "ERROR ({})".format(type(exc).__name__))
        failures.append("SQLite")

    try:
        import yara
        rule_path = os.path.join(ROOT, "database", "rules", "sentinelxt.yar")
        yara.compile(filepath=rule_path)
        show("YARA rules", "COMPILED")
    except Exception as exc:
        show("YARA rules", "ERROR ({})".format(type(exc).__name__))
        failures.append("YARA rules")

    print("=" * 36)
    if sys.version_info[:2] != (3, 8):
        failures.append("Python 3.8 expected")
    if struct.calcsize("P") * 8 != 64:
        failures.append("64-bit Python expected")
    if failures:
        print("CHECK FAILED: " + ", ".join(failures))
        return 1
    print("ALL CHECKS PASSED")
    return 0

if __name__ == "__main__":
    sys.exit(main())
