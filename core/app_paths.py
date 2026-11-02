
"""User-writable paths for SentinelXT data and reports."""
import os

def get_data_dir():
    appdata = os.environ.get("APPDATA")
    if appdata:
        base = appdata
    else:
        base = os.path.expanduser("~")
    path = os.path.join(base, "SentinelXT")
    if not os.path.isdir(path):
        os.makedirs(path)
    return path

def get_reports_dir():
    path = os.path.join(get_data_dir(), "reports")
    if not os.path.isdir(path):
        os.makedirs(path)
    return path
