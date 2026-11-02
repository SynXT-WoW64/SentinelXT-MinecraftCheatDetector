
"""JSON report writer. Reports stay on the local computer."""
import datetime
import json
import os

from core.app_paths import get_reports_dir

def save_report(report):
    reports_dir = get_reports_dir()
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = "SentinelXT_forensic_{}.json".format(stamp)
    path = os.path.join(reports_dir, filename)
    with open(path, "w", encoding="utf-8") as report_file:
        json.dump(report, report_file, ensure_ascii=False, indent=2)
    return path
