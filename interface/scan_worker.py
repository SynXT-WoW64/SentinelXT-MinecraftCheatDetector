
from PySide2.QtCore import QThread, Signal

from scanners.inventory_scanner import scan_inventory
from core.reporting import save_report

class ScanWorker(QThread):
    progress = Signal(str)
    completed = Signal(object, str)
    failed = Signal(str)

    def __init__(self, full_scan=False, parent=None):
        QThread.__init__(self, parent)
        self.full_scan = bool(full_scan)

    def run(self):
        try:
            report = scan_inventory(self.progress.emit, full_scan=self.full_scan)
            report_path = save_report(report)
            self.completed.emit(report, report_path)
        except Exception as exc:
            self.failed.emit("{}: {}".format(type(exc).__name__, exc))
