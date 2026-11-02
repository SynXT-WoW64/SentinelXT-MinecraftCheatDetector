
import json
import os
import re
import subprocess
import sys

from PySide2.QtCore import Qt, QUrl, QSettings
from PySide2.QtGui import QPixmap, QColor, QBrush, QDesktopServices
from PySide2.QtWidgets import (
    QMainWindow, QWidget, QFrame, QLabel, QPushButton, QVBoxLayout,
    QHBoxLayout, QStackedWidget, QProgressBar, QTextEdit, QListWidget,
    QListWidgetItem, QMessageBox, QCheckBox, QComboBox, QApplication, QLineEdit
)

from interface.scan_worker import ScanWorker
from core.app_paths import get_reports_dir
from interface.results_model import (
    RESULT_FILTER_GROUPS, build_groups, short_path_parts, finding_time_hint, export_text
)
from core.version import PRODUCT_VERSION, BUILD_NUMBER, BUILD_LABEL, VERSION_LABEL, AUTHOR, DISCORD_INVITE_URL
from core import i18n
from core.i18n import tr

STYLE = """
QMainWindow, QWidget#root { background: #090909; color: #f5f5f5; }
QWidget { color: #f5f5f5; font-family: 'Segoe UI'; font-size: 10pt; }
QFrame#sidebar { background: #101010; border-right: 1px solid #292929; }
QFrame#topbar { background: #111111; border-bottom: 1px solid #292929; }
QLabel#brand { color: #ffffff; font-size: 19pt; font-weight: 700; }
QLabel#subtitle { color: #8e8e8e; font-size: 8pt; letter-spacing: 1px; }
QLabel#pageTitle { color: #ffffff; font-size: 21pt; font-weight: 700; }
QLabel#muted { color: #a5a5a5; }
QPushButton#nav { text-align: left; padding: 12px 14px; border: 0; border-radius: 8px; color: #bdbdbd; background: transparent; }
QPushButton#nav:hover { background: #202020; color: #ffffff; }
QPushButton#nav:checked { background: #2a1113; color: #ffffff; border-left: 3px solid #e21b2d; }
QPushButton#primary { background: #d7192d; color: #ffffff; border: 0; border-radius: 9px; padding: 12px 20px; font-weight: 700; }
QPushButton#primary:hover { background: #f02b3f; }
QPushButton#primary:disabled { background: #542126; color: #a9a9a9; }
QPushButton#secondary { background: #1b1b1b; color: #f0f0f0; border: 1px solid #383838; border-radius: 8px; padding: 10px 14px; }
QPushButton#secondary:hover { background: #292929; border-color: #777777; }
QPushButton#discord { background: #5865f2; color: #ffffff; border: 0; border-radius: 8px; padding: 10px 14px; font-weight: 700; }
QPushButton#discord:hover { background: #6d79ff; }
QFrame#card { background: #141414; border: 1px solid #303030; border-radius: 13px; }
QFrame#verdictCard { background: #151515; border: 1px solid #383838; border-left: 4px solid #777777; border-radius: 10px; }
QLabel#verdictValue { color: #ffffff; font-size: 16pt; font-weight: 700; }
QLabel#metric { color: #ffffff; font-size: 23pt; font-weight: 700; }
QLabel#metricLabel { color: #9c9c9c; font-size: 9pt; }
QTextEdit, QListWidget { background: #080808; border: 1px solid #303030; border-radius: 8px; padding: 8px; color: #eeeeee; selection-background-color: #9e1422; }
QListWidget::item { padding: 8px 7px; border-bottom: 1px solid #222222; }
QLineEdit { background: #151515; color: #eeeeee; border: 1px solid #444444; border-radius: 7px; padding: 7px 10px; }
QListWidget::item:selected { background: #2a1113; }
QComboBox { background: #151515; color: #eeeeee; border: 1px solid #444444; border-radius: 7px; padding: 7px 10px; min-width: 150px; }
QComboBox QAbstractItemView { background: #151515; color: #eeeeee; selection-background-color: #9e1422; }
QCheckBox { color: #b0b0b0; spacing: 8px; padding-top: 5px; }
QCheckBox::indicator { width: 15px; height: 15px; }
QCheckBox::indicator:unchecked { background: #080808; border: 1px solid #5b5b5b; border-radius: 4px; }
QCheckBox::indicator:checked { background: #d7192d; border: 1px solid #d7192d; border-radius: 4px; }
QProgressBar { background: #282828; border: 0; border-radius: 5px; height: 10px; text-align: center; color: #ffffff; }
QProgressBar::chunk { background: #d7192d; border-radius: 5px; }
"""

RESULT_CATEGORY_LABELS = {
    "verified_hash_match": "SHA-256 совпадение",
    "known_client_identity": "Идентификатор клиента",
    "ambiguous_client_metadata": "Неоднозначные метаданные",
    "policy_forbidden_mod_identifier": "Запрещённый ID мода",
    "gray_zone_mod_identifier": "Серая зона правил",
    "multi_family_behavior_markers": "Группы игровых функций",
    "archive_feature_strings": "Строки в JAR",
    "allow_listed_mod": "Разрешённый мод",
    "namespace_reference": "Ссылка на namespace",
    "yara_client_signature": "YARA-сигнатура",
    "ambiguous_pe_metadata": "Неоднозначные PE-метаданные",
    "client_name_in_pe_metadata": "Название в PE-метаданных",
    "pe_feature_families": "Группы строк в PE",
    "pe_feature_strings": "Строки в EXE/DLL",
    "recognized_launcher": "Minecraft-лаунчер",
    "xray_texture_pattern": "X-Ray-подобные текстуры",
    "xray_texture_clues": "Особенности текстур",
    "xray_model_pattern": "X-Ray-подобные модели блоков",
    "disguised_archive": "Ресурс-пак под чужим именем",
    "name_trace_file": "Название файла/папки",
    "name_trace_deleted": "Удалён (корзина)",
    "name_trace_recent": "Недавние файлы",
    "name_trace_execution": "Запускалась (Prefetch)",
    "resource_pack_name_hint": "Название ресурс-пака",
    "client_filename_match": "Совпадение имени файла",
    "client_directory_match": "Совпадение имени каталога",
    "java_runtime_config": "JVM-конфигурация",
    "running_client_process": "Активный процесс",
    "java_runtime_injection": "Java Agent / runtime",
    "historical_client_trace": "Историческая запись",
    "minecraft_automation_script": "Скрипт Minecraft",
    "generic_automation_script": "Скрипт автоматизации",
    "context_dependent_software": "ПО двойного назначения",
}

class MetricCard(QFrame):
    def __init__(self, title, value="—"):
        QFrame.__init__(self)
        self.setObjectName("card")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(7)
        self.value_label = QLabel(str(value))
        self.value_label.setObjectName("metric")
        title_label = QLabel(title)
        title_label.setObjectName("metricLabel")
        title_label.setWordWrap(True)
        layout.addWidget(self.value_label)
        layout.addWidget(title_label)

    def set_value(self, value):
        self.value_label.setText(str(value))

class MainWindow(QMainWindow):
    def __init__(self, resource_path, language=None):
        QMainWindow.__init__(self)
        self._settings = QSettings("SynXT", "SentinelXT")
        if language is None:
            language = self._settings.value("language", i18n.DEFAULT_LANGUAGE)
        i18n.set_language(str(language))
        self.resource_path = resource_path
        self.worker = None
        self.last_report_path = None
        self.last_report = None
        self.setWindowTitle("SentinelXT — Minecraft Client Forensics · {}".format(VERSION_LABEL))
        self.setMinimumSize(920, 620)
        self.resize(1160, 760)
        self.setStyleSheet(STYLE)
        self._build_ui()
        self._show_page(0)

    def _build_ui(self):
        root = QWidget()
        root.setObjectName("root")
        self.setCentralWidget(root)
        outer = QHBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(225)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(16, 24, 16, 18)
        side.setSpacing(9)

        brand_row = QHBoxLayout()
        brand_icon = QLabel()
        brand_icon.setFixedSize(38, 38)
        pixmap = QPixmap(self.resource_path(os.path.join("assets", "sentinelxt.png")))
        if not pixmap.isNull():
            brand_icon.setPixmap(pixmap.scaled(38, 38, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        brand_row.addWidget(brand_icon)
        brand_text = QVBoxLayout()
        brand = QLabel("SentinelXT")
        brand.setObjectName("brand")
        subtitle = QLabel("MINECRAFT FORENSICS")
        subtitle.setObjectName("subtitle")
        brand_text.addWidget(brand)
        brand_text.addWidget(subtitle)
        brand_row.addLayout(brand_text, 1)
        side.addLayout(brand_row)
        side.addSpacing(24)

        self.nav_buttons = []
        nav_items = [(tr("Обзор"), 0), (tr("Проверка"), 1), (tr("Результаты"), 2), (tr("Отчёты"), 3), (tr("О программе"), 4)]
        for text, index in nav_items:
            button = QPushButton(text)
            button.setObjectName("nav")
            button.setCheckable(True)
            button.clicked.connect(lambda checked=False, page=index: self._show_page(page))
            side.addWidget(button)
            self.nav_buttons.append(button)

        side.addStretch(1)
        self.discord_button = self._make_discord_button()
        side.addWidget(self.discord_button)
        version_label = QLabel("LEGACY EDITION  ·  {}".format(VERSION_LABEL))
        version_label.setObjectName("subtitle")
        side.addWidget(version_label)
        self.author_label = QLabel(tr("Автор: {}").format(AUTHOR))
        self.author_label.setObjectName("subtitle")
        side.addWidget(self.author_label)

        outer.addWidget(sidebar)

        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(28, 22, 28, 24)
        content_layout.setSpacing(18)
        outer.addWidget(content, 1)

        topbar = QFrame()
        topbar.setObjectName("topbar")
        topbar.setFixedHeight(48)
        top_layout = QHBoxLayout(topbar)
        top_layout.setContentsMargins(14, 0, 14, 0)
        self.status_label = QLabel(tr("Локальный режим · данные не отправляются"))
        self.status_label.setObjectName("muted")
        top_layout.addWidget(self.status_label)
        top_layout.addStretch(1)
        top_layout.addWidget(QLabel(tr("Язык:")))
        self.language_combo = QComboBox()
        self.language_combo.setMinimumWidth(130)
        for code, name in i18n.LANGUAGES:
            self.language_combo.addItem(name, code)
        self.language_combo.setCurrentIndex(max(0, self.language_combo.findData(i18n.get_language())))
        self.language_combo.currentIndexChanged.connect(self._on_language_changed)
        top_layout.addWidget(self.language_combo)
        content_layout.addWidget(topbar)

        self.pages = QStackedWidget()
        content_layout.addWidget(self.pages, 1)
        self._build_dashboard_page()
        self._build_scan_page()
        self._build_results_page()
        self._build_reports_page()
        self._build_about_page()

    def _page_container(self, title, description):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 2, 0, 0)
        layout.setSpacing(12)
        title_label = QLabel(title)
        title_label.setObjectName("pageTitle")
        desc_label = QLabel(description)
        desc_label.setObjectName("muted")
        desc_label.setWordWrap(True)
        layout.addWidget(title_label)
        layout.addWidget(desc_label)
        return page, layout

    def _build_dashboard_page(self):
        page, layout = self._page_container(
            tr("Панель проверки"),
            tr("Поиск Minecraft-лаунчеров, игровых директорий, чит-клиентских маркеров и подозрительных ресурс-паков.")
        )

        intro = QFrame()
        intro.setObjectName("card")
        intro_layout = QVBoxLayout(intro)
        intro_layout.setContentsMargins(22, 20, 22, 20)
        headline = QLabel(tr("Проверь, что находится на компьютере"))
        headline.setStyleSheet("font-size: 16pt; font-weight: 700; color: #ffffff;")
        body = QLabel(
            tr("SentinelXT ищет Minecraft-лаунчеры, игровые версии, моды, ресурс-паки и известные запрещённые клиенты. "
            "Windows и системные каталоги не обходятся; изображения, аудио, видео и документы пропускаются. "
            "Найденные файлы не запускаются, не изменяются и не отправляются в интернет.")
        )
        body.setObjectName("muted")
        body.setWordWrap(True)
        self.start_button = QPushButton(tr("Запустить проверку"))
        self.start_button.setObjectName("primary")
        self.start_button.clicked.connect(self.start_scan)
        intro_layout.addWidget(headline)
        intro_layout.addWidget(body)
        intro_layout.addSpacing(8)
        intro_layout.addWidget(self.start_button, 0, Qt.AlignLeft)
        self.deep_scan_checkbox = QCheckBox(tr("Расширенная проверка дополнительных локальных дисков"))
        self.deep_scan_checkbox.setChecked(False)
        self.deep_scan_checkbox.setToolTip(tr("По умолчанию SentinelXT проверяет профили пользователей, игровые папки и известные каталоги лаунчеров. Расширенный режим дополнительно просматривает другие локальные диски, но пропускает Windows, системные каталоги, кэши и мультимедиа."))
        intro_layout.addWidget(self.deep_scan_checkbox)
        layout.addWidget(intro)

        metrics = QHBoxLayout()
        metrics.setSpacing(12)
        self.metric_launchers = MetricCard(tr("Папки лаунчеров"))
        self.metric_games = MetricCard(tr("Игровые папки"))
        self.metric_mods = MetricCard(tr("Архивы модов"))
        self.metric_packs = MetricCard(tr("Ресурс-паки и шейдеры"))
        self.metric_findings = MetricCard(tr("Индикаторы"))
        for card in (self.metric_launchers, self.metric_games, self.metric_mods, self.metric_packs, self.metric_findings):
            metrics.addWidget(card)
        layout.addLayout(metrics)

        note = QFrame()
        note.setObjectName("card")
        note_layout = QVBoxLayout(note)
        note_layout.setContentsMargins(18, 14, 18, 14)
        note_title = QLabel(tr("Важно о результатах"))
        note_title.setStyleSheet("font-weight: 700; color: #e21b2d;")
        note_text = QLabel(
            tr("Версия 0.1.4 использует реестр запрещённого ПО RUStrengthSMP: 161 наименование клиентов и 146 запрещённых идентификаторов функций/модов. "
            "Анализируются идентификаторы JAR, PE-метаданные EXE/DLL, JVM-аргументы и YARA-правила. "
            "Совпадения с названиями клиентских проектов и cheat-функций — это индикаторы для "
            "расследования, а не автоматическое доказательство использования или основание для бана.")
        )
        note_text.setWordWrap(True)
        note_text.setObjectName("muted")
        note_layout.addWidget(note_title)
        note_layout.addWidget(note_text)
        layout.addWidget(note)
        layout.addStretch(1)
        self.pages.addWidget(page)

    def _build_scan_page(self):
        page, layout = self._page_container(
            tr("Ход проверки"),
            tr("Поиск в выбранных пользовательских и игровых каталогах, статический анализ JAR/ZIP/EXE и анализ параметров Minecraft.")
        )
        card = QFrame()
        card.setObjectName("card")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(18, 18, 18, 18)
        self.scan_status = QLabel(tr("Ожидание запуска"))
        self.scan_status.setStyleSheet("font-size: 12pt; font-weight: 700;")
        self.verdict_card = QFrame()
        self.verdict_card.setObjectName("verdictCard")
        verdict_layout = QVBoxLayout(self.verdict_card)
        verdict_layout.setContentsMargins(14, 10, 14, 10)
        self.verdict_value = QLabel(tr("Ожидается результат проверки"))
        self.verdict_value.setObjectName("verdictValue")
        self.verdict_detail = QLabel(tr("После завершения здесь появится итоговый вердикт и количество найденных индикаторов."))
        self.verdict_detail.setObjectName("muted")
        self.verdict_detail.setWordWrap(True)
        verdict_layout.addWidget(self.verdict_value)
        verdict_layout.addWidget(self.verdict_detail)
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.scan_log = QTextEdit()
        self.scan_log.setReadOnly(True)
        self.scan_log.setMinimumHeight(240)
        self.scan_log.setPlaceholderText(tr("Здесь появятся этапы инвентаризации..."))
        card_layout.addWidget(self.scan_status)
        card_layout.addWidget(self.verdict_card)
        card_layout.addWidget(self.progress)
        card_layout.addWidget(self.scan_log, 1)
        layout.addWidget(card, 1)

        actions = QHBoxLayout()
        self.scan_again_button = QPushButton(tr("Запустить проверку"))
        self.scan_again_button.setObjectName("primary")
        self.scan_again_button.clicked.connect(self.start_scan)
        self.show_results_button = QPushButton(tr("Открыть результаты"))
        self.show_results_button.setObjectName("secondary")
        self.show_results_button.clicked.connect(lambda: self._show_page(2))
        self.open_reports_button = QPushButton(tr("Открыть папку отчётов"))
        self.open_reports_button.setObjectName("secondary")
        self.open_reports_button.clicked.connect(self.open_reports_folder)
        actions.addWidget(self.scan_again_button)
        actions.addWidget(self.show_results_button)
        actions.addWidget(self.open_reports_button)
        actions.addStretch(1)
        layout.addLayout(actions)
        self.pages.addWidget(page)

    def _build_results_page(self):
        page, layout = self._page_container(
            tr("Результаты проверки"),
            tr("Все найденные индикаторы, неоднозначные совпадения и X-Ray-подобные признаки ресурс-паков.")
        )
        toolbar = QHBoxLayout()
        self.results_filter = QComboBox()
        self.results_filter.addItem(tr("Все результаты"), "all")
        self.results_filter.addItem(tr("Ресурс-паки и X-Ray"), "packs")
        self.results_filter.addItem(tr("Клиенты и сигнатуры"), "clients")
        self.results_filter.addItem(tr("Моды и функции"), "mods")
        self.results_filter.addItem(tr("Следы по названиям"), "traces")
        self.results_filter.addItem(tr("Процессы и запуск"), "runtime")
        self.results_filter.addItem(tr("Файлы и лаунчеры"), "files")
        self.results_filter.addItem(tr("Скрипты и другое ПО"), "tools")
        self.results_filter.currentIndexChanged.connect(self._populate_results_from_filter)
        self.results_search = QLineEdit()
        self.results_search.setPlaceholderText(tr("Поиск по пути, названию, доказательствам..."))
        self.results_search.setClearButtonEnabled(True)
        self.results_search.setMinimumWidth(240)
        self.results_search.textChanged.connect(self._populate_results_from_filter)
        self.results_show_info = QCheckBox(tr("Показывать информационные (разрешённые моды, лаунчеры)"))
        self.results_show_info.stateChanged.connect(self._populate_results_from_filter)
        self.results_count_label = QLabel(tr("Пока нет результатов"))
        self.results_count_label.setObjectName("muted")
        toolbar.addWidget(QLabel(tr("Фильтр:")))
        toolbar.addWidget(self.results_filter)
        toolbar.addWidget(self.results_search, 1)
        toolbar.addWidget(self.results_show_info)
        layout.addLayout(toolbar)
        count_row = QHBoxLayout()
        count_row.addWidget(self.results_count_label)
        count_row.addStretch(1)
        self.copy_all_button = QPushButton(tr("Копировать список"))
        self.copy_all_button.setObjectName("secondary")
        self.copy_all_button.clicked.connect(self._copy_all_results)
        count_row.addWidget(self.copy_all_button)
        layout.addLayout(count_row)

        content = QHBoxLayout()
        content.setSpacing(12)
        self.results_list = QListWidget()
        self.results_list.setMinimumWidth(380)
        self.results_list.setMaximumWidth(620)
        self.results_list.setUniformItemSizes(False)
        self.results_list.setWordWrap(False)
        self.results_list.setTextElideMode(Qt.ElideMiddle)
        self.results_list.currentItemChanged.connect(self._show_finding_details)
        content.addWidget(self.results_list, 2)

        detail_card = QFrame()
        detail_card.setObjectName("card")
        detail_layout = QVBoxLayout(detail_card)
        detail_layout.setContentsMargins(14, 14, 14, 14)
        self.result_detail_title = QLabel(tr("Выбери обнаружение"))
        self.result_detail_title.setStyleSheet("font-size: 13pt; font-weight: 700; color: #ffffff;")
        self.result_detail_text = QTextEdit()
        self.result_detail_text.setReadOnly(True)
        self.result_detail_text.setPlaceholderText(tr("Здесь будут подробности, путь и доказательства выбранной зацепки."))
        detail_layout.addWidget(self.result_detail_title)
        detail_layout.addWidget(self.result_detail_text, 1)
        result_actions = QHBoxLayout()
        self.copy_result_path_button = QPushButton(tr("Копировать путь"))
        self.copy_result_path_button.setObjectName("secondary")
        self.copy_result_path_button.setEnabled(False)
        self.copy_result_path_button.clicked.connect(self._copy_selected_result_path)
        self.open_result_location_button = QPushButton(tr("Открыть расположение"))
        self.open_result_location_button.setObjectName("secondary")
        self.open_result_location_button.setEnabled(False)
        self.open_result_location_button.clicked.connect(self._open_selected_result_location)
        result_actions.addWidget(self.copy_result_path_button)
        result_actions.addWidget(self.open_result_location_button)
        result_actions.addStretch(1)
        detail_layout.addLayout(result_actions)
        content.addWidget(detail_card, 3)
        layout.addLayout(content, 1)
        self.current_findings = []
        self.filtered_findings = []
        self.result_groups = []
        self._populate_results([])
        self.pages.addWidget(page)

    @staticmethod
    def _category_label(category):
        return tr(RESULT_CATEGORY_LABELS.get(category, category.replace("_", " ").capitalize()))

    @staticmethod
    def _category_labels():
        return {key: tr(value) for key, value in RESULT_CATEGORY_LABELS.items()}

    @staticmethod
    def _localize_finding(finding):
        """Translated copy of a finding for display; the stored report keeps the original text."""
        item = dict(finding)
        for key in ("title", "details"):
            if isinstance(item.get(key), str):
                item[key] = tr(item[key])
        if "evidence" in item:
            item["evidence"] = i18n.localize(item["evidence"])
        return item

    @staticmethod
    def _time_hint(finding):
        hint = finding_time_hint(finding)
        prefix, separator, rest = hint.partition(": ")
        return "{}{}{}".format(tr(prefix), separator, rest) if separator else hint

    def _populate_results(self, findings):
        self.raw_findings = list(findings or [])
        self.current_findings = [self._localize_finding(item) for item in self.raw_findings]
        self._populate_results_from_filter()

    def _populate_results_from_filter(self, *_args):
        if not hasattr(self, "results_list"):
            return
        selected = self.results_filter.currentData() if hasattr(self, "results_filter") else "all"
        if selected is None:
            selected = "all"
        query = self.results_search.text() if hasattr(self, "results_search") else ""
        show_info = self.results_show_info.isChecked() if hasattr(self, "results_show_info") else False
        groups, hidden = build_groups(
            self.current_findings, selected, query, show_info, self._category_labels()
        )
        self.result_groups = groups
        self.filtered_findings = []
        self.results_list.clear()
        first_selectable = None
        for _key, group_label, items in groups:
            header = QListWidgetItem("{}  ·  {}".format(tr(group_label).upper(), len(items)))
            header.setFlags(Qt.NoItemFlags)
            header.setForeground(QBrush(QColor("#ff6b78")))
            header_font = header.font()
            header_font.setBold(True)
            header.setFont(header_font)
            self.results_list.addItem(header)
            for finding in items:
                category = finding.get("category", "other")
                label = self._category_label(category)
                name, folder = short_path_parts(finding.get("path"))
                lines = ["{}  —  {}".format(tr(name), label), folder or finding.get("title", "")]
                time_hint = self._time_hint(finding)
                if time_hint:
                    lines.append(time_hint)
                item = QListWidgetItem("\n".join(lines))
                item.setForeground(QBrush(QColor("#dedede")))
                item.setToolTip("{}\n{}".format(finding.get("title", label), finding.get("path") or tr("Путь не указан")))
                item.setData(Qt.UserRole, len(self.filtered_findings))
                self.filtered_findings.append(finding)
                self.results_list.addItem(item)
                if first_selectable is None:
                    first_selectable = self.results_list.count() - 1
        total = len(self.current_findings)
        text = tr("Показано: {} из {}").format(len(self.filtered_findings), total)
        if hidden:
            text += tr(" · скрыто информационных: {}").format(hidden)
        self.results_count_label.setText(text)
        if hasattr(self, "copy_all_button"):
            self.copy_all_button.setEnabled(bool(self.filtered_findings))
        if first_selectable is not None:
            self.results_list.setCurrentRow(first_selectable)
        else:
            self.result_detail_title.setText(tr("Нет записей по выбранным условиям"))
            self.result_detail_text.setPlainText(tr("Измени фильтр или строку поиска. Информационные записи можно включить флажком сверху."))
            self.copy_result_path_button.setEnabled(False)
            self.open_result_location_button.setEnabled(False)

    def _copy_all_results(self):
        groups = getattr(self, "result_groups", [])
        if groups:
            QApplication.clipboard().setText(export_text(groups, self._category_labels(), tr))
            self.status_label.setText(tr("Список результатов скопирован в буфер обмена"))

    def _show_finding_details(self, current, _previous=None):
        if current is None:
            return
        index = current.data(Qt.UserRole)
        if index is None or index < 0 or index >= len(self.filtered_findings):
            return
        finding = self.filtered_findings[index]
        category = finding.get("category", "other")
        label = self._category_label(category)
        self.result_detail_title.setText(finding.get("title", label))
        evidence = finding.get("evidence", {})
        try:
            evidence_text = json.dumps(evidence, ensure_ascii=False, indent=2, sort_keys=True)
        except Exception:
            evidence_text = repr(evidence)
        text = [
            tr("КАТЕГОРИЯ"),
            label,
            tr("Идентификатор: {}").format(category),
            "",
            tr("ПУТЬ"),
            finding.get("path") or tr("Не указан"),
            "",
            tr("ОБЪЯСНЕНИЕ"),
            finding.get("details", tr("Подробности отсутствуют.")),
            "",
            tr("ДАННЫЕ И ДОКАЗАТЕЛЬСТВА"),
            evidence_text,
        ]
        if finding.get("sha256"):
            text.extend(["", "SHA-256", finding.get("sha256")])
        self.result_detail_text.setPlainText("\n".join(text))
        has_path = bool(finding.get("path"))
        self.copy_result_path_button.setEnabled(has_path)
        self.open_result_location_button.setEnabled(has_path and os.path.exists(finding.get("path", "")))

    def _selected_finding(self):
        item = self.results_list.currentItem() if hasattr(self, "results_list") else None
        if item is None:
            return None
        index = item.data(Qt.UserRole)
        if index is None or index < 0 or index >= len(self.filtered_findings):
            return None
        return self.filtered_findings[index]

    def _copy_selected_result_path(self):
        finding = self._selected_finding()
        if finding and finding.get("path"):
            QApplication.clipboard().setText(str(finding.get("path")))
            self.status_label.setText(tr("Путь скопирован в буфер обмена"))

    def _open_selected_result_location(self):
        finding = self._selected_finding()
        path = finding.get("path") if finding else None
        if not path or not os.path.exists(path):
            return
        try:
            if sys.platform == "win32":
                if os.path.isfile(path):
                    subprocess.Popen(["explorer.exe", "/select," + os.path.normpath(path)])
                else:
                    os.startfile(path)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", "-R", path])
            else:
                subprocess.Popen(["xdg-open", path if os.path.isdir(path) else os.path.dirname(path)])
        except Exception as exc:
            QMessageBox.warning(self, tr("Не удалось открыть расположение"), str(exc))

    def _build_reports_page(self):
        page, layout = self._page_container(
            tr("Отчёты"),
            tr("Отчёты сохраняются локально в JSON и могут быть открыты обычным текстовым редактором.")
        )
        self.report_list = QListWidget()
        layout.addWidget(self.report_list, 1)
        row = QHBoxLayout()
        refresh = QPushButton(tr("Обновить список"))
        refresh.setObjectName("secondary")
        refresh.clicked.connect(self.refresh_reports)
        open_folder = QPushButton(tr("Открыть папку"))
        open_folder.setObjectName("secondary")
        open_folder.clicked.connect(self.open_reports_folder)
        row.addWidget(refresh)
        row.addWidget(open_folder)
        row.addStretch(1)
        layout.addLayout(row)
        self.pages.addWidget(page)
        self.refresh_reports()

    def _build_about_page(self):
        page, layout = self._page_container(
            tr("О SentinelXT"),
            "Minecraft Client Forensic System · SynXT"
        )
        card = QFrame()
        card.setObjectName("card")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(20, 20, 20, 20)
        paragraphs = [
            tr("SentinelXT — локальная система инвентаризации Minecraft-лаунчеров и статического анализа связанных файлов для RUStrengthSMP."),
            tr("Версия {} включает серверный реестр из 161 названия запрещённых клиентов и 146 идентификаторов функций/модов, плюс whitelist и gray zone. Анализируются JAR/ZIP, EXE/DLL, YARA, JVM-аргументы, ZIP-ресурс-паки и распакованные resource packs.").format(VERSION_LABEL),
            tr("Быстрый режим ищет в известных игровых каталогах, найденных папках лаунчеров и выбранных пользовательских местах. Папки .minecraft\\libraries и assets пропускаются как массовые служебные зависимости; моды, версии, ресурс-паки и шейдеры проверяются отдельными быстрыми проходами."),
            tr("Windows, System32, ProgramData, Program Files целиком, Recovery, корзина, Minecraft libraries/assets и кэш/служебные каталоги не обходятся. PNG/JPG, аудио, видео, PDF и офисные документы пропускаются. Prefetch и память процессов не сканируются."),
            tr("Для скорости архив ограничен по количеству записей, объёму распакованных данных и времени анализа. Ресурс-паки получают отдельный текстурный анализ с собственными лимитами. Вкладка «Результаты» показывает все найденные признаки и информационные совпадения."),
            tr("Программа не запускает, не удаляет, не изменяет и не загружает найденные файлы. Имя файла или общий клиентский бренд не являются доказательством: например, xray.exe не классифицируется как чит по названию."),
            tr("Даже точное обнаружение известного клиентского архива доказывает наличие артефакта, но не его запуск или использование во время матча. Решение о наказании требует ручной проверки и серверных доказательств."),
        ]
        for paragraph in paragraphs:
            label = QLabel(paragraph)
            label.setWordWrap(True)
            label.setObjectName("muted")
            card_layout.addWidget(label)
        self.about_author_label = QLabel(tr("Автор: {}").format(AUTHOR))
        self.about_author_label.setStyleSheet("font-weight: 700; color: #ffffff;")
        card_layout.addSpacing(6)
        card_layout.addWidget(self.about_author_label)
        about_discord = self._make_discord_button()
        card_layout.addWidget(about_discord, 0, Qt.AlignLeft)
        layout.addWidget(card)
        layout.addStretch(1)
        self.pages.addWidget(page)

    def _show_page(self, index):
        self.pages.setCurrentIndex(index)
        for i, button in enumerate(self.nav_buttons):
            button.setChecked(i == index)
        if index == 3:
            self.refresh_reports()

    def _append_log(self, message):
        display = tr(message)
        self.scan_log.append(display)
        self.scan_status.setText(display)

        match = re.match(r"Анализ архивов (\d+)/(\d+):", message)
        if match:
            current = int(match.group(1))
            total = max(1, int(match.group(2)))
            self.progress.setRange(0, total)
            self.progress.setValue(current)
        elif message.startswith("Поиск известных директорий"):
            self.progress.setRange(0, 100)
            self.progress.setValue(4)
        elif message.startswith("Поиск игровых файлов"):
            self.progress.setRange(0, 100)
            self.progress.setValue(max(self.progress.value(), 12))
        elif message.startswith("Поиск вложенных игровых"):
            self.progress.setRange(0, 100)
            self.progress.setValue(max(self.progress.value(), 28))
        elif message.startswith("Подготовка игрового каталога"):
            self.progress.setRange(0, 100)
            self.progress.setValue(max(self.progress.value(), 34))
        elif message.startswith("Инвентаризация"):
            self.progress.setRange(0, 100)
            self.progress.setValue(max(self.progress.value(), 38))
        elif message.startswith("Достигнут лимит времени"):
            self.progress.setRange(0, 100)
            self.progress.setValue(max(self.progress.value(), 70))
        elif message.startswith("Проверка JVM"):
            self.progress.setRange(0, 100)
            self.progress.setValue(max(self.progress.value(), 76))
        elif message.startswith("Анализ метаданных EXE"):
            self.progress.setRange(0, 100)
            self.progress.setValue(max(self.progress.value(), 82))
        elif message.startswith("Проверка скриптов"):
            self.progress.setRange(0, 100)
            self.progress.setValue(max(self.progress.value(), 94))
        elif message.startswith("Анализ завершён"):
            self.progress.setRange(0, 100)
            self.progress.setValue(100)

    def start_scan(self):
        if self.worker is not None and self.worker.isRunning():
            return
        self._show_page(1)
        self.scan_log.clear()
        self.verdict_value.setText(tr("Проверка выполняется…"))
        self.verdict_value.setStyleSheet("color: #ffffff;")
        self.verdict_detail.setText(tr("Итоговый вердикт появится автоматически после завершения анализа."))
        self.verdict_card.setStyleSheet("QFrame#verdictCard { border-left: 4px solid #777777; }")
        self._append_log(tr("Подготовка инвентаризации..."))
        self.progress.setRange(0, 100)
        self.progress.setValue(2)
        self.start_button.setDisabled(True)
        self.scan_again_button.setDisabled(True)
        self.status_label.setText(tr("Выполняется локальная инвентаризация…"))
        self.worker = ScanWorker(full_scan=self.deep_scan_checkbox.isChecked())
        self.worker.progress.connect(self._append_log)
        self.worker.completed.connect(self._scan_completed)
        self.worker.failed.connect(self._scan_failed)
        self.worker.start()

    def _scan_completed(self, report, report_path):
        self.last_report = report
        self.last_report_path = report_path
        self._populate_results(report.get("findings", []))
        summary = report.get("summary", {})
        self.metric_launchers.set_value(summary.get("launcher_directories", 0))
        self.metric_games.set_value(summary.get("game_directories", 0))
        self.metric_mods.set_value(summary.get("mod_archives", 0))
        self.metric_packs.set_value(summary.get("resource_and_shader_packs", 0))
        self.metric_findings.set_value(summary.get("total_findings", 0))
        verdict = tr(report.get("verdict", "Нет вердикта"))
        partial = bool(report.get("partial_scan"))
        self._render_verdict()
        self.verdict_value.setStyleSheet("color: #ffffff;")
        self.verdict_card.setStyleSheet("QFrame#verdictCard { border-left: 4px solid #d7192d; }")
        self._append_log(tr("Проверка завершена{}: {}").format(tr(" частично") if partial else "", verdict))
        scope = report.get("scan_scope", {})
        self._append_log(tr("Режим: {} · обход системных каталогов отключён").format(tr("расширенный") if scope.get("full_local_drive_scan") else tr("быстрый")))
        self._append_log(tr("Пропущено системных/служебных каталогов: {}").format(scope.get("skipped_directories", 0)))
        self._append_log(tr("Файлы-кандидаты: {} (прочие расширения исключены)").format(scope.get("candidate_files_seen", 0)))
        self._append_log(tr("Найдено папок лаунчеров: {}").format(summary.get("launcher_directories", 0)))
        self._append_log(tr("Найдено исполняемых файлов лаунчеров: {}").format(summary.get("launcher_executables", 0)))
        self._append_log(tr("Найдено игровых папок: {}").format(summary.get("game_directories", 0)))
        self._append_log(tr("Проверено архивов: {}").format(summary.get("archive_checks", 0)))
        self._append_log(tr("Проверено EXE/DLL (PE): {}").format(summary.get("pe_checks", 0)))
        self._append_log(tr("Параметров Java Agent в конфигурациях: {}").format(summary.get("runtime_config_injection_flags", 0)))
        self._append_log(tr("Совпадений YARA: {}").format(summary.get("yara_matches", 0)))
        self._append_log(tr("Обнаружено подходящих процессов: {}").format(summary.get("running_minecraft_processes", 0)))
        for category, count in sorted(summary.get("finding_category_counts", {}).items()):
            label = tr(RESULT_CATEGORY_LABELS.get(category, category))
            self._append_log(tr("Категория {}: {}").format(label, count))
        everything_status = report.get("integrations", {}).get("everything", {})
        self._append_log("Everything: {}".format(tr(everything_status.get("message", "не использовался"))))
        for finding in report.get("findings", [])[:30]:
            category = finding.get("category", "other")
            label = tr(RESULT_CATEGORY_LABELS.get(category, category))
            self._append_log("[{}] {} — {}".format(label, tr(finding.get("title", "Обнаружение")), finding.get("path", "")))
        self._append_log(tr("Отчёт сохранён: {}").format(report_path))
        self.progress.setRange(0, 100)
        self.progress.setValue(100)
        self.start_button.setEnabled(True)
        self.scan_again_button.setEnabled(True)
        self.status_label.setText((tr("Частичная проверка · отчёт сохранён локально") if partial else tr("Проверка завершена · отчёт сохранён локально")))
        self.refresh_reports()

    def _render_verdict(self):
        report = self.last_report
        if not report:
            return
        summary = report.get("summary", {})
        self.verdict_value.setText(tr(report.get("verdict", "Нет вердикта")))
        detail = tr("Записей для просмотра: {} · Архивов: {} · EXE/DLL: {}").format(
            summary.get("total_findings", 0), summary.get("archive_checks", 0), summary.get("pe_checks", 0)
        )
        if report.get("partial_scan"):
            reasons = report.get("partial_reasons", [])
            reason_text = ", ".join(tr(reason) for reason in reasons) if reasons else tr("лимиты сканирования")
            detail += tr(" · ЧАСТИЧНАЯ ПРОВЕРКА ({}): отсутствие находок не означает, что система чиста.").format(reason_text)
        self.verdict_detail.setText(detail)

    def _make_discord_button(self):
        button = QPushButton(tr("Наш Discord"))
        button.setObjectName("discord")
        button.setCursor(Qt.PointingHandCursor)
        button.setToolTip(tr("Открыть Discord-сервер RUStrengthSMP (ссылка откроется в браузере или в приложении Discord)"))
        button.clicked.connect(self.open_discord)
        return button

    def open_discord(self):
        if not QDesktopServices.openUrl(QUrl(DISCORD_INVITE_URL)):
            QMessageBox.information(self, tr("Ссылка"), tr("Не удалось открыть ссылку. Откройте её вручную: {}").format(DISCORD_INVITE_URL))

    def _on_language_changed(self, _index=None):
        code = self.language_combo.currentData()
        if not code or code == i18n.get_language():
            return
        i18n.set_language(code)
        self._settings.setValue("language", code)
        self._retranslate_ui()

    def _retranslate_ui(self):
        """Re-apply the current language to every widget (texts are found through their source strings)."""
        def convert(text):
            source = i18n.source_of(text)
            return tr(source) if source else None
        for widget in self.findChildren(QWidget):
            if isinstance(widget, (QLabel, QPushButton, QCheckBox)):
                new = convert(widget.text())
                if new is not None:
                    widget.setText(new)
            elif isinstance(widget, QLineEdit):
                new = convert(widget.placeholderText())
                if new is not None:
                    widget.setPlaceholderText(new)
            elif isinstance(widget, QTextEdit):
                new = convert(widget.placeholderText())
                if new is not None:
                    widget.setPlaceholderText(new)
            elif isinstance(widget, QComboBox) and widget is not self.language_combo:
                for index in range(widget.count()):
                    new = convert(widget.itemText(index))
                    if new is not None:
                        widget.setItemText(index, new)
            new = convert(widget.toolTip())
            if new is not None:
                widget.setToolTip(new)
        self.author_label.setText(tr("Автор: {}").format(AUTHOR))
        self.about_author_label.setText(tr("Автор: {}").format(AUTHOR))
        self._populate_results(getattr(self, "raw_findings", []))
        self._render_verdict()
        self.refresh_reports()

    def _scan_failed(self, message):
        self._append_log(tr("Ошибка: {}").format(message))
        self.verdict_value.setText(tr("Проверка не завершена"))
        self.verdict_value.setStyleSheet("color: #ff394d;")
        self.verdict_detail.setText(message)
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.start_button.setEnabled(True)
        self.scan_again_button.setEnabled(True)
        self.status_label.setText(tr("Во время проверки возникла ошибка"))
        QMessageBox.warning(self, tr("Ошибка сканирования"), message)

    def refresh_reports(self):
        if not hasattr(self, "report_list"):
            return
        self.report_list.clear()
        reports_dir = get_reports_dir()
        try:
            names = sorted(
                (name for name in os.listdir(reports_dir) if name.lower().endswith(".json")),
                reverse=True
            )
        except OSError:
            names = []
        for name in names:
            item = QListWidgetItem(name)
            item.setToolTip(os.path.join(reports_dir, name))
            self.report_list.addItem(item)
        if not names:
            self.report_list.addItem(tr("Отчётов пока нет — запусти инвентаризацию."))

    def open_reports_folder(self):
        path = get_reports_dir()
        try:
            if sys.platform == "win32":
                os.startfile(path)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", path])
            else:
                subprocess.Popen(["xdg-open", path])
        except Exception as exc:
            QMessageBox.warning(self, tr("Не удалось открыть папку"), str(exc))
