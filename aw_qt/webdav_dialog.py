"""Settings dialog for the automatic WebDAV backup.

Shown from the tray menu.  Configuration is persisted in ``aw-qt.toml`` in
the ``[webdav-backup]`` table (see :mod:`aw_qt.webdav_backup`).
"""

from __future__ import annotations

import logging

from PyQt6 import QtWidgets

from . import webdav_backup as wb

logger = logging.getLogger(__name__)


class WebDavSettingsDialog(QtWidgets.QDialog):
    def __init__(self, profile: str | None = None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("WebDAV 自动备份设置")
        self.setModal(True)
        self.profile = profile

        cfg = wb.load_webdav_config(profile)

        form = QtWidgets.QFormLayout()

        self.enabled_cb = QtWidgets.QCheckBox("启用自动备份")
        self.enabled_cb.setChecked(cfg.enabled)
        form.addRow(self.enabled_cb)

        self.url_edit = QtWidgets.QLineEdit(cfg.url)
        self.url_edit.setPlaceholderText("https://nas.example:5008/data 或 http://192.168.1.8:5005/backup")
        form.addRow("服务器地址", self.url_edit)

        self.user_edit = QtWidgets.QLineEdit(cfg.username)
        self.user_edit.setPlaceholderText("用户名（可留空）")
        form.addRow("用户名", self.user_edit)

        self.password_edit = QtWidgets.QLineEdit()
        self.password_edit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        if cfg.password:
            self.password_edit.setPlaceholderText("密码已保存（留空保持不变）")
        else:
            self.password_edit.setPlaceholderText("密码（可留空）")
        form.addRow("密码", self.password_edit)

        self.dir_edit = QtWidgets.QLineEdit(cfg.remote_dir)
        self.dir_edit.setPlaceholderText("activitywatch")
        form.addRow("远程目录", self.dir_edit)

        self.interval_spin = QtWidgets.QSpinBox()
        self.interval_spin.setRange(1, 24 * 60)
        self.interval_spin.setValue(cfg.interval_minutes)
        self.interval_spin.setSuffix(" 分钟")
        form.addRow("备份间隔", self.interval_spin)

        hint = QtWidgets.QLabel(
            "数据先通过 aw-sync 同步到本地缓存目录，再上传到 WebDAV\n"
            "<远程目录>/<设备名>/<device_id>/sync.db，与手机端共用同一目录。\n"
            "服务器地址应指向一个可写目录。"
        )
        hint.setWordWrap(True)

        buttons = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Save
            | QtWidgets.QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._on_save)
        buttons.rejected.connect(self.reject)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(hint)
        layout.addWidget(buttons)

    def _on_save(self) -> None:
        existing = wb.load_webdav_config(self.profile)
        entered_password = self.password_edit.text()
        cfg = wb.WebDavConfig(
            enabled=self.enabled_cb.isChecked(),
            url=self.url_edit.text(),
            username=self.user_edit.text().strip(),
            # Blank means "keep the saved password".
            password=entered_password if entered_password else existing.password,
            remote_dir=self.dir_edit.text(),
            interval_minutes=self.interval_spin.value(),
        )
        try:
            cfg = wb.validate_config(cfg)
            wb.save_webdav_config(cfg, self.profile)
        except (wb.BackupError, ValueError) as exc:
            QtWidgets.QMessageBox.warning(self, "WebDAV 备份设置", str(exc))
            return
        except OSError as exc:
            logger.exception("failed to save WebDAV backup config")
            QtWidgets.QMessageBox.warning(self, "WebDAV 备份设置", f"保存失败: {exc}")
            return
        self.accept()

    @classmethod
    def check_settings(cls, profile: str | None = None) -> bool:
        """Return true when the configuration is usable.

        Mirrors the tray sync-settings behaviour: when misconfigured, the
        dialog opens so the user can fix it.
        """
        try:
            cfg = wb.load_webdav_config(profile)
            if not cfg.url:
                raise wb.BackupError("missing configuration")
            wb.validate_config(cfg)
            return True
        except (wb.BackupError, ValueError):
            dialog = cls(profile=profile)
            return dialog.exec() == QtWidgets.QDialog.DialogCode.Accepted
