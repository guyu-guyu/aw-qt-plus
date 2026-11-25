"""Tests for the WebDAV auto-backup (aw_qt.webdav_backup).

Everything runs locally: uploads are exercised against an in-memory fake
client and against a throwaway ``http.server`` WebDAV stub; ``aw-sync`` is
replaced by an injected runner that just creates staging files.
"""

import base64
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from aw_qt import webdav_backup as wb


def make_cfg(**overrides) -> wb.WebDavConfig:
    values = dict(
        enabled=True,
        url="https://nas.example:5008/data",
        username="user",
        password="secret",
        remote_dir="activitywatch",
        interval_minutes=15,
    )
    values.update(overrides)
    return wb.WebDavConfig(**values)


# ---------------------------------------------------------------------------
# URL / remote-dir validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("https://nas.example/dav", "https://nas.example/dav"),
        ("https://nas.example/dav/", "https://nas.example/dav"),
        ("HTTP://192.168.1.8:5005/backup/", "http://192.168.1.8:5005/backup"),
        ("  https://nas.example  ", "https://nas.example"),
    ],
)
def test_normalize_base_url(raw, expected):
    assert wb.normalize_base_url(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "nas.example/dav",
        "ftp://nas.example/dav",
        "https://user:pass@nas.example/dav",
        "https://nas.example/dav?x=1",
        "https://nas.example/dav#frag",
        "https:///dav",
    ],
)
def test_normalize_base_url_rejects(raw):
    with pytest.raises(ValueError):
        wb.normalize_base_url(raw)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("", ["activitywatch"]),
        ("activitywatch", ["activitywatch"]),
        ("/a//b/", ["a", "b"]),
        ("a/b/c", ["a", "b", "c"]),
    ],
)
def test_normalize_remote_dir(raw, expected):
    assert wb.normalize_remote_dir(raw) == expected


@pytest.mark.parametrize("raw", ["..", "a/../b", "a/./b", "a\\b"])
def test_normalize_remote_dir_rejects(raw):
    with pytest.raises(ValueError):
        wb.normalize_remote_dir(raw)


def test_validate_config_requires_credentials_together():
    with pytest.raises(ValueError):
        wb.validate_config(make_cfg(password=""))
    with pytest.raises(ValueError):
        wb.validate_config(make_cfg(username=""))
    # Both empty is fine (anonymous access).
    cfg = wb.validate_config(make_cfg(username="", password=""))
    assert cfg.username == "" and cfg.password == ""


def test_file_and_collection_urls_quote_segments():
    cfg = make_cfg(url="http://h:5005/d/")
    assert cfg.file_url("My PC/dev 1/sync.db") == (
        "http://h:5005/d/activitywatch/My%20PC/dev%201/sync.db"
    )
    assert cfg.collection_urls("My PC/dev 1/sync.db") == [
        "http://h:5005/d/activitywatch",
        "http://h:5005/d/activitywatch/My%20PC",
        "http://h:5005/d/activitywatch/My%20PC/dev%201",
    ]


# ---------------------------------------------------------------------------
# Config persistence (config/data dirs are redirected to tmp by conftest)
# ---------------------------------------------------------------------------


def test_config_roundtrip_and_password_not_plaintext():
    cfg = make_cfg()
    wb.save_webdav_config(cfg)
    raw = wb.config_file_path().read_text(encoding="utf-8")
    if sys.platform == "win32":
        assert "password_dpapi" in raw
        assert "secret" not in raw
    loaded = wb.load_webdav_config()
    assert loaded == cfg


def test_config_toggle_enabled_preserves_password():
    wb.save_webdav_config(make_cfg(enabled=False))
    cfg = wb.load_webdav_config()
    cfg.enabled = True
    wb.save_webdav_config(cfg)
    assert wb.load_webdav_config().password == "secret"
    assert wb.load_webdav_config().enabled is True


def test_load_config_defaults_when_missing():
    assert wb.load_webdav_config() == wb.WebDavConfig()


@pytest.mark.skipif(sys.platform != "win32", reason="DPAPI is Windows-only")
def test_dpapi_roundtrip():
    field_name, stored = wb.protect_password("päss wörd")
    assert field_name == "password_dpapi"
    assert base64.b64decode(stored)  # opaque ciphertext
    assert wb.unprotect_password({"password_dpapi": stored}) == "päss wörd"


# ---------------------------------------------------------------------------
# Upload tree with a fake client
# ---------------------------------------------------------------------------


class FakeClient:
    def __init__(self):
        self.files = {}  # url -> bytes
        self.collections = []
        self.puts = []

    def resource_length(self, url):
        data = self.files.get(url)
        return None if data is None else len(data)

    def create_collection(self, url):
        self.collections.append(url)

    def put_file(self, url, file_path):
        data = Path(file_path).read_bytes()
        self.files[url] = data
        self.puts.append(url)


def _write_staging(root: Path) -> Path:
    db = root / "my-pc" / "device123" / "sync.db"
    db.parent.mkdir(parents=True)
    db.write_bytes(b"snapshot-v1")
    return db


def test_upload_tree_uploads_then_skips_unchanged(tmp_path):
    staging = tmp_path / "staging"
    staging.mkdir()
    _write_staging(staging)
    cfg = wb.validate_config(make_cfg())
    client = FakeClient()

    outcome, manifest = wb.upload_tree(staging, cfg, wb.Manifest(), client)
    assert (outcome.uploaded, outcome.unchanged) == (1, 0)
    url = cfg.file_url("my-pc/device123/sync.db")
    assert client.files[url] == b"snapshot-v1"
    # Remote dir + hostname + device collections were created first.
    assert client.collections == cfg.collection_urls("my-pc/device123/sync.db")

    outcome, manifest = wb.upload_tree(staging, cfg, manifest, client)
    assert (outcome.uploaded, outcome.unchanged) == (0, 1)
    assert len(client.puts) == 1


def test_upload_tree_reuploads_changed_file(tmp_path):
    staging = tmp_path / "staging"
    staging.mkdir()
    db = _write_staging(staging)
    cfg = wb.validate_config(make_cfg())
    client = FakeClient()
    _, manifest = wb.upload_tree(staging, cfg, wb.Manifest(), client)

    db.write_bytes(b"snapshot-v2-longer")
    outcome, _ = wb.upload_tree(staging, cfg, manifest, client)
    assert (outcome.uploaded, outcome.unchanged) == (1, 0)


def test_upload_tree_cancelled(tmp_path):
    staging = tmp_path / "staging"
    staging.mkdir()
    _write_staging(staging)
    cfg = wb.validate_config(make_cfg())
    with pytest.raises(wb.BackupError):
        wb.upload_tree(
            staging, cfg, wb.Manifest(), FakeClient(), is_cancelled=lambda: True
        )


# ---------------------------------------------------------------------------
# Real HTTP round-trip against a stub WebDAV server
# ---------------------------------------------------------------------------


class _DavHandler(BaseHTTPRequestHandler):
    store = {}
    lock = threading.Lock()

    def log_message(self, *args):  # keep test output quiet
        pass

    def _authorized(self) -> bool:
        expected = "Basic " + base64.b64encode(b"user:secret").decode()
        return self.headers.get("Authorization") == expected

    def do_PROPFIND(self):
        if not self._authorized():
            self.send_response(401)
            self.end_headers()
            return
        with self.lock:
            data = self.store.get(self.path)
        if data is None:
            self.send_response(404)
            self.end_headers()
            return
        body = (
            '<?xml version="1.0"?><D:multistatus xmlns:D="DAV:"><D:response>'
            f"<D:propstat><D:prop><D:getcontentlength>{len(data)}"
            "</D:getcontentlength></D:prop></D:propstat></D:response></D:multistatus>"
        ).encode()
        self.send_response(207)
        self.send_header("Content-Type", "application/xml")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_MKCOL(self):
        if not self._authorized():
            self.send_response(401)
            self.end_headers()
            return
        with self.lock:
            exists = self.path in self.store
            if not exists:
                self.store[self.path] = None  # collection marker
        self.send_response(405 if exists else 201)
        self.end_headers()

    def do_PUT(self):
        if not self._authorized():
            self.send_response(401)
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length") or 0)
        with self.lock:
            self.store[self.path] = self.rfile.read(length)
        self.send_response(201)
        self.end_headers()


@pytest.fixture()
def dav_server():
    _DavHandler.store = {}
    server = ThreadingHTTPServer(("127.0.0.1", 0), _DavHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}/dav"
    server.shutdown()


def test_http_upload_roundtrip(tmp_path, dav_server):
    staging = tmp_path / "staging"
    staging.mkdir()
    _write_staging(staging)
    cfg = wb.validate_config(make_cfg(url=dav_server))
    client = wb.WebDavClient(cfg.username, cfg.password)

    outcome, manifest = wb.upload_tree(staging, cfg, wb.Manifest(), client)
    assert (outcome.uploaded, outcome.unchanged) == (1, 0)
    outcome, _ = wb.upload_tree(staging, cfg, manifest, client)
    assert (outcome.uploaded, outcome.unchanged) == (0, 1)


def test_http_wrong_password_rejected(tmp_path, dav_server):
    cfg = wb.validate_config(make_cfg(url=dav_server, password="wrong"))
    client = wb.WebDavClient(cfg.username, cfg.password)
    with pytest.raises(wb.BackupError):
        client.resource_length(cfg.file_url("a/b/sync.db"))


# ---------------------------------------------------------------------------
# Full backup cycle
# ---------------------------------------------------------------------------


def test_build_aw_sync_command(tmp_path):
    cmd = wb.build_aw_sync_command(Path("aw-sync"), tmp_path, 5600)
    assert cmd == [
        "aw-sync",
        "--sync-dir",
        str(tmp_path),
        "--port",
        "5600",
        "sync",
        "--mode",
        "push",
    ]


def test_build_aw_sync_command_testing_profile(tmp_path):
    cmd = wb.build_aw_sync_command(Path("aw-sync"), tmp_path, 5666, "testing")
    assert cmd == [
        "aw-sync",
        "--sync-dir",
        str(tmp_path),
        "--port",
        "5666",
        "--profile",
        "testing",
        "sync",
        "--mode",
        "push",
    ]


def test_find_aw_sync_does_not_pick_aw_server_rust(tmp_path, monkeypatch):
    server = tmp_path / "aw-server-rust.exe"
    sync = tmp_path / "aw-sync.exe"
    server.write_bytes(b"server")
    sync.write_bytes(b"sync")
    monkeypatch.setattr(wb.shutil, "which", lambda name: None)

    assert wb.find_aw_sync([server, sync]) == sync


def _fake_sync_runner(command):
    staging = Path(command[2])
    db = staging / "my-pc" / "device123" / "sync.db"
    db.parent.mkdir(parents=True, exist_ok=True)
    db.write_bytes(b"snapshot-v1")


def test_run_backup_success_and_status(tmp_path):
    cfg = make_cfg(url="http://127.0.0.1:9/unused")
    client = FakeClient()
    aw_sync = tmp_path / "aw-sync.exe"
    aw_sync.write_bytes(b"fake aw-sync")
    outcome = wb.run_backup(
        cfg,
        5600,
        aw_sync_candidates=[aw_sync],
        client=client,
        sync_runner=_fake_sync_runner,
    )
    assert outcome.uploaded == 1
    status = wb.BackupStatus.load(wb.status_path())
    assert status is not None and status.success
    # Second run: aw-sync rewrites sync.db, but an identical stamp skips upload.
    outcome = wb.run_backup(
        cfg,
        5600,
        aw_sync_candidates=[aw_sync],
        client=client,
        sync_runner=_fake_sync_runner,
    )
    assert outcome.uploaded == 1  # new file mtime -> uploaded again


def test_run_backup_missing_aw_sync(monkeypatch):
    monkeypatch.setattr(wb.shutil, "which", lambda name: None)
    with pytest.raises(wb.BackupError):
        wb.run_backup(
            make_cfg(),
            5600,
            aw_sync_candidates=[Path("definitely/not/here/aw-sync")],
            client=FakeClient(),
            sync_runner=_fake_sync_runner,
        )
    status = wb.BackupStatus.load(wb.status_path())
    assert status is not None and not status.success


def test_run_backup_empty_staging_fails(tmp_path):
    def empty_runner(command):
        return None

    aw_sync = tmp_path / "aw-sync.exe"
    aw_sync.write_bytes(b"fake aw-sync")
    with pytest.raises(wb.BackupError):
        wb.run_backup(
            make_cfg(),
            5600,
            aw_sync_candidates=[aw_sync],
            client=FakeClient(),
            sync_runner=empty_runner,
        )
    status = wb.BackupStatus.load(wb.status_path())
    assert status is not None and not status.success
