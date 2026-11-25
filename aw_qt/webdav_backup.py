# -*- coding: utf-8 -*-
"""One-way WebDAV backup of the aw-sync snapshot (Windows/desktop).

Every backup cycle first asks the bundled ``aw-sync`` binary for a one-shot
push into a local staging directory, then uploads the resulting tree
(``<hostname>/<device_id>/sync.db`` as produced by aw-sync) to a WebDAV
server. Nothing is ever downloaded, mirroring the Android implementation in
aw-android-plus. Files that have not changed since the last successful upload
are skipped, using a small manifest of source size/mtime stamps.
"""

import base64
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

import tomlkit
from aw_core import dirs

from .config import _atomic_write, _with_profile_env
from .profile import DEFAULT_PROFILE

logger = logging.getLogger(__name__)

DEFAULT_REMOTE_DIR = "activitywatch"
DEFAULT_INTERVAL_MINUTES = 15
CONFIG_SECTION = "webdav-backup"
MANIFEST_FILENAME = "webdav-backup-manifest.json"
STATUS_FILENAME = "webdav-backup-status.json"
SYNC_TIMEOUT_SECONDS = 600


class BackupError(Exception):
    """A backup failure with a message safe to show in the tray."""


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------


@dataclass
class WebDavConfig:
    enabled: bool = False
    url: str = ""
    username: str = ""
    password: str = ""
    remote_dir: str = DEFAULT_REMOTE_DIR
    interval_minutes: int = DEFAULT_INTERVAL_MINUTES

    @property
    def remote_parts(self) -> List[str]:
        return normalize_remote_dir(self.remote_dir)

    def target_key(self) -> str:
        """Destination identity (no password): changing it forces re-upload."""
        return "\n".join(
            [normalize_base_url(self.url), self.username.strip(), "/".join(self.remote_parts)]
        )

    def file_url(self, relative_path: str) -> str:
        return webdav_url(normalize_base_url(self.url), self.remote_parts + relative_path.split("/"))

    def collection_urls(self, relative_path: str) -> List[str]:
        parts = self.remote_parts + relative_path.split("/")[:-1]
        return [
            webdav_url(normalize_base_url(self.url), parts[: i + 1])
            for i in range(len(parts))
        ]


def _has_line_break(value: str) -> bool:
    return "\n" in value or "\r" in value


def normalize_base_url(raw: str) -> str:
    value = (raw or "").strip()
    if not value:
        raise ValueError("WebDAV URL is required")
    if _has_line_break(value):
        raise ValueError("WebDAV URL cannot contain line breaks")
    parsed = urllib.parse.urlparse(value)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError("WebDAV URL must start with http:// or https://")
    if not parsed.hostname:
        raise ValueError("WebDAV URL must include a host")
    if parsed.username or parsed.password:
        raise ValueError("Put the username and password in their own fields, not in the URL")
    if parsed.query or parsed.fragment:
        raise ValueError("WebDAV URL cannot include a query or fragment")
    host = parsed.hostname
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return f"{scheme}://{host}{parsed.path.rstrip('/')}"


def _is_safe_segment(segment: str) -> bool:
    return (
        bool(segment)
        and segment not in (".", "..")
        and "/" not in segment
        and "\\" not in segment
        and all(ord(c) >= 0x20 for c in segment)
    )


def normalize_remote_dir(raw: str) -> List[str]:
    value = (raw or "").strip()
    if "\\" in value:
        raise ValueError("Remote directory cannot contain backslashes")
    # Empty segments (leading/trailing/double slashes) are ignored, as on Android.
    parts = [p for p in value.split("/") if p]
    if not parts:
        parts = [DEFAULT_REMOTE_DIR]
    if any(not _is_safe_segment(p) for p in parts):
        raise ValueError('Remote directory cannot contain ".", or ".." segments')
    return parts


def validate_config(cfg: WebDavConfig) -> WebDavConfig:
    """Return a normalized copy, raising ValueError with a user-facing message."""
    username = cfg.username.strip()
    # Username and password are optional (anonymous access), but must be
    # given together so a stored password is never silently ignored.
    if bool(username) != bool(cfg.password):
        raise ValueError("Username and password must be filled in together, or both left empty")
    if _has_line_break(username) or _has_line_break(cfg.password):
        raise ValueError("Username and password cannot contain line breaks")
    interval = cfg.interval_minutes
    if not isinstance(interval, int) or interval < 1:
        raise ValueError("Backup interval must be at least 1 minute")
    return WebDavConfig(
        enabled=cfg.enabled,
        url=normalize_base_url(cfg.url),
        username=username,
        password=cfg.password,
        remote_dir="/".join(normalize_remote_dir(cfg.remote_dir)),
        interval_minutes=interval,
    )


def webdav_url(base: str, segments: List[str]) -> str:
    root = base.rstrip("/")
    if not segments:
        return root
    quoted = "/".join(urllib.parse.quote(seg, safe="") for seg in segments)
    return f"{root}/{quoted}"


# --------------------------------------------------------------------------
# Password protection (Windows DPAPI; plaintext fallback elsewhere)
# --------------------------------------------------------------------------

_DPAPI_ENTROPY = b"aw-qt-webdav-backup"


def _dpapi_transform(data: bytes, protect: bool) -> bytes:
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_char)),
        ]

    def blob_from(b: bytes) -> Tuple[DATA_BLOB, object]:
        buf = ctypes.create_string_buffer(b, len(b))
        return DATA_BLOB(len(b), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf

    crypt32 = ctypes.windll.crypt32  # type: ignore[attr-defined]
    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    in_blob, _in_buf = blob_from(data)
    entropy_blob, _entropy_buf = blob_from(_DPAPI_ENTROPY)
    out_blob = DATA_BLOB()
    func = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    ok = func(
        ctypes.byref(in_blob),
        None,
        ctypes.byref(entropy_blob),
        None,
        None,
        0x01,  # CRYPTPROTECT_UI_FORBIDDEN
        ctypes.byref(out_blob),
    )
    if not ok:
        raise BackupError("Windows DPAPI failed to process the WebDAV password")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


def protect_password(password: str) -> Tuple[str, str]:
    """Return (field_name, stored_value) for the config file."""
    if sys.platform == "win32":
        encrypted = _dpapi_transform(password.encode("utf-8"), protect=True)
        return "password_dpapi", base64.b64encode(encrypted).decode("ascii")
    logger.warning("Storing the WebDAV password unencrypted (DPAPI is Windows-only)")
    return "password", password


def unprotect_password(section: Dict) -> str:
    stored = section.get("password_dpapi")
    if stored:
        if sys.platform != "win32":
            logger.warning("WebDAV password was DPAPI-protected on Windows; cannot read it here")
            return ""
        try:
            raw = _dpapi_transform(base64.b64decode(str(stored)), protect=False)
            return raw.decode("utf-8")
        except Exception as e:
            logger.warning(f"Could not decrypt the stored WebDAV password: {e}")
            return ""
    return str(section.get("password", "") or "")


# --------------------------------------------------------------------------
# Config persistence (aw-qt.toml, [webdav-backup] section)
# --------------------------------------------------------------------------


def config_file_path(profile: str = DEFAULT_PROFILE) -> Path:
    with _with_profile_env(profile):
        return Path(dirs.get_config_dir("aw-qt")) / "aw-qt.toml"


def load_webdav_config(profile: str = DEFAULT_PROFILE) -> WebDavConfig:
    path = config_file_path(profile)
    if not path.is_file():
        return WebDavConfig()
    try:
        doc = tomlkit.parse(path.read_text(encoding="utf-8"))
    except Exception as e:
        logger.warning(f"Could not parse {path}: {e}")
        return WebDavConfig()
    section = doc.get(CONFIG_SECTION)
    if not isinstance(section, dict):
        return WebDavConfig()
    interval = section.get("interval_minutes", DEFAULT_INTERVAL_MINUTES)
    try:
        interval = int(interval)
    except (TypeError, ValueError):
        interval = DEFAULT_INTERVAL_MINUTES
    return WebDavConfig(
        enabled=bool(section.get("enabled", False)),
        url=str(section.get("url", "") or ""),
        username=str(section.get("username", "") or ""),
        password=unprotect_password(section),
        remote_dir=str(section.get("remote_dir", "") or DEFAULT_REMOTE_DIR),
        interval_minutes=interval,
    )


def save_webdav_config(cfg: WebDavConfig, profile: str = DEFAULT_PROFILE) -> None:
    path = config_file_path(profile)
    doc = tomlkit.parse(path.read_text(encoding="utf-8")) if path.is_file() else tomlkit.document()
    section = doc.get(CONFIG_SECTION)
    if not isinstance(section, dict):
        section = tomlkit.table()
        doc[CONFIG_SECTION] = section
    section["enabled"] = bool(cfg.enabled)
    section["url"] = cfg.url.strip()
    section["username"] = cfg.username.strip()
    section["remote_dir"] = cfg.remote_dir.strip() or DEFAULT_REMOTE_DIR
    section["interval_minutes"] = int(cfg.interval_minutes)
    field_name, stored = protect_password(cfg.password) if cfg.password else ("password", "")
    # Never leave the other representation behind after a change.
    for key in ("password", "password_dpapi"):
        if key in section:
            del section[key]
    if stored:
        section[field_name] = stored
    path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(str(path), doc.as_string())


# --------------------------------------------------------------------------
# WebDAV client (stdlib only)
# --------------------------------------------------------------------------

_CONTENT_LENGTH_RE = re.compile(
    r"<(?:[^>:]+:)?getcontentlength[^>]*>\s*(\d+)\s*<", re.IGNORECASE
)
_PROPFIND_BODY = (
    b'<?xml version="1.0" encoding="utf-8"?>'
    b'<propfind xmlns="DAV:"><prop><getcontentlength/></prop></propfind>'
)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


class WebDavClient:
    def __init__(self, username: str, password: str, timeout: float = 120.0):
        self._auth: Optional[str] = None
        if username:
            token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
            self._auth = f"Basic {token}"
        self._timeout = timeout
        self._opener = urllib.request.build_opener(_NoRedirect())

    def _request(self, method: str, url: str, data: Optional[bytes] = None,
                 headers: Optional[Dict[str, str]] = None) -> Tuple[int, bytes]:
        req = urllib.request.Request(url, data=data, method=method)
        if self._auth is not None:
            req.add_header("Authorization", self._auth)
        for key, value in (headers or {}).items():
            req.add_header(key, value)
        try:
            with self._opener.open(req, timeout=self._timeout) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()
        except (urllib.error.URLError, OSError) as e:
            raise BackupError(f"{method} failed: {e}") from e

    def _checked(self, method: str, status: int, body: bytes) -> None:
        if status in (301, 302, 303, 307, 308):
            raise BackupError(f"{method} was redirected. Use the server's final WebDAV URL.")
        if status in (401, 403):
            raise BackupError(f"WebDAV authentication failed ({method} {status})")

    def resource_length(self, url: str) -> Optional[int]:
        status, body = self._request(
            "PROPFIND", url, data=_PROPFIND_BODY,
            headers={"Depth": "0", "Content-Type": "application/xml; charset=utf-8"},
        )
        self._checked("PROPFIND", status, body)
        if status in (404, 409, 410):
            return None
        if status in (200, 207):
            match = _CONTENT_LENGTH_RE.search(body.decode("utf-8", errors="replace"))
            return int(match.group(1)) if match else None
        raise BackupError(f"PROPFIND failed with HTTP {status}: {_short(body)}")

    def create_collection(self, url: str) -> None:
        status, body = self._request("MKCOL", url)
        self._checked("MKCOL", status, body)
        if status in (200, 201, 204, 405):
            return
        if status == 301 and not url.endswith("/"):
            self.create_collection(url + "/")
            return
        raise BackupError(f"MKCOL failed with HTTP {status}: {_short(body)}")

    def put_file(self, url: str, file_path: Path) -> None:
        data = file_path.read_bytes()
        status, body = self._request(
            "PUT", url, data=data, headers={"Content-Type": "application/octet-stream"}
        )
        self._checked("PUT", status, body)
        if status not in (200, 201, 204):
            raise BackupError(f"PUT failed with HTTP {status}: {_short(body)}")


def _short(body: bytes) -> str:
    return " ".join(body.decode("utf-8", errors="replace").split())[:160]


# --------------------------------------------------------------------------
# Upload of the staging tree
# --------------------------------------------------------------------------


@dataclass
class FileStamp:
    source_length: int
    source_modified: int  # milliseconds
    remote_length: int

    def to_json(self) -> Dict[str, int]:
        return {
            "sourceLength": self.source_length,
            "sourceModified": self.source_modified,
            "remoteLength": self.remote_length,
        }

    @staticmethod
    def from_json(data: Dict) -> Optional["FileStamp"]:
        try:
            return FileStamp(
                source_length=int(data["sourceLength"]),
                source_modified=int(data["sourceModified"]),
                remote_length=int(data.get("remoteLength", 0)),
            )
        except (KeyError, TypeError, ValueError):
            return None


@dataclass
class Manifest:
    target_key: str = ""
    files: Dict[str, FileStamp] = field(default_factory=dict)

    @staticmethod
    def load(path: Path) -> "Manifest":
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            files = {}
            for rel, stamp in (raw.get("files") or {}).items():
                parsed = FileStamp.from_json(stamp)
                if parsed is not None:
                    files[rel] = parsed
            return Manifest(target_key=str(raw.get("target", "")), files=files)
        except Exception:
            return Manifest()

    def save(self, path: Path) -> None:
        payload = {
            "target": self.target_key,
            "files": {rel: stamp.to_json() for rel, stamp in self.files.items()},
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload), encoding="utf-8")


@dataclass
class UploadOutcome:
    uploaded: int = 0
    unchanged: int = 0


def collect_files(root: Path) -> List[Tuple[str, Path]]:
    out: List[Tuple[str, Path]] = []
    if not root.is_dir():
        return out
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            full = Path(dirpath) / name
            rel = full.relative_to(root).as_posix()
            if all(_is_safe_segment(part) for part in rel.split("/")):
                out.append((rel, full))
    return out


def upload_tree(
    root: Path,
    cfg: WebDavConfig,
    previous: Manifest,
    client: WebDavClient,
    is_cancelled: Callable[[], bool] = lambda: False,
) -> Tuple[UploadOutcome, Manifest]:
    outcome = UploadOutcome()
    written: Dict[str, FileStamp] = {}
    same_target = previous.target_key == cfg.target_key()
    created: set = set()
    for rel, file_path in collect_files(root):
        if is_cancelled():
            raise BackupError("Backup cancelled")
        stat = file_path.stat()
        source_length = stat.st_size
        source_modified = int(stat.st_mtime * 1000)
        prior = previous.files.get(rel)
        remote_length = client.resource_length(cfg.file_url(rel))
        if (
            same_target
            and prior is not None
            and prior.source_length == source_length
            and prior.source_modified == source_modified
            and source_modified > 0
            and remote_length is not None
            and remote_length == source_length
        ):
            written[rel] = prior
            outcome.unchanged += 1
            continue
        for collection in cfg.collection_urls(rel):
            if collection not in created:
                client.create_collection(collection)
                created.add(collection)
        client.put_file(cfg.file_url(rel), file_path)
        written[rel] = FileStamp(source_length, source_modified, source_length)
        outcome.uploaded += 1
    return outcome, Manifest(target_key=cfg.target_key(), files=written)


# --------------------------------------------------------------------------
# Backup status
# --------------------------------------------------------------------------


@dataclass
class BackupStatus:
    completed_at: float = 0.0
    success: bool = False
    message: str = ""

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "completedAt": self.completed_at,
                    "success": self.success,
                    "message": " ".join(self.message.split())[:300],
                }
            ),
            encoding="utf-8",
        )

    @staticmethod
    def load(path: Path) -> Optional["BackupStatus"]:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            return BackupStatus(
                completed_at=float(raw.get("completedAt", 0)),
                success=bool(raw.get("success", False)),
                message=str(raw.get("message", "")),
            )
        except Exception:
            return None


# --------------------------------------------------------------------------
# One full backup cycle
# --------------------------------------------------------------------------


def staging_dir(profile: str = DEFAULT_PROFILE) -> Path:
    with _with_profile_env(profile):
        return Path(dirs.get_data_dir("aw-qt")) / "webdav-sync"


def manifest_path(profile: str = DEFAULT_PROFILE) -> Path:
    with _with_profile_env(profile):
        return Path(dirs.get_data_dir("aw-qt")) / MANIFEST_FILENAME


def status_path(profile: str = DEFAULT_PROFILE) -> Path:
    with _with_profile_env(profile):
        return Path(dirs.get_data_dir("aw-qt")) / STATUS_FILENAME


def find_aw_sync(candidate_paths: List[Path]) -> Optional[Path]:
    for candidate in candidate_paths:
        if candidate and Path(candidate).is_file():
            return Path(candidate)
    found = shutil.which("aw-sync")
    return Path(found) if found else None


def build_aw_sync_command(
    aw_sync: Path, staging: Path, port: int, profile: str = DEFAULT_PROFILE
) -> List[str]:
    command = [
        str(aw_sync),
        "--sync-dir",
        str(staging),
        "--port",
        str(port),
    ]
    if profile != DEFAULT_PROFILE:
        command += ["--profile", profile]
    return command + ["sync", "--mode", "push"]


def _run_aw_sync(command: List[str]) -> None:
    kwargs: Dict = {"capture_output": True, "text": True, "timeout": SYNC_TIMEOUT_SECONDS}
    if sys.platform == "win32":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        proc = subprocess.run(command, **kwargs)
    except FileNotFoundError:
        raise BackupError("aw-sync was not found next to ActivityWatch")
    except subprocess.TimeoutExpired:
        raise BackupError("aw-sync did not finish within 10 minutes")
    if proc.returncode != 0:
        detail = " ".join((proc.stderr or proc.stdout or "").split())[:300]
        raise BackupError(f"aw-sync failed (exit {proc.returncode}): {detail}")


def run_backup(
    cfg: WebDavConfig,
    port: int,
    profile: str = DEFAULT_PROFILE,
    aw_sync_candidates: Optional[List[Path]] = None,
    client: Optional[WebDavClient] = None,
    sync_runner: Optional[Callable[[List[str]], None]] = None,
) -> UploadOutcome:
    """Run one cycle: aw-sync push to staging, then upload the tree."""
    status_file = status_path(profile)
    try:
        cfg = validate_config(cfg)
        aw_sync = find_aw_sync(aw_sync_candidates or [])
        if aw_sync is None:
            raise BackupError("aw-sync was not found; WebDAV backup needs the bundled aw-sync")
        staging = staging_dir(profile)
        staging.mkdir(parents=True, exist_ok=True)
        (sync_runner or _run_aw_sync)(
            build_aw_sync_command(aw_sync, staging, port, profile)
        )
        if not collect_files(staging):
            raise BackupError("aw-sync produced no backup files; is the server running?")
        manifest_file = manifest_path(profile)
        previous = Manifest.load(manifest_file)
        outcome, updated = upload_tree(
            staging, cfg, previous, client or WebDavClient(cfg.username, cfg.password)
        )
        try:
            updated.save(manifest_file)
        except OSError as e:
            logger.warning(f"Could not save WebDAV backup manifest: {e}")
        message = f"uploaded {outcome.uploaded}, unchanged {outcome.unchanged}"
        BackupStatus(time.time(), True, message).save(status_file)
        return outcome
    except (BackupError, ValueError) as e:
        BackupStatus(time.time(), False, str(e)).save(status_file)
        raise
