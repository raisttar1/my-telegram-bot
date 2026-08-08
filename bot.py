#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Telegram Script-Hosting Bot
===========================

A production-oriented Telegram bot that lets approved users upload Python or
Node.js projects (or .zip archives), have dependencies installed automatically,
and run the code in a hardened sandbox.

Security model
--------------
* All user code runs inside a disposable Docker container (default) with:
  network disabled for the execution phase, read-only root filesystem,
  dropped capabilities, no-new-privileges, PID/CPU/memory limits and a
  writable /tmp only. Only the user's own workspace is mounted.
* The *dependency install* phase needs network access and runs in a separate
  short-lived container so untrusted code never runs with network on.
* Uploads are validated for extension, size and name; ZIP archives are
  extracted with traversal / bomb protection.
* A restricted terminal enforces an allowlist of commands and keeps every path
  inside the user's workspace.
* Unsandboxed local subprocess execution is DISABLED unless explicitly allowed
  by ALLOW_UNSANDBOXED_EXECUTION=true and is only ever used when the operator
  trusts every user.

Everything sensitive is read from the environment (see .env.example).
No secrets are hardcoded in this file.
"""

from __future__ import annotations

import asyncio
import contextlib
import html
import json
import logging
import os
import psutil
import re
import resource
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Dependencies (optional imports handled lazily so the bot can start even if
# Docker is not present — the Docker backend just reports an error at runtime).
# ---------------------------------------------------------------------------
try:  # pragma: no cover - import guard
    import docker  # type: ignore
    DOCKER_SDK = True
except Exception:  # pragma: no cover
    DOCKER_SDK = False

try:  # pragma: no cover - import guard
    from dotenv import load_dotenv
    load_dotenv()
except Exception:  # pragma: no cover
    pass

from flask import Flask, jsonify
from waitress import serve

from telegram import (
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Update,
    error as tg_error,
)
from telegram.constants import ParseMode
from telegram.request import HTTPXRequest
from telegram.ext import (
    Application,
    ApplicationBuilder,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
APP_NAME = "telegram-script-bot"
CONFIG_VERSION = 1
ALLOWED_EXTENSIONS = {".py", ".js", ".zip"}
ZIP_ENTRY_LIMIT_MSG = "Archive contains too many files."

log = logging.getLogger(APP_NAME)

START_TIME = time.monotonic()

# ---------------------------------------------------------------------------
# 13. Configuration
# ---------------------------------------------------------------------------


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        log.warning("Invalid integer for %s, using default %s", name, default)
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        log.warning("Invalid float for %s, using default %s", name, default)
        return default


@dataclass(frozen=True)
class Config:
    bot_token: str
    owner_id: int
    channel_username: str
    port: int
    base_dir: Path

    max_upload_mb: int
    max_archive_mb: int
    max_extracted_mb: int
    max_archive_entries: int
    max_projects_per_user: int

    max_processes_per_user: int
    max_global_processes: int
    execution_timeout: int
    max_stored_processes_per_user: int

    max_log_bytes: int
    live_update_seconds: int

    execution_mode: str
    allow_unsandboxed: bool
    docker_network_disabled: bool

    docker_image: str
    node_docker_image: str
    docker_cpus: float
    docker_memory: str
    docker_pids: int
    docker_tmp_size: str

    stdin_timeout_seconds: int
    input_wait_detect_seconds: int
    terminal_timeout: int
    log_level: str

    http_connect_timeout: float
    http_read_timeout: float
    http_write_timeout: float
    http_pool_timeout: float
    http_pool_size: int
    watchdog_retry_seconds: float

    @classmethod
    def from_env(cls) -> "Config":
        token = os.getenv("BOT_TOKEN", "").strip()
        owner_id = _env_int("OWNER_ID", 0)
        if not token:
            raise ValueError("BOT_TOKEN is required (set it in .env)")
        if owner_id <= 0:
            raise ValueError("OWNER_ID is required and must be a positive integer")

        base_dir = Path(os.getenv("BASE_DIR", "./data")).expanduser().resolve()

        mode = os.getenv("EXECUTION_MODE", "docker").strip().lower()
        if mode not in {"docker", "unsandboxed"}:
            mode = "docker"
        if mode == "unsandboxed" and not _env_bool("ALLOW_UNSANDBOXED_EXECUTION", False):
            raise ValueError(
                "EXECUTION_MODE=unsandboxed requires ALLOW_UNSANDBOXED_EXECUTION=true "
                "(running untrusted code on the host is unsafe)"
            )

        return cls(
            bot_token=token,
            owner_id=owner_id,
            channel_username=os.getenv("CHANNEL_USERNAME", "").strip(),
            port=_env_int("PORT", 8080),
            base_dir=base_dir,
            max_upload_mb=_env_int("MAX_UPLOAD_MB", 20),
            max_archive_mb=_env_int("MAX_ARCHIVE_MB", 50),
            max_extracted_mb=_env_int("MAX_EXTRACTED_MB", 200),
            max_archive_entries=_env_int("MAX_ARCHIVE_ENTRIES", 500),
            max_projects_per_user=_env_int("MAX_PROJECTS_PER_USER", 10),
            max_processes_per_user=_env_int("MAX_PROCESSES_PER_USER", 2),
            max_global_processes=_env_int("MAX_GLOBAL_PROCESSES", 10),
            execution_timeout=_env_int("EXECUTION_TIMEOUT", 3600),
            max_stored_processes_per_user=_env_int("MAX_STORED_PROCESSES_PER_USER", 25),
            max_log_bytes=_env_int("MAX_LOG_BYTES", 262144),
            live_update_seconds=max(1, _env_int("LIVE_UPDATE_SECONDS", 3)),
            execution_mode=mode,
            allow_unsandboxed=_env_bool("ALLOW_UNSANDBOXED_EXECUTION", False),
            docker_network_disabled=_env_bool("DOCKER_NETWORK_DISABLED", True),
            docker_image=os.getenv("DOCKER_IMAGE", "python:3.11-slim").strip(),
            node_docker_image=os.getenv("NODE_DOCKER_IMAGE", "node:20-slim").strip(),
            docker_cpus=max(0.05, _env_float("DOCKER_CPUS", 1.0)),
            docker_memory=os.getenv("DOCKER_MEMORY", "256m").strip() or "256m",
            docker_pids=max(16, _env_int("DOCKER_PIDS", 128)),
            docker_tmp_size=os.getenv("DOCKER_TMP_SIZE", "64m").strip() or "64m",
            stdin_timeout_seconds=_env_int("STDIN_TIMEOUT_SECONDS", 3600),
            input_wait_detect_seconds=max(3, _env_int("INPUT_WAIT_DETECT_SECONDS", 8)),
            terminal_timeout=_env_int("TERMINAL_TIMEOUT", 15),
            log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
            http_connect_timeout=_env_float("HTTP_CONNECT_TIMEOUT", 30),
            http_read_timeout=_env_float("HTTP_READ_TIMEOUT", 30),
            http_write_timeout=_env_float("HTTP_WRITE_TIMEOUT", 30),
            http_pool_timeout=_env_float("HTTP_POOL_TIMEOUT", 10),
            http_pool_size=max(1, _env_int("HTTP_POOL_SIZE", 10)),
            watchdog_retry_seconds=max(1.0, _env_float("WATCHDOG_RETRY_SECONDS", 5)),
        )

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024

    @property
    def max_archive_bytes(self) -> int:
        return self.max_archive_mb * 1024 * 1024

    @property
    def max_extracted_bytes(self) -> int:
        return self.max_extracted_mb * 1024 * 1024


# ---------------------------------------------------------------------------
# 2 / 12. Logging
# ---------------------------------------------------------------------------
def setup_logging(level: str) -> None:
    fmt = "%(asctime)s %(levelname)-7s [%(name)s] %(message)s"
    logging.basicConfig(level=getattr(logging, level, logging.INFO), format=fmt)
    # Quiet noisy libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# 10. Atomic persistence
# ---------------------------------------------------------------------------
class AtomicJsonStore:
    """Load/save a JSON document with atomic writes and corruption handling."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.RLock()

    def load(self, default: dict) -> dict:
        if not self.path.exists():
            return dict(default)
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if not isinstance(data, dict):
                raise ValueError("root is not an object")
            return data
        except Exception as exc:  # noqa: BLE001
            log.error("Failed to read %s (%s); recovering", self.path, exc)
            backup = self.path.with_suffix(".corrupt.json")
            try:
                shutil.copy2(self.path, backup)
                log.warning("Backed up corrupt state to %s", backup)
            except OSError:
                log.exception("Could not back up corrupt state")
            return dict(default)

    def save(self, data: dict) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)


# ---------------------------------------------------------------------------
# 10. Data model
# ---------------------------------------------------------------------------
USER_PENDING = "pending"
USER_APPROVED = "approved"
USER_BANNED = "banned"

PROC_INSTALLING = "installing"
PROC_RUNNING = "running"
PROC_WAITING_INPUT = "waiting_input"
PROC_FINISHED = "finished"
PROC_FAILED = "failed"
PROC_KILLED = "killed"
PROC_TIMED_OUT = "timed_out"
PROC_INTERRUPTED = "interrupted"

RUNNING_STATUSES = {PROC_INSTALLING, PROC_RUNNING, PROC_WAITING_INPUT}
TERMINAL_STATUSES = {PROC_RUNNING, PROC_WAITING_INPUT}


class DataStore:
    """Typed facade over the atomic JSON file holding users, projects, processes."""

    def __init__(self, store: AtomicJsonStore) -> None:
        self._store = store
        self._data = store.load(
            {"version": CONFIG_VERSION, "users": {}, "projects": {}, "processes": []}
        )
        self._lock = threading.RLock()

    # -- low level ----------------------------------------------------------
    def _commit(self) -> None:
        self._data["version"] = CONFIG_VERSION
        self._store.save(self._data)

    # -- users --------------------------------------------------------------
    def get_user(self, user_id: int) -> Optional[dict]:
        return self._data["users"].get(str(user_id))

    def ensure_user(self, user: Any) -> dict:
        """Create a user record if absent; returns the (maybe new) record."""
        uid = str(user.id)
        with self._lock:
            record = self._data["users"].get(uid)
            if record is None:
                record = {
                    "id": user.id,
                    "full_name": (user.full_name or "")[:200],
                    "username": (user.username or "")[:64],
                    "status": USER_PENDING,
                    "first_seen": time.time(),
                    "last_active": time.time(),
                    "approved_at": None,
                    "request_message": None,
                }
                self._data["users"][uid] = record
                self._commit()
            else:
                record["full_name"] = (user.full_name or "")[:200]
                record["username"] = (user.username or "")[:64]
                record["last_active"] = time.time()
            return record

    def touch(self, user_id: int) -> None:
        with self._lock:
            rec = self._data["users"].get(str(user_id))
            if rec:
                rec["last_active"] = time.time()

    def set_user_status(self, user_id: int, status: str) -> None:
        with self._lock:
            rec = self._data["users"].get(str(user_id))
            if rec is None:
                return
            rec["status"] = status
            if status == USER_APPROVED and not rec.get("approved_at"):
                rec["approved_at"] = time.time()
            self._commit()

    def set_request_message(self, user_id: int, chat_id: int, message_id: int) -> None:
        with self._lock:
            rec = self._data["users"].get(str(user_id))
            if rec:
                rec["request_message"] = {"chat_id": chat_id, "message_id": message_id}
                self._commit()

    def clear_request_message(self, user_id: int) -> None:
        with self._lock:
            rec = self._data["users"].get(str(user_id))
            if rec:
                rec["request_message"] = None
                self._commit()

    def all_users(self) -> list[dict]:
        return sorted(
            self._data["users"].values(), key=lambda u: u.get("first_seen", 0)
        )

    def users_with_status(self, status: str) -> list[dict]:
        return [u for u in self.all_users() if u.get("status") == status]

    # -- projects -----------------------------------------------------------
    def add_project(self, user_id: int, project: dict) -> None:
        with self._lock:
            key = str(user_id)
            self._data["projects"].setdefault(key, []).insert(0, project)
            self._data["projects"][key] = self._data["projects"][key][
                : self._cfg_max_projects
            ]
            self._commit()

    def projects_for(self, user_id: int) -> list[dict]:
        return list(self._data["projects"].get(str(user_id), []))

    def get_project(self, user_id: int, project_id: str) -> Optional[dict]:
        for p in self.projects_for(user_id):
            if p.get("id") == project_id:
                return p
        return None

    def remove_project(self, user_id: int, project_id: str) -> Optional[dict]:
        with self._lock:
            key = str(user_id)
            projects = self._data["projects"].get(key, [])
            for i, p in enumerate(projects):
                if p.get("id") == project_id:
                    removed = projects.pop(i)
                    self._data["projects"][key] = projects
                    self._commit()
                    return removed
        return None

    # -- processes ----------------------------------------------------------
    def add_process(self, proc: dict) -> None:
        with self._lock:
            self._data["processes"].insert(0, proc)
            self._trim_processes(proc.get("user_id"))
            self._commit()

    def update_process(self, proc_id: str, **fields: Any) -> None:
        with self._lock:
            for p in self._data["processes"]:
                if p.get("id") == proc_id:
                    p.update(fields)
                    break
            self._commit()

    def _trim_processes(self, user_id: int) -> None:
        key = str(user_id)
        keep = []
        for p in self._data["processes"]:
            if p.get("user_id") == user_id:
                keep.append(p)
        limit = self._cfg_max_stored
        if len(keep) > limit:
            over = {p["id"] for p in keep[limit:]}
            self._data["processes"] = [
                p for p in self._data["processes"] if p["id"] not in over
            ]

    def processes_for(self, user_id: int) -> list[dict]:
        return [p for p in self._data["processes"] if p.get("user_id") == user_id]

    def all_processes(self) -> list[dict]:
        return list(self._data["processes"])

    def count_active(self, user_id: Optional[int] = None) -> int:
        if user_id is None:
            return sum(
                1 for p in self._data["processes"] if p.get("status") in RUNNING_STATUSES
            )
        return sum(
            1
            for p in self._data["processes"]
            if p.get("user_id") == user_id and p.get("status") in RUNNING_STATUSES
        )

    # used to wire limits from config
    _cfg_max_projects = 10
    _cfg_max_stored = 25


# ---------------------------------------------------------------------------
# 5. Log file helpers
# ---------------------------------------------------------------------------
def append_log(path: Path, chunk: bytes, max_bytes: int) -> None:
    """Append bytes to a log file, truncating from the head to honor max_bytes."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if not chunk:
        return
    try:
        existing = path.read_bytes() if path.exists() else b""
        data = existing + chunk
        if len(data) > max_bytes:
            data = data[-max_bytes:]
        with open(path, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
    except OSError:
        log.exception("Failed to append to log %s", path)


def tail_text(path: Path, max_chars: int = 3500) -> str:
    """Return the tail of a log file decoded safely (UTF-8 errors replaced)."""
    try:
        if not path.exists():
            return ""
        size = path.stat().st_size
        with open(path, "rb") as fh:
            if size > 4096 * 100:
                fh.seek(-(4096 * 100), os.SEEK_END)
            raw = fh.read()
        text = raw.decode("utf-8", errors="replace")
        return text[-max_chars:]
    except OSError:
        log.exception("Failed to read log %s", path)
        return ""


# ---------------------------------------------------------------------------
# 6. Security helpers (filenames, paths)
# ---------------------------------------------------------------------------
_FILENAME_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")


def sanitize_filename(name: str) -> str:
    """Return a safe basename: no slashes, no '..', no leading dots, no odd chars."""
    base = os.path.basename(name.replace("\\", "/"))
    base = base.strip()
    base = _FILENAME_SAFE_RE.sub("_", base)
    base = base.lstrip(".")
    if base in {"", ".", ".."}:
        raise ValueError("invalid filename")
    # enforce a sane maximum
    if len(base) > 128:
        root, ext = os.path.splitext(base)
        base = root[:120] + ext
    return base


def is_within(base: Path, target: Path) -> bool:
    """True when target is strictly inside base (both resolved)."""
    try:
        base_res = base.resolve()
        target_res = target.resolve()
        return target_res == base_res or target_res.is_relative_to(base_res)
    except OSError:
        return False


def resolve_within(base: Path, cwd: Path, rel: str) -> Path:
    """Join rel onto cwd and verify the result stays inside base."""
    candidate = Path(os.path.normpath(os.path.join(str(cwd), rel)))
    if not is_within(base, candidate):
        raise ValueError("path escapes the workspace")
    return candidate


def validate_file_extension(filename: str) -> str:
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError(f"Unsupported file type '{ext}'. Allowed: .py, .js, .zip")
    return ext


def human_size(num_bytes: int) -> str:
    value = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{value:.1f} GB"


# ---------------------------------------------------------------------------
# 2. ZIP extraction (traversal + bomb protection)
# ---------------------------------------------------------------------------
def safe_extract_zip(zip_path: Path, dest_dir: Path, cfg: Config) -> int:
    """
    Extract a zip archive safely.

    Rules enforced:
      * no absolute paths, no '..' traversal
      * no symlinks are materialized (they are skipped)
      * per-entry and total uncompressed size capped (MAX_EXTRACTED_MB)
      * entry count capped (MAX_ARCHIVE_ENTRIES)

    Returns the number of files extracted.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_root = dest_dir.resolve()

    with zipfile.ZipFile(zip_path, "r") as zf:
        infos = zf.infolist()
        if len(infos) > cfg.max_archive_entries:
            raise ValueError(
                f"{ZIP_ENTRY_LIMIT_MSG} Limit: {cfg.max_archive_entries}"
            )

        total = 0
        extracted = 0
        for info in infos:
            name = info.filename
            if name.endswith("/"):
                continue

            # traversal / absolute path protection
            norm = os.path.normpath(name.replace("\\", "/"))
            if norm.startswith(("..", "/")) or ".." in norm.split("/"):
                raise ValueError(f"Archive entry escapes destination: {name!r}")

            # symlink entries are never materialized
            mode = (info.external_attr >> 16) & 0xFFFF
            if mode and (mode & 0o170000) == 0o120000:
                log.warning("Skipping symlink entry %r", name)
                continue

            # per-entry size cap
            if info.file_size > cfg.max_extracted_bytes:
                raise ValueError(
                    f"Entry {name!r} too large: {human_size(info.file_size)}"
                )
            total += info.file_size
            if total > cfg.max_extracted_bytes:
                raise ValueError(
                    f"Archive would extract to more than {cfg.max_extracted_mb} MB"
                )

            target = (dest_dir / norm).resolve()
            if not (target == dest_root or target.is_relative_to(dest_root)):
                raise ValueError(f"Archive entry escapes destination: {name!r}")

            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info, "r") as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst, length=256 * 1024)
            extracted += 1

    return extracted


# ---------------------------------------------------------------------------
# 2. Workspace layout helpers
# ---------------------------------------------------------------------------
def project_ignored_dir(name: str) -> bool:
    return name in {"node_modules", "__pycache__", ".git", ".venv", "venv"}


def scan_project_files(project_dir: Path) -> list[str]:
    """Return relative file paths in a project, ignoring noise dirs."""
    files: list[str] = []
    for root, dirs, names in os.walk(project_dir):
        dirs[:] = [d for d in dirs if not project_ignored_dir(d)]
        for name in names:
            rel = os.path.relpath(os.path.join(root, name), project_dir)
            files.append(rel)
    return files


def detect_entrypoint(project_dir: Path) -> tuple[str, str]:
    """
    Determine the runnable entrypoint and runtime.

    Priority: main.py -> index.js -> package.json "main" -> exactly one file.
    Raises ValueError when no unambiguous entrypoint exists.
    """
    files = scan_project_files(project_dir)
    lower = {f.lower().replace("\\", "/") for f in files}

    if "main.py" in lower:
        for f in files:
            if f.lower().replace("\\", "/") == "main.py":
                return f, "python"
    if "index.js" in lower:
        for f in files:
            if f.lower().replace("\\", "/") == "index.js":
                return f, "node"

    pkg = project_dir / "package.json"
    if pkg.exists():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8"))
            main = (data.get("main") or "index.js").strip()
            if main:
                candidate = project_dir / main
                if candidate.is_file():
                    return main, "node"
        except (OSError, ValueError, TypeError):
            pass

    if len(files) == 1:
        ext = os.path.splitext(files[0])[1].lower()
        if ext == ".py":
            return files[0], "python"
        if ext == ".js":
            return files[0], "node"

    raise ValueError(
        "Could not detect entrypoint. Upload code containing 'main.py' "
        "(Python) or 'index.js' (Node.js), or a zip with exactly one source file."
    )


# ---------------------------------------------------------------------------
# Backends: Docker (default) and unsandboxed subprocess (opt-in, unsafe)
# ---------------------------------------------------------------------------
class InstallHandle:
    """Blocking handle for a dependency-install step."""

    def stream(self):
        raise NotImplementedError

    def wait_exit(self) -> int:
        raise NotImplementedError

    def stop(self) -> None:
        raise NotImplementedError


class RunHandle:
    """Blocking handle for the actual program execution."""

    def stream(self):
        raise NotImplementedError

    def wait_exit(self) -> int:
        raise NotImplementedError

    def stop(self) -> None:
        raise NotImplementedError

    def write_stdin(self, data: bytes) -> None:
        raise NotImplementedError

    def close_stdin(self) -> None:
        raise NotImplementedError

    @property
    def identifier(self) -> str:
        return ""


class DockerBackend:
    """Runs everything inside disposable, hardened Docker containers."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self._client = None
        if DOCKER_SDK:
            try:
                self._client = docker.from_env()
            except Exception as exc:  # noqa: BLE001
                log.warning("Docker client init failed: %s", exc)
                self._client = None

    def check(self) -> tuple[bool, str]:
        if not DOCKER_SDK:
            return False, "The 'docker' Python package is not installed."
        if self._client is None:
            return False, "Could not connect to the Docker daemon."
        try:
            self._client.ping()
            return True, ""
        except Exception as exc:  # noqa: BLE001
            return False, f"Docker daemon unreachable: {exc}"

    # -- image / command builders ------------------------------------------
    def _ensure_image(self, image: str) -> None:
        """Pull the image if it is not present locally (needs network)."""
        try:
            self._client.images.get(image)  # type: ignore
        except Exception:  # noqa: BLE001 - ImageNotFound
            log.info("Pulling Docker image %s (one-time)", image)
            self._client.images.pull(image)  # type: ignore

    def cleanup_orphan(self, proc_id: str) -> None:
        """Remove any leftover containers from a previous bot run."""
        if self._client is None:
            return
        names = {f"tgbot-{proc_id}", f"tgbot-{proc_id}-inst"}
        try:
            for container in self._client.containers.list(all=True):
                label = (container.labels or {}).get("telegram-bot.process", "")
                if label in names or container.name in names:
                    with contextlib.suppress(Exception):
                        container.remove(force=True)
                    log.info("Removed orphan container %s", container.name)
        except Exception:  # noqa: BLE001
            log.warning("Orphan cleanup failed", exc_info=True)

    def _image(self, runtime: str) -> str:
        return (
            self.cfg.docker_image
            if runtime == "python"
            else self.cfg.node_docker_image
        )

    def _install_command(self, runtime: str) -> Optional[str]:
        if runtime == "python":
            return (
                "pip install --no-cache-dir --disable-pip-version-check "
                "-r requirements.txt --target /venv && "
                "touch /venv/.installed_marker"
            )
        return (
            "npm install --ignore-scripts --no-audit --no-fund --cache /tmp/npm-cache "
            "&& touch node_modules/.installed_marker"
        )

    def _run_command(self, runtime: str, entrypoint: str) -> list[str]:
        if runtime == "python":
            return ["python", "-u", entrypoint]
        return ["node", entrypoint]

    def _base_volumes(self, project_dir: Path, venv_dir: Path) -> dict:
        return {
            str(project_dir): {"bind": "/workspace", "mode": "rw"},
            str(venv_dir): {"bind": "/venv", "mode": "rw"},
        }

    def _run_volumes(self, project_dir: Path, venv_dir: Path) -> dict:
        return {
            str(project_dir): {"bind": "/workspace", "mode": "rw"},
            str(venv_dir): {"bind": "/venv", "mode": "ro"},
        }

    def _common_kwargs(self, container_name: str, project_id: str, user_id: int) -> dict:
        return {
            "name": container_name,
            "detach": True,
            "read_only": True,
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges"],
            "pids_limit": self.cfg.docker_pids,
            "mem_limit": self.cfg.docker_memory,
            "nano_cpus": int(self.cfg.docker_cpus * 1_000_000_000),
            "tmpfs": {"/tmp": f"size={self.cfg.docker_tmp_size},mode=1777"},
            "labels": {
                "telegram-bot.process": container_name,
                "telegram-bot.project": project_id,
                "telegram-bot.user": str(user_id),
            },
            "working_dir": "/workspace",
            "environment": {"HOME": "/tmp"},
        }

    def install(self, proc) -> Optional[InstallHandle]:
        cmd = self._install_command(proc.runtime)
        if cmd is None:
            return None
        # skip install if a previous run already installed dependencies
        if proc.runtime == "python":
            if (proc.venv_dir / ".installed_marker").exists():
                return None
        else:
            if (proc.project_dir / "node_modules" / ".installed_marker").exists():
                return None
        kwargs = self._common_kwargs(
            f"tgbot-{proc.id}-inst", proc.project_id, proc.user_id
        )
        kwargs.update(
            {
                "image": self._image(proc.runtime),
                "command": ["sh", "-c", cmd],
                "volumes": self._base_volumes(proc.project_dir, proc.venv_dir),
                "network_disabled": False,
            }
        )
        self._ensure_image(self._image(proc.runtime))
        container = self._client.containers.run(**kwargs)  # type: ignore
        return _DockerInstallHandle(container)

    def run(self, proc) -> RunHandle:
        self._ensure_image(self._image(proc.runtime))
        kwargs = self._common_kwargs(f"tgbot-{proc.id}", proc.project_id, proc.user_id)
        kwargs.update(
            {
                "image": self._image(proc.runtime),
                "command": self._run_command(proc.runtime, proc.entrypoint),
                "volumes": self._run_volumes(proc.project_dir, proc.venv_dir),
                "network_disabled": self.cfg.docker_network_disabled,
                "stdin_open": True,
            }
        )
        if proc.runtime == "python":
            kwargs["environment"]["PYTHONPATH"] = "/venv"
            kwargs["environment"]["PYTHONUNBUFFERED"] = "1"
        container = self._client.containers.run(**kwargs)  # type: ignore
        return _DockerRunHandle(container)

    def cleanup_project(self, project_dir: Path, venv_dir: Path) -> None:
        for d in (venv_dir,):
            if d.exists():
                with contextlib.suppress(OSError):
                    shutil.rmtree(d, ignore_errors=True)


class _DockerInstallHandle(InstallHandle):
    def __init__(self, container) -> None:
        self.container = container

    def stream(self):
        yield from self.container.logs(stream=True, follow=True, stdout=True, stderr=True)

    def wait_exit(self) -> int:
        try:
            result = self.container.wait(timeout=3600)
            if isinstance(result, dict):
                return int(result.get("StatusCode", 1))
            return int(result)
        except Exception:  # noqa: BLE001
            return 1

    def stop(self) -> None:
        with contextlib.suppress(Exception):
            self.container.remove(force=True)


class _DockerRunHandle(RunHandle):
    def __init__(self, container) -> None:
        self.container = container
        self._stdin = None
        try:
            self._stdin = container.attach(stdin=True, stream=True, logs=False)
        except Exception:  # noqa: BLE001
            self._stdin = None

    def stream(self):
        yield from self.container.logs(stream=True, follow=True, stdout=True, stderr=True)

    def wait_exit(self) -> int:
        try:
            result = self.container.wait(timeout=3600)
            if isinstance(result, dict):
                return int(result.get("StatusCode", 1))
            return int(result)
        except Exception:  # noqa: BLE001
            return 137

    def write_stdin(self, data: bytes) -> None:
        if self._stdin is None:
            raise OSError("stdin is not attached")
        try:
            self._stdin.write(data)
            self._stdin.flush()
        except Exception:  # noqa: BLE001
            raise OSError("stdin write failed (process likely exited)")

    def close_stdin(self) -> None:
        if self._stdin is not None:
            with contextlib.suppress(Exception):
                self._stdin.close()
            self._stdin = None

    def stop(self) -> None:
        with contextlib.suppress(Exception):
            self.container.remove(force=True)

    @property
    def identifier(self) -> str:
        return self.container.short_id or ""


class SubprocessBackend:
    """UNSAFE host execution. Only enabled when the operator opts in."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg

    def check(self) -> tuple[bool, str]:
        return True, ""

    def _clean_env(self, runtime: str) -> dict:
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": tempfile.gettempdir(),
            "LANG": "C.UTF-8",
        }
        if runtime == "python":
            env["PYTHONUNBUFFERED"] = "1"
        return env

    def _venv(self, project_id: str) -> Path:
        return self.cfg.base_dir / "venvs" / project_id

    def install(self, proc) -> Optional[InstallHandle]:
        if proc.runtime == "python":
            req = proc.project_dir / "requirements.txt"
            if not req.exists():
                return None
            marker = self._venv(proc.project_id) / ".installed_marker"
            if marker.exists():
                return None
            target = str(self._venv(proc.project_id))
            cmd = (
                f"{shlex.quote(sys.executable)} -m pip install "
                "--no-cache-dir --disable-pip-version-check "
                f"-r {shlex.quote(str(req))} --target {shlex.quote(target)} "
                f"&& touch {shlex.quote(str(marker))}"
            )
        else:
            pkg = proc.project_dir / "package.json"
            if not pkg.exists():
                return None
            marker = proc.project_dir / "node_modules" / ".installed_marker"
            if marker.exists():
                return None
            cmd = (
                "npm install --ignore-scripts --no-audit --no-fund "
                f"--cache {shlex.quote(str(self._venv(proc.project_id) / 'npm-cache'))} "
                f"&& touch {shlex.quote(str(marker))}"
            )
        env = dict(os.environ)
        env.pop("BOT_TOKEN", None)
        return _SubprocessInstallHandle(
            ["sh", "-c", cmd], cwd=str(proc.project_dir), env=env
        )

    def run(self, proc) -> RunHandle:
        if proc.runtime == "python":
            cmd = [sys.executable, "-u", proc.entrypoint]
            env = self._clean_env("python")
            env["PYTHONPATH"] = str(self._venv(proc.project_id))
        else:
            cmd = ["node", proc.entrypoint]
            env = self._clean_env("node")
        env.pop("BOT_TOKEN", None)

        def _limits() -> None:
            with contextlib.suppress(Exception):
                resource.setrlimit(
                    resource.RLIMIT_CPU,
                    (max(1, self.cfg.execution_timeout), max(1, self.cfg.execution_timeout)),
                )
            with contextlib.suppress(Exception):
                resource.setrlimit(
                    resource.RLIMIT_FSIZE,
                    (self.cfg.max_log_bytes, self.cfg.max_log_bytes),
                )
            with contextlib.suppress(Exception):
                resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))

        return _SubprocessRunHandle(
            cmd,
            cwd=str(proc.project_dir),
            env=env,
            preexec_fn=_limits,
        )

    def cleanup_project(self, project_dir: Path, venv_dir: Path) -> None:
        with contextlib.suppress(OSError):
            shutil.rmtree(venv_dir, ignore_errors=True)

    def cleanup_orphan(self, proc_id: str) -> None:
        # host subprocesses cannot outlive the bot; nothing to reconcile
        return


class _SubprocessInstallHandle(InstallHandle):
    def __init__(self, cmd: list[str], cwd: str, env: dict) -> None:
        self.proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        self._done = False

    def stream(self):
        assert self.proc.stdout is not None
        while True:
            chunk = self.proc.stdout.readline()
            if not chunk:
                break
            yield chunk
        self._done = True

    def wait_exit(self) -> int:
        try:
            return self.proc.wait(timeout=300)
        except subprocess.TimeoutExpired:
            self.stop()
            return 1

    def stop(self) -> None:
        with contextlib.suppress(Exception):
            self.proc.terminate()
        with contextlib.suppress(Exception):
            self.proc.wait(timeout=5)


class _SubprocessRunHandle(RunHandle):
    def __init__(self, cmd: list[str], cwd: str, env: dict, preexec_fn=None) -> None:
        self.proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            preexec_fn=preexec_fn,
            start_new_session=True,
        )

    def stream(self):
        assert self.proc.stdout is not None
        while True:
            chunk = self.proc.stdout.readline()
            if not chunk:
                break
            yield chunk

    def wait_exit(self) -> int:
        try:
            return self.proc.wait(timeout=300)
        except subprocess.TimeoutExpired:
            self.stop()
            return 137

    def write_stdin(self, data: bytes) -> None:
        if self.proc.stdin is None or self.proc.stdin.closed:
            raise OSError("stdin is closed")
        try:
            self.proc.stdin.write(data)
            self.proc.stdin.flush()
        except BrokenPipeError:
            raise OSError("stdin write failed (process likely exited)")

    def close_stdin(self) -> None:
        if self.proc.stdin is not None and not self.proc.stdin.closed:
            with contextlib.suppress(Exception):
                self.proc.stdin.close()

    def stop(self) -> None:
        with contextlib.suppress(Exception):
            self.proc.terminate()
        with contextlib.suppress(Exception):
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    @property
    def identifier(self) -> str:
        return str(self.proc.pid or "")


# ---------------------------------------------------------------------------
# 5. Process model + manager
# ---------------------------------------------------------------------------
class ActiveProcess:
    def __init__(
        self,
        *,
        id: str,
        user_id: int,
        user_name: str,
        project_id: str,
        project_name: str,
        entrypoint: str,
        runtime: str,
        project_dir: Path,
        venv_dir: Path,
        log_path: Path,
        install_log_path: Path,
        timeout: int,
    ) -> None:
        self.id = id
        self.user_id = user_id
        self.user_name = user_name
        self.project_id = project_id
        self.project_name = project_name
        self.entrypoint = entrypoint
        self.runtime = runtime
        self.project_dir = project_dir
        self.venv_dir = venv_dir
        self.log_path = log_path
        self.install_log_path = install_log_path
        self.timeout = timeout

        self.status = PROC_INSTALLING
        self.started_at = time.time()
        self.ended_at: Optional[float] = None
        self.exit_code: Optional[int] = None
        self.note: Optional[str] = None
        self.container_id: Optional[str] = None

        # runtime-only state
        self.run_handle: Optional[RunHandle] = None
        self.install_handle: Optional[InstallHandle] = None
        self.last_output_at = time.time()
        self.awaiting_input = False
        self.awaiting_since = 0.0
        self.stdin_open = True
        self.stop_requested = False
        self.timed_out = False
        self.finished = False
        self.live_message: Optional[tuple[int, int]] = None  # (chat_id, message_id)
        self.last_rendered: Optional[str] = None
        self.last_sent = 0.0
        self.tasks: list[asyncio.Task] = []

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "user_name": self.user_name,
            "project_id": self.project_id,
            "project_name": self.project_name,
            "entrypoint": self.entrypoint,
            "runtime": self.runtime,
            "status": self.status,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "exit_code": self.exit_code,
            "note": self.note,
            "container_id": self.container_id,
            "log_path": str(self.log_path),
            "install_log_path": str(self.install_log_path),
        }


class ProcessManager:
    """
    Owns the lifecycle of every process: limits, install + run orchestration,
    log streaming, live Telegram updates, stdin forwarding, timeouts, cleanup.
    """

    def __init__(self, cfg: Config, store: DataStore) -> None:
        self.cfg = cfg
        self.store = store
        if cfg.execution_mode == "docker":
            self.backend: Any = DockerBackend(cfg)
        else:
            self.backend = SubprocessBackend(cfg)
        self.active: dict[str, ActiveProcess] = {}
        self.bot = None  # set after Application is built
        self._start_lock = asyncio.Lock()
        self._shutting_down = False

    # -- startup reconciliation ---------------------------------------------
    async def reconcile(self) -> None:
        """Clean up leftovers from a previous run (orphaned containers/procs)."""
        ok, _ = self.backend.check()
        if not ok:
            log.warning("Backend unavailable; skipping reconciliation: %s", _)
        stale = [
            p
            for p in self.store.all_processes()
            if p.get("status") in RUNNING_STATUSES
        ]
        for p in stale:
            proc_id = p["id"]
            if hasattr(self.backend, "cleanup_orphan"):
                await asyncio.to_thread(self.backend.cleanup_orphan, proc_id)
            self.store.update_process(
                proc_id,
                status=PROC_INTERRUPTED,
                ended_at=time.time(),
                note="bot restarted while process was active",
            )
            log.info("Marked stale process %s as interrupted", proc_id)

    # -- limits --------------------------------------------------------------
    def _limit_error(self) -> Optional[str]:
        global_active = len(self.active)
        if global_active >= self.cfg.max_global_processes:
            return f"Global process limit reached ({self.cfg.max_global_processes}). Try later."
        return None

    def _limit_error_user(self, user_id: int) -> Optional[str]:
        mine = sum(1 for p in self.active.values() if p.user_id == user_id)
        if mine >= self.cfg.max_processes_per_user:
            return (
                f"You already have {mine} active process(es) "
                f"(limit {self.cfg.max_processes_per_user})."
            )
        return None

    # -- start ---------------------------------------------------------------
    async def start(self, user: Any, project: dict) -> tuple[bool, str, str]:
        """
        Begin a process for a project. Returns (ok, message, proc_id).
        """
        async with self._start_lock:
            if self._shutting_down:
                return False, "The bot is shutting down. Try again shortly.", ""
            err = self._limit_error()
            if err:
                return False, err, ""
            err = self._limit_error_user(user.id)
            if err:
                return False, err, ""

            ok, check_err = await asyncio.to_thread(self.backend.check)
            if not ok:
                return False, f"Execution backend unavailable: {check_err}", ""

            project_dir = self.cfg.base_dir / "users" / str(user.id) / project["id"]
            if not project_dir.exists():
                return False, "Project folder no longer exists.", ""

            proc = ActiveProcess(
                id=uuid.uuid4().hex[:12],
                user_id=user.id,
                user_name=(user.full_name or str(user.id))[:100],
                project_id=project["id"],
                project_name=project.get("name", project["id"]),
                entrypoint=project["entrypoint"],
                runtime=project["runtime"],
                project_dir=project_dir,
                venv_dir=self.cfg.base_dir / "venvs" / project["id"],
                log_path=self.cfg.base_dir / "logs" / f"{uuid.uuid4().hex[:12]}.log",
                install_log_path=self.cfg.base_dir
                / "logs"
                / f"{uuid.uuid4().hex[:12]}_install.log",
                timeout=self.cfg.execution_timeout,
            )
            self.active[proc.id] = proc
            self.store.add_process(proc.to_dict())
            log.info(
                "Starting process %s user=%s project=%s entry=%s runtime=%s",
                proc.id,
                proc.user_id,
                proc.project_id,
                proc.entrypoint,
                proc.runtime,
            )
            runner = asyncio.create_task(self._runner(proc))
            proc.tasks.append(runner)
            return True, "Process started.", proc.id

    # -- runner --------------------------------------------------------------
    async def _runner(self, proc: ActiveProcess) -> None:
        try:
            if proc.stop_requested:
                await self._finalize(proc, PROC_KILLED, None, note="stopped before start")
                return
            install = await asyncio.to_thread(self._install_or_none, proc)
            if install is not None:
                proc.install_handle = install
                proc.status = PROC_INSTALLING
                self._persist(proc)
                await asyncio.to_thread(
                    self._stream_to_log, proc, install, proc.install_log_path
                )
                code = await asyncio.to_thread(install.wait_exit)
                with contextlib.suppress(Exception):
                    await asyncio.to_thread(install.stop)
                proc.install_handle = None
                if code != 0:
                    await self._finalize(
                        proc,
                        PROC_FAILED,
                        code,
                        note="dependency install failed (see install log)",
                    )
                    return

            run_handle = await asyncio.to_thread(self.backend.run, proc)
            proc.run_handle = run_handle
            proc.container_id = run_handle.identifier
            proc.status = PROC_RUNNING
            proc.last_output_at = time.time()
            self._persist(proc)
            if proc.stop_requested:
                # a stop request raced with startup; kill immediately
                await asyncio.to_thread(self._stop_handle, proc)
            self._spawn_monitors(proc)

            await asyncio.to_thread(
                self._stream_to_log, proc, run_handle, proc.log_path
            )
            code = await asyncio.to_thread(run_handle.wait_exit)

            if proc.timed_out:
                await self._finalize(proc, PROC_TIMED_OUT, code, note="timed out")
            elif proc.stop_requested:
                await self._finalize(proc, PROC_KILLED, code, note="stopped by user")
            else:
                status = PROC_FINISHED if code == 0 else PROC_FAILED
                await self._finalize(proc, status, code)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            log.exception("Process %s crashed in runner", proc.id)
            await self._finalize(proc, PROC_FAILED, None, note=str(exc))

    def _install_or_none(self, proc: ActiveProcess) -> Optional[InstallHandle]:
        try:
            return self.backend.install(proc)
        except Exception as exc:  # noqa: BLE001
            log.exception("Install failed for %s", proc.id)
            raise RuntimeError(f"dependency install could not start: {exc}") from exc

    def _stream_to_log(
        self, proc: ActiveProcess, handle, log_path: Path
    ) -> None:
        try:
            for chunk in handle.stream():
                if chunk:
                    append_log(log_path, chunk, self.cfg.max_log_bytes)
                    proc.last_output_at = time.time()
        except Exception as exc:  # noqa: BLE001
            log.warning("Log stream ended for %s: %s", proc.id, exc)

    def _spawn_monitors(self, proc: ActiveProcess) -> None:
        for coro in (
            self._timeout_monitor(proc),
            self._input_monitor(proc),
            self._live_loop(proc),
        ):
            task = asyncio.create_task(coro)
            proc.tasks.append(task)

    def _persist(self, proc: ActiveProcess) -> None:
        self.store.update_process(proc.id, **proc.to_dict())

    # -- monitors ------------------------------------------------------------
    async def _timeout_monitor(self, proc: ActiveProcess) -> None:
        deadline = proc.started_at + proc.timeout
        while not proc.finished and time.time() < deadline:
            await asyncio.sleep(1)
        if proc.finished:
            return
        log.info("Process %s timed out after %ss", proc.id, proc.timeout)
        proc.timed_out = True
        await asyncio.to_thread(self._stop_handle, proc)

    async def _input_monitor(self, proc: ActiveProcess) -> None:
        while not proc.finished:
            await asyncio.sleep(2)
            now = time.time()
            if proc.awaiting_input:
                if (
                    proc.stdin_open
                    and now - proc.awaiting_since > self.cfg.stdin_timeout_seconds
                ):
                    log.info("Closing stdin for %s (timeout)", proc.id)
                    await asyncio.to_thread(self._close_stdin, proc)
                    await self._notify(
                        proc,
                        "No input was received in time; stdin was closed (EOF).",
                    )
            elif (
                proc.status in TERMINAL_STATUSES
                and proc.stdin_open
                and now - proc.last_output_at > self.cfg.input_wait_detect_seconds
                and now - proc.started_at > self.cfg.input_wait_detect_seconds
            ):
                proc.awaiting_input = True
                proc.awaiting_since = now
                log.info("Process %s appears to wait for input", proc.id)
                await self._notify(
                    proc,
                    "The program appears to be waiting for input. "
                    "Send your input as a normal message, or use /cancel_input. "
                    f"Timeout: {self.cfg.stdin_timeout_seconds}s.",
                )

    async def _live_loop(self, proc: ActiveProcess) -> None:
        while not proc.finished:
            await asyncio.sleep(1)
            await self._maybe_render_live(proc)
        await self._maybe_render_live(proc, force=True)

    async def _maybe_render_live(self, proc: ActiveProcess, force: bool = False) -> None:
        if not proc.live_message or self.bot is None:
            return
        now = time.time()
        if not force and now - proc.last_sent < self.cfg.live_update_seconds:
            return
        text = tail_text(proc.log_path)
        if text == proc.last_rendered and not force:
            return
        chat_id, message_id = proc.live_message
        content = self._format_log_view(proc)
        try:
            await self.bot.edit_message_text(
                chat_id=chat_id,
                message_id=message_id,
                text=content,
                parse_mode=ParseMode.HTML,
            )
            proc.last_rendered = text
            proc.last_sent = now
        except tg_error.BadRequest as exc:
            if "message is not modified" not in str(exc).lower():
                log.debug("Live log edit failed: %s", exc)
            else:
                proc.last_rendered = text
        except Exception:  # noqa: BLE001
            log.debug("Live log edit failed", exc_info=True)

    def _format_log_view(self, proc: ActiveProcess) -> str:
        status = html.escape(proc.status)
        lines = [
            f"<b>Process</b> <code>{html.escape(proc.project_name)}</code>",
            f"<b>Status</b>: {status}",
        ]
        if proc.exit_code is not None:
            lines.append(f"<b>Exit code</b>: {proc.exit_code}")
        tail = tail_text(proc.log_path)
        body = html.escape(tail) if tail else "<i>(no output yet)</i>"
        lines.append(f"<b>Output</b>:\n<pre>{body}</pre>")
        return "\n".join(lines)

    # -- stdin ---------------------------------------------------------------
    async def write_stdin(self, proc_id: str, user_id: int, text: str) -> tuple[bool, str]:
        proc = self.active.get(proc_id)
        if proc is None or proc.finished:
            return False, "Process no longer exists."
        if proc.user_id != user_id and user_id != self.cfg.owner_id:
            return False, "This process does not belong to you."
        if not proc.awaiting_input:
            return False, "This process is not waiting for input."
        try:
            await asyncio.to_thread(self._write_stdin_blocking, proc, text)
        except OSError as exc:
            proc.awaiting_input = False
            return False, str(exc)
        proc.awaiting_input = False
        return True, "Input sent."

    def _write_stdin_blocking(self, proc: ActiveProcess, text: str) -> None:
        if proc.run_handle is None:
            raise OSError("process has no stdin")
        proc.run_handle.write_stdin((text.rstrip("\n") + "\n").encode("utf-8", "replace"))

    def _close_stdin(self, proc: ActiveProcess) -> None:
        if proc.run_handle is not None:
            proc.run_handle.close_stdin()
        proc.stdin_open = False

    # -- stop ---------------------------------------------------------------
    async def stop(self, proc_id: str, actor_id: int) -> tuple[bool, str]:
        proc = self.active.get(proc_id)
        if proc is None:
            return False, "Process not found or already finished."
        if actor_id != self.cfg.owner_id and actor_id != proc.user_id:
            return False, "You can only stop your own processes."
        if proc.finished:
            return False, "Process already finished."
        log.info("Stopping process %s (by user %s)", proc_id, actor_id)
        proc.stop_requested = True
        await asyncio.to_thread(self._stop_handle, proc)
        return True, "Stop requested."

    def _stop_handle(self, proc: ActiveProcess) -> None:
        if proc.run_handle is not None:
            proc.run_handle.stop()
        else:
            # may be in install phase
            with contextlib.suppress(Exception):
                if proc.install_handle is not None:
                    proc.install_handle.stop()

    # -- finalize ------------------------------------------------------------
    async def _finalize(
        self,
        proc: ActiveProcess,
        status: str,
        exit_code: Optional[int],
        note: Optional[str] = None,
    ) -> None:
        if proc.finished:
            return
        proc.finished = True
        proc.status = status
        proc.ended_at = time.time()
        proc.exit_code = exit_code
        proc.note = note
        self._close_stdin(proc)
        with contextlib.suppress(Exception):
            self._stop_handle(proc)

        for task in list(proc.tasks):
            if task is not asyncio.current_task():
                task.cancel()
        proc.tasks.clear()

        self.active.pop(proc.id, None)
        self._persist(proc)
        await self._maybe_render_live(proc, force=True)
        log.info(
            "Process %s finalized: status=%s exit=%s note=%s",
            proc.id,
            status,
            exit_code,
            note,
        )

    # -- notifications to the owning user ------------------------------------
    async def _notify(self, proc: ActiveProcess, text: str) -> None:
        if self.bot is None:
            return
        try:
            await self.bot.send_message(chat_id=proc.user_id, text=text)
        except Exception:  # noqa: BLE001
            log.warning("Could not notify user %s", proc.user_id, exc_info=True)

    # -- shutdown ------------------------------------------------------------
    async def shutdown(self) -> None:
        log.info("Shutting down process manager")
        self._shutting_down = True
        procs = list(self.active.values())
        for proc in procs:
            proc.stop_requested = True
            proc.timed_out = False
            await asyncio.to_thread(self._stop_handle, proc)
        for proc in procs:
            if proc.run_handle is not None:
                await asyncio.to_thread(self._finalize, proc, PROC_KILLED, None, "shutdown")
        self._shutting_down = False


# ---------------------------------------------------------------------------
# 8. Restricted terminal
# ---------------------------------------------------------------------------
class RestrictedTerminal:
    """Allowlisted command executor restricted to one user workspace."""

    ALLOWED = {"pwd", "ls", "cd", "cat", "head", "tail", "mkdir", "cp", "mv", "rm"}
    FORBIDDEN_CHARS = set(";&|<>`$\n\r")

    # simple flag allowlist per command
    FLAGS = {
        "ls": {"-l", "-a", "-h", "-la", "-al", "-lh", "-lha", "-hal"},
        "rm": {"-r", "-f", "-rf", "-fr"},
        "cp": {"-r"},
        "mkdir": {"-p"},
        "head": {"-n"},
        "tail": {"-n"},
    }

    def __init__(self, workspace: Path, timeout: int) -> None:
        self.workspace = workspace.resolve()
        self.timeout = timeout

    def _validate(self, command: str, cwd: Path) -> list[str]:
        if any(ch in command for ch in self.FORBIDDEN_CHARS):
            raise ValueError("Shell operators are not allowed.")
        try:
            tokens = shlex.split(command)
        except ValueError as exc:
            raise ValueError(f"Could not parse command: {exc}") from exc
        if not tokens:
            raise ValueError("Empty command.")
        name = tokens[0]
        if name not in self.ALLOWED:
            raise ValueError(f"Command '{name}' is not allowed.")

        allowed_flags = self.FLAGS.get(name, set())
        args: list[str] = []
        for tok in tokens[1:]:
            if tok.startswith("-"):
                if tok not in allowed_flags:
                    raise ValueError(f"Flag '{tok}' is not allowed for '{name}'.")
            else:
                args.append(tok)

        if name == "cd":
            if len(args) > 1:
                raise ValueError("cd accepts at most one argument.")
            return [name, *args]

        # validate every path argument stays inside the workspace
        for arg in args:
            candidate = Path(os.path.normpath(os.path.join(str(cwd), arg)))
            if not is_within(self.workspace, candidate):
                raise ValueError(f"Path '{arg}' escapes the workspace.")
            if name == "rm" and candidate.resolve() == self.workspace.resolve():
                raise ValueError("You cannot delete your workspace root.")

        return [name, *args]

    def run(self, cwd: Path, command: str) -> tuple[str, Optional[Path]]:
        """Execute a restricted command. Returns (text_output, new_cwd_or_None)."""
        argv = self._validate(command, cwd)
        name = argv[0]

        if name == "cd":
            target = cwd
            if len(argv) > 1:
                target = Path(
                    os.path.normpath(os.path.join(str(cwd), argv[1]))
                )
            target = Path(os.path.normpath(str(target)))
            if not is_within(self.workspace, target):
                target = self.workspace
            if not target.exists():
                return f"cd: no such directory: {argv[1]}", None
            return f"cwd -> {target}", target

        if name == "pwd":
            return str(cwd), None

        try:
            result = subprocess.run(
                argv,
                cwd=str(cwd),
                capture_output=True,
                timeout=self.timeout,
                text=True,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return f"Command timed out after {self.timeout}s.", None
        except OSError as exc:
            return f"Command failed to start: {exc}", None

        out = (result.stdout or "") + (result.stderr or "")
        if not out.strip():
            out = f"(no output, exit code {result.returncode})"
        return out.rstrip(), None


# ---------------------------------------------------------------------------
# Telegram UI helpers
# ---------------------------------------------------------------------------
def btn(text: str, data: str) -> InlineKeyboardButton:
    return InlineKeyboardButton(text, callback_data=data)


def row(*buttons: InlineKeyboardButton) -> list[InlineKeyboardButton]:
    return list(buttons)


def main_menu_markup(is_owner: bool) -> InlineKeyboardMarkup:
    keys = [
        row(btn("⌨️ Terminal", "ui:term"), btn("📤 Upload Script", "ui:upload")),
        row(btn("⏹️ Stop Tasks", "ui:stop"), btn("📂 Workspace", "my:0")),
        row(btn("📜 View Logs", "plist:0"), btn("🖥 Running", "running:0")),
        row(btn("⚡ Server Health", "health")),
    ]
    if is_owner:
        keys.append(row(btn("👑 Admin Dashboard", "admin:home")))
    return InlineKeyboardMarkup(keys)


def _back_home_markup(is_owner: bool) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[btn("⬅ Back", "menu")]])


def esc(text: Any) -> str:
    return html.escape(str(text))


# ---------------------------------------------------------------------------
# Telegram handlers
# ---------------------------------------------------------------------------
async def _owner_menu(update: Update, context: ContextTypes.DEFAULT_TYPE, text: str) -> None:
    user = update.effective_user
    is_owner = user is not None and user.id == _cfg(context).owner_id
    await update.effective_message.reply_text(
        text, reply_markup=main_menu_markup(is_owner), parse_mode=ParseMode.HTML
    )


def _cfg(context: ContextTypes.DEFAULT_TYPE) -> Config:
    return context.bot_data["cfg"]


def _store(context: ContextTypes.DEFAULT_TYPE) -> DataStore:
    return context.bot_data["store"]


def _manager(context: ContextTypes.DEFAULT_TYPE) -> ProcessManager:
    return context.bot_data["manager"]


def _workspace(user_id: int) -> Path:
    return _BASE_DIR / "users" / str(user_id)


_BASE_DIR: Path = Path(".").resolve()


async def _is_member(context: ContextTypes.DEFAULT_TYPE, user_id: int) -> bool:
    cfg = _cfg(context)
    if not cfg.channel_username:
        return True
    try:
        member = await context.bot.get_chat_member(cfg.channel_username, user_id)
        return member.status in {"member", "administrator", "creator"}
    except Exception:  # noqa: BLE001
        log.warning("Channel membership check failed for %s", user_id, exc_info=True)
        return False


async def _require_approved(update: Update, context: ContextTypes.DEFAULT_TYPE) -> Optional[dict]:
    """Return the user record if the user may use the bot, else reply and return None."""
    user = update.effective_user
    if user is None:
        return None
    cfg = _cfg(context)
    store = _store(context)
    record = store.get_user(user.id)
    if user.id == cfg.owner_id:
        return store.ensure_user(user)
    if record is None or record.get("status") == USER_PENDING:
        await update.effective_message.reply_text(
            "Your access request is pending admin approval."
        )
        return None
    if record.get("status") == USER_BANNED:
        await update.effective_message.reply_text(
            "You are banned from using this bot."
        )
        return None
    return record


def _fmt_ts(ts: Optional[float]) -> str:
    if not ts:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def _safe_int(s: str) -> Optional[int]:
    try:
        return int(s)
    except (TypeError, ValueError):
        return None


# ---- /start ---------------------------------------------------------------
async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    if user is None:
        return
    cfg = _cfg(context)
    store = _store(context)
    record = store.ensure_user(user)

    if user.id == cfg.owner_id:
        await _owner_menu(
            update, context,
            f"✨ Welcome back, <b>{esc(user.full_name)}</b>! You are the owner.\n"
            "🟢 ONLINE 24/7",
        )
        return

    if record.get("status") == USER_BANNED:
        await update.effective_message.reply_text("You are banned from using this bot.")
        return

    if not await _is_member(context, user.id):
        channel = cfg.channel_username.lstrip("@")
        keys = [
            [
                btn(f"📢 Channel", f"https://t.me/{channel}"),
                btn("✅ I Joined — Check", "join"),
            ]
        ]
        await update.effective_message.reply_text(
            f"To use this bot you must join our channel:\n"
            f"@{esc(channel)}\n\n"
            f"Tap <b>I Joined</b> after joining.",
            reply_markup=InlineKeyboardMarkup(keys),
            parse_mode=ParseMode.HTML,
        )
        return

    if record.get("status") == USER_APPROVED:
        await _owner_menu(
            update, context,
            f"✨ Welcome, <b>{esc(user.full_name)}</b>!\n"
            "🟢 ONLINE 24/7\n"
            "Upload a <code>.py</code> / <code>.js</code> / <code>.zip</code> "
            "project, then run it.",
        )
        return

    # new user: request access
    await _request_access(update, context, user, record)


async def _request_access(update: Update, context: ContextTypes.DEFAULT_TYPE, user, record: dict) -> None:
    cfg = _cfg(context)
    store = _store(context)
    store.set_user_status(user.id, USER_PENDING)
    # Notify the owner only once per pending lifecycle to avoid duplicate spam.
    if record.get("request_message") is None:
        keys = [
            [
                btn("✅ Approve", f"approve:{user.id}"),
                btn("🚫 Ban", f"ban:{user.id}"),
            ]
        ]
        text = (
            f"<b>New access request</b>\n"
            f"Name: <code>{esc(user.full_name)}</code>\n"
            f"Username: @{esc(user.username or '-')}\n"
            f"ID: <code>{user.id}</code>\n"
            f"Time: {_fmt_ts(time.time())}"
        )
        try:
            msg = await context.bot.send_message(
                cfg.owner_id,
                text,
                reply_markup=InlineKeyboardMarkup(keys),
                parse_mode=ParseMode.HTML,
            )
            store.set_request_message(user.id, cfg.owner_id, msg.message_id)
        except Exception:  # noqa: BLE001
            log.warning("Could not notify owner about access request", exc_info=True)
    await update.effective_message.reply_text(
        "Your request has been sent to the admin for approval. "
        "You will be notified when approved."
    )


# ---- /help -----------------------------------------------------------------
async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (
        "<b>How to use</b>\n"
        "1. Send a <code>.py</code>, <code>.js</code> or <code>.zip</code> file "
        "(zip may contain a full project with <code>main.py</code>/<code>index.js</code> "
        "and <code>requirements.txt</code>/<code>package.json</code>).\n"
        "2. Dependencies are installed automatically in the sandbox.\n"
        "3. Run it from the menu and watch live output.\n\n"
        "<b>Commands</b>\n"
        "/start — main menu\n"
        "/run — run your latest project\n"
        "/stats — owner-only bot statistics\n"
        "/cancel_input — cancel a waiting-for-input prompt\n"
        "/exit_term — leave terminal mode\n"
        "/help — this help"
    )
    await update.effective_message.reply_text(text, parse_mode=ParseMode.HTML)


# ---- callback routing ------------------------------------------------------
async def on_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if query is None:
        return
    await query.answer()
    user = query.from_user
    if user is None:
        return
    data = query.data or ""
    verb, sep, payload = data.partition(":")

    cfg = _cfg(context)
    store = _store(context)

    if verb == "join":
        await _cb_join(update, context)
        return
    if verb == "menu":
        await _owner_menu(update, context, "Main menu.")
        return

    # admin-only zone
    admin_verbs = {"admin", "approve", "ban", "unban", "astop", "aprofile"}
    if verb in admin_verbs:
        if user.id != cfg.owner_id:
            await _safe_edit(
                context, query,
                "You are not authorized to use the admin panel.",
                None,
            )
            return
        await _cb_admin(update, context, verb, payload)
        return

    # normal-user zone (channel gate + approval)
    if user.id != cfg.owner_id:
        if not await _is_member(context, user.id):
            await _safe_edit(
                context, query,
                "You must join the channel first. Use /start.",
                None,
            )
            return
        record = store.get_user(user.id)
        if record is None or record.get("status") != USER_APPROVED:
            await _safe_edit(context, query, "Your access is pending or revoked.", None)
            return

    if verb == "ui":
        await _cb_ui(update, context, payload)
        return
    if verb == "run":
        await _cb_run(update, context, payload)
        return
    if verb == "my":
        await _cb_my_scripts(update, context, payload)
        return
    if verb == "dl":
        await _cb_delete_project(update, context, payload)
        return
    if verb == "plist":
        await _cb_process_list(update, context, payload)
        return
    if verb == "plog":
        await _cb_view_log(update, context, payload)
        return
    if verb == "stop":
        await _cb_stop(update, context, payload)
        return
    if verb == "running":
        await _cb_running(update, context, payload)
        return
    if verb == "health":
        await _cb_health(update, context)
        return

    await _safe_edit(context, query, "Unknown action.", None)


async def _cb_join(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    user = update.effective_user
    if query is None or user is None:
        return
    cfg = _cfg(context)
    store = _store(context)
    store.ensure_user(user)

    if not await _is_member(context, user.id):
        channel = cfg.channel_username.lstrip("@")
        keys = [
            [btn("📢 Channel", f"https://t.me/{channel}"),
             btn("✅ I Joined — Check", "join")]
        ]
        await _safe_edit(
            context, query,
            f"Still not a member. Please join @{esc(channel)} first.",
            InlineKeyboardMarkup(keys),
        )
        return

    record = store.get_user(user.id) or {}
    if record.get("status") == USER_BANNED:
        await _safe_edit(context, query, "You are banned.", None)
        return

    if user.id == cfg.owner_id:
        await _owner_menu(update, context, "Welcome, owner!")
        return

    if record.get("status") == USER_APPROVED:
        await _owner_menu(update, context, "Verified!")
        return

    # pending or brand-new member: submit an admin access request
    await _request_access(update, context, user, record)
    await _safe_edit(
        context, query,
        "Membership verified. Your access request has been submitted to the admin.",
        None,
    )


async def _cb_ui(update: Update, context: ContextTypes.DEFAULT_TYPE, payload: str) -> None:
    query = update.callback_query
    if query is None:
        return
    user = update.effective_user
    if user is None:
        return
    if payload == "term":
        context.user_data["term_mode"] = True
        await _safe_edit(
            context, query,
            "⌨️ <b>Terminal mode is ON</b>.\n\nAllowed: <code>pwd ls cd cat head tail mkdir "
            "cp mv rm</code>\nNo shell operators/pipes.\n\nSend a command, or /exit_term.",
            _back_home_markup(user.id == _cfg(context).owner_id),
        )
    elif payload == "upload":
        await _safe_edit(
            context, query,
            "📤 Send me a <code>.py</code>, <code>.js</code> or <code>.zip</code> file. "
            "Max <code>" + str(_cfg(context).max_upload_mb) + " MB</code>.",
            _back_home_markup(user.id == _cfg(context).owner_id),
        )
    elif payload == "stop":
        await _cb_process_list(update, context, "0", header="running")


async def _cb_run(update: Update, context: ContextTypes.DEFAULT_TYPE, payload: str) -> None:
    query = update.callback_query
    user = update.effective_user
    if query is None or user is None:
        return
    store = _store(context)
    project = store.get_project(user.id, payload)
    if not project:
        await _safe_edit(context, query, "Project not found.", None)
        return
    manager = _manager(context)
    ok, msg, proc_id = await manager.start(user, project)
    await _safe_edit(context, query, msg, None)
    if ok:
        proc = manager.active.get(proc_id)
        if proc is not None:
            proc.live_message = (user.id, query.message.message_id)
        await _maybe_render_live_soon(manager, proc_id)


async def _maybe_render_live_soon(manager: ProcessManager, proc_id: str) -> None:
    proc = manager.active.get(proc_id)
    if proc is not None:
        task = asyncio.create_task(proc_awaiter(manager, proc))
        proc.tasks.append(task)


async def proc_awaiter(manager: ProcessManager, proc) -> None:
    await asyncio.sleep(1)
    await manager._maybe_render_live(proc, force=True)


async def _cb_my_scripts(update: Update, context: ContextTypes.DEFAULT_TYPE, payload: str) -> None:
    query = update.callback_query
    user = update.effective_user
    if query is None or user is None:
        return
    store = _store(context)
    projects = store.projects_for(user.id)
    if not projects:
        await _safe_edit(
            context, query,
            "📂 You have no scripts yet. Upload a <code>.py</code>/<code>.js</code>/<code>.zip</code>.",
            _back_home_markup(user.id == _cfg(context).owner_id),
        )
        return
    keys = []
    for p in projects[:12]:
        label = f"{p.get('name', p['id'])}  [{p['runtime']}]"
        keys.append(row(btn(label, f"run:{p['id']}"), btn("Del", f"dl:{p['id']}")))
    keys.append([btn("⬅ Back", "menu")])
    await _safe_edit(
        context, query,
        "📂 <b>Workspace</b> — your scripts; tap one to run it.",
        InlineKeyboardMarkup(keys),
    )


async def _cb_delete_project(update: Update, context: ContextTypes.DEFAULT_TYPE, payload: str) -> None:
    query = update.callback_query
    user = update.effective_user
    if query is None or user is None:
        return
    cfg = _cfg(context)
    store = _store(context)
    removed = store.remove_project(user.id, payload)
    if removed:
        project_dir = cfg.base_dir / "users" / str(user.id) / payload
        venv_dir = cfg.base_dir / "venvs" / payload
        with contextlib.suppress(OSError):
            shutil.rmtree(project_dir, ignore_errors=True)
        with contextlib.suppress(OSError):
            shutil.rmtree(venv_dir, ignore_errors=True)
        await _safe_edit(context, query, "Script deleted.", _back_home_markup(user.id == cfg.owner_id))
    else:
        await _safe_edit(context, query, "Script not found.", None)


async def _cb_process_list(
    update: Update, context: ContextTypes.DEFAULT_TYPE, payload: str,
    header: str = "",
) -> None:
    query = update.callback_query
    user = update.effective_user
    if query is None or user is None:
        return
    store = _store(context)
    cfg = _cfg(context)
    procs = store.processes_for(user.id)
    if not procs:
        await _safe_edit(
            context, query,
            "📜 No processes yet.",
            _back_home_markup(user.id == cfg.owner_id),
        )
        return
    keys = []
    for p in procs[:15]:
        label = (
            f"{p.get('status')} | {p.get('project_name', '?')} "
            f"({p.get('exit_code', '-')})"
        )
        keys.append(row(btn(label, f"plog:{p['id']}")))
    if header == "running":
        keys.append([btn("⏹️ Stop running", f"running:{user.id}")])
    keys.append([btn("⬅ Back", "menu")])
    await _safe_edit(
        context, query,
        f"📜 <b>Your processes</b>\n{header or ''}",
        InlineKeyboardMarkup(keys),
    )


async def _cb_view_log(update: Update, context: ContextTypes.DEFAULT_TYPE, payload: str) -> None:
    query = update.callback_query
    user = update.effective_user
    if query is None or user is None:
        return
    store = _store(context)
    cfg = _cfg(context)
    manager = _manager(context)
    proc_rec = next((p for p in store.processes_for(user.id) if p["id"] == payload), None)
    if not proc_rec:
        await _safe_edit(context, query, "Process not found.", None)
        return

    active = manager.active.get(payload)
    if active is not None:
        active.live_message = (user.id, query.message.message_id)
        await manager._maybe_render_live(active, force=True)
        return

    lines = [
        f"<b>Process</b> <code>{esc(proc_rec.get('project_name'))}</code>",
        f"<b>Status</b>: {esc(proc_rec.get('status'))}",
        f"<b>Exit code</b>: {proc_rec.get('exit_code') if proc_rec.get('exit_code') is not None else '-'}",
        f"<b>Started</b>: {_fmt_ts(proc_rec.get('started_at'))}",
        f"<b>Ended</b>: {_fmt_ts(proc_rec.get('ended_at'))}",
    ]
    note = proc_rec.get("note")
    if note:
        lines.append(f"<b>Note</b>: {esc(note)}")
    log_path = Path(proc_rec.get("log_path") or "")
    tail = tail_text(log_path)
    body = esc(tail) if tail else "<i>(no output)</i>"
    lines.append(f"<b>Output</b>:\n<pre>{body}</pre>")
    keys = []
    if proc_rec.get("status") in RUNNING_STATUSES:
        keys.append(row(btn("⏹️ Stop", f"stop:{payload}")))
    keys.append([btn("⬅ Back", "plist:0")])
    await _safe_edit(context, query, "\n".join(lines), InlineKeyboardMarkup(keys))


async def _cb_stop(update: Update, context: ContextTypes.DEFAULT_TYPE, payload: str) -> None:
    query = update.callback_query
    user = update.effective_user
    if query is None or user is None:
        return
    manager = _manager(context)
    ok, msg = await manager.stop(payload, user.id)
    await _safe_edit(context, query, msg, None)


async def _cb_running(update: Update, context: ContextTypes.DEFAULT_TYPE, payload: str) -> None:
    query = update.callback_query
    user = update.effective_user
    if query is None or user is None:
        return
    manager = _manager(context)
    cfg = _cfg(context)
    procs = [
        p for p in manager.active.values()
        if p.user_id == user.id and not p.finished
    ]
    if not procs:
        await _safe_edit(
            context, query,
            "Nothing is running.",
            _back_home_markup(user.id == cfg.owner_id),
        )
        return
    keys = []
    for p in procs:
        keys.append(row(btn(f"⏹️ {p.project_name} ({p.id})", f"stop:{p.id}")))
    keys.append([btn("⬅ Back", "menu")])
    await _safe_edit(context, query, "🖥 <b>Running processes</b>:", InlineKeyboardMarkup(keys))


async def _cb_health(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    user = update.effective_user
    if query is None or user is None:
        return
    cfg = _cfg(context)
    manager = _manager(context)
    health = _system_health(manager)
    mem = psutil.virtual_memory()
    uptime = int(health["uptime_seconds"])
    lines = [
        "⚡ <b>Server Health</b>",
        f"🟢 Status: <b>{health['status'].upper()}</b> — ONLINE 24/7",
        f"⏱ Uptime: {uptime // 3600}h {uptime % 3600 // 60}m",
        f"📦 Active processes: {health['active_processes']}",
        f"🧠 CPU: {health['cpu_percent']:.1f}%",
        f"💾 RAM: {health['ram_percent']:.1f}% "
        f"({human_size(mem.used)} / {human_size(mem.total)})",
    ]
    await _safe_edit(context, query, "\n".join(lines), _back_home_markup(user.id == cfg.owner_id))


# ---- admin callbacks -------------------------------------------------------
async def _cb_admin(
    update: Update, context: ContextTypes.DEFAULT_TYPE, verb: str, payload: str
) -> None:
    query = update.callback_query
    if query is None:
        return
    cfg = _cfg(context)
    store = _store(context)
    manager = _manager(context)

    if verb == "approve":
        uid = _safe_int(payload)
        if uid is None:
            await _safe_edit(context, query, "Invalid request.", None)
            return
        store.set_user_status(uid, USER_APPROVED)
        await _notify_user(context, uid, "✅ Your access request was approved! Send /start.")
        await _refresh_request_message(context, store, uid, "approved")
        await _safe_edit(context, query, f"Approved user {uid}.", None)
        return
    if verb == "ban":
        uid = _safe_int(payload)
        if uid is None:
            await _safe_edit(context, query, "Invalid request.", None)
            return
        store.set_user_status(uid, USER_BANNED)
        await _notify_user(context, uid, "You have been banned from this bot.")
        await _refresh_request_message(context, store, uid, "banned")
        await _safe_edit(context, query, f"Banned user {uid}.", None)
        return
    if verb == "unban":
        uid = _safe_int(payload)
        if uid is None:
            await _safe_edit(context, query, "Invalid request.", None)
            return
        store.set_user_status(uid, USER_PENDING)
        await _refresh_request_message(context, store, uid, "unbanned")
        await _safe_edit(context, query, f"Unbanned user {uid} (pending re-approval).", None)
        return
    if verb == "astop":
        ok, msg = await manager.stop(payload, cfg.owner_id)
        await _safe_edit(context, query, msg, None)
        return

    if verb == "admin":
        if payload == "home":
            keys = [
                row(btn("👥 User List", "alist:0")),
                row(btn("⏳ Pending Requests", "apending"), btn("🖥 Running", "arunning")),
                row(btn("📊 Statistics", "astats"), btn("🚫 Banned", "abanned")),
                row(btn("⬅ Back", "menu")),
            ]
            await _safe_edit(
                context, query, "👑 Admin Dashboard", InlineKeyboardMarkup(keys)
            )
            return
        await _safe_edit(context, query, "Unknown admin action.", None)
        return

    if verb == "alist":
        users = store.all_users()
        page = _safe_int(payload) or 0
        page = max(0, page)
        size = 8
        start = page * size
        chunk = users[start:start + size]
        lines = [f"<b>Users ({len(users)})</b>"]
        keys = []
        for u in chunk:
            st = u.get("status", "?")
            keys.append(
                row(
                    btn(
                        f"{st} | {esc(u.get('full_name') or u.get('id'))}",
                        f"aprofile:{u.get('id')}",
                    )
                )
            )
        nav = []
        if start > 0:
            nav.append(btn("⬅", f"alist:{page - 1}"))
        if start + size < len(users):
            nav.append(btn("➡", f"alist:{page + 1}"))
        if nav:
            keys.append(nav)
        keys.append([btn("⬅ Back", "admin:home")])
        await _safe_edit(context, query, "\n".join(lines), InlineKeyboardMarkup(keys))
        return

    if verb == "aprofile":
        uid = _safe_int(payload)
        if uid is None:
            await _safe_edit(context, query, "Invalid request.", None)
            return
        u = store.get_user(uid)
        if not u:
            await _safe_edit(context, query, "User not found.", None)
            return
        keys = []
        if u.get("status") == USER_PENDING:
            keys.append(row(btn("✅ Approve", f"approve:{uid}"), btn("🚫 Ban", f"ban:{uid}")))
        elif u.get("status") == USER_APPROVED:
            keys.append(row(btn("🚫 Ban", f"ban:{uid}")))
        elif u.get("status") == USER_BANNED:
            keys.append(row(btn("♻ Unban", f"unban:{uid}")))
        keys.append([btn("⬅ Back", "alist:0")])
        lines = [
            f"<b>{esc(u.get('full_name'))}</b>",
            f"Username: @{esc(u.get('username') or '-')}",
            f"ID: <code>{uid}</code>",
            f"Status: <code>{u.get('status')}</code>",
            f"First seen: {_fmt_ts(u.get('first_seen'))}",
            f"Last active: {_fmt_ts(u.get('last_active'))}",
        ]
        await _safe_edit(context, query, "\n".join(lines), InlineKeyboardMarkup(keys))
        return

    if verb == "apending":
        users = store.users_with_status(USER_PENDING)
        if not users:
            await _safe_edit(context, query, "No pending requests.", _back_home_markup(True))
            return
        keys = []
        for u in users[:15]:
            keys.append(
                row(
                    btn(
                        f"{esc(u.get('full_name') or u.get('id'))} ({u.get('id')})",
                        f"aprofile:{u.get('id')}",
                    )
                )
            )
        keys.append([btn("⬅ Back", "admin:home")])
        await _safe_edit(context, query, f"<b>Pending ({len(users)})</b>", InlineKeyboardMarkup(keys))
        return

    if verb == "abanned":
        users = store.users_with_status(USER_BANNED)
        if not users:
            await _safe_edit(context, query, "No banned users.", _back_home_markup(True))
            return
        keys = []
        for u in users[:15]:
            keys.append(
                row(
                    btn(f"♻ {esc(u.get('full_name') or u.get('id'))} ({u.get('id')})", f"unban:{u.get('id')}"),
                )
            )
        keys.append([btn("⬅ Back", "admin:home")])
        await _safe_edit(context, query, f"<b>Banned ({len(users)})</b>", InlineKeyboardMarkup(keys))
        return

    if verb == "arunning":
        procs = [p for p in manager.active.values() if not p.finished]
        if not procs:
            await _safe_edit(context, query, "No running processes.", _back_home_markup(True))
            return
        keys = []
        for p in procs[:15]:
            keys.append(
                row(
                    btn(
                        f"🛑 {esc(p.project_name)} | user {p.user_id} | {p.status}",
                        f"astop:{p.id}",
                    )
                )
            )
        keys.append([btn("⬅ Back", "admin:home")])
        await _safe_edit(context, query, f"<b>Running ({len(procs)})</b>", InlineKeyboardMarkup(keys))
        return

    if verb == "astats":
        users = store.all_users()
        running = sum(1 for p in manager.active.values() if not p.finished)
        procs = store.all_processes()
        lines = [
            "<b>Statistics</b>",
            f"Total users: {len(users)}",
            f"Approved: {len(store.users_with_status(USER_APPROVED))}",
            f"Pending: {len(store.users_with_status(USER_PENDING))}",
            f"Banned: {len(store.users_with_status(USER_BANNED))}",
            f"Running now: {running}",
            f"Total recorded processes: {len(procs)}",
        ]
        keys = [[btn("⬅ Back", "admin:home")]]
        await _safe_edit(context, query, "\n".join(lines), InlineKeyboardMarkup(keys))
        return

    await _safe_edit(context, query, "Unknown action.", None)


async def _notify_user(context: ContextTypes.DEFAULT_TYPE, uid: int, text: str) -> None:
    try:
        await context.bot.send_message(uid, text)
    except Exception:  # noqa: BLE001
        log.warning("Could not message user %s", uid, exc_info=True)


async def _refresh_request_message(
    context: ContextTypes.DEFAULT_TYPE, store: DataStore, uid: int, outcome: str
) -> None:
    rec = store.get_user(uid)
    if not rec or not rec.get("request_message"):
        return
    rm = rec["request_message"]
    store.clear_request_message(uid)
    try:
        await context.bot.edit_message_text(
            chat_id=rm["chat_id"],
            message_id=rm["message_id"],
            text=f"Access request from <code>{uid}</code> — <b>{outcome}</b>.",
            parse_mode=ParseMode.HTML,
        )
    except Exception:  # noqa: BLE001
        log.debug("Could not edit old request message", exc_info=True)


# ---- text handler (terminal / stdin / messages) ----------------------------
async def on_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    message = update.effective_message
    if user is None or message is None or not message.text:
        return
    cfg = _cfg(context)
    store = _store(context)
    store.ensure_user(user)
    if user.id != cfg.owner_id:
        record = store.get_user(user.id) or {}
        if record.get("status") != USER_APPROVED:
            await message.reply_text(
                "Your access is pending or revoked. Use /start to check your status."
            )
            return

    manager = _manager(context)

    # 1) stdin forwarding: active process of this user waiting for input
    awaiting = [
        p for p in manager.active.values()
        if p.user_id == user.id and p.awaiting_input and not p.finished
    ]
    if awaiting:
        proc = awaiting[0]
        ok, msg = await manager.write_stdin(proc.id, user.id, message.text)
        await message.reply_text(msg)
        return

    # 2) terminal mode
    if context.user_data.get("term_mode"):
        term = context.bot_data.get("term_engines", {}).get(user.id)
        if term is None:
            term = RestrictedTerminal(_workspace(user.id), cfg.terminal_timeout)
            context.bot_data.setdefault("term_engines", {})[user.id] = term
        cwd = Path(context.user_data.get("term_cwd") or str(_workspace(user.id)))
        cwd.mkdir(parents=True, exist_ok=True)
        try:
            out, new_cwd = term.run(cwd, message.text)
        except ValueError as exc:
            await message.reply_text(f"<b>Rejected</b>: {esc(exc)}", parse_mode=ParseMode.HTML)
            return
        if new_cwd is not None:
            context.user_data["term_cwd"] = str(new_cwd)
        body = esc(out)
        if len(body) > 3500:
            body = body[-3500:]
        await message.reply_text(f"<pre>{body}</pre>", parse_mode=ParseMode.HTML)
        return

    # 3) fallback help
    await message.reply_text(
        "Send me a file to upload a script, or use /start for the menu."
    )


def _prepare_zip_project(tmp: Path, project_dir: Path, cfg: Config) -> tuple[str, str, list[str]]:
    count = safe_extract_zip(tmp, project_dir, cfg)
    tmp.unlink(missing_ok=True)
    entrypoint, runtime = detect_entrypoint(project_dir)
    return entrypoint, runtime, scan_project_files(project_dir)


# ---- file upload handler ---------------------------------------------------
async def on_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    message = update.effective_message
    if user is None or message is None or message.document is None:
        return
    cfg = _cfg(context)
    store = _store(context)

    if user.id != cfg.owner_id:
        record = store.get_user(user.id) or {}
        if record.get("status") != USER_APPROVED:
            await message.reply_text("Your access is pending or revoked.")
            return
        if not await _is_member(context, user.id):
            await message.reply_text("You must join the channel first. Use /start.")
            return

    doc = message.document
    filename = doc.file_name or "upload"
    try:
        ext = validate_file_extension(filename)
    except ValueError as exc:
        await message.reply_text(str(exc))
        return

    if doc.file_size and doc.file_size > cfg.max_upload_bytes:
        await message.reply_text(
            f"File too large: {human_size(doc.file_size)} (max {cfg.max_upload_mb} MB)."
        )
        return

    projects = store.projects_for(user.id)
    if len(projects) >= cfg.max_projects_per_user:
        await message.reply_text(
            f"Project limit reached ({cfg.max_projects_per_user}). Delete a script first."
        )
        return

    project_id = uuid.uuid4().hex[:12]
    project_dir = cfg.base_dir / "users" / str(user.id) / project_id
    project_dir.mkdir(parents=True, exist_ok=True)
    safe_name = sanitize_filename(filename)
    dest = project_dir / safe_name

    try:
        tmp = project_dir / f".tmp_{project_id}"
        file = await context.bot.get_file(doc.file_id)
        await file.download_to_drive(tmp)
        if tmp.stat().st_size > cfg.max_upload_bytes:
            raise ValueError(
                f"File too large: {human_size(tmp.stat().st_size)} (max {cfg.max_upload_mb} MB)."
            )

        if ext == ".zip":
            if tmp.stat().st_size > cfg.max_archive_bytes:
                raise ValueError(
                    f"Archive too large: {human_size(tmp.stat().st_size)} (max {cfg.max_archive_mb} MB)."
                )
            entrypoint, runtime, files = await asyncio.to_thread(
                _prepare_zip_project, tmp, project_dir, cfg
            )
            log.info("Extracted %s files for project %s (user %s)", len(files), project_id, user.id)
        else:
            shutil.move(str(tmp), str(dest))
            entrypoint, runtime = detect_entrypoint(project_dir)
            files = scan_project_files(project_dir)
    except Exception as exc:  # noqa: BLE001
        log.warning("Upload rejected for user %s: %s", user.id, exc)
        shutil.rmtree(project_dir, ignore_errors=True)
        await message.reply_text(f"Upload rejected: {esc(exc)}", parse_mode=ParseMode.HTML)
        return

    has_req = (project_dir / "requirements.txt").exists()
    has_pkg = (project_dir / "package.json").exists()
    project = {
        "id": project_id,
        "name": safe_name if ext != ".zip" else f"{safe_name} ({project_id[:6]})",
        "entrypoint": entrypoint,
        "runtime": runtime,
        "uploaded_at": time.time(),
        "files": files,
        "has_requirements": has_req,
        "has_package_json": has_pkg,
    }
    store.add_project(user.id, project)

    dep_note = ""
    if has_req:
        dep_note = "\nDependencies from <code>requirements.txt</code> will be installed automatically."
    elif has_pkg:
        dep_note = "\nDependencies from <code>package.json</code> will be installed automatically."

    keys = [[btn("▶ Run", f"run:{project_id}"), btn("📂 Workspace", "my:0")]]
    await message.reply_text(
        f"Uploaded <code>{esc(safe_name)}</code>\n"
        f"Entrypoint: <code>{esc(entrypoint)}</code> ({runtime}){dep_note}",
        reply_markup=InlineKeyboardMarkup(keys),
        parse_mode=ParseMode.HTML,
    )


# ---- commands: /run, /stats, /exit_term, /cancel_input ----------------------
async def cmd_run(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    message = update.effective_message
    if user is None or message is None:
        return
    record = await _require_approved(update, context)
    if record is None:
        return
    store = _store(context)
    projects = store.projects_for(user.id)
    if not projects:
        await message.reply_text("No scripts uploaded yet.")
        return
    project = projects[0]
    manager = _manager(context)
    ok, msg, proc_id = await manager.start(user, project)
    await message.reply_text(msg)


async def cmd_stats(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Owner-only /stats: user & process counts read from the persisted state."""
    user = update.effective_user
    message = update.effective_message
    if user is None or message is None:
        return
    cfg = _cfg(context)
    if user.id != cfg.owner_id:
        await message.reply_text("This command is only available to the bot owner.")
        return
    store = _store(context)
    manager = _manager(context)
    users = store.all_users()
    procs = store.all_processes()
    live = [p for p in manager.active.values() if not p.finished]
    projects = sum(len(store.projects_for(u["id"])) for u in users)
    lines = [
        "<b>Bot statistics</b>",
        f"Users: {len(users)}",
        f"  Approved: {len(store.users_with_status(USER_APPROVED))}",
        f"  Pending: {len(store.users_with_status(USER_PENDING))}",
        f"  Banned: {len(store.users_with_status(USER_BANNED))}",
        f"Projects uploaded: {projects}",
        f"Processes (recorded): {len(procs)}",
        f"Processes (active now): {len(live)}",
    ]
    running = [
        p for p in procs if p.get("status") in RUNNING_STATUSES
    ]
    if running:
        lines.append("")
        lines.append("<b>Active</b>")
        for p in running[:10]:
            lines.append(
                f"  <code>{esc(p.get('project_name', '?'))}</code> — "
                f"{esc(p.get('status'))} (user {p.get('user_id')})"
            )
    await message.reply_text("\n".join(lines), parse_mode=ParseMode.HTML)


async def cmd_exit_term(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    context.user_data.pop("term_mode", None)
    await update.effective_message.reply_text("Terminal mode OFF.")


async def cmd_cancel_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    if user is None:
        return
    manager = _manager(context)
    for proc in manager.active.values():
        if proc.user_id == user.id and proc.awaiting_input:
            proc.awaiting_input = False
            await manager._close_stdin(proc)
            await update.effective_message.reply_text("Cancelled input prompt; stdin closed.")
            return
    await update.effective_message.reply_text("No active input prompt.")


# ---- editing helper --------------------------------------------------------
async def _safe_edit(
    context: ContextTypes.DEFAULT_TYPE,
    query: Any,
    text: str,
    markup: Optional[InlineKeyboardMarkup],
) -> None:
    try:
        await query.edit_message_text(text=text, reply_markup=markup, parse_mode=ParseMode.HTML)
    except tg_error.BadRequest as exc:
        if "message is not modified" in str(exc).lower():
            return
        with contextlib.suppress(Exception):
            await query.message.reply_text(text, reply_markup=markup, parse_mode=ParseMode.HTML)
    except Exception:  # noqa: BLE001
        log.warning("Failed to edit message", exc_info=True)
        with contextlib.suppress(Exception):
            await query.message.reply_text(text, reply_markup=markup, parse_mode=ParseMode.HTML)


# ---------------------------------------------------------------------------
# 11. Flask health server
# ---------------------------------------------------------------------------
def _system_health(manager: Optional[ProcessManager] = None) -> dict:
    active = 0
    if manager is not None:
        active = sum(1 for p in manager.active.values() if not p.finished)
    mem = psutil.virtual_memory()
    return {
        "status": "ok",
        "service": "telegram-bot",
        "uptime_seconds": int(time.monotonic() - START_TIME),
        "active_processes": active,
        "cpu_percent": round(psutil.cpu_percent(interval=0.1), 1),
        "ram_percent": round(mem.percent, 1),
    }


def create_flask_app(manager: Optional[ProcessManager] = None) -> Flask:
    app = Flask(__name__)

    @app.get("/")
    @app.get("/api/")
    @app.get("/api/healthz")
    def healthz():
        return jsonify(_system_health(manager))

    return app


def start_health_server(cfg: Config, manager: Optional[ProcessManager] = None) -> None:
    app = create_flask_app(manager)

    def _serve() -> None:
        try:
            serve(app, host="0.0.0.0", port=cfg.port, threads=4)
        except Exception:  # noqa: BLE001
            log.exception("Health server stopped unexpectedly")

    t = threading.Thread(target=_serve, name="flask-health", daemon=True)
    t.start()
    log.info("Health server on 0.0.0.0:%s", cfg.port)


# ---------------------------------------------------------------------------
# 12. Main
# ---------------------------------------------------------------------------
def _build_app(cfg: Config, store: DataStore, manager: ProcessManager) -> Application:
    request = HTTPXRequest(
        connect_timeout=cfg.http_connect_timeout,
        read_timeout=cfg.http_read_timeout,
        write_timeout=cfg.http_write_timeout,
        pool_timeout=cfg.http_pool_timeout,
        connection_pool_size=cfg.http_pool_size,
    )
    app = (
        ApplicationBuilder()
        .token(cfg.bot_token)
        .request(request)
        .post_init(lambda application: manager.reconcile())
        .build()
    )
    app.bot_data["cfg"] = cfg
    app.bot_data["store"] = store
    app.bot_data["manager"] = manager
    app.bot_data["term_engines"] = {}
    manager.bot = app.bot

    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(CommandHandler("run", cmd_run))
    app.add_handler(CommandHandler("stats", cmd_stats))
    app.add_handler(CommandHandler("exit_term", cmd_exit_term))
    app.add_handler(CommandHandler("cancel_input", cmd_cancel_input))
    app.add_handler(CallbackQueryHandler(on_callback))
    app.add_handler(MessageHandler(filters.Document.ALL, on_document))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))
    app.add_error_handler(_error_handler)
    return app


async def _error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    log.error("Unhandled exception in update %r", update, exc_info=context.error)
    if isinstance(context.error, Exception):
        try:
            chat_id = None
            if isinstance(update, Update) and update.effective_chat:
                chat_id = update.effective_chat.id
            if chat_id:
                await context.bot.send_message(
                    chat_id,
                    "Something went wrong. The error has been logged.",
                )
        except Exception:  # noqa: BLE001
            log.exception("Failed to report error to user")


async def _run_once(
    cfg: Config, store: DataStore, manager: ProcessManager
) -> None:
    app = _build_app(cfg, store, manager)

    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def _signal_handler() -> None:
        log.info("Signal received; shutting down")
        stop_event.set()
        asyncio.create_task(app.stop())

    with contextlib.suppress(NotImplementedError):
        loop.add_signal_handler(signal.SIGTERM, _signal_handler)
        loop.add_signal_handler(signal.SIGINT, _signal_handler)

    await app.initialize()
    await app.start()
    await app.updater.start_polling(
        allowed_updates=["message", "callback_query"], drop_pending_updates=True
    )
    try:
        await stop_event.wait()
    finally:
        log.info("Cleaning up app")
        with contextlib.suppress(Exception):
            await app.updater.stop()
        with contextlib.suppress(Exception):
            await app.stop()
        with contextlib.suppress(Exception):
            await app.shutdown()
        log.info("App stopped")


async def run() -> None:
    cfg = Config.from_env()
    setup_logging(cfg.log_level)
    log.info("Starting %s (mode=%s)", APP_NAME, cfg.execution_mode)

    cfg.base_dir.mkdir(parents=True, exist_ok=True)
    (cfg.base_dir / "users").mkdir(exist_ok=True)
    (cfg.base_dir / "venvs").mkdir(exist_ok=True)
    (cfg.base_dir / "logs").mkdir(exist_ok=True)

    global _BASE_DIR
    _BASE_DIR = cfg.base_dir / "users"

    store = DataStore(AtomicJsonStore(cfg.base_dir / "bot_data.json"))
    store._cfg_max_projects = cfg.max_projects_per_user
    store._cfg_max_stored = cfg.max_stored_processes_per_user
    manager = ProcessManager(cfg, store)

    start_health_server(cfg, manager)

    retry_delay = cfg.watchdog_retry_seconds
    attempt = 0
    while True:
        attempt += 1
        try:
            await _run_once(cfg, store, manager)
            log.info("Bot exiting after graceful shutdown")
            break
        except (KeyboardInterrupt, SystemExit):
            raise
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception(
                "Bot crashed (attempt %s); reconnecting in %ss",
                attempt,
                retry_delay,
            )
            await asyncio.sleep(retry_delay)

    log.info("Cleaning up")
    await manager.shutdown()
    log.info("Bye")


def main() -> None:
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        log.info("Interrupted")


if __name__ == "__main__":
    main()
