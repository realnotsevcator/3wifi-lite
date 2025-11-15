import atexit
import logging
import os
import queue
import re
import shutil
import sqlite3
import threading
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from time import monotonic
from typing import Any, Callable, Dict, List, Optional, Tuple

from flask import Flask, jsonify, render_template, request

APP_ROOT = Path(__file__).resolve().parent
DATABASE_PATH = APP_ROOT / "data.sqlite3"
BACKUP_INTERVAL_SECONDS = int(os.getenv("BACKUP_INTERVAL_SECONDS", "3600"))
DAILY_BACKUP_DIR = Path(os.getenv("DAILY_BACKUP_DIR", APP_ROOT / "daily_backups"))
DAILY_BACKUP_RETENTION = int(os.getenv("DAILY_BACKUP_RETENTION", "30"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "5"))
MAX_UPLOADS_PER_DAY = int(os.getenv("MAX_UPLOADS_PER_DAY", "30"))
PAGE_SIZE = int(os.getenv("PAGE_SIZE", "100"))
DB_WORKER_THREADS = int(os.getenv("DB_WORKER_THREADS", "4"))

BSSID_PATTERN = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
WPS_PIN_PATTERN = re.compile(r"^[0-9]{8}$")


logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger(__name__)


_last_request_times: Dict[str, float] = {}
_upload_counters: Dict[str, int] = {}
_daily_upload_totals = {"date": None, "count": 0}


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_db_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS wifi_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bssid TEXT NOT NULL,
                essid TEXT NOT NULL,
                password TEXT,
                wps_pin TEXT,
                wsc_device_name TEXT,
                wsc_model TEXT,
                added TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        existing_columns = {
            column_info["name"] for column_info in conn.execute("PRAGMA table_info(wifi_records)")
        }
        if "wsc_device_name" not in existing_columns:
            conn.execute("ALTER TABLE wifi_records ADD COLUMN wsc_device_name TEXT")
        if "wsc_model" not in existing_columns:
            conn.execute("ALTER TABLE wifi_records ADD COLUMN wsc_model TEXT")
        conn.commit()


@dataclass
class WifiRecord:
    bssid: str
    essid: str
    password: Optional[str]
    wps_pin: Optional[str]
    wsc_device_name: Optional[str]
    wsc_model: Optional[str]
    added: str

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "WifiRecord":
        return cls(
            bssid=row["bssid"],
            essid=row["essid"],
            password=row["password"],
            wps_pin=row["wps_pin"],
            wsc_device_name=row["wsc_device_name"],
            wsc_model=row["wsc_model"],
            added=_format_timestamp(row["added"]),
        )

    def as_dict(self) -> dict:
        return {
            "bssid": self.bssid,
            "essid": self.essid,
            "password": self.password,
            "wps_pin": self.wps_pin,
            "wsc_device_name": self.wsc_device_name,
            "wsc_model": self.wsc_model,
            "added": self.added,
        }


class BackupError(RuntimeError):
    """Raised when a backup cannot be created."""


class DuplicateRecordError(ValueError):
    """Raised when attempting to add an existing Wi-Fi record."""


class BaseBackupProvider:
    def backup(self, source_path: Path, destination_name: str) -> None:
        raise NotImplementedError


class LocalBackupProvider(BaseBackupProvider):
    def __init__(self, directory: Path):
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)

    def backup(self, source_path: Path, destination_name: str) -> None:
        destination = self.directory / destination_name
        shutil.copy2(source_path, destination)
        logger.info("Stored local backup at %s", destination)


class MegaBackupProvider(BaseBackupProvider):
    def __init__(self, email: str, password: str, folder: str):
        try:
            from mega import Mega
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise BackupError(
                "mega.py package is required for Mega backups. Install it with 'pip install mega.py'."
            ) from exc

        self._mega = Mega()
        self._m = self._mega.login(email, password)
        self._folder_name = folder
        self._folder_handle = self._ensure_folder(folder)
        logger.info("Authenticated with Mega.nz for automatic backups")

    def _ensure_folder(self, folder_name: str):
        existing = self._m.find(folder_name)
        if existing:
            return existing[0]
        created = self._m.create_folder(folder_name)
        # mega.py returns dict mapping folder name to node id
        return created[folder_name]

    def backup(self, source_path: Path, destination_name: str) -> None:
        logger.info("Uploading backup %s to Mega.nz", destination_name)
        self._m.upload(
            str(source_path),
            dest=self._folder_handle,
            dest_filename=destination_name,
        )


class BackupManager:
    def __init__(self, provider: Optional[BaseBackupProvider], interval_seconds: int):
        self.provider = provider
        self.interval_seconds = interval_seconds
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self.provider is None:
            logger.warning("Backup provider not configured; automatic backups are disabled")
            return
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info("Backup manager started with interval %ss", self.interval_seconds)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2)

    def trigger_backup(self) -> None:
        if not self.provider:
            raise BackupError("Backup provider is not configured")
        backup_name = _generate_backup_filename()
        self.provider.backup(DATABASE_PATH, backup_name)

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.trigger_backup()
            except BackupError as err:
                logger.error("Backup failed: %s", err)
            except Exception:  # pragma: no cover - safeguard
                logger.exception("Unexpected error during backup")
            self._stop_event.wait(self.interval_seconds)


class DailyBackupManager:
    def __init__(self, directory: Path, retention: int):
        self.directory = directory
        self.retention = max(1, retention)
        self.directory.mkdir(parents=True, exist_ok=True)
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info(
            "Daily backup manager started at directory %s with retention %s", self.directory, self.retention
        )

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _run(self) -> None:
        while not self._stop_event.is_set():
            wait_seconds = self._seconds_until_next_midnight()
            if wait_seconds <= 0:
                wait_seconds = 1
            if self._stop_event.wait(wait_seconds):
                break
            try:
                self._create_backup()
            except Exception:  # pragma: no cover - safeguard
                logger.exception("Unexpected error while creating daily backup")

    def _create_backup(self) -> None:
        if not DATABASE_PATH.exists():
            logger.warning("Database file %s not found; skipping daily backup", DATABASE_PATH)
            return
        timestamp = datetime.now().strftime("%Y%m%d")
        destination = self.directory / f"wifi-daily-backup-{timestamp}.sqlite3"
        if destination.exists():
            logger.info("Daily backup already exists for %s; skipping", timestamp)
        else:
            shutil.copy2(DATABASE_PATH, destination)
            logger.info("Created daily backup at %s", destination)
        self._enforce_retention()

    def _enforce_retention(self) -> None:
        backups = sorted(
            self.directory.glob("wifi-daily-backup-*.sqlite3"),
            key=lambda path: path.stat().st_mtime,
        )
        excess = len(backups) - self.retention
        for i in range(excess):
            to_remove = backups[i]
            try:
                to_remove.unlink()
                logger.info("Removed expired daily backup %s", to_remove)
            except FileNotFoundError:
                logger.debug("Daily backup %s already removed", to_remove)

    @staticmethod
    def _seconds_until_next_midnight() -> float:
        now = datetime.now()
        next_midnight = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        return (next_midnight - now).total_seconds()


class DatabaseWorkerPool:
    def __init__(self, worker_count: int):
        self._worker_count = max(1, worker_count)
        self._tasks: "queue.Queue[Optional[Tuple[Callable[..., Any], tuple, dict, queue.Queue]]]" = queue.Queue()
        self._threads: List[threading.Thread] = []
        self._shutdown = threading.Event()

        for index in range(self._worker_count):
            thread = threading.Thread(
                target=self._worker,
                name=f"DatabaseWorker-{index + 1}",
                daemon=True,
            )
            self._threads.append(thread)
            thread.start()

    def submit(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        if self._shutdown.is_set():
            raise RuntimeError("Database worker pool has been shut down")

        result_queue: "queue.Queue[Tuple[bool, Any]]" = queue.Queue(maxsize=1)
        self._tasks.put((func, args, kwargs, result_queue))
        success, payload = result_queue.get()
        if success:
            return payload
        if isinstance(payload, BaseException):
            raise payload
        raise RuntimeError("Database task failed without raising an exception")

    def shutdown(self) -> None:
        if self._shutdown.is_set():
            return
        self._shutdown.set()
        for _ in self._threads:
            self._tasks.put(None)
        for thread in self._threads:
            thread.join(timeout=2)

    def _worker(self) -> None:
        while True:
            task = self._tasks.get()
            if task is None:
                self._tasks.task_done()
                break
            func, args, kwargs, result_queue = task
            try:
                result = func(*args, **kwargs)
            except Exception as exc:  # pragma: no cover - defensive guard
                result_queue.put((False, exc))
            else:
                result_queue.put((True, result))
            finally:
                self._tasks.task_done()


database_worker_pool = DatabaseWorkerPool(DB_WORKER_THREADS)
atexit.register(database_worker_pool.shutdown)


def create_backup_provider() -> Optional[BaseBackupProvider]:
    provider_name = os.getenv("BACKUP_PROVIDER", "local").strip().lower()
    if provider_name == "none":
        return None
    if provider_name == "local":
        directory = Path(os.getenv("LOCAL_BACKUP_DIR", APP_ROOT / "backups"))
        return LocalBackupProvider(directory=directory)
    if provider_name == "mega":
        email = os.getenv("MEGA_EMAIL")
        password = os.getenv("MEGA_PASSWORD")
        folder = os.getenv("MEGA_FOLDER", "3wifi-lite-backups")
        if not email or not password:
            raise BackupError("MEGA_EMAIL and MEGA_PASSWORD environment variables must be set for Mega backups")
        return MegaBackupProvider(email=email, password=password, folder=folder)
    raise BackupError(f"Unsupported backup provider: {provider_name}")


def _generate_backup_filename() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"wifi-backup-{timestamp}.sqlite3"


def _get_client_ip() -> str:
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        ip = forwarded_for.split(",")[0].strip()
        if ip:
            return ip
    return request.remote_addr or "unknown"


def _prune_stale_rate_limits(now: float) -> None:
    expiry = RATE_LIMIT_WINDOW_SECONDS * 12
    if expiry <= 0:
        return
    stale_ips = [ip for ip, ts in _last_request_times.items() if now - ts > expiry]
    for ip in stale_ips:
        _last_request_times.pop(ip, None)


def _can_upload_today(ip: str) -> bool:
    today = datetime.now().date()
    _refresh_daily_upload_state(today)
    if _daily_upload_totals["count"] >= MAX_UPLOADS_PER_DAY:
        return False
    return _upload_counters.get(ip, 0) < MAX_UPLOADS_PER_DAY


def _mark_upload(ip: str) -> None:
    today = datetime.now().date()
    _refresh_daily_upload_state(today)
    _upload_counters[ip] = _upload_counters.get(ip, 0) + 1
    _daily_upload_totals["count"] += 1


def _refresh_daily_upload_state(today: date) -> None:
    if _daily_upload_totals["date"] != today:
        _daily_upload_totals["date"] = today
        _daily_upload_totals["count"] = 0
        _upload_counters.clear()


def _format_timestamp(value: Optional[str]) -> str:
    if not value:
        return ""
    value = value.strip()
    try:
        if value.endswith("Z"):
            dt = datetime.fromisoformat(value[:-1]).replace(tzinfo=timezone.utc)
        else:
            dt = datetime.fromisoformat(value)
    except ValueError:
        try:
            dt = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
            dt = dt.replace(tzinfo=timezone.utc)
        except ValueError:
            match = re.match(r"^(\d{4}-\d{2})", value)
            if match:
                return match.group(1)
            return value
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m")


def _normalize_optional_text(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def validate_bssid(bssid: str) -> str:
    if not bssid:
        raise ValueError("BSSID is required")
    if not BSSID_PATTERN.fullmatch(bssid):
        raise ValueError("BSSID must match pattern XX:XX:XX:XX:XX:XX")
    return bssid.upper()


def validate_wps_pin(wps_pin: Optional[str]) -> str:
    if wps_pin is None:
        raise ValueError("WPS Pin is required")
    wps_pin = str(wps_pin).strip()
    if not wps_pin:
        raise ValueError("WPS Pin is required")
    if wps_pin.upper() == "NULL":
        return "NULL"
    if not WPS_PIN_PATTERN.fullmatch(wps_pin):
        raise ValueError("WPS Pin must be exactly 8 digits or the word NULL")
    return wps_pin


def validate_essid(essid: str) -> str:
    if not essid:
        raise ValueError("ESSID is required")
    essid = essid.strip()
    if not essid:
        raise ValueError("ESSID is required")
    return essid


def validate_password(password: Optional[str]) -> str:
    if password is None:
        raise ValueError("Password is required")
    password = str(password).strip()
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long")
    return password


def _insert_record_task(
    bssid: str,
    essid: str,
    password: str,
    wps_pin: str,
    *,
    wsc_device_name: Optional[str],
    wsc_model: Optional[str],
) -> WifiRecord:
    with get_db_connection() as conn:
        duplicate = conn.execute(
            """
            SELECT 1
            FROM wifi_records
            WHERE bssid = ?
              AND essid = ?
              AND password = ?
              AND wps_pin = ?
            LIMIT 1
            """,
            (bssid, essid, password, wps_pin),
        ).fetchone()
        if duplicate:
            raise DuplicateRecordError(
                "A record with the same BSSID, ESSID, Password, and WPS Pin already exists."
            )
        cursor = conn.execute(
            """
            INSERT INTO wifi_records (
                bssid,
                essid,
                password,
                wps_pin,
                wsc_device_name,
                wsc_model
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (bssid, essid, password, wps_pin, wsc_device_name, wsc_model),
        )
        conn.commit()
        record_id = cursor.lastrowid
        row = conn.execute(
            """
            SELECT
                bssid,
                essid,
                password,
                wps_pin,
                wsc_device_name,
                wsc_model,
                added
            FROM wifi_records
            WHERE id = ?
            """,
            (record_id,),
        ).fetchone()
    return WifiRecord.from_row(row)


def insert_record(
    bssid: str,
    essid: str,
    password: str,
    wps_pin: str,
    *,
    wsc_device_name: Optional[str],
    wsc_model: Optional[str],
) -> WifiRecord:
    return database_worker_pool.submit(
        _insert_record_task,
        bssid,
        essid,
        password,
        wps_pin,
        wsc_device_name=wsc_device_name,
        wsc_model=wsc_model,
    )


def _build_query_filters(
    *,
    bssid: Optional[str] = None,
    essid: Optional[str] = None,
    password: Optional[str] = None,
    wps_pin: Optional[str] = None,
    wsc_device_name: Optional[str] = None,
    wsc_model: Optional[str] = None,
    search: Optional[str] = None,
) -> Tuple[List[str], List[str]]:
    clauses: List[str] = []
    params: List[str] = []

    if bssid:
        clauses.append("bssid = ?")
        params.append(bssid.upper())
    if essid:
        clauses.append("essid = ?")
        params.append(essid)
    if password:
        clauses.append("password = ?")
        params.append(password)
    if wps_pin:
        clauses.append("wps_pin = ?")
        params.append(wps_pin.upper() if wps_pin.upper() == "NULL" else wps_pin)
    if wsc_device_name:
        clauses.append("wsc_device_name = ?")
        params.append(wsc_device_name)
    if wsc_model:
        clauses.append("wsc_model = ?")
        params.append(wsc_model)
    if search:
        like_term = f"%{search.lower()}%"
        clauses.append(
            "(LOWER(essid) LIKE ?"
            " OR LOWER(bssid) LIKE ?"
            " OR LOWER(password) LIKE ?"
            " OR LOWER(wps_pin) LIKE ?"
            " OR LOWER(COALESCE(wsc_device_name, '')) LIKE ?"
            " OR LOWER(COALESCE(wsc_model, '')) LIKE ?)"
        )
        params.extend([like_term, like_term, like_term, like_term, like_term, like_term])

    return clauses, params


def _query_records_task(
    *,
    bssid: Optional[str] = None,
    essid: Optional[str] = None,
    password: Optional[str] = None,
    wps_pin: Optional[str] = None,
    wsc_device_name: Optional[str] = None,
    wsc_model: Optional[str] = None,
    search: Optional[str] = None,
    limit: Optional[int] = None,
    offset: Optional[int] = None,
) -> List[WifiRecord]:
    clauses, params = _build_query_filters(
        bssid=bssid,
        essid=essid,
        password=password,
        wps_pin=wps_pin,
        wsc_device_name=wsc_device_name,
        wsc_model=wsc_model,
        search=search,
    )

    sql = (
        "SELECT "
        "bssid, essid, password, wps_pin, wsc_device_name, wsc_model, added "
        "FROM wifi_records"
    )
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY datetime(added) DESC"

    query_params = list(params)
    if limit is not None:
        sql += " LIMIT ?"
        query_params.append(limit)
        if offset is not None:
            sql += " OFFSET ?"
            query_params.append(offset)
    elif offset is not None:
        sql += " LIMIT -1 OFFSET ?"
        query_params.append(offset)

    with get_db_connection() as conn:
        rows = conn.execute(sql, query_params).fetchall()
    return [WifiRecord.from_row(row) for row in rows]


def query_records(
    *,
    bssid: Optional[str] = None,
    essid: Optional[str] = None,
    password: Optional[str] = None,
    wps_pin: Optional[str] = None,
    wsc_device_name: Optional[str] = None,
    wsc_model: Optional[str] = None,
    search: Optional[str] = None,
    limit: Optional[int] = None,
    offset: Optional[int] = None,
) -> List[WifiRecord]:
    return database_worker_pool.submit(
        _query_records_task,
        bssid=bssid,
        essid=essid,
        password=password,
        wps_pin=wps_pin,
        wsc_device_name=wsc_device_name,
        wsc_model=wsc_model,
        search=search,
        limit=limit,
        offset=offset,
    )


def _count_records_task(
    *,
    bssid: Optional[str] = None,
    essid: Optional[str] = None,
    password: Optional[str] = None,
    wps_pin: Optional[str] = None,
    wsc_device_name: Optional[str] = None,
    wsc_model: Optional[str] = None,
    search: Optional[str] = None,
) -> int:
    clauses, params = _build_query_filters(
        bssid=bssid,
        essid=essid,
        password=password,
        wps_pin=wps_pin,
        wsc_device_name=wsc_device_name,
        wsc_model=wsc_model,
        search=search,
    )

    sql = "SELECT COUNT(*) FROM wifi_records"
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)

    with get_db_connection() as conn:
        (total,) = conn.execute(sql, params).fetchone()
    return int(total)


def count_records(
    *,
    bssid: Optional[str] = None,
    essid: Optional[str] = None,
    password: Optional[str] = None,
    wps_pin: Optional[str] = None,
    wsc_device_name: Optional[str] = None,
    wsc_model: Optional[str] = None,
    search: Optional[str] = None,
) -> int:
    return database_worker_pool.submit(
        _count_records_task,
        bssid=bssid,
        essid=essid,
        password=password,
        wps_pin=wps_pin,
        wsc_device_name=wsc_device_name,
        wsc_model=wsc_model,
        search=search,
    )


init_db()
app = Flask(
    __name__,
    template_folder=str(APP_ROOT),
    static_folder=str(APP_ROOT),
)
backup_manager = BackupManager(create_backup_provider(), BACKUP_INTERVAL_SECONDS)
backup_manager.start()
daily_backup_manager = DailyBackupManager(DAILY_BACKUP_DIR, DAILY_BACKUP_RETENTION)
daily_backup_manager.start()


@app.before_request
def enforce_request_limits():
    if request.endpoint == "static" or RATE_LIMIT_WINDOW_SECONDS <= 0:
        return None

    ip = _get_client_ip()
    now = monotonic()
    _prune_stale_rate_limits(now)

    last_seen = _last_request_times.get(ip)
    if last_seen is not None and now - last_seen < RATE_LIMIT_WINDOW_SECONDS:
        response = jsonify({"error": "Please wait before use this again!"})
        return response, 429

    _last_request_times[ip] = now


@app.route("/")
def index() -> str:
    raw_search = request.args.get("search", "")
    search = raw_search.strip()
    page_param = request.args.get("page", "1")
    try:
        page = int(page_param)
    except ValueError:
        page = 1
    if page < 1:
        page = 1

    per_page = PAGE_SIZE
    total_count = count_records(search=search or None)
    total_pages = (total_count + per_page - 1) // per_page if total_count else 0

    if total_pages == 0:
        page = 1
        offset = 0
    else:
        if page > total_pages:
            page = total_pages
        offset = (page - 1) * per_page

    records = query_records(search=search or None, limit=per_page, offset=offset if total_count else 0)
    start_index = offset + 1 if total_count else 0
    end_index = offset + len(records) if total_count else 0
    has_prev = total_pages > 0 and page > 1
    has_next = total_pages > 0 and page < total_pages

    return render_template(
        "index.html",
        records=records,
        search=search,
        page=page,
        per_page=per_page,
        total_count=total_count,
        total_pages=total_pages,
        start_index=start_index,
        end_index=end_index,
        has_prev=has_prev,
        has_next=has_next,
    )


@app.post("/api/records")
def add_record():
    ip = _get_client_ip()
    if not _can_upload_today(ip):
        return jsonify({"error": "Daily upload limit reached"}), 429
    if request.is_json:
        payload = request.get_json() or {}
    else:
        payload = request.form.to_dict()
    try:
        bssid = validate_bssid(payload.get("bssid", "").strip())
        essid = validate_essid(payload.get("essid", "").strip())
        password = validate_password(payload.get("password"))
        wps_pin = validate_wps_pin(payload.get("wps_pin"))
        wsc_device_name = _normalize_optional_text(payload.get("wsc_device_name"))
        wsc_model = _normalize_optional_text(payload.get("wsc_model"))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    try:
        record = insert_record(
            bssid=bssid,
            essid=essid,
            password=password,
            wps_pin=wps_pin,
            wsc_device_name=wsc_device_name,
            wsc_model=wsc_model,
        )
    except DuplicateRecordError as exc:
        return jsonify({"error": str(exc)}), 400
    except sqlite3.IntegrityError as exc:
        logger.exception("Failed to insert record")
        return jsonify({"error": "Failed to insert record", "details": str(exc)}), 400

    _mark_upload(ip)
    return jsonify(record.as_dict()), 201


@app.get("/api/records")
def get_records():
    search = _normalize_optional_text(request.args.get("search"))
    bssid = _normalize_optional_text(request.args.get("bssid"))
    essid = _normalize_optional_text(request.args.get("essid"))
    wsc_device_name = _normalize_optional_text(request.args.get("wsc_device_name"))
    wsc_model = _normalize_optional_text(request.args.get("wsc_model"))
    try:
        limit = int(request.args.get("limit", "0"))
    except ValueError:
        return jsonify({"error": "limit must be an integer"}), 400
    limit = limit or None

    password = _normalize_optional_text(request.args.get("password"))

    wps_pin = _normalize_optional_text(request.args.get("wps_pin"))

    records = query_records(
        bssid=bssid,
        essid=essid,
        password=password,
        wps_pin=wps_pin,
        wsc_device_name=wsc_device_name,
        wsc_model=wsc_model,
        search=search,
        limit=limit,
    )
    return jsonify([record.as_dict() for record in records])


@app.get("/api/records/<bssid>")
def get_record_by_bssid(bssid: str):
    try:
        bssid = validate_bssid(bssid)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    records = query_records(bssid=bssid)
    if not records:
        return jsonify({"error": "Record not found"}), 404
    return jsonify([record.as_dict() for record in records])


@app.errorhandler(404)
def handle_404(error):  # pragma: no cover - Flask default behavior
    if request.path.startswith("/api/"):
        return jsonify({"error": "Not found"}), 404
    return error


@app.errorhandler(500)
def handle_500(error):  # pragma: no cover - Flask default behavior
    logger.exception("Internal server error")
    if request.path.startswith("/api/"):
        return jsonify({"error": "Internal server error"}), 500
    return error


if __name__ == "__main__":
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "12345"))
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    logger.info("Starting server on %s:%s", host, port)
    app.run(host=host, port=port, debug=debug)
