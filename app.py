import atexit
import logging
import os
import queue
import re
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from time import monotonic
from typing import Any, Callable, Dict, Iterator, List, Mapping, Optional, Tuple, Union

from flask import Flask, jsonify, render_template, request
from sqlalchemy import (
    Column,
    DateTime,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    and_,
    create_engine,
    func,
    insert,
    or_,
    select,
)
from sqlalchemy.engine import Connection
from sqlalchemy.engine.url import make_url
from sqlalchemy.exc import IntegrityError, SQLAlchemyError


logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger(__name__)


def _get_int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    try:
        return int(value)
    except ValueError:
        logger.warning(
            "Environment variable %s=%r is not an integer; falling back to %s",
            name,
            value,
            default,
        )
        return default


def _auto_worker_threads() -> int:
    cpu_total = os.cpu_count()
    if not cpu_total or cpu_total < 1:
        return 1
    # avoid spawning an excessive number of background workers on high-core systems
    return max(1, min(32, cpu_total))


APP_ROOT = Path(__file__).resolve().parent
RATE_LIMIT_WINDOW_SECONDS = _get_int_env("RATE_LIMIT_WINDOW_SECONDS", 5)
MAX_UPLOADS_PER_DAY = _get_int_env("MAX_UPLOADS_PER_DAY", 30)
PAGE_SIZE = _get_int_env("PAGE_SIZE", 100)
DB_WORKER_THREADS = _get_int_env("DB_WORKER_THREADS", _auto_worker_threads())

BSSID_PATTERN = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
WPS_PIN_PATTERN = re.compile(r"^[0-9]{8}$")

raw_database_url = os.getenv("DATABASE_URL")
if not raw_database_url:
    raise RuntimeError(
        "DATABASE_URL environment variable must be set to a MySQL connection string"
    )

database_url_object = make_url(raw_database_url)
if database_url_object.get_backend_name() != "mysql":
    raise RuntimeError("DATABASE_URL must use the MySQL backend (e.g. mysql+pymysql)")

DATABASE_URL = database_url_object.render_as_string(hide_password=False)

engine = create_engine(
    DATABASE_URL,
    future=True,
    pool_pre_ping=True,
)


metadata = MetaData()

wifi_records_table = Table(
    "wifi_records",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("bssid", String(17), nullable=False),
    Column("essid", String(255), nullable=False),
    Column("password", String(255)),
    Column("wps_pin", String(16)),
    Column("wsc_device_name", String(255)),
    Column("wsc_model", String(255)),
    Column("added", DateTime(timezone=True), server_default=func.now(), nullable=False),
    mysql_engine="InnoDB",
    mysql_charset="utf8mb4",
    mysql_collate="utf8mb4_unicode_ci",
)

Index("ix_wifi_records_bssid", wifi_records_table.c.bssid)
Index("ix_wifi_records_essid", wifi_records_table.c.essid)
Index("ix_wifi_records_wps_pin", wifi_records_table.c.wps_pin)


_last_request_times: Dict[str, float] = {}
_upload_counters: Dict[str, int] = {}
_daily_upload_totals = {"date": None, "count": 0}


@contextmanager
def get_db_connection() -> Iterator[Connection]:
    with engine.begin() as connection:
        yield connection


def init_db() -> None:
    metadata.create_all(engine, checkfirst=True)


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
    def from_row(cls, row: Mapping[str, Any]) -> "WifiRecord":
        if hasattr(row, "_mapping"):
            data = row._mapping  # type: ignore[attr-defined]
        else:
            data = row
        return cls(
            bssid=data["bssid"],
            essid=data["essid"],
            password=data["password"],
            wps_pin=data["wps_pin"],
            wsc_device_name=data["wsc_device_name"],
            wsc_model=data["wsc_model"],
            added=_format_timestamp(data["added"]),
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


class DuplicateRecordError(ValueError):
    """Raised when attempting to add an existing Wi-Fi record."""


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


def _format_timestamp(value: Optional[Union[str, datetime]]) -> str:
    if value is None:
        return ""
    if isinstance(value, datetime):
        dt = value
    else:
        text_value = str(value).strip()
        if not text_value:
            return ""
        try:
            if text_value.endswith("Z"):
                dt = datetime.fromisoformat(text_value[:-1]).replace(tzinfo=timezone.utc)
            else:
                dt = datetime.fromisoformat(text_value)
        except ValueError:
            try:
                dt = datetime.strptime(text_value, "%Y-%m-%d %H:%M:%S")
                dt = dt.replace(tzinfo=timezone.utc)
            except ValueError:
                match = re.match(r"^(\d{4}-\d{2})", text_value)
                if match:
                    return match.group(1)
                return text_value
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
        duplicate_query = (
            select(wifi_records_table.c.id)
            .where(
                and_(
                    wifi_records_table.c.bssid == bssid,
                    wifi_records_table.c.essid == essid,
                    wifi_records_table.c.password == password,
                    wifi_records_table.c.wps_pin == wps_pin,
                )
            )
            .limit(1)
        )
        duplicate = conn.execute(duplicate_query).first()
        if duplicate:
            raise DuplicateRecordError(
                "A record with the same BSSID, ESSID, Password, and WPS Pin already exists."
            )
        insert_stmt = insert(wifi_records_table).values(
            bssid=bssid,
            essid=essid,
            password=password,
            wps_pin=wps_pin,
            wsc_device_name=wsc_device_name,
            wsc_model=wsc_model,
        )
        result = conn.execute(insert_stmt)
        record_id = result.inserted_primary_key[0] if result.inserted_primary_key else None
        if record_id is None:
            raise RuntimeError("Failed to retrieve inserted record identifier")
        row = (
            conn.execute(
                select(
                    wifi_records_table.c.bssid,
                    wifi_records_table.c.essid,
                    wifi_records_table.c.password,
                    wifi_records_table.c.wps_pin,
                    wifi_records_table.c.wsc_device_name,
                    wifi_records_table.c.wsc_model,
                    wifi_records_table.c.added,
                ).where(wifi_records_table.c.id == record_id)
            )
            .mappings()
            .first()
        )
        if row is None:
            raise RuntimeError("Inserted record could not be retrieved")
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
) -> List[Any]:
    clauses: List[Any] = []

    if bssid:
        clauses.append(wifi_records_table.c.bssid == bssid.upper())
    if essid:
        clauses.append(wifi_records_table.c.essid == essid)
    if password:
        clauses.append(wifi_records_table.c.password == password)
    if wps_pin:
        normalized_pin = wps_pin.upper() if wps_pin.upper() == "NULL" else wps_pin
        clauses.append(wifi_records_table.c.wps_pin == normalized_pin)
    if wsc_device_name:
        clauses.append(wifi_records_table.c.wsc_device_name == wsc_device_name)
    if wsc_model:
        clauses.append(wifi_records_table.c.wsc_model == wsc_model)
    if search:
        like_term = f"%{search.lower()}%"
        clauses.append(
            or_(
                func.lower(wifi_records_table.c.essid).like(like_term),
                func.lower(wifi_records_table.c.bssid).like(like_term),
                func.lower(wifi_records_table.c.password).like(like_term),
                func.lower(wifi_records_table.c.wps_pin).like(like_term),
                func.lower(func.coalesce(wifi_records_table.c.wsc_device_name, "")).like(
                    like_term
                ),
                func.lower(func.coalesce(wifi_records_table.c.wsc_model, "")).like(like_term),
            )
        )

    return clauses


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
    clauses = _build_query_filters(
        bssid=bssid,
        essid=essid,
        password=password,
        wps_pin=wps_pin,
        wsc_device_name=wsc_device_name,
        wsc_model=wsc_model,
        search=search,
    )
    query = (
        select(
            wifi_records_table.c.bssid,
            wifi_records_table.c.essid,
            wifi_records_table.c.password,
            wifi_records_table.c.wps_pin,
            wifi_records_table.c.wsc_device_name,
            wifi_records_table.c.wsc_model,
            wifi_records_table.c.added,
        )
        .order_by(wifi_records_table.c.added.desc())
    )
    if clauses:
        query = query.where(and_(*clauses))
    if limit is not None:
        query = query.limit(limit)
    if offset is not None:
        query = query.offset(offset)

    with get_db_connection() as conn:
        rows = conn.execute(query).mappings().all()
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
    clauses = _build_query_filters(
        bssid=bssid,
        essid=essid,
        password=password,
        wps_pin=wps_pin,
        wsc_device_name=wsc_device_name,
        wsc_model=wsc_model,
        search=search,
    )

    query = select(func.count()).select_from(wifi_records_table)
    if clauses:
        query = query.where(and_(*clauses))

    with get_db_connection() as conn:
        (total,) = conn.execute(query).one()
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
    except IntegrityError as exc:
        logger.exception("Failed to insert record")
        return jsonify({"error": "Failed to insert record", "details": str(exc)}), 400
    except SQLAlchemyError as exc:
        logger.exception("Unexpected database error")
        return jsonify({"error": "Database error", "details": str(exc)}), 500

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
