import logging
import os
import re
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from time import monotonic
from typing import Any, Dict, Iterator, List, Mapping, Optional, Tuple, Union
from urllib.parse import parse_qs, urlparse

from flask import Flask, jsonify, render_template, request
import pymysql
from pymysql import err as pymysql_err
from pymysql.cursors import DictCursor


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


APP_ROOT = Path(__file__).resolve().parent
RATE_LIMIT_WINDOW_SECONDS = _get_int_env("RATE_LIMIT_WINDOW_SECONDS", 5)
MAX_UPLOADS_PER_DAY = _get_int_env("MAX_UPLOADS_PER_DAY", 30)
PAGE_SIZE = _get_int_env("PAGE_SIZE", 100)

BSSID_PATTERN = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
WPS_PIN_PATTERN = re.compile(r"^[0-9]{8}$")

# 3-6 octets separated by colons (e.g. XX:XX:XX or XX:XX:XX:XX:XX:XX)
PARTIAL_BSSID_SEARCH_PATTERN = re.compile(
    r"^([0-9A-Fa-f]{2}:){2,5}[0-9A-Fa-f]{2}$"
)


@dataclass(frozen=True)
class DatabaseConfig:
    host: str
    port: int
    user: str
    password: str
    database: str
    charset: str = "utf8mb4"


def _parse_database_url(url: str) -> DatabaseConfig:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.scheme.startswith("mysql"):
        raise RuntimeError(
            "DATABASE_URL must use the MySQL backend (e.g. mysql://user:pass@host/db)"
        )

    if not parsed.path or parsed.path == "/":
        raise RuntimeError("DATABASE_URL must include the database name")

    query_params = parse_qs(parsed.query)
    charset = query_params.get("charset", ["utf8mb4"])[0] or "utf8mb4"

    return DatabaseConfig(
        host=parsed.hostname or "localhost",
        port=parsed.port or 3306,
        user=parsed.username or "",
        password=parsed.password or "",
        database=parsed.path.lstrip("/"),
        charset=charset,
    )


raw_database_url = os.getenv("DATABASE_URL")
if not raw_database_url:
    raise RuntimeError(
        "DATABASE_URL environment variable must be set to a MySQL connection string"
    )

DATABASE_CONFIG = _parse_database_url(raw_database_url)


_last_request_times: Dict[str, float] = {}
_upload_counters: Dict[str, int] = {}
_daily_upload_totals = {"date": None, "count": 0}


@contextmanager
def get_db_connection() -> Iterator[pymysql.connections.Connection]:
    connection = pymysql.connect(
        host=DATABASE_CONFIG.host,
        port=DATABASE_CONFIG.port,
        user=DATABASE_CONFIG.user,
        password=DATABASE_CONFIG.password,
        database=DATABASE_CONFIG.database,
        charset=DATABASE_CONFIG.charset,
        autocommit=False,
        cursorclass=DictCursor,
    )
    try:
        yield connection
    finally:
        connection.close()


def init_db() -> None:
    create_table_sql = """
    CREATE TABLE IF NOT EXISTS wifi_records (
        id INT AUTO_INCREMENT PRIMARY KEY,
        bssid VARCHAR(17) NOT NULL,
        essid VARCHAR(255) NOT NULL,
        password VARCHAR(255),
        wps_pin VARCHAR(16),
        wsc_device_name VARCHAR(255),
        wsc_model VARCHAR(255),
        added TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        KEY ix_wifi_records_bssid (bssid),
        KEY ix_wifi_records_essid (essid),
        KEY ix_wifi_records_wps_pin (wps_pin)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """

    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(create_table_sql)
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
    def from_row(cls, row: Mapping[str, Any]) -> "WifiRecord":
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


def insert_record(
    bssid: str,
    essid: str,
    password: str,
    wps_pin: str,
    *,
    wsc_device_name: Optional[str],
    wsc_model: Optional[str],
) -> WifiRecord:
    with get_db_connection() as conn:
        row_result: Mapping[str, Any]
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT id FROM wifi_records
                    WHERE bssid = %s AND essid = %s AND password = %s AND wps_pin = %s
                    LIMIT 1
                    """,
                    (bssid, essid, password, wps_pin),
                )
                duplicate = cursor.fetchone()
                if duplicate:
                    raise DuplicateRecordError(
                        "A record with the same BSSID, ESSID, Password, and WPS Pin already exists."
                    )

                cursor.execute(
                    """
                    INSERT INTO wifi_records
                        (bssid, essid, password, wps_pin, wsc_device_name, wsc_model)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (bssid, essid, password, wps_pin, wsc_device_name, wsc_model),
                )
                record_id = cursor.lastrowid
                if not record_id:
                    raise RuntimeError("Failed to retrieve inserted record identifier")

                cursor.execute(
                    """
                    SELECT bssid, essid, password, wps_pin, wsc_device_name, wsc_model, added
                    FROM wifi_records
                    WHERE id = %s
                    """,
                    (record_id,),
                )
                row = cursor.fetchone()
                if row is None:
                    raise RuntimeError("Inserted record could not be retrieved")

                row_result = row

            conn.commit()
        except Exception:
            conn.rollback()
            raise
    return WifiRecord.from_row(row_result)


def _build_query_filters(
    *,
    bssid: Optional[str] = None,
    essid: Optional[str] = None,
    password: Optional[str] = None,
    wps_pin: Optional[str] = None,
    wsc_device_name: Optional[str] = None,
    wsc_model: Optional[str] = None,
    search: Optional[str] = None,
    search_include_bssid: bool = True,
    search_include_wps_pin: bool = True,
    search_only_bssid: bool = False,
) -> Tuple[List[str], List[Any]]:
    clauses: List[str] = []
    params: List[Any] = []

    if bssid:
        clauses.append("bssid = %s")
        params.append(bssid.upper())
    if essid:
        clauses.append("essid = %s")
        params.append(essid)
    if password:
        clauses.append("password = %s")
        params.append(password)
    if wps_pin:
        normalized_pin = wps_pin.upper() if wps_pin.upper() == "NULL" else wps_pin
        clauses.append("wps_pin = %s")
        params.append(normalized_pin)
    if wsc_device_name:
        clauses.append("wsc_device_name = %s")
        params.append(wsc_device_name)
    if wsc_model:
        clauses.append("wsc_model = %s")
        params.append(wsc_model)
    if search:
        like_term = f"%{search.lower()}%"
        if search_only_bssid:
            clauses.append("LOWER(bssid) LIKE %s")
            params.append(like_term)
        else:
            sub_clauses: List[str] = []

            sub_clauses.append("LOWER(essid) LIKE %s")
            params.append(like_term)

            if search_include_bssid:
                sub_clauses.append("LOWER(bssid) LIKE %s")
                params.append(like_term)

            sub_clauses.append("LOWER(password) LIKE %s")
            params.append(like_term)

            if search_include_wps_pin:
                sub_clauses.append("LOWER(wps_pin) LIKE %s")
                params.append(like_term)

            sub_clauses.append("LOWER(COALESCE(wsc_device_name, '')) LIKE %s")
            params.append(like_term)
            sub_clauses.append("LOWER(COALESCE(wsc_model, '')) LIKE %s")
            params.append(like_term)

            clauses.append("(" + " OR ".join(sub_clauses) + ")")

    return clauses, params


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
    search_include_bssid: bool = True,
    search_include_wps_pin: bool = True,
    search_only_bssid: bool = False,
) -> List[WifiRecord]:
    clauses, params = _build_query_filters(
        bssid=bssid,
        essid=essid,
        password=password,
        wps_pin=wps_pin,
        wsc_device_name=wsc_device_name,
        wsc_model=wsc_model,
        search=search,
        search_include_bssid=search_include_bssid,
        search_include_wps_pin=search_include_wps_pin,
        search_only_bssid=search_only_bssid,
    )
    query = [
        "SELECT bssid, essid, password, wps_pin, wsc_device_name, wsc_model, added",
        "FROM wifi_records",
    ]

    if clauses:
        query.append("WHERE " + " AND ".join(clauses))

    query.append("ORDER BY added DESC")

    if limit is not None:
        query.append("LIMIT %s")
        params.append(limit)
    if offset is not None:
        if limit is None:
            query.append("LIMIT 18446744073709551615")
        query.append("OFFSET %s")
        params.append(offset)

    sql = " ".join(query)

    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(sql, params)
            rows = cursor.fetchall()
    return [WifiRecord.from_row(row) for row in rows]


def count_records(
    *,
    bssid: Optional[str] = None,
    essid: Optional[str] = None,
    password: Optional[str] = None,
    wps_pin: Optional[str] = None,
    wsc_device_name: Optional[str] = None,
    wsc_model: Optional[str] = None,
    search: Optional[str] = None,
    search_include_bssid: bool = True,
    search_include_wps_pin: bool = True,
    search_only_bssid: bool = False,
) -> int:
    clauses, params = _build_query_filters(
        bssid=bssid,
        essid=essid,
        password=password,
        wps_pin=wps_pin,
        wsc_device_name=wsc_device_name,
        wsc_model=wsc_model,
        search=search,
        search_include_bssid=search_include_bssid,
        search_include_wps_pin=search_include_wps_pin,
        search_only_bssid=search_only_bssid,
    )

    sql_parts = ["SELECT COUNT(*) AS total FROM wifi_records"]
    if clauses:
        sql_parts.append("WHERE " + " AND ".join(clauses))

    sql = " ".join(sql_parts)

    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(sql, params)
            row = cursor.fetchone()
            total = row["total"] if row else 0
    return int(total)


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
    search_include_bssid = True
    search_include_wps_pin = True
    search_only_bssid = False

    if search:
        upper_search = search.upper()

        if PARTIAL_BSSID_SEARCH_PATTERN.fullmatch(search):
            search_only_bssid = True
            search_include_bssid = True
            search_include_wps_pin = False
        else:
            search_include_bssid = False

        if "NULL" in upper_search:
            search_include_wps_pin = True
        else:
            if search.isdigit() and len(search) <= 9:
                search_include_wps_pin = True
            else:
                search_include_wps_pin = False

    page_param = request.args.get("page", "1")
    try:
        page = int(page_param)
    except ValueError:
        page = 1
    if page < 1:
        page = 1

    per_page = PAGE_SIZE
    offset = (page - 1) * per_page
    fetch_limit = per_page + 1

    records = query_records(
        search=search or None,
        limit=fetch_limit,
        offset=offset,
        search_include_bssid=search_include_bssid,
        search_include_wps_pin=search_include_wps_pin,
        search_only_bssid=search_only_bssid,
    )

    has_next = len(records) > per_page
    if has_next:
        records = records[:per_page]
    has_prev = page > 1
    record_count = len(records)

    return render_template(
        "index.html",
        records=records,
        search=search,
        page=page,
        per_page=per_page,
        record_count=record_count,
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
    except pymysql_err.IntegrityError as exc:
        logger.exception("Failed to insert record")
        return jsonify({"error": "Failed to insert record", "details": str(exc)}), 400
    except pymysql_err.MySQLError as exc:
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
    raw_limit = request.args.get("limit")
    try:
        if raw_limit is None or not raw_limit.strip():
            limit = PAGE_SIZE
        else:
            limit = int(raw_limit)
    except ValueError:
        return jsonify({"error": "limit must be an integer"}), 400
    if limit <= 0:
        limit = PAGE_SIZE
    limit = min(limit, PAGE_SIZE)

    page_param = request.args.get("page", "1")
    try:
        page = int(page_param)
    except ValueError:
        page = 1
    if page < 1:
        page = 1
    offset = (page - 1) * limit

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
        offset=offset,
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
