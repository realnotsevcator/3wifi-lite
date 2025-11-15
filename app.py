import logging
import os
import re
import shutil
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from flask import Flask, jsonify, render_template, request

APP_ROOT = Path(__file__).resolve().parent
DATABASE_PATH = APP_ROOT / "data.sqlite3"
BACKUP_INTERVAL_SECONDS = int(os.getenv("BACKUP_INTERVAL_SECONDS", "3600"))

BSSID_PATTERN = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
WPS_PIN_PATTERN = re.compile(r"^[0-9]{8}$")


logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger(__name__)


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
) -> List[WifiRecord]:
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

    sql = (
        "SELECT "
        "bssid, essid, password, wps_pin, wsc_device_name, wsc_model, added "
        "FROM wifi_records"
    )
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY datetime(added) DESC"
    if limit:
        sql += " LIMIT ?"
        params.append(str(limit))

    with get_db_connection() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [WifiRecord.from_row(row) for row in rows]


init_db()
app = Flask(
    __name__,
    template_folder=str(APP_ROOT),
    static_folder=str(APP_ROOT),
)
backup_manager = BackupManager(create_backup_provider(), BACKUP_INTERVAL_SECONDS)
backup_manager.start()


@app.route("/")
def index() -> str:
    raw_search = request.args.get("search", "")
    search = raw_search.strip()
    records = query_records(search=search or None)
    return render_template("index.html", records=records, search=search)


@app.post("/api/records")
def add_record():
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
    except sqlite3.IntegrityError as exc:
        logger.exception("Failed to insert record")
        return jsonify({"error": "Failed to insert record", "details": str(exc)}), 400

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
