# 3WiFi Lite

Lightweight Flask web service that exposes an HTML page and REST API for storing Wi-Fi access point details.

## Features

* Renders a table with columns **BSSID | ESSID | Password | WPS Pin | WSC Device Name | WSC Model | Added** on the landing page. The `Added` column shows the record month in `YYYY-MM` (UTC).
* REST API for adding new entries and searching by BSSID, ESSID, password, WPS pin, WSC device name, WSC model, or any partial match.
* Automatic database backups to local storage, Mega.nz, or another configured provider.
* Provided strictly as a website template for safeguarding and testing your own Wi-Fi network.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

By default the server listens on `http://0.0.0.0:12345`.

## API

### Create a record

```
POST /api/records
Content-Type: application/json
```

Request body:

```json
{
  "bssid": "04:95:E6:37:C5:E8",
  "essid": "ExampleWiFi",
  "password": "secret123",
  "wps_pin": "12345670", // or "NULL"
  "wsc_device_name": "RouterBoard",
  "wsc_model": "RB2011"
}
```

**Validation rules:**

* `bssid` — format `XX:XX:XX:XX:XX:XX` (hex digits, case insensitive).
* `wps_pin` — required. Either 8 digits or the string `NULL`.
* `essid` — required field.
* `password` — required and must be at least 8 characters long.
* `wsc_device_name`, `wsc_model` — optional strings. Omit or send as empty strings when not available.

Response `201 Created` returns the stored record in JSON.

### Search records

```
GET /api/records?search=ELTEX
GET /api/records?bssid=04:95:E6:37:C5:E8
GET /api/records?essid=ExactESSID
GET /api/records?password=rostelecom
GET /api/records?wps_pin=12345670
GET /api/records?wsc_device_name=RouterBoard
GET /api/records?wsc_model=RB2011
```

The `search` parameter performs a case-insensitive partial lookup on BSSID, ESSID, password, WPS pin, WSC device name, and WSC model. You can search for any substring (for example `12`) via the API or the homepage search bar and all matching records will be returned.

Exact filters are available through the `bssid`, `essid`, `password`, `wps_pin`, `wsc_device_name`, and `wsc_model` query parameters.
The response contains an array of objects with fields `bssid`, `essid`, `password`, `wps_pin`, `wsc_device_name`, `wsc_model`, `added` (month captured in `YYYY-MM`, UTC).

### Fetch records by BSSID

```
GET /api/records/04:95:E6:37:C5:E8
```

Returns an array of all matching records for the specified BSSID or `404` when nothing matches.

## Backups

Backups run automatically in a background thread with the interval `BACKUP_INTERVAL_SECONDS` (default 3600 seconds).

The `BACKUP_PROVIDER` environment variable selects the provider:

* `local` (default) — copies are stored in `./backups` or the directory specified by `LOCAL_BACKUP_DIR`.
* `mega` — uploads to Mega.nz. Requires `MEGA_EMAIL` and `MEGA_PASSWORD`. Folder name is controlled by `MEGA_FOLDER` (default `3wifi-lite-backups`). Needs the [`mega.py`](https://pypi.org/project/mega.py/) package.
* `none` — disable automatic backups.

Example run with Mega.nz:

```bash
export BACKUP_PROVIDER=mega
export MEGA_EMAIL="user@example.com"
export MEGA_PASSWORD="your-strong-password"
pip install mega.py
python app.py
```

## Environment variables

| Name | Default | Description |
| --- | --- | --- |
| `HOST` | `0.0.0.0` | Address the server binds to |
| `PORT` | `12345` | HTTP port |
| `BACKUP_INTERVAL_SECONDS` | `3600` | Delay between automatic backups |
| `BACKUP_PROVIDER` | `local` | Backup provider (`local`, `mega`, `none`) |
| `LOCAL_BACKUP_DIR` | `./backups` | Directory for local copies |
| `MEGA_EMAIL`, `MEGA_PASSWORD` | — | Mega.nz credentials |
| `MEGA_FOLDER` | `3wifi-lite-backups` | Mega.nz folder name |

## Project layout

```
.
├── app.py
├── data.sqlite3          # created automatically on first run
├── index.html
├── style.css
└── README.md
```

## Disclaimer

This repository is a template meant solely for protecting and testing wireless networks that you own or administer. Always follow applicable laws and obtain explicit permission before interacting with third-party infrastructure.

## License

MIT
