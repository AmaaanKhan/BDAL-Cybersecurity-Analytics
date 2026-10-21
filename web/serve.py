r"""Static server + small read-only API for the BDAL web frontend.

    python web\serve.py            # http://localhost:8080/web/
    python web\serve.py 9000       # custom port

Serves the repo root and exposes:
  GET /api/status                 -> pipeline status (JSON)
  GET /api/analytics/<name>       -> PySpark aggregation output as
                                     {"columns": [...], "rows": [[...]]}

Read-only. Never writes to the repo.
"""
import csv
import json
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_FILE = ROOT / "data" / "Global_Cybersecurity_Threats_2015-2024.csv"
ANALYTICS_DIR = ROOT / "output" / "analytics"
FLUME_DIR = ROOT / "output" / "flume"
INCOMING_DIR = ROOT / "incoming"


def _num(value):
    """Return int/float for numeric-looking strings, else the original string."""
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        return value


def _read_aggregation(folder):
    """Merge every part-*.csv of a Spark aggregation into columns + rows."""
    files = sorted(folder.glob("*.csv"))
    columns, rows = [], []
    for path in files:
        with path.open(newline="", encoding="utf-8") as handle:
            for row in csv.reader(handle):
                if not row:
                    continue
                if not columns:
                    columns = row
                    continue
                elif row == columns:
                    continue
                rows.append([_num(cell) for cell in row])
    return columns, rows


def _status():
    flume_files = [p for p in FLUME_DIR.glob("*") if p.is_file()] if FLUME_DIR.exists() else []
    completed = list(INCOMING_DIR.glob("*.COMPLETED")) if INCOMING_DIR.exists() else []
    pending = list(INCOMING_DIR.glob("*.csv")) if INCOMING_DIR.exists() else []

    analytics = {}
    records = 0
    if ANALYTICS_DIR.exists():
        for folder in sorted(p for p in ANALYTICS_DIR.iterdir() if p.is_dir()):
            columns, rows = _read_aggregation(folder)
            analytics[folder.name] = len(rows)
            if folder.name == "attacks_by_year":
                records = sum((row[1] if len(row) > 1 else 0) or 0 for row in rows)

    dataset_rows = 0
    if DATA_FILE.exists():
        with DATA_FILE.open(encoding="utf-8") as handle:
            dataset_rows = max(sum(1 for _ in handle) - 1, 0)

    return {
        "dataset_rows": dataset_rows,
        "records_ingested": records,
        "flume_files": len(flume_files),
        "flume_bytes": sum(p.stat().st_size for p in flume_files),
        "incoming_completed": len(completed),
        "incoming_pending": len(pending),
        "analytics": analytics,
    }


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/api/status":
            return self._json(_status())
        if path.startswith("/api/analytics/"):
            return self._analytics(path[len("/api/analytics/"):])
        return super().do_GET()

    def _analytics(self, name):
        if not name or "/" in name or "\\" in name or name.startswith("."):
            return self.send_error(404, "Unknown aggregation")
        folder = ANALYTICS_DIR / name
        if not folder.is_dir():
            return self.send_error(404, "No such aggregation")
        columns, rows = _read_aggregation(folder)
        return self._json({"columns": columns, "rows": rows})

    def _json(self, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    print(f"BDAL web frontend -> http://localhost:{port}/web/")
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
