# BDAL — Cybersecurity Threat Analytics

A **simulated** cybersecurity data pipeline built for a BDAL academic research project: raw threat records are streamed in batches, ingested by Apache Flume, aggregated with PySpark, and presented through a Streamlit dashboard and a vanilla HTML/CSS/JS console.

> **The dataset is synthetic.** 3,000 generated records (2015–2024, 10 countries, 6 attack types) with no real victims, incidents, or financial figures. This is a research demonstration, **not** a live threat feed.

---

## Architecture

```
data/Global_Cybersecurity_Threats_2015-2024.csv
        │
        │  src/stream_data.py      (headerless CSV batches, atomic rename)
        ▼
    incoming/                    ← Flume spooldir
        │
        │  Apache Flume: spooldir → memory channel → file_roll sink
        ▼
    output/flume/                (flat roll files)
        │
        │  src/analytics.py       (PySpark, local[*])
        ▼
    output/analytics/<name>/     (7 headed CSV aggregations)
        │
        ├─► dashboard/app.py      (Streamlit, :8501)   → charts from the RAW csv
        └─► web/                  (HTML/CSS/JS console) → charts from RAW csv + PySpark output
```

### The seven PySpark aggregations

`attacks_by_year` · `attacks_by_country` · `attacks_by_type` · `attacks_by_industry` · `attacks_by_source` · `attacks_by_vulnerability` · `attacks_by_defense`

---

## Requirements

| Component | Version used | Notes |
|---|---|---|
| Python | 3.14 (3.11+ works) | `pip install -r requirements.txt` |
| Java | 17 (Temurin 17) | Spark and Flume both need 8/11/17; Java 21+ breaks Spark |
| Apache Flume | 1.11.0 | agent reads `flume/flume.conf` |
| Hadoop winutils | 3.3.6 | **Windows only** — see [Windows notes](#windows-notes) |
| PySpark | 4.2.0 | ships its own Hadoop 3.5.0 jars |

`requirements.txt` is intentionally unpinned (`streamlit`, `pandas`, `plotly`, `pyspark`).

---

## Quick start

```bash
pip install -r requirements.txt

# 1. batch the dataset into incoming/  (30 files × 100 rows by default)
python src/stream_data.py --batch-size 100 --delay 0 --max-batches 0

# 2. start the Flume agent (spooldir → output/flume/)
export PROJECT_DIR="$PWD"
bin/flume-ng agent --conf conf --conf-file flume/flume.conf --name a1

# 3. aggregate with PySpark → output/analytics/
python src/analytics.py

# 4a. Streamlit dashboard
streamlit run dashboard/app.py        # http://localhost:8501

# 4b. vanilla web console
python web/serve.py 8080               # http://localhost:8080/web/
```

`--max-batches 0` means "all rows". `--delay` is the pause between batches (use `0` to generate everything at once).

Flume renames every consumed batch to `*.COMPLETED` inside `incoming/`. Rename one back to `.csv` to re-ingest it.

### The web console (`web/`)

A dependency-free front end (no build step, no framework) with four screens — **Dashboard**, **Threat Analytics**, **Records**, **Diagnostics** — plus filters, live pipeline status, and Chart.js visualisations.

`web/serve.py` is a small read-only static server that also exposes the pipeline state as JSON:

| Endpoint | Returns |
|---|---|
| `GET /api/status` | dataset rows, records ingested, Flume roll files/bytes, pending batches, per-aggregation row counts |
| `GET /api/analytics/<name>` | `{"columns": [...], "rows": [[...]]}` for one aggregation |

It only reads files — it never writes to the pipeline directories.

---

## Project layout

```
├── data/       generated dataset (3000 rows, 10 columns)
├── src/        stream_data.py (batching) · analytics.py (PySpark)
├── flume/      flume.conf (agent a1: spooldir → memory → file_roll)
├── dashboard/  app.py (Streamlit, port 8501)
├── web/        index.html · styles.css · animations.css · app.js · serve.py
├── incoming/   Flume spool dir (generated, git-ignored)
├── output/     flume roll files + analytics output (generated, git-ignored)
└── screenshots/ reference screenshots of the Streamlit dashboard
```

---

## Things worth knowing before you change something

- **Column order is positional and unversioned.** `stream_data.py` writes headerless CSV; `analytics.py` splits each line on `,` and maps fields by index to a hardcoded `COLUMNS` list. Reordering or renaming dataset columns silently corrupts every aggregate.
- **`analytics.py` needs Flume to have run first** — it reads `output/flume/`, and raises `RuntimeError("No valid records found in Flume output.")` on zero valid rows. It re-reads the whole directory on every run, so clear `output/flume/` between full reruns or old roll files get counted twice.
- **The Streamlit dashboard does not consume the PySpark output.** Every chart and metric in `dashboard/app.py` is computed from the raw dataset. The helper `load_pyspark_yearly()` (`dashboard/app.py:38`) reads `output/analytics/attacks_by_year/` but is never called — it is the intended hook if you want to surface the Spark results in that UI. The `web/` console *does* read both.
- **`flume/flume.conf` uses `${env:PROJECT_DIR}`** for the spool dir and the sink directory, so export `PROJECT_DIR` before starting the agent.
- `stream_data.py` stages each batch as `.batch_XXXX.tmp` in the project root and then atomically renames it into `incoming/`. The temp file must not sit in the spool dir or Flume would read a partial batch.

---

## Windows notes

- Spark and Flume need **Java 17**; the machine's default `java` may be a newer JDK, which breaks Spark with `ClassNotFoundException: jdk.internal.ref.Cleaner`. Set `JAVA_HOME` explicitly.
- Hadoop needs its native Windows library. Without it, PySpark fails with `UnsatisfiedLinkError: 'boolean org.apache.hadoop.io.nativeio.NativeIO$Windows.access0(...)'`. Fix: point `HADOOP_HOME` at a folder whose `bin/` contains `hadoop.dll` + `winutils.exe` and put that `bin` on `PATH`. Overriding `java.library.path` does **not** work — the JVM's Windows DLL search still applies.
- `PROJECT_DIR` must use **forward slashes**: Flume writes it into a Java properties file where a backslash is an escape character.

```powershell
$env:JAVA_HOME   = 'C:\path\to\jdk-17'
$env:HADOOP_HOME = 'C:\path\to\hadoop-win'
$env:PATH        = "$env:JAVA_HOME\bin;$env:HADOOP_HOME\bin;$env:PATH"
$env:PROJECT_DIR = 'C:/path/to/BDAL-Cybersecurity-Analytics'
```

---

## License / attribution

The dataset is synthetic and generated for this project. Apache Flume, PySpark, Streamlit, Plotly and Chart.js are used under their own licenses.
