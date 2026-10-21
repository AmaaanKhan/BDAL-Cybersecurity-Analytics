# AGENTS.md

## What this project is

A BDAL academic research project: a **simulated** cybersecurity threat pipeline
(dataset → batch generator → Apache Flume → PySpark → Streamlit dashboard).

The data is synthetic (3000 rows, 2015–2024, 10 countries, 6 attack types).
Nothing here is a live threat feed — keep the "research demonstration" framing in
any UI copy or documentation you add.

## Pipeline wiring (not obvious from the filenames)

1. `src/stream_data.py` → writes **headerless** CSV batches into `incoming/`
   (this is Flume's spooldir directory).
2. Flume: spooldir source → memory channel → file_roll sink → `output/flume/`.
3. `src/analytics.py` (PySpark, `local[*]`) reads `output/flume/` and writes
   `output/analytics/<aggregation_name>/` as headed CSV.
4. `dashboard/app.py` (Streamlit, port 8501) renders the charts.

**The dashboard does not actually consume step 3.** Every chart and metric in
`dashboard/app.py` is computed from the raw dataset in `data/`. The helper
`load_pyspark_yearly()` (`dashboard/app.py:38`) reads `output/analytics/attacks_by_year/`
but is **never called** — it is the intended hook if you are ever asked to surface
the PySpark results in the UI.

## Commands

```bash
pip install -r requirements.txt

python src/stream_data.py --batch-size 100 --delay 2 --max-batches 30
#   --max-batches 0 (default) = all 3000 rows; default batch 100 -> 30 files

bin/flume-ng agent --conf flume --conf-file flume/flume.conf --name a1

python src/analytics.py

streamlit run dashboard/app.py     # http://localhost:8501
```

`--max-batches` and `--delay` are the only knobs; there is no config file for them.

## Gotchas (all verified against this checkout)

- **`flume/flume.conf` used to hardcode absolute Linux paths**
  (`/home/personal/BDAL-Cybersecurity-Analytics/{incoming,output/flume}`). It now
  uses `${env:PROJECT_DIR}/incoming` and `${env:PROJECT_DIR}/output/flume`, so
  `PROJECT_DIR` must be exported before starting the agent — Flume resolves
  `${env:VAR}` in config *values* only. The Python scripts are **not**
  path-bound: they derive everything from `Path(__file__).resolve().parent.parent`.
- **Column order is positional and unversioned.** `stream_data.py` writes
  `header=False`; `analytics.py` splits each line on `,` and maps fields by index
  to the hardcoded `COLUMNS` list (`src/analytics.py:10`). Reordering or renaming
  dataset columns silently corrupts every aggregate. All 3000 rows currently have
  exactly 10 fields and no embedded commas — the naive split breaks the day that
  stops being true.
- **`analytics.py` requires Flume to have run first.** It does
  `spark.read.text(output/flume)` — a missing directory is a Spark path error, and
  0 valid rows raises `RuntimeError("No valid records found in Flume output.")`.
  It re-reads the **whole** `output/flume/` directory on every run, so clear that
  directory between full pipeline reruns or old roll files are counted twice.
- **`flume.conf` does not set `a1.sinks.k1.fileType`.** `analytics.py` requires the
  roll files to be plain headerless text CSV. If the sink writes a sequence or
  serialized file instead, `spark.read.text` finds nothing. Add
  `a1.sinks.k1.fileType = CSV` if the defaults differ on your Flume build.
- **The spooldir source renames consumed files with a `.COMPLETED` suffix** — they
  stay in `incoming/`. Renaming one back to `.csv` re-ingests it.
- **`stream_data.py` writes its temp file to the project root** (`.batch_XXXX.tmp`),
  then atomically renames it into `incoming/`. That is deliberate: the temp file must
  not sit in the spool directory or Flume would read a partial batch. An interrupted
  run leaves `.batch_*.tmp` in the root — delete them.
- **`.gitignore` ignores all of `output/` and `incoming/`.** The `!output/analytics/`
  / `!output/flume/` negation lines are overridden by the later `output/analytics/`
  and `output/flume/` lines, so nothing under `output/` is tracked. Do not expect
  generated CSVs to be committed.

## Environment reality on this machine (verified working end to end)

Installed: pandas 3.0.6, plotly 7.0.0, streamlit 1.64.0, **pyspark 4.2.0**
(Python 3.14). `requirements.txt` is **unpinned**, so these are whatever pip
resolved last.

Tooling installed outside the repo (not in the checkout):

| Tool | Path |
|---|---|
| JDK 17 (Temurin 17.0.20.1+1) | `C:\Users\HP\Downloads\YT-DLP\jdk17\jdk-17.0.20.1+1` |
| Flume 1.11.0 | `C:\Users\HP\Downloads\YT-DLP\apache-flume-1.11.0-bin` |
| Hadoop 3.3.6 winutils (`hadoop.dll` + `winutils.exe`) | `C:\Users\HP\Downloads\YT-DLP\hadoop-win\bin` |

System Java is 26 — Spark/Flume need 17. `JAVA_HOME` (JDK 17) and `HADOOP_HOME`
(winutils) are now **persisted at user scope**, and `hadoop-win\bin` +
`jdk17\bin` are on the machine/user PATH, so a fresh terminal works with no
setup. Note `java` on PATH still resolves to Oracle's Java 26 (machine PATH
wins) — that is fine: Spark and Flume both honour `JAVA_HOME`. Java 26 breaks
Spark with `ClassNotFoundException: jdk.internal.ref.Cleaner`.

### Windows run recipe (this is the sequence that works)

```powershell
# 1. batches -> incoming/   (30 files, 100 rows each)
python src\stream_data.py --batch-size 100 --delay 0 --max-batches 0

# 2. Flume agent: spooldir -> memory channel -> file_roll -> output/flume/
#    JAVA_HOME/HADOOP_HOME/PATH are already persisted (see above) —
#    only PROJECT_DIR is per-shell.
$env:PROJECT_DIR = 'C:/Users/HP/Downloads/YT-DLP/BDAL-Cybersecurity-Analytics-main'
Set-Location 'C:\Users\HP\Downloads\YT-DLP\apache-flume-1.11.0-bin'
.\bin\flume-ng.cmd agent --conf conf --conf-file "$env:PROJECT_DIR/flume/flume.conf" --name a1

# 3. PySpark -> output/analytics/<name>/
python src\analytics.py

# 4. dashboard
streamlit run dashboard\app.py
```

`PROJECT_DIR` must use **forward slashes** — Flume writes it into a Java
properties file where a backslash is an escape character.

### Hadoop needs winutils on Windows (the classic trap)

`src/analytics.py` fails on Windows with
`UnsatisfiedLinkError: 'boolean org.apache.hadoop.io.nativeio.NativeIO$Windows.access0(...)'`
raised from `FileUtil.canRead` → `RawLocalFileSystem.listStatus`. That is
Hadoop calling its **native** Windows library. Fix = `HADOOP_HOME` pointing at a
folder whose `bin/` holds `hadoop.dll` + `winutils.exe` (Hadoop 3.3.6 build works
against the Hadoop 3.5.0 jars Spark 4.2.0 ships), plus that `bin` on `PATH`.
Overriding `java.library.path` does **not** help — the JVM's Windows DLL search
still applies. `winutils.exe` itself is not needed for this code path; the
`hadoop.dll` is the part that matters.

- `pandas 3.x` / `streamlit 1.64` use `use_container_width=`, which is deprecated
  in favour of `width="stretch"` in current Streamlit. It still runs.

## What does not exist here

No README, no tests, no CI workflow, no linter/formatter/typechecker config, no
`opencode.json`, no package manifest. Verification is manual: run the script and
read its stdout. `analytics.py` prints a summary and a per-aggregation "Saved:"
line; `stream_data.py` prints per-batch counts.

## Conventions to keep

- All three Python scripts resolve paths relative to their own file
  (`Path(__file__).resolve().parent.parent`). Keep it that way; do not hardcode
  absolute paths into the scripts.
- `analytics.py` casts `Year` to int, `Financial Loss` to double,
  `Number of Affected Users` to long, `Incident Resolution Time` to double, and
  drops rows where any of those are null. `dashboard/app.py` does the equivalent
  with `pd.to_numeric(..., errors="coerce")`. Keep both casts in sync if you add
  a numeric column.
