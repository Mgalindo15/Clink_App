import sqlite3
from pathlib import Path

# Path fixed to file parent (clink-lab), can change later to parameterize based on env
DB_PATH = Path(__file__).parent / "clink-db"
SCHEMA_SQL = Path(__file__).parent / "schema.sql"

def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db():
    with get_conn as conn:
        conn.executescript(SCHEMA_SQL.read_text())
