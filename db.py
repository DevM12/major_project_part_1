import sqlite3
from pathlib import Path

DB = Path(__file__).with_name("zero_trust.db")


def connect():
    return sqlite3.connect(DB)


def init_db():
    con = connect()
    con.execute("""CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT, user_name TEXT, resource_id TEXT,
        authenticated INTEGER, asset_criticality INTEGER,
        threat_probability REAL, impact REAL,
        requests_per_minute REAL, failed_logins INTEGER,
        label TEXT, risk_score REAL, risk_level TEXT,
        z_score REAL, anomaly INTEGER, decision TEXT,
        access_level TEXT, reason TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""")
    con.commit()
    return con


def save_event(e, risk, level, z, anomaly, decision, access, reason):
    con = connect()
    con.execute("""INSERT INTO events
        (user_id,user_name,resource_id,authenticated,asset_criticality,
         threat_probability,impact,requests_per_minute,failed_logins,label,
         risk_score,risk_level,z_score,anomaly,decision,access_level,reason)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (e.user_id,e.user_name,e.resource_id,int(e.authenticated),e.asset_criticality,
         e.threat_probability,e.impact,e.requests_per_minute,e.failed_logins,e.label,
         risk,level,z,int(anomaly),decision,access,reason))
    con.commit()
    con.close()


def all_events():
    con = connect()
    con.row_factory = sqlite3.Row
    rows = [dict(r) for r in con.execute("SELECT * FROM events ORDER BY id DESC LIMIT 50")]
    con.close()
    return rows


def benign_training_events():
    con = connect()
    con.row_factory = sqlite3.Row
    rows = [dict(r) for r in con.execute("SELECT requests_per_minute, failed_logins FROM events WHERE label='benign' LIMIT 100")]
    con.close()
    return rows


def metrics():
    con = connect()
    total = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    counts = dict(con.execute("SELECT decision, COUNT(*) FROM events GROUP BY decision").fetchall())
    con.close()
    return {"total": total, "decisions": counts}
