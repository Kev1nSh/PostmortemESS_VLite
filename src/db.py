import sqlite3
import hashlib
import json
import os 
import hmac
from datetime import datetime, timedelta
from contextlib import closing

DB_FILE = '/data/postmortem.db'

REPORT_RETAIN_DAYS = 30     # Number of days to retain full reports
ADDRESS_TTL_DAYS = 90     # Number of days to retain hashed sender addresses 
DOMAIN_HITS_TTL_DAYS = 90     # Number of days to retain domain daily report counts

_key = os.environ.get("HASH_KEY")
if not _key:
    raise ValueError("HASH_KEY environment variable is not set")
HASH_KEY = _key.encode()  # Convert to bytes for HMAC

PERIODS = {
    "24h": "-24 hours",
    "7d": "-7 days",
    "14d": "-14 days",
    "21d": "-21 days",
    "30d": "-30 days",
    "90d": "-90 days",
    "all": None,
}

def _modifier(period: str) -> str | None:
    # Validates the period and translates it to an SQL modifier string.
    # "all" returns None, which means no time filter will be applied.
    if period not in PERIODS:
        raise ValueError(f"Invalid period: {period!r}")
    return PERIODS[period]

def get_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA secure_delete = ON;")  # Overwrite deleted data for security
    return conn

def init_db():
    conn = get_connection()
    conn.executescript("""
    
        CREATE TABLE IF NOT EXISTS reports (
            report_id TEXT PRIMARY KEY,
            created_at TIMESTAMP NOT NULL,
            verdict TEXT NOT NULL,
            sender_address TEXT,
            sender_domain TEXT,
            report_json TEXT,
            purge_at TIMESTAMP NOT NULL
        );

        CREATE TABLE IF NOT EXISTS known_addresses (
            address_hash TEXT PRIMARY KEY,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            report_count INTEGER DEFAULT 1,
            last_verdict TEXT NOT NULL,
            expires_at TIMESTAMP NOT NULL
        );

        CREATE TABLE IF NOT EXISTS domain_daily_reports (
            sender_domain TEXT NOT NULL,
            day  TEXT NOT NULL,
            report_count INTEGER DEFAULT 0,
            PRIMARY KEY (sender_domain, day)        
        );
    
        CREATE INDEX IF NOT EXISTS idx_reports_created_at 
        ON reports (created_at);

    """)
    conn.commit()
    conn.close()

def address_hasher(value: str) -> str:
    # This function is for hashing the sender addresses
    # This func takes a string, lowercase it and strip down all the "spaces"
    # Then makes a HMAC hash using the HASH_KEY and returns the hashed value
    
    normalized = value.strip().lower()
    return hmac.new(HASH_KEY, normalized.encode(), hashlib.sha256).hexdigest()


def save_report(report_id: str, verdict: str, sender_address: str,
                sender_domain: str, full_result: dict) -> None:
    # This function is for saving the report after being scanned
    # The func takes all important variables and saved it in to their correspondent variable in the db (reports)
    # Report is saved with a purge date, which is the current date + REPORT_RETAIN_DAYS
    now = datetime.utcnow()
    with closing(get_connection()) as conn:
        conn.execute(
            "INSERT INTO reports (report_id, created_at, verdict, sender_address, "
            "sender_domain, report_json, purge_at) VALUES (?,?,?,?,?,?,?)", 
            (report_id, now, verdict, sender_address, sender_domain, 
            json.dumps(full_result), now + timedelta(days=REPORT_RETAIN_DAYS)),
        )
        conn.commit()

def get_reports(limit: int = 50):
    # This function returns the 50 latest reports without the full report json
    # Only reports inside the retention period will be returned

    cutoff = datetime.utcnow() - timedelta(days=REPORT_RETAIN_DAYS)
    with closing(get_connection()) as conn:
        rows = conn.execute(
            """
            SELECT
                report_id, 
                created_at, 
                verdict, 
                sender_address,
                sender_domain, 
                purge_at
            FROM reports            
            WHERE created_at >= ?
            ORDER BY created_at DESC
            LIMIT ? 
            """,
            (cutoff, limit),
        ).fetchall()
    return [dict(row) for row in rows]

def record_domain_report(domain: str) -> None:
    # Adds one report to the domain_daily_reports table for the given domain and current day.
    # Domain is normalized to lowercase and stripped of "spaces" before being stored in clean format.
    if not domain or not domain.strip():
        return  # Skip if domain is empty or None

    day = datetime.utcnow().strftime("%Y-%m-%d")
    with closing(get_connection()) as conn:
        conn.execute(
            """
            INSERT INTO domain_daily_reports (sender_domain, day, report_count)
            VALUES (?, ?, 1)
            ON CONFLICT(sender_domain, day) DO UPDATE SET report_count = report_count + 1
            """,
            (domain.strip().lower(), day),
        )
        conn.commit()

def record_sender_address(address: str, verdict: str) -> None:
    # This function records and updates a sender address in the known_addresses table.
    # The address is hashed with secret key and only the hash is stored in the database.
    # First time an address is seen a new row is created, seen again the counter goes up.
    # The latest verdict is also stored, and the expires_at is updated to now + ADDRESS_TTL_DAYS.
    
    if not address or not address.strip():
        return  # Skip if address is empty or None  

    hashed_address = address_hasher(address)
    now = datetime.utcnow()
    expires_at = now + timedelta(days=ADDRESS_TTL_DAYS)

    with closing(get_connection()) as conn:
        conn.execute(
            "DELETE FROM known_addresses WHERE address_hash = ? AND expires_at < ?",
            (hashed_address, now),
        )   
        conn.execute(
            """
            INSERT INTO known_addresses 
                (address_hash, first_seen, 
                last_seen, report_count, last_verdict, expires_at)
            VALUES (?, ?, ?, 1, ?, ?)
            ON CONFLICT(address_hash) DO UPDATE SET 
                last_seen = excluded.last_seen,
                report_count = known_addresses.report_count + 1,
                last_verdict = excluded.last_verdict,
                expires_at = excluded.expires_at
            """,
            (hashed_address, now, now, verdict, expires_at),
        )
        conn.commit()
       
def get_known_address(address: str) -> dict | None:
    # This function retrieves a known address from the known_addresses table.
    # Returns a dictionary with parameters or None if the address is not found or has expired.

    if not address or not address.strip():
        return None  # Skip if address is empty or None

    with closing(get_connection()) as conn:
        row = conn.execute(
            """
            SELECT first_seen, last_seen, report_count, last_verdict
            FROM known_addresses
            WHERE address_hash = ? and expires_at >= ?
            """,
            (address_hasher(address), datetime.utcnow()),
        ).fetchone()
    return dict(row) if row else None

def purge_expired_data() -> None:
    # This function purges everything that has passed its retention time:
    # - Full reports (purge_at)
    # - Hashed sender addresses (expires_at)
    # - Domain daily reports older (DOMAIN_HITS_TTL_DAYS)
    now = datetime.utcnow()
    with closing(get_connection()) as conn:
        conn.execute("DELETE FROM reports WHERE purge_at < ?", (now,))
        conn.execute("DELETE FROM known_addresses WHERE expires_at < ?", (now,))
        conn.execute(
            "DELETE FROM domain_daily_reports WHERE day < date('now', ?)",
            (f"-{DOMAIN_HITS_TTL_DAYS} days",)
        )
        conn.commit()

def get_verdict_stats(period: str = "30d") -> list[dict]:

    # Feeds the verdict graph: how many reports of each verdict type were received in the last 30 days.
    # Reads from reports so it only look back as far as the retention period (REPORT_RETAIN_DAYS)

    mod = _modifier(period)
    with closing(get_connection()) as conn:
        rows = conn.execute(
            """
            SELECT 
                verdict, 
                COUNT(*) as count 
            FROM reports 
            WHERE (:mod IS NULL OR created_at >= datetime('now', :mod))
            GROUP BY verdict
            ORDER BY count DESC
            """,
            {"mod": mod},
        ).fetchall()
    return [dict(row) for row in rows]

def get_domain_stats(period: str = "90d") -> list[dict]:
    # Feeds the top domains graph: the top 10 domains most often reported in the specified period.
    # Reads from domain_daily_reports so it can look back as far as 90 days even though full reports are deleted after 30 days.
    
    mod = _modifier(period)
    with closing(get_connection()) as conn:
        rows = conn.execute(
            """
            SELECT sender_domain AS domain, SUM(report_count) AS count 
            FROM domain_daily_reports
            WHERE (:mod IS NULL OR day >= date('now', :mod))
            GROUP BY sender_domain
            ORDER BY count DESC
            LIMIT 10
            """,
            {"mod": mod},
        ).fetchall()
    return [dict(row) for row in rows]

def get_analysis_stats(period: str = "30d") -> list[dict]:
    # Feeds the analysis graph: how many analyses were made each day.

    mod = _modifier(period)
    with closing(get_connection()) as conn:
        rows = conn.execute(
            """
            SELECT DATE(created_at) AS day, COUNT(*) AS count
            FROM reports
            WHERE (:mod IS NULL OR created_at >= datetime('now', :mod))
            GROUP BY DATE(created_at)
            ORDER BY DATE(created_at) ASC            
            """,
            {"mod": mod},
        ).fetchall()
    return [dict(row) for row in rows]