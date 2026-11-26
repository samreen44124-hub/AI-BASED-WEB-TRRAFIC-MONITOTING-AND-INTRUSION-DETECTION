import sqlite3
import os
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

DB_PATH = os.path.join(
    BASE_DIR,
    "database",
    "ids.db"
)


def get_connection():

    conn = sqlite3.connect(DB_PATH)

    conn.row_factory = sqlite3.Row

    return conn


def initialize_database():

    os.makedirs(
        os.path.dirname(DB_PATH),
        exist_ok=True
    )

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS traffic_logs
        (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            source_ip TEXT,
            method TEXT,
            url TEXT,
            path TEXT,
            query_string TEXT,
            user_agent TEXT,

            content_length INTEGER DEFAULT 0,

            status TEXT DEFAULT 'Pending',
            attack_type TEXT DEFAULT 'Unknown',
            risk_level TEXT DEFAULT 'Low',

            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # -------------------------------------------------
    # Add ML detection columns to existing databases
    # -------------------------------------------------

    cursor.execute(
        "PRAGMA table_info(traffic_logs)"
    )

    existing_columns = {
        row[1]
        for row in cursor.fetchall()
    }

    if "confidence" not in existing_columns:
        cursor.execute("""
            ALTER TABLE traffic_logs
            ADD COLUMN confidence REAL DEFAULT 0
        """)

    if "model_name" not in existing_columns:
        cursor.execute("""
            ALTER TABLE traffic_logs
            ADD COLUMN model_name TEXT DEFAULT ''
        """)
    if "status_code" not in existing_columns:
        cursor.execute("""
            ALTER TABLE traffic_logs
            ADD COLUMN status_code INTEGER DEFAULT 0
        """)
    # -------------------------------------------------
    # Network Flow Logs
    # -------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS network_flow_logs
        (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            flow_key TEXT,
            flow_id TEXT,

            source_ip TEXT,
            source_port INTEGER,

            destination_ip TEXT,
            destination_port INTEGER,

            protocol INTEGER,

            flow_timestamp TEXT,

            status TEXT NOT NULL DEFAULT 'Normal',
            attack_type TEXT NOT NULL DEFAULT 'Normal',
            risk_level TEXT NOT NULL DEFAULT 'Low',

            class_id INTEGER NOT NULL DEFAULT 0,
            confidence REAL NOT NULL DEFAULT 0,

            model_name TEXT DEFAULT '',

            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS
        idx_network_flow_key_unique
        ON network_flow_logs(flow_key)
        WHERE flow_key IS NOT NULL
    """)

    # -------------------------------------------------
    # Network Flow Indexes
    # -------------------------------------------------

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_network_flow_created_at
        ON network_flow_logs(created_at)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_network_flow_status
        ON network_flow_logs(status)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_network_flow_attack_type
        ON network_flow_logs(attack_type)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_network_flow_source_ip
        ON network_flow_logs(source_ip)
    """)
    # -------------------------------------------------
    # Network Flow Schema Migration
    # -------------------------------------------------

    cursor.execute(
        "PRAGMA table_info(network_flow_logs)"
    )

    network_columns = {
        row[1]
        for row in cursor.fetchall()
    }

    if "flow_key" not in network_columns:

        cursor.execute("""
            ALTER TABLE network_flow_logs
            ADD COLUMN flow_key TEXT
        """)
    # -------------------------------------------------
    # Security Alerts
    # -------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts
        (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            alert_time DATETIME DEFAULT CURRENT_TIMESTAMP,

            source_ip TEXT,

            http_traffic_id INTEGER,
            network_flow_id INTEGER,

            http_attack_type TEXT DEFAULT 'Normal',
            network_attack_type TEXT DEFAULT 'Normal',

            correlation_status TEXT DEFAULT 'Not Correlated',
            correlation_score REAL DEFAULT 0,

            status TEXT DEFAULT 'Intrusion',
            risk_level TEXT DEFAULT 'Low',
            confidence REAL DEFAULT 0,

            description TEXT DEFAULT '',

            alert_status TEXT DEFAULT 'New',

            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # -------------------------------------------------
    # Alert Indexes
    # -------------------------------------------------

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_alerts_alert_time
        ON alerts(alert_time)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_alerts_source_ip
        ON alerts(source_ip)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_alerts_risk_level
        ON alerts(risk_level)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_alerts_alert_status
        ON alerts(alert_status)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_alerts_http_attack
        ON alerts(http_attack_type)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_alerts_network_attack
        ON alerts(network_attack_type)
    """)


    cursor.execute("""
        CREATE TABLE IF NOT EXISTS administrators
        (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        SELECT COUNT(*)
        FROM administrators
    """)

    admin_count = cursor.fetchone()[0]

    if admin_count == 0:
        password_hash = generate_password_hash(
            "Admin@123"
        )

        cursor.execute("""
            INSERT INTO administrators
            (
                username,
                password_hash,
                full_name
            )
            VALUES (?, ?, ?)
        """, (
            "admin",
            password_hash,
            "System Administrator"
        ))
        

    conn.commit()
    conn.close()
def get_http_traffic_by_id(traffic_id):
    """
    Return one HTTP traffic record.
    """

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            source_ip,
            method,
            url,
            path,
            query_string,
            user_agent,
            content_length,
            status,
            attack_type,
            risk_level,
            confidence,
            model_name,
            created_at
        FROM traffic_logs
        WHERE id = ?
    """, (traffic_id,))

    row = cursor.fetchone()

    conn.close()

    return dict(row) if row else None

def parse_flow_timestamp(value):
    """
    Convert CICFlowMeter timestamp to datetime.
    """

    if not value:
        return None

    formats = [
        "%d/%m/%Y %I:%M:%S %p",
        "%d/%m/%Y %H:%M:%S",
        "%Y-%m-%d %H:%M:%S"
    ]

    for fmt in formats:
        try:
            return datetime.strptime(
                str(value).strip(),
                fmt
            )
        except ValueError:
            continue

    return None
def get_network_flows_in_time_window(
    start_time,
    end_time
):
    """
    Return network flows whose CICFlowMeter timestamp
    falls inside the requested time window.

    We intentionally retrieve candidates here.
    IP/port/direction matching is performed by the
    correlation service.
    """

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            flow_key,
            flow_id,
            source_ip,
            source_port,
            destination_ip,
            destination_port,
            protocol,
            flow_timestamp,
            status,
            attack_type,
            risk_level,
            class_id,
            confidence,
            model_name,
            created_at
        FROM network_flow_logs
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()
    conn.close()

    results = []

    for row in rows:

        item = dict(row)

        flow_time = parse_flow_timestamp(
            item.get("flow_timestamp")
        )

        if flow_time is None:
            continue

        if start_time <= flow_time <= end_time:
            results.append(item)

    return results
def insert_network_flow(data):

    conn = get_connection()

    cursor = conn.cursor()

    attack_type = data.get(
        "attack_type",
        "Normal"
    )

    # For the network model at this stage:
    #
    # Normal prediction     -> Normal
    # Non-Normal prediction -> Intrusion
    #
    # More advanced fusion decisions will later
    # belong in decision_service.py.

    if attack_type == "Normal":

        status = "Normal"
        risk_level = "Low"

    else:

        status = "Intrusion"

        # Temporary operational mapping.
        # This is NOT an ML confidence threshold.
        if attack_type in (
            "DDoS",
            "DoS"
        ):
            risk_level = "Critical"

        elif attack_type in (
            "Port Scan",
            "Network Brute Force",
            "Bot",
            "Web Attack"
        ):
            risk_level = "High"

        else:
            risk_level = "High"

    cursor.execute("""
        INSERT OR IGNORE INTO network_flow_logs
        (
            flow_key,
            flow_id,

            source_ip,
            source_port,

            destination_ip,
            destination_port,

            protocol,

            flow_timestamp,

            status,
            attack_type,
            risk_level,

            class_id,
            confidence,

            model_name,
            created_at
        )
        VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?,?
        )
    """, (
        data.get("flow_key"),
        data.get("flow_id"),

        data.get("source_ip"),
        data.get("source_port"),

        data.get("destination_ip"),
        data.get("destination_port"),

        data.get("protocol"),

        data.get("timestamp"),

        status,
        attack_type,
        risk_level,

        data.get("class_id", 0),
        data.get("confidence", 0.0),

        data.get(
            "model_name",
            "CIC-IDS2017 Network RF"
        ),
        data.get("created_at")
    ))

    inserted = cursor.rowcount > 0

    if inserted:
        network_flow_id = cursor.lastrowid
    else:
        network_flow_id = None

    conn.commit()
    conn.close()

    return network_flow_id
def get_recent_network_flows(limit=50):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            flow_id,

            source_ip,
            source_port,

            destination_ip,
            destination_port,

            protocol,

            flow_timestamp,

            status,
            attack_type,
            risk_level,

            class_id,
            confidence,

            flow_key,
            
            model_name,
            created_at

        FROM network_flow_logs

        ORDER BY id DESC

        LIMIT ?
    """, (
        limit,
    ))

    rows = cursor.fetchall()

    conn.close()

    return [
        dict(row)
        for row in rows
    ]
def get_network_flow_statistics():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""
        SELECT

            COUNT(*) AS total,

            SUM(
                CASE
                    WHEN status = 'Normal'
                    THEN 1
                    ELSE 0
                END
            ) AS normal,

            SUM(
                CASE
                    WHEN status = 'Intrusion'
                    THEN 1
                    ELSE 0
                END
            ) AS intrusion,

            SUM(
                CASE
                    WHEN attack_type = 'DoS'
                    THEN 1
                    ELSE 0
                END
            ) AS dos,

            SUM(
                CASE
                    WHEN attack_type = 'DDoS'
                    THEN 1
                    ELSE 0
                END
            ) AS ddos,

            SUM(
                CASE
                    WHEN attack_type = 'Port Scan'
                    THEN 1
                    ELSE 0
                END
            ) AS port_scan,

            SUM(
                CASE
                    WHEN attack_type = 'Network Brute Force'
                    THEN 1
                    ELSE 0
                END
            ) AS brute_force,

            SUM(
                CASE
                    WHEN attack_type = 'Bot'
                    THEN 1
                    ELSE 0
                END
            ) AS bot,

            SUM(
                CASE
                    WHEN attack_type = 'Web Attack'
                    THEN 1
                    ELSE 0
                END
            ) AS web_attack,

            SUM(
                CASE
                    WHEN risk_level = 'Critical'
                    THEN 1
                    ELSE 0
                END
            ) AS critical

        FROM network_flow_logs
    """)

    row = cursor.fetchone()

    conn.close()

    return {
        "total": row["total"] or 0,
        "normal": row["normal"] or 0,
        "intrusion": row["intrusion"] or 0,
        "dos": row["dos"] or 0,
        "ddos": row["ddos"] or 0,
        "port_scan": row["port_scan"] or 0,
        "brute_force": row["brute_force"] or 0,
        "bot": row["bot"] or 0,
        "web_attack": row["web_attack"] or 0,
        "critical": row["critical"] or 0
    }
def get_administrator_by_username(username):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            username,
            password_hash,
            full_name,
            is_active
        FROM administrators
        WHERE username = ?
        LIMIT 1
    """, (username,))

    row = cursor.fetchone()

    conn.close()

    if row:
        return dict(row)

    return None
def update_administrator_password(
        administrator_id,
        password_hash):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""
        UPDATE administrators

        SET password_hash = ?

        WHERE id = ?
    """, (
        password_hash,
        administrator_id
    ))

    updated = cursor.rowcount > 0

    conn.commit()
    conn.close()

    return updated
def get_administrator_by_id(
        administrator_id):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            username,
            password_hash,
            full_name,
            is_active

        FROM administrators

        WHERE id = ?

        LIMIT 1
    """, (
        administrator_id,
    ))

    row = cursor.fetchone()

    conn.close()

    if row:
        return dict(row)

    return None
def get_recent_traffic(limit=10):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            source_ip,
            method,
            url,
            path,
            query_string,
            user_agent,
            content_length,
            status,
            attack_type,
            risk_level,
            confidence,
            model_name,
            created_at
        FROM traffic_logs
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    rows = cursor.fetchall()

    conn.close()

    return [dict(row) for row in rows]
def insert_traffic(data):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO traffic_logs
        (
            source_ip,
            method,
            url,
            path,
            query_string,
            user_agent,
            content_length,

            status,
            attack_type,
            risk_level,
            confidence,
            model_name,
            created_at,
            status_code
        )
        VALUES (?,?, ?,?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data.get("source_ip", ""),
        data.get("method", ""),
        data.get("url", ""),
        data.get("path", ""),
        data.get("query_string", ""),
        data.get("user_agent", ""),
        data.get("content_length", 0),

        data.get("status", "Pending"),
        data.get("attack_type", "Unknown"),
        data.get("risk_level", "Low"),
        data.get("confidence", 0.0),
        data.get("model_name", ""),

        data.get("created_at", ""),
        data.get("response_status", "")

                   ))

    traffic_id = cursor.lastrowid

    conn.commit()
    conn.close()

    return traffic_id

def get_recent_failed_login_attempts(
        source_ip,
        seconds=60):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            COUNT(*) AS attempt_count
        FROM traffic_logs

        WHERE source_ip = ?

        AND method = 'POST'

        AND path = '/login'

        AND created_at >= datetime(
            'now',
            ?
        )

        AND status_code = 401
    """, (
        source_ip,
        f"-{seconds} seconds"
    ))

    row = cursor.fetchone()

    conn.close()

    return row["attempt_count"] or 0
def get_latest_traffic(limit=100):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            source_ip,
            method,
            url,
            path,
            query_string,
            user_agent,
            content_length,
            status,
            attack_type,
            risk_level,
            confidence,
            model_name,
            created_at

        FROM traffic_logs

        ORDER BY id DESC

        LIMIT ?
    """, (limit,))

    rows = cursor.fetchall()

    conn.close()

    return [dict(row) for row in rows]


def get_traffic_after_id(last_id):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            source_ip,
            method,
            url,
            path,
            query_string,
            user_agent,
            content_length,
            status,
            attack_type,
            risk_level,
            confidence,
            model_name,
            created_at

        FROM traffic_logs

        WHERE id > ?

        ORDER BY id ASC
    """, (last_id,))

    rows = cursor.fetchall()

    conn.close()

    return [dict(row) for row in rows]


def get_traffic_statistics():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""
        SELECT

            COUNT(*) AS total,

            SUM(
                CASE
                    WHEN status = 'Normal'
                    THEN 1
                    ELSE 0
                END
            ) AS normal,

            SUM(
                CASE
                    WHEN status = 'Suspicious'
                    THEN 1
                    ELSE 0
                END
            ) AS suspicious,

            SUM(
                CASE
                    WHEN status = 'Intrusion'
                    THEN 1
                    ELSE 0
                END
            ) AS intrusion,

            SUM(
                CASE
                    WHEN status = 'Pending'
                    THEN 1
                    ELSE 0
                END
            ) AS pending,

            SUM(
                CASE
                    WHEN risk_level = 'Critical'
                    THEN 1
                    ELSE 0
                END
            ) AS critical

        FROM traffic_logs
    """)

    row = cursor.fetchone()

    conn.close()

    return {
        "total": row["total"] or 0,
        "normal": row["normal"] or 0,
        "suspicious": row["suspicious"] or 0,
        "intrusion": row["intrusion"] or 0,
        "pending": row["pending"] or 0,
        "critical": row["critical"] or 0
    }
def get_traffic_activity():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            strftime(
                '%Y-%m-%d %H:',
                created_at
            )
            ||
            printf(
                '%02d',
                (CAST(strftime('%M', created_at) AS INTEGER) / 10) * 10
            ) AS time_bucket,

            COUNT(*) AS request_count

        FROM traffic_logs

        WHERE created_at >= datetime(
            'now',
            '-70 minutes'
        )

        GROUP BY time_bucket

        ORDER BY time_bucket ASC
    """)

    rows = cursor.fetchall()

    conn.close()


    database_counts = {
        row["time_bucket"]:
            row["request_count"]

        for row in rows
    }


    # SQLite CURRENT_TIMESTAMP is UTC.
    now = datetime.utcnow()

    current_bucket = now.replace(
        minute=(now.minute // 10) * 10,
        second=0,
        microsecond=0
    )


    activity = []


    # Seven points:
    # current bucket + previous 60 minutes.
    for offset in range(6, -1, -1):

        bucket = (
            current_bucket
            -
            timedelta(
                minutes=offset * 10
            )
        )

        database_key = (
            bucket.strftime(
                "%Y-%m-%d %H:%M"
            )
        )

        activity.append({
            "label":
                bucket.strftime(
                    "%H:%M"
                ),

            "count":
                database_counts.get(
                    database_key,
                    0
                )
        })


    return activity
# =========================================================
# ALERT FUNCTIONS
# =========================================================


def insert_alert(data):
    """
    Insert one security alert.

    Duplicate protection is based on the same HTTP
    traffic record and network flow record.
    """

    conn = get_connection()
    cursor = conn.cursor()

    http_traffic_id = data.get(
        "http_traffic_id"
    )

    network_flow_id = data.get(
        "network_flow_id"
    )

    # -----------------------------------------------------
    # Prevent duplicate alerts
    # -----------------------------------------------------

    if http_traffic_id is not None:

        if network_flow_id is not None:

            cursor.execute("""
                SELECT id
                FROM alerts
                WHERE http_traffic_id = ?
                AND network_flow_id = ?
                LIMIT 1
            """, (
                http_traffic_id,
                network_flow_id
            ))

        else:

            cursor.execute("""
                SELECT id
                FROM alerts
                WHERE http_traffic_id = ?
                AND network_flow_id IS NULL
                LIMIT 1
            """, (
                http_traffic_id,
            ))

        existing = cursor.fetchone()

        if existing:

            conn.close()

            return existing["id"]

    elif network_flow_id is not None:

        cursor.execute("""
            SELECT id
            FROM alerts
            WHERE http_traffic_id IS NULL
            AND network_flow_id = ?
            LIMIT 1
        """, (
            network_flow_id,
        ))

        existing = cursor.fetchone()

        if existing:

            conn.close()

            return existing["id"]

    # -----------------------------------------------------
    # Insert alert
    # -----------------------------------------------------

    cursor.execute("""
        INSERT INTO alerts
        (
            alert_time,

            source_ip,

            http_traffic_id,
            network_flow_id,

            http_attack_type,
            network_attack_type,

            correlation_status,
            correlation_score,

            status,
            risk_level,
            confidence,

            description,

            alert_status
        )
        VALUES
        (
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?
        )
    """, (
        data.get(
            "alert_time",
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        ),

        data.get(
            "source_ip",
            ""
        ),

        http_traffic_id,
        network_flow_id,

        data.get(
            "http_attack_type",
            "Normal"
        ),

        data.get(
            "network_attack_type",
            "Normal"
        ),

        data.get(
            "correlation_status",
            "Not Correlated"
        ),

        data.get(
            "correlation_score",
            0
        ),

        data.get(
            "status",
            "Intrusion"
        ),

        data.get(
            "risk_level",
            "Low"
        ),

        data.get(
            "confidence",
            0.0
        ),

        data.get(
            "description",
            ""
        ),

        data.get(
            "alert_status",
            "New"
        )
    ))

    alert_id = cursor.lastrowid

    conn.commit()
    conn.close()

    return alert_id


def get_alert_by_id(alert_id):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            alert_time,
            source_ip,

            http_traffic_id,
            network_flow_id,

            http_attack_type,
            network_attack_type,

            correlation_status,
            correlation_score,

            status,
            risk_level,
            confidence,

            description,

            alert_status,
            created_at

        FROM alerts

        WHERE id = ?

        LIMIT 1
    """, (
        alert_id,
    ))

    row = cursor.fetchone()

    conn.close()

    return dict(row) if row else None


def get_recent_alerts(limit=100):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            alert_time,
            source_ip,

            http_traffic_id,
            network_flow_id,

            http_attack_type,
            network_attack_type,

            correlation_status,
            correlation_score,

            status,
            risk_level,
            confidence,

            description,

            alert_status,
            created_at

        FROM alerts

        ORDER BY id DESC

        LIMIT ?
    """, (
        limit,
    ))

    rows = cursor.fetchall()

    conn.close()

    return [
        dict(row)
        for row in rows
    ]


def get_alert_statistics():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT

            COUNT(*) AS total,

            SUM(
                CASE
                    WHEN alert_status = 'New'
                    THEN 1
                    ELSE 0
                END
            ) AS new,

            SUM(
                CASE
                    WHEN alert_status = 'Acknowledged'
                    THEN 1
                    ELSE 0
                END
            ) AS acknowledged,

            SUM(
                CASE
                    WHEN alert_status = 'Resolved'
                    THEN 1
                    ELSE 0
                END
            ) AS resolved,

            SUM(
                CASE
                    WHEN risk_level = 'Critical'
                    THEN 1
                    ELSE 0
                END
            ) AS critical,

            SUM(
                CASE
                    WHEN risk_level = 'High'
                    THEN 1
                    ELSE 0
                END
            ) AS high,

            SUM(
                CASE
                    WHEN risk_level = 'Medium'
                    THEN 1
                    ELSE 0
                END
            ) AS medium,

            SUM(
                CASE
                    WHEN risk_level = 'Low'
                    THEN 1
                    ELSE 0
                END
            ) AS low

        FROM alerts
    """)

    row = cursor.fetchone()

    conn.close()

    return {
        "total": row["total"] or 0,
        "new": row["new"] or 0,
        "acknowledged": row["acknowledged"] or 0,
        "resolved": row["resolved"] or 0,
        "critical": row["critical"] or 0,
        "high": row["high"] or 0,
        "medium": row["medium"] or 0,
        "low": row["low"] or 0
    }


def update_alert_status(
        alert_id,
        alert_status):

    allowed_statuses = (
        "New",
        "Acknowledged",
        "Resolved"
    )

    if alert_status not in allowed_statuses:

        raise ValueError(
            "Invalid alert status."
        )

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE alerts

        SET alert_status = ?

        WHERE id = ?
    """, (
        alert_status,
        alert_id
    ))

    updated = cursor.rowcount > 0

    conn.commit()
    conn.close()

    return updated