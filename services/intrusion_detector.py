import re
import urllib.parse

from services.model_service import (
    web_attack_model
)

from services.database_service import (
    get_recent_failed_login_attempts
)


WEB_ANOMALY_THRESHOLD = 0.72


def get_request_text(request_data):
    """
    Build one normalized text representation from
    the HTTP request for attack-pattern analysis.
    """

    method = str(
        request_data.get("Method")
        or request_data.get("method")
        or ""
    )

    url = str(
        request_data.get("URL")
        or request_data.get("url")
        or ""
    )

    path = str(
        request_data.get("path")
        or ""
    )

    query_string = str(
        request_data.get("query_string")
        or ""
    )

    content = str(
        request_data.get("content")
        or ""
    )

    try:
        decoded_url = urllib.parse.unquote_plus(
            url
        )
    except Exception:
        decoded_url = url

    try:
        decoded_query_string = urllib.parse.unquote_plus(
            query_string
        )
    except Exception:
        decoded_query_string = query_string

    try:
        decoded_content = urllib.parse.unquote_plus(
            content
        )
    except Exception:
        decoded_content = content

    return (
        method
        + " "
        + path
        + " "
        + decoded_url
        + " "
        + decoded_query_string
        + " "
        + decoded_content
    ).lower()


def detect_attack_type(request_data):
    """
    Detect obvious HTTP attack patterns.

    The CSIC model remains the ML anomaly detector.
    This function provides the human-readable attack
    category required by the IDS interface.
    """

    text = get_request_text(
        request_data
    )

    # =================================================
    # SQL INJECTION
    # =================================================

    sql_patterns = [

        # Boolean based SQL injection
        r"\b(?:or|and)\b\s+['\"`]?\w+['\"`]?\s*=\s*['\"`]?\w+['\"`]?",

        # Numeric boolean SQL injection
        r"\b(?:or|and)\b\s+\d+\s*=\s*\d+",

        # Quoted boolean SQL injection
        r"['\"]\s*(?:or|and)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?",

        # Explicit classic payload:
        # ' OR 1=1
        r"['\"]\s*(?:or|and)\s+\d+\s*=\s*\d+",

        # UNION SELECT
        r"\bunion\b\s+(?:all\s+)?\bselect\b",

        # SELECT ... FROM
        r"\bselect\b.+\bfrom\b",

        # INSERT ... INTO
        r"\binsert\b.+\binto\b",

        # UPDATE ... SET
        r"\bupdate\b.+\bset\b",

        # DELETE ... FROM
        r"\bdelete\b.+\bfrom\b",

        # SQL comment
        r"--",

        # Block SQL comment
        r"/\*.*\*/",

        # Common SQL keywords combined with quotes
        r"['\"]\s*(?:or|and)\b",

        # SQL function / statement patterns
        r"\bsleep\s*\(",
        r"\bbenchmark\s*\(",
        r"\bwaitfor\s+delay\b"
    ]

    for pattern in sql_patterns:

        if re.search(
            pattern,
            text,
            re.IGNORECASE
        ):
            return "SQL Injection"


    # =================================================
    # CROSS-SITE SCRIPTING
    # =================================================

    xss_patterns = [
        r"<script\b",
        r"</script>",
        r"javascript:",
        r"onerror\s*=",
        r"onload\s*=",
        r"<iframe\b",
        r"<img\b[^>]*onerror"
    ]

    for pattern in xss_patterns:

        if re.search(
            pattern,
            text,
            re.IGNORECASE
        ):
            return "XSS"


    # =================================================
    # DIRECTORY TRAVERSAL
    # =================================================

    traversal_patterns = [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e%2f",
        r"%2e%2e/",
        r"\.\.%2f",
        r"\.\.%5c"
    ]

    for pattern in traversal_patterns:

        if re.search(
            pattern,
            text,
            re.IGNORECASE
        ):
            return "Directory Traversal"


    # =================================================
    # COMMAND INJECTION
    # =================================================

    command_patterns = [
        r";\s*(?:whoami|id|dir|ls|cat|type|ping|curl|wget)\b",
        r"\|\s*(?:whoami|id|dir|ls|cat|type|ping|curl|wget)\b",
        r"&&\s*(?:whoami|id|dir|ls|cat|type|ping|curl|wget)\b",
        r"\$\([^)]*\)",
        r"`[^`]+`"
    ]

    for pattern in command_patterns:

        if re.search(
            pattern,
            text,
            re.IGNORECASE
        ):
            return "Command Injection"


    return None


def analyze_http_request(
    request_data
):

    result = (
        web_attack_model.predict(
            request_data
        )
    )

    probability = result[
        "anomaly_probability"
    ]

    source_ip = request_data.get(
        "source_ip",
        ""
    )

    response_status = int(
        request_data.get(
            "response_status",
            0
        )
        or 0
    )

    brute_force = False

    # =================================================
    # BRUTE FORCE
    # =================================================

    if (
        request_data.get("Method", "").upper()
        == "POST"
        and
        request_data.get("path", "")
        == "/login"
        and
        response_status == 401
        and
        source_ip
    ):

        failed_attempts = (
            get_recent_failed_login_attempts(
                source_ip,
                seconds=60
            )
        )

        # Current request is not yet in database,
        # so add it to the count.
        failed_attempts += 1

        if failed_attempts >= 5:

            brute_force = True


    detected_attack = detect_attack_type(
        request_data
    )


    # =================================================
    # FINAL HTTP DECISION
    # =================================================

    # Brute Force has highest priority.

    if brute_force:

        status = "Intrusion"
        risk_level = "High"
        attack_type = "Brute Force"


    # Explicit HTTP attack pattern.

    elif detected_attack:

        status = "Intrusion"
        risk_level = "High"
        attack_type = detected_attack


    # Normal request.

    else:

        status = "Normal"
        risk_level = "Low"
        attack_type = "Normal"


    return {

        "status":
            status,

        "attack_type":
            attack_type,

        "risk_level":
            risk_level,

        "confidence":
            round(
                probability,
                6
            ),

        "model_name":
            "CSIC HTTP V2"
    }