
from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    session,
    redirect,
    url_for,
    flash
)
from services.correlation_service import correlation_service
from services.decision_service import decision_service
from services.alert_service import alert_service
from functools import wraps

from werkzeug.security import (
    check_password_hash,
    generate_password_hash
)
from datetime import timedelta

from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from services.database_service import (
    initialize_database,
    insert_traffic,
    get_latest_traffic,
    get_traffic_after_id,
    get_traffic_statistics,
    get_administrator_by_username,
get_administrator_by_id,
update_administrator_password,
get_traffic_activity,
    get_recent_network_flows,
    get_network_flow_statistics,
    get_http_traffic_by_id,
get_connection
)
from services.intrusion_detector import (
    analyze_http_request
)

from services.correlation_service import (
    correlation_service
)

from services.decision_service import (
    decision_service
)

from services.alert_service import (
    alert_service
)


app = Flask(__name__)

app.config["SECRET_KEY"] = "ai-ids-development-secret-key-2026"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(
    minutes=30
)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Keep False while developing over HTTP localhost.
# Change to True when the application uses HTTPS.
app.config["SESSION_COOKIE_SECURE"] = False


csrf = CSRFProtect(app)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[]
)

initialize_database()
def login_required(view_function):

    @wraps(view_function)
    def wrapped_view(*args, **kwargs):

        if "admin_id" not in session:

            return redirect(
                url_for("login")
            )

        return view_function(
            *args,
            **kwargs
        )

    return wrapped_view
@app.route("/api/alerts")
@login_required
def alerts_api():

    try:

        limit = request.args.get(
            "limit",
            100,
            type=int
        )

        if limit < 1:
            limit = 100

        if limit > 500:
            limit = 500

        alerts_data = alert_service.get_alerts(
            limit
        )

        statistics = alert_service.get_statistics()

        return jsonify({
            "success": True,
            "alerts": alerts_data,
            "statistics": statistics
        })

    except Exception:

        app.logger.exception(
            "Alerts API failed."
        )

        return jsonify({
            "success": False,
            "message": "Unable to retrieve alerts.",
            "alerts": [],
            "statistics": {}
        }), 500
@app.route("/api/alerts/<int:alert_id>", methods=["GET"])
@login_required
def alert_detail_api(alert_id):

    try:

        alert = alert_service.get_alert(
            alert_id
        )

        if not alert:

            return jsonify({
                "success": False,
                "message": "Alert not found."
            }), 404

        return jsonify({
            "success": True,
            "alert": alert
        })

    except Exception:

        app.logger.exception(
            "Alert detail API failed."
        )

        return jsonify({
            "success": False,
            "message": "Unable to retrieve alert."
        }), 500
@app.route(
    "/api/alerts/<int:alert_id>/status",
    methods=["POST"]
)
@csrf.exempt
@login_required
def update_alert_status_api(alert_id):

    try:

        data = request.get_json(silent=True) or {}

        alert_status = str(
            data.get("alert_status", "")
        ).strip()

        if alert_status not in (
            "New",
            "Acknowledged",
            "Resolved"
        ):

            return jsonify({
                "success": False,
                "message": "Invalid alert status."
            }), 400

        updated = alert_service.change_status(
            alert_id,
            alert_status
        )

        if not updated:

            return jsonify({
                "success": False,
                "message": "Alert not found."
            }), 404

        return jsonify({
            "success": True,
            "message": "Alert status updated successfully.",
            "alert_id": alert_id,
            "alert_status": alert_status
        })

    except Exception as exc:

        app.logger.exception(
            "Alert status update failed."
        )

        return jsonify({
            "success": False,
            "message": "Unable to update alert status.",
            "error": str(exc)
        }), 500

@app.route("/api/traffic", methods=["POST"])
@csrf.exempt
def receive_traffic():
    try:
        data = request.get_json(silent=True)

        if not data:
            return jsonify({
                "success": False,
                "message": "No traffic data received."
            }), 400

        source_ip = str(
            data.get("source_ip", "127.0.0.1")
        ).strip()

        method = str(
            data.get("method", "")
        ).strip().upper()

        path = str(
            data.get("path", "")
        ).strip()

        if not source_ip:
            source_ip = "127.0.0.1"

        if not method:
            return jsonify({
                "success": False,
                "message": "HTTP method is required."
            }), 400

        if not path:
            return jsonify({
                "success": False,
                "message": "HTTP path is required."
            }), 400

        # -------------------------------------------------
        # 1. HTTP MODEL / DETECTION
        # -------------------------------------------------

        detection = analyze_http_request(data)

        # Preserve detector result in traffic record.
        data["status"] = detection.get(
            "status",
            "Normal"
        )

        data["attack_type"] = detection.get(
            "attack_type",
            "Normal"
        )

        data["risk_level"] = detection.get(
            "risk_level",
            "Low"
        )

        data["confidence"] = detection.get(
            "confidence",
            0.0
        )

        data["model_name"] = detection.get(
            "model_name",
            "CSIC HTTP V2"
        )

        # -------------------------------------------------
        # 2. STORE HTTP TRAFFIC
        # -------------------------------------------------

        traffic_id = insert_traffic(data)

        # -------------------------------------------------
        # 3. CORRELATE WITH NETWORK EVIDENCE
        # -------------------------------------------------

        correlation = correlation_service.correlate_http_log(
            traffic_id
        )

        network_result = None
        network_flow_id = None

        if correlation.get("matched"):

            network_flow = correlation.get(
                "network_flow"
            )

            if network_flow:

                network_flow_id = network_flow.get(
                    "id"
                )

                network_result = {
                    "attack_type": network_flow.get(
                        "attack_type",
                        "Normal"
                    ),
                    "class_id": network_flow.get(
                        "class_id",
                        0
                    ),
                    "confidence": network_flow.get(
                        "confidence",
                        0.0
                    ),
                    "model_name": network_flow.get(
                        "model_name",
                        "CIC-IDS2017 Network RF"
                    ),
                    "source_ip": network_flow.get(
                        "source_ip"
                    )
                }

        # -------------------------------------------------
        # 4. FINAL SECURITY DECISION
        # -------------------------------------------------

        decision = decision_service.decide(
            http_result=detection,
            network_result=network_result
        )

        # -------------------------------------------------
        # 5. CREATE ALERT IF REQUIRED
        # -------------------------------------------------

        alert_id = alert_service.create_from_decision(
            decision=decision,
            correlation=correlation,
            http_traffic_id=traffic_id,
            network_flow_id=network_flow_id,
            source_ip=source_ip
        )

        # -------------------------------------------------
        # 6. RETURN COMPLETE RESULT
        # -------------------------------------------------

        return jsonify({
            "success": True,

            "traffic_id": traffic_id,

            "detection": detection,

            "correlation": {
                "matched": correlation.get(
                    "matched",
                    False
                ),
                "reason": correlation.get(
                    "reason",
                    ""
                ),
                "network_flow_id": network_flow_id,
                "correlation_score": correlation.get(
                    "correlation_score",
                    0
                ),
                "time_difference_seconds":
                    correlation.get(
                        "time_difference_seconds"
                    )
            },

            "decision": decision,

            "alert_id": alert_id
        })

    except Exception as exc:

        app.logger.exception(
            "Traffic processing failed."
        )

        return jsonify({
            "success": False,
            "message": "Traffic processing failed.",
            "error": str(exc)
        }), 500
@app.route("/api/network-flows")
@login_required
def network_flows_api():
    try:
        limit = request.args.get("limit", 50, type=int)

        if limit < 1:
            limit = 50

        if limit > 200:
            limit = 200

        flows = get_recent_network_flows(limit)
        statistics = get_network_flow_statistics()

        return jsonify({
            "success": True,
            "flows": flows,
            "statistics": statistics
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "message": str(e),
            "flows": [],
            "statistics": {}
        }), 500


@app.route(
    "/change-password",
    methods=["GET", "POST"]
)
@login_required
def change_password():

    if request.method == "POST":

        current_password = request.form.get(
            "current_password",
            ""
        )

        new_password = request.form.get(
            "new_password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        admin = get_administrator_by_id(
            session["admin_id"]
        )

        if not admin:

            session.clear()

            return redirect(
                url_for("login")
            )

        if not check_password_hash(
            admin["password_hash"],
            current_password
        ):

            flash(
                "Current password is incorrect.",
                "danger"
            )

            return render_template(
                "change_password.html"
            )

        if len(new_password) < 10:

            flash(
                "New password must contain at least 10 characters.",
                "danger"
            )

            return render_template(
                "change_password.html"
            )

        if new_password != confirm_password:

            flash(
                "New password and confirmation do not match.",
                "danger"
            )

            return render_template(
                "change_password.html"
            )

        if check_password_hash(
            admin["password_hash"],
            new_password
        ):

            flash(
                "New password must be different from the current password.",
                "danger"
            )

            return render_template(
                "change_password.html"
            )

        new_hash = generate_password_hash(
            new_password
        )

        update_administrator_password(
            admin["id"],
            new_hash
        )

        # Require a fresh login after changing password.
        session.clear()

        flash(
            "Password changed successfully. Please sign in again.",
            "success"
        )

        return redirect(
            url_for("login")
        )

    return render_template(
        "change_password.html"
    )
@app.route("/api/live-traffic")
@login_required
def live_traffic():

    try:
        last_id = request.args.get(
            "last_id",
            default=0,
            type=int
        )

        if last_id < 0:
            last_id = 0

        if last_id == 0:

            logs = get_latest_traffic(100)

        else:

            logs = get_traffic_after_id(last_id)

        statistics = get_traffic_statistics()

        return jsonify({
            "success": True,
            "logs": logs,
            "statistics": statistics
        })

    except Exception as e:

        app.logger.exception(
            "Live traffic API failed"
        )

        return jsonify({
            "success": False,
            "message": "Unable to retrieve live traffic."
        }), 500
@app.route("/login", methods=["GET", "POST"])
@limiter.limit(
    "5 per minute",
    methods=["POST"]
)
def login():

    if "admin_id" in session:
        return redirect(
            url_for("dashboard")
        )

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        if not username or not password:

            flash(
                "Please enter username and password.",
                "danger"
            )

            return render_template(
                "login.html"
            )

        admin = get_administrator_by_username(
            username
        )

        if not admin:

            flash(
                "Invalid username or password.",
                "danger"
            )

            return render_template(
                "login.html"
            )

        if not admin["is_active"]:

            flash(
                "This administrator account is disabled.",
                "danger"
            )

            return render_template(
                "login.html"
            )

        if not check_password_hash(
            admin["password_hash"],
            password
        ):

            flash(
                "Invalid username or password.",
                "danger"
            )

            return render_template(
                "login.html"
            )

        session.clear()

        session.permanent = True

        session["admin_id"] = admin["id"]
        session["username"] = admin["username"]
        session["full_name"] = admin["full_name"]

        return redirect(
            url_for("dashboard")
        )

    return render_template(
        "login.html"
    )
@app.route("/")
@login_required
def dashboard():

    statistics = get_traffic_statistics()

    recent_logs = get_latest_traffic(10)

    traffic_activity = (
        get_traffic_activity()
    )


    return render_template(
        "dashboard.html",

        total_traffic=
            statistics["total"],

        normal_traffic=
            statistics["normal"],

        suspicious_count=
            statistics["suspicious"],

        intrusion_count=
            statistics["intrusion"],

        critical_count=
            statistics["critical"],

        pending_count=
            statistics["pending"],

        recent_logs=
            recent_logs,

        traffic_activity=
            traffic_activity
    )

@app.route("/api/dashboard-data")
@login_required
def dashboard_data():

    try:

        statistics = get_traffic_statistics()
        alert_statistics = (
            alert_service.get_statistics()
        )
        traffic_activity = (
            get_traffic_activity()
        )

        recent_logs = (
            get_latest_traffic(10)
        )

        return jsonify({
            "success": True,

            "statistics": {
                "total":
                    statistics["total"],

                "normal":
                    statistics["normal"],

                "suspicious":
                    statistics["suspicious"],

                "intrusion":
                    statistics["intrusion"],

                "pending":
                    statistics["pending"],

                "critical":
                    statistics["critical"]
            },
            "alerts": {

                "total":
                    alert_statistics["total"],

                "new":
                    alert_statistics["new"],

                "acknowledged":
                    alert_statistics["acknowledged"],

                "resolved":
                    alert_statistics["resolved"],

                "critical":
                    alert_statistics["critical"],

                "high":
                    alert_statistics["high"],

                "medium":
                    alert_statistics["medium"],

                "low":
                    alert_statistics["low"]
            },

            "traffic_activity":
                traffic_activity,

            "recent_logs":
                recent_logs
        })


    except Exception:

        app.logger.exception(
            "Dashboard data loading failed."
        )

        return jsonify({
            "success": False,
            "message":
                "Dashboard data could not be loaded."
        }), 500
@app.route("/traffic")
@login_required
def traffic():

    logs = get_latest_traffic(100)

    statistics = get_traffic_statistics()

    return render_template(
        "traffic.html",
        logs=logs,
        statistics=statistics
    )
@app.route("/network-flows")
@login_required
def network_flows():

    try:

        network_flows_data = get_recent_network_flows(100)
        network_statistics = get_network_flow_statistics()

        return render_template(
            "network_flows.html",
            network_flows=network_flows_data,
            network_statistics=network_statistics
        )

    except Exception as e:

        return render_template(
            "network_flows.html",
            network_flows=[],
            network_statistics={},
            error=str(e)
        )
@app.route("/alerts")
@login_required
def alerts():

    try:

        statistics = alert_service.get_statistics()

        recent_alerts = alert_service.get_alerts(
            100
        )

        return render_template(
            "alerts.html",
            alerts=recent_alerts,
            statistics=statistics
        )

    except Exception as exc:

        app.logger.exception(
            "Alerts page failed."
        )

        return render_template(
            "alerts.html",
            alerts=[],
            statistics={},
            error=str(exc)
        )


@app.route("/reports")
@login_required
def reports():

    try:

        conn = get_connection()
        cursor = conn.cursor()

        # -------------------------------------------------
        # HTTP TRAFFIC SUMMARY
        # -------------------------------------------------

        cursor.execute("""
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN status = 'Normal'
                    THEN 1 ELSE 0 END) AS normal,
                SUM(CASE WHEN status = 'Suspicious'
                    THEN 1 ELSE 0 END) AS suspicious,
                SUM(CASE WHEN status = 'Intrusion'
                    THEN 1 ELSE 0 END) AS intrusion
            FROM traffic_logs
        """)

        http_summary = dict(cursor.fetchone())

        # -------------------------------------------------
        # HTTP ATTACK DISTRIBUTION
        # -------------------------------------------------

        cursor.execute("""
            SELECT
                attack_type,
                COUNT(*) AS count
            FROM traffic_logs
            WHERE attack_type IS NOT NULL
              AND attack_type != 'Normal'
            GROUP BY attack_type
            ORDER BY count DESC
        """)

        http_attacks = [
            dict(row)
            for row in cursor.fetchall()
        ]

        # -------------------------------------------------
        # NETWORK SUMMARY
        # -------------------------------------------------

        cursor.execute("""
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN status = 'Normal'
                    THEN 1 ELSE 0 END) AS normal,
                SUM(CASE WHEN status = 'Intrusion'
                    THEN 1 ELSE 0 END) AS intrusion
            FROM network_flow_logs
        """)

        network_summary = dict(cursor.fetchone())

        # -------------------------------------------------
        # NETWORK ATTACK DISTRIBUTION
        # -------------------------------------------------

        cursor.execute("""
            SELECT
                attack_type,
                COUNT(*) AS count
            FROM network_flow_logs
            WHERE attack_type IS NOT NULL
              AND attack_type != 'Normal'
            GROUP BY attack_type
            ORDER BY count DESC
        """)

        network_attacks = [
            dict(row)
            for row in cursor.fetchall()
        ]

        # -------------------------------------------------
        # RISK DISTRIBUTION
        # -------------------------------------------------

        cursor.execute("""
            SELECT
                risk_level,
                COUNT(*) AS count
            FROM alerts
            GROUP BY risk_level
            ORDER BY
                CASE risk_level
                    WHEN 'Critical' THEN 1
                    WHEN 'High' THEN 2
                    WHEN 'Medium' THEN 3
                    WHEN 'Low' THEN 4
                    ELSE 5
                END
        """)

        risk_distribution = [
            dict(row)
            for row in cursor.fetchall()
        ]

        # -------------------------------------------------
        # CORRELATION SUMMARY
        # -------------------------------------------------

        cursor.execute("""
            SELECT
                correlation_status,
                COUNT(*) AS count
            FROM alerts
            GROUP BY correlation_status
        """)

        correlation_summary = [
            dict(row)
            for row in cursor.fetchall()
        ]

        # -------------------------------------------------
        # ALERT STATUS SUMMARY
        # -------------------------------------------------

        cursor.execute("""
            SELECT
                alert_status,
                COUNT(*) AS count
            FROM alerts
            GROUP BY alert_status
        """)

        alert_status_summary = [
            dict(row)
            for row in cursor.fetchall()
        ]

        # -------------------------------------------------
        # RECENT SECURITY INCIDENTS
        # -------------------------------------------------

        cursor.execute("""
            SELECT
                id,
                alert_time,
                source_ip,
                http_attack_type,
                network_attack_type,
                correlation_status,
                status,
                risk_level,
                confidence,
                alert_status,
                description
            FROM alerts
            ORDER BY id DESC
            LIMIT 50
        """)

        recent_incidents = [
            dict(row)
            for row in cursor.fetchall()
        ]

        conn.close()

        return render_template(
            "reports.html",
            http_summary=http_summary,
            http_attacks=http_attacks,
            network_summary=network_summary,
            network_attacks=network_attacks,
            risk_distribution=risk_distribution,
            correlation_summary=correlation_summary,
            alert_status_summary=alert_status_summary,
            recent_incidents=recent_incidents
        )

    except Exception as exc:

        app.logger.exception(
            "Reports page failed."
        )

        return render_template(
            "reports.html",
            http_summary={
                "total": 0,
                "normal": 0,
                "suspicious": 0,
                "intrusion": 0
            },
            http_attacks=[],
            network_summary={
                "total": 0,
                "normal": 0,
                "intrusion": 0
            },
            network_attacks=[],
            risk_distribution=[],
            correlation_summary=[],
            alert_status_summary=[],
            recent_incidents=[],
            error=str(exc)
        )
@app.route("/logout")
@login_required
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )

if __name__ == "__main__":
    app.run(port=5000, debug=True)