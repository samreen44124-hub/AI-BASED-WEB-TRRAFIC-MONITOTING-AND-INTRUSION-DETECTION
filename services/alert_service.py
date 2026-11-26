from datetime import datetime

from services.database_service import (
    insert_alert,
    get_recent_alerts,
    get_alert_by_id,
    get_alert_statistics,
    update_alert_status
)


class AlertService:

    # -----------------------------------------------------
    # ATTACK TYPE HELPERS
    # -----------------------------------------------------

    @staticmethod
    def get_http_attack_type(decision):

        http_evidence = decision.get(
            "http_evidence"
        )

        if not http_evidence:
            return "Normal"

        return http_evidence.get(
            "attack_type",
            "Normal"
        )

    @staticmethod
    def get_network_attack_type(decision):

        network_evidence = decision.get(
            "network_evidence"
        )

        if not network_evidence:
            return "Normal"

        return network_evidence.get(
            "attack_type",
            "Normal"
        )

    # -----------------------------------------------------
    # DESCRIPTION
    # -----------------------------------------------------

    @staticmethod
    def build_description(
            decision,
            correlation=None):

        http_attack = (
            AlertService.get_http_attack_type(
                decision
            )
        )

        network_attack = (
            AlertService.get_network_attack_type(
                decision
            )
        )

        correlated = (
            correlation
            and
            correlation.get("matched") is True
        )

        if correlated:

            if (
                http_attack != "Normal"
                and
                network_attack != "Normal"
            ):

                return (
                    f"Correlated security incident: "
                    f"HTTP {http_attack} with "
                    f"network {network_attack}."
                )

            if http_attack != "Normal":

                return (
                    f"HTTP security incident detected: "
                    f"{http_attack}. "
                    f"Network evidence was correlated."
                )

            if network_attack != "Normal":

                return (
                    f"Network security incident detected: "
                    f"{network_attack}. "
                    f"HTTP traffic was correlated."
                )

        if http_attack != "Normal":

            return (
                f"HTTP security incident detected: "
                f"{http_attack}."
            )

        if network_attack != "Normal":

            return (
                f"Network security incident detected: "
                f"{network_attack}."
            )

        return "Security event detected."

    # -----------------------------------------------------
    # CREATE ALERT FROM DECISION
    # -----------------------------------------------------

    def create_from_decision(
            self,
            decision,
            correlation=None,
            http_traffic_id=None,
            network_flow_id=None,
            source_ip=None):

        if not decision:

            return None

        decision_status = decision.get(
            "status",
            "Normal"
        )

        # -------------------------------------------------
        # Only suspicious/intrusion decisions become alerts.
        # Normal traffic does not create an alert.
        # -------------------------------------------------

        if decision_status not in (
            "Intrusion",
            "Suspicious"
        ):

            return None

        http_attack = (
            self.get_http_attack_type(
                decision
            )
        )

        network_attack = (
            self.get_network_attack_type(
                decision
            )
        )

        correlation_matched = (
            correlation
            and
            correlation.get("matched") is True
        )

        if correlation_matched:

            correlation_status = (
                "Correlated"
            )

            correlation_score = (
                correlation.get(
                    "correlation_score",
                    0
                )
            )

        else:

            correlation_status = (
                "Not Correlated"
            )

            correlation_score = 0

        http_evidence = decision.get(
            "http_evidence"
        )

        network_evidence = decision.get(
            "network_evidence"
        )

        # -------------------------------------------------
        # Source IP
        # -------------------------------------------------

        if not source_ip:

            if http_evidence:

                source_ip = http_evidence.get(
                    "source_ip"
                )

            if not source_ip and network_evidence:

                source_ip = network_evidence.get(
                    "source_ip"
                )

        # -------------------------------------------------
        # Alert data
        # -------------------------------------------------

        alert_data = {

            "alert_time":
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),

            "source_ip":
                source_ip or "",

            "http_traffic_id":
                http_traffic_id,

            "network_flow_id":
                network_flow_id,

            "http_attack_type":
                http_attack,

            "network_attack_type":
                network_attack,

            "correlation_status":
                correlation_status,

            "correlation_score":
                correlation_score,

            "status":
                decision.get(
                    "status",
                    "Intrusion"
                ),

            "risk_level":
                decision.get(
                    "risk_level",
                    "Low"
                ),

            "confidence":
                decision.get(
                    "confidence",
                    0.0
                ),

            "description":
                self.build_description(
                    decision,
                    correlation
                ),

            "alert_status":
                "New"
        }

        return insert_alert(
            alert_data
        )

    # -----------------------------------------------------
    # READ OPERATIONS
    # -----------------------------------------------------

    def get_alerts(self, limit=100):

        return get_recent_alerts(
            limit
        )

    def get_alert(
            self,
            alert_id):

        return get_alert_by_id(
            alert_id
        )

    def get_statistics(self):

        return get_alert_statistics()

    # -----------------------------------------------------
    # STATUS
    # -----------------------------------------------------

    def change_status(
            self,
            alert_id,
            alert_status):

        return update_alert_status(
            alert_id,
            alert_status
        )


alert_service = AlertService()