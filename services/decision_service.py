class DecisionService:

    HTTP_MODEL_NAME = "CSIC HTTP V2"
    NETWORK_MODEL_NAME = "CIC-IDS2017 Network RF"

    # -----------------------------------------------------
    # RISK PRIORITY
    # -----------------------------------------------------

    RISK_PRIORITY = {
        "Low": 0,
        "Medium": 1,
        "High": 2,
        "Critical": 3
    }

    # -----------------------------------------------------
    # NETWORK ATTACK RISK
    # -----------------------------------------------------

    NETWORK_RISK = {
        "Normal": "Low",
        "DoS": "Critical",
        "DDoS": "Critical",
        "Port Scan": "High",
        "Network Brute Force": "High",
        "Bot": "High",
        "Web Attack": "High"
    }

    # -----------------------------------------------------
    # HTTP EVIDENCE NORMALIZATION
    # -----------------------------------------------------

    def normalize_http_evidence(
            self,
            http_result):

        if not http_result:
            return None

        status = http_result.get(
            "status",
            "Normal"
        )

        confidence = float(
            http_result.get(
                "confidence",
                0.0
            )
        )

        attack_type = http_result.get(
            "attack_type",
            "Normal"
        )

        risk_level = http_result.get(
            "risk_level",
            "Low"
        )

        return {
            "source": "http",

            "status": status,

            "attack_type": attack_type,

            "risk_level": risk_level,

            "confidence": confidence,

            "model_name": http_result.get(
                "model_name",
                self.HTTP_MODEL_NAME
            )
        }

    # -----------------------------------------------------
    # NETWORK EVIDENCE NORMALIZATION
    # -----------------------------------------------------

    def normalize_network_evidence(
            self,
            network_result):

        if not network_result:
            return None

        attack_type = network_result.get(
            "attack_type",
            "Normal"
        )

        confidence = float(
            network_result.get(
                "confidence",
                0.0
            )
        )

        if attack_type == "Normal":
            status = "Normal"
        else:
            status = "Intrusion"

        risk_level = self.NETWORK_RISK.get(
            attack_type,
            "High"
        )

        return {
            "source": "network",

            "status": status,

            "attack_type": attack_type,

            "risk_level": risk_level,

            "confidence": confidence,

            "model_name": network_result.get(
                "model_name",
                self.NETWORK_MODEL_NAME
            )
        }

    # -----------------------------------------------------
    # HIGHEST RISK
    # -----------------------------------------------------

    def highest_risk(
            self,
            *risk_levels):

        valid = [
            risk
            for risk in risk_levels
            if risk in self.RISK_PRIORITY
        ]

        if not valid:
            return "Low"

        return max(
            valid,
            key=lambda risk:
                self.RISK_PRIORITY[risk]
        )

    # -----------------------------------------------------
    # FINAL DECISION
    # -----------------------------------------------------

    def decide(
            self,
            http_result=None,
            network_result=None):

        http = self.normalize_http_evidence(
            http_result
        )

        network = (
            self.normalize_network_evidence(
                network_result
            )
        )

        if http is None and network is None:
            raise ValueError(
                "DecisionService requires HTTP "
                "or network evidence."
            )

        # -------------------------------------------------
        # CASE 1:
        # Network model identifies an attack class.
        #
        # Network evidence is specific enough to provide
        # the final attack type.
        # -------------------------------------------------

        if (
            network
            and
            network["status"] == "Intrusion"
        ):

            risk_level = network[
                "risk_level"
            ]

            # If HTTP also sees suspicious activity,
            # preserve the highest risk.
            if http:
                risk_level = self.highest_risk(
                    risk_level,
                    http["risk_level"]
                )

            return {
                "status": "Intrusion",

                "attack_type":
                    network["attack_type"],

                "risk_level":
                    risk_level,

                "confidence":
                    network["confidence"],

                "decision_source":
                    "Network Model",

                "http_evidence":
                    http,

                "network_evidence":
                    network
            }

        # -------------------------------------------------
        # CASE 2:
        # Network says Normal but HTTP model detects
        # suspicious/anomalous request behavior.
        #
        # Do NOT fabricate SQLi/XSS subtype.
        # -------------------------------------------------

        if (
            http
            and
            http["status"] == "Suspicious"
        ):

            return {
                "status": "Suspicious",

                "attack_type":
                    "HTTP Anomaly",

                "risk_level":
                    http["risk_level"],

                "confidence":
                    http["confidence"],

                "decision_source":
                    "HTTP Model",

                "http_evidence":
                    http,

                "network_evidence":
                    network
            }

        # -------------------------------------------------
        # CASE 3:
        # HTTP layer already reports Intrusion.
        #
        # Kept for future compatibility even though
        # current HTTP-only model normally emits
        # Normal/Suspicious.
        # -------------------------------------------------

        if (
            http
            and
            http["status"] == "Intrusion"
        ):

            return {
                "status": "Intrusion",

                "attack_type":
                    http["attack_type"],

                "risk_level":
                    http["risk_level"],

                "confidence":
                    http["confidence"],

                "decision_source":
                    "HTTP Model",

                "http_evidence":
                    http,

                "network_evidence":
                    network
            }

        # -------------------------------------------------
        # CASE 4:
        # Available evidence is Normal.
        # -------------------------------------------------

        confidences = []

        if http:
            confidences.append(
                http["confidence"]
            )

        if network:
            confidences.append(
                network["confidence"]
            )

        confidence = (
            max(confidences)
            if confidences
            else 0.0
        )

        return {
            "status": "Normal",

            "attack_type": "Normal",

            "risk_level": "Low",

            "confidence": confidence,

            "decision_source":
                "Available Models",

            "http_evidence":
                http,

            "network_evidence":
                network
        }


decision_service = DecisionService()