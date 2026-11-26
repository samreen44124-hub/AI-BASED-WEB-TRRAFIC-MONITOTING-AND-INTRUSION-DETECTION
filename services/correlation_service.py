from datetime import datetime, timedelta
import ipaddress

from services.database_service import (
    get_http_traffic_by_id,
    get_network_flows_in_time_window
)


class CorrelationService:

    def __init__(
        self,
        backward_seconds=10,
        forward_seconds=120
    ):
        self.backward_seconds = backward_seconds
        self.forward_seconds = forward_seconds

    # ---------------------------------------------------------
    # TIME
    # ---------------------------------------------------------

    @staticmethod
    def parse_http_timestamp(value):

        if not value:
            return None

        formats = [
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%d/%m/%Y %I:%M:%S %p",
            "%d/%m/%Y %H:%M:%S"
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

    @staticmethod
    def parse_flow_timestamp(value):

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

    # ---------------------------------------------------------
    # IP NORMALIZATION
    # ---------------------------------------------------------

    @staticmethod
    def normalize_ip(value):

        if value is None:
            return None

        value = str(value).strip()

        if not value:
            return None

        # Common localhost forms
        if value.lower() == "localhost":
            return "127.0.0.1"

        try:

            ip = ipaddress.ip_address(value)

            # Convert IPv4-mapped IPv6:
            # ::ffff:127.0.0.1 -> 127.0.0.1
            if (
                isinstance(ip, ipaddress.IPv6Address)
                and ip.ipv4_mapped
            ):
                return str(ip.ipv4_mapped)

            # Treat IPv6 loopback as the same logical
            # localhost endpoint for our local test system.
            if ip.is_loopback:
                return "127.0.0.1"

            return str(ip)

        except ValueError:
            return value.lower()

    # ---------------------------------------------------------
    # IP MATCHING
    # ---------------------------------------------------------

    def ip_matches(self, http_ip, flow):

        http_ip = self.normalize_ip(http_ip)

        flow_source = self.normalize_ip(
            flow.get("source_ip")
        )

        flow_destination = self.normalize_ip(
            flow.get("destination_ip")
        )

        if not http_ip:
            return False

        return (
            http_ip == flow_source
            or
            http_ip == flow_destination
        )

    # ---------------------------------------------------------
    # PORT MATCHING
    # ---------------------------------------------------------

    @staticmethod
    def port_matches(flow, target_port=None):

        if target_port is None:
            return True

        try:
            target_port = int(target_port)
        except (TypeError, ValueError):
            return False

        try:
            source_port = int(
                flow.get("source_port")
            )
        except (TypeError, ValueError):
            source_port = None

        try:
            destination_port = int(
                flow.get("destination_port")
            )
        except (TypeError, ValueError):
            destination_port = None

        return (
            source_port == target_port
            or
            destination_port == target_port
        )

    # ---------------------------------------------------------
    # TIME DIFFERENCE
    # ---------------------------------------------------------

    def calculate_time_difference(
        self,
        http_time,
        flow
    ):

        flow_time = self.parse_http_timestamp(
            flow.get("flow_timestamp")
        )
        if flow_time is None:
            return None

        return abs(
            (flow_time - http_time).total_seconds()
        )

    # ---------------------------------------------------------
    # CANDIDATE SCORING
    # ---------------------------------------------------------

    def score_candidate(
        self,
        http_log,
        flow,
        target_port=None
    ):
        """
        Score correlation evidence.

        This score represents match quality only.
        It is NOT an intrusion probability.
        """

        http_ip = http_log.get("source_ip")

        if not self.ip_matches(
            http_ip,
            flow
        ):
            return None

        http_time = self.parse_http_timestamp(
            http_log.get("created_at")
        )

        if http_time is None:
            return None

        time_difference = (
            self.calculate_time_difference(
                http_time,
                flow
            )
        )

        if time_difference is None:
            return None

        maximum_window = max(
            self.backward_seconds,
            self.forward_seconds
        )

        if time_difference > maximum_window:
            return None

        score = 0

        # Strong requirement: source IP appears
        # on either side of the network flow.
        score += 50

        port_match = self.port_matches(
            flow,
            target_port
        )

        if target_port is not None:

            if not port_match:
                return None

            score += 30

        # Closer timestamps receive a larger score.
        if time_difference <= 2:
            score += 20

        elif time_difference <= 5:
            score += 15

        elif time_difference <= 10:
            score += 10

        elif time_difference <= 20:
            score += 5

        return {
            "score": score,
            "time_difference_seconds": (
                time_difference
            ),
            "port_match": port_match
        }

    # ---------------------------------------------------------
    # MAIN CORRELATION
    # ---------------------------------------------------------

    def correlate_http_log(
        self,
        traffic_id,
        target_port=None
    ):

        http_log = get_http_traffic_by_id(
            traffic_id
        )

        if http_log is None:

            return {
                "matched": False,
                "reason": "HTTP traffic log not found.",
                "http_log": None,
                "network_flow": None
            }

        http_time = self.parse_http_timestamp(
            http_log.get("created_at")
        )

        if http_time is None:

            return {
                "matched": False,
                "reason": (
                    "HTTP timestamp could not "
                    "be parsed."
                ),
                "http_log": http_log,
                "network_flow": None
            }

        start_time = http_time - timedelta(
            seconds=self.backward_seconds
        )

        end_time = http_time + timedelta(
            seconds=self.forward_seconds
        )

        candidates = (
            get_network_flows_in_time_window(
                start_time,
                end_time
            )
        )

        matches = []

        for flow in candidates:

            match_info = self.score_candidate(
                http_log=http_log,
                flow=flow,
                target_port=target_port
            )

            if match_info is None:
                continue

            matches.append({
                "flow": flow,
                **match_info
            })

        if not matches:

            return {
                "matched": False,
                "reason": (
                    "No matching network flow "
                    "was found."
                ),
                "http_log": http_log,
                "network_flow": None,
                "candidate_count": len(candidates)
            }

        matches.sort(
            key=lambda item: (
                -item["score"],
                item["time_difference_seconds"]
            )
        )

        best = matches[0]

        return {
            "matched": True,
            "reason": "Network evidence matched.",
            "http_log": http_log,
            "network_flow": best["flow"],
            "correlation_score": best["score"],
            "time_difference_seconds": (
                best["time_difference_seconds"]
            ),
            "candidate_count": len(candidates),
            "matched_candidate_count": len(matches)
        }


correlation_service = CorrelationService()