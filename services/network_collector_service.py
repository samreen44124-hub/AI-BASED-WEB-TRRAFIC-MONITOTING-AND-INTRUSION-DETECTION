import os
import time
from datetime import datetime
import pandas as pd

from services.network_flow_service import (
    network_flow_service
)

from services.database_service import (
    insert_network_flow,
    get_latest_traffic
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


class NetworkCollectorService:

    def __init__(
            self,
            csv_path,
            poll_interval=2):

        self.csv_path = csv_path

        self.poll_interval = poll_interval

        self.running = False

        # -------------------------------------------------
        # In-memory optimization only.
        #
        # Persistent duplicate protection still belongs
        # to SQLite through flow_key UNIQUE.
        # -------------------------------------------------

        self.seen_flow_keys = set()

        # File information used to detect replacement
        # or truncation.
        self.last_file_size = None
        self.last_modified_time = None

    # -----------------------------------------------------
    # CSV EXISTS
    # -----------------------------------------------------

    def csv_exists(self):

        return os.path.exists(
            self.csv_path
        )

    # -----------------------------------------------------
    # READ CICFLOWMETER CSV
    # -----------------------------------------------------

    def read_csv(self):

        if not self.csv_exists():

            raise FileNotFoundError(
                "CICFlowMeter CSV not found: "
                f"{self.csv_path}"
            )

        try:

            df = pd.read_csv(
                self.csv_path
            )

        except pd.errors.EmptyDataError:

            return pd.DataFrame()

        except pd.errors.ParserError as exc:

            # CICFlowMeter may be writing while
            # Python tries to read the file.
            raise RuntimeError(
                "CICFlowMeter CSV is temporarily "
                f"unreadable: {exc}"
            )

        return df

    # -----------------------------------------------------
    # FILE STATE
    # -----------------------------------------------------

    def get_file_state(self):

        if not self.csv_exists():
            return None

        stat = os.stat(
            self.csv_path
        )

        return {
            "size": stat.st_size,
            "modified": stat.st_mtime
        }

    # -----------------------------------------------------
    # DETECT FILE RESET / REPLACEMENT
    # -----------------------------------------------------

    def check_file_reset(self):

        state = self.get_file_state()

        if state is None:
            return

        current_size = state["size"]

        # A smaller file normally means CICFlowMeter
        # created/truncated a new CSV.
        if (
            self.last_file_size is not None
            and
            current_size < self.last_file_size
        ):

            print()
            print(
                "[NETWORK] CICFlowMeter CSV "
                "was truncated/replaced."
            )

            print(
                "[NETWORK] Clearing in-memory "
                "flow cache."
            )

            self.seen_flow_keys.clear()

        self.last_file_size = (
            current_size
        )

        self.last_modified_time = (
            state["modified"]
        )

    # -----------------------------------------------------
    # CREATE NETWORK ALERT
    # -----------------------------------------------------

    def create_network_alert(
            self,
            network_flow_id,
            network_result):

        try:

            attack_type = (
                network_result.get(
                    "attack_type",
                    "Normal"
                )
            )

            # -------------------------------------------------
            # Normal network traffic does not create an alert.
            # -------------------------------------------------

            if attack_type == "Normal":

                return {
                    "alert_created": False,
                    "correlated": False,
                    "alert_id": None
                }

            # -------------------------------------------------
            # Build network evidence for DecisionService.
            # -------------------------------------------------

            network_evidence = {
                "status":
                    network_result.get(
                        "status",
                        "Intrusion"
                    ),

                "attack_type":
                    attack_type,

                "risk_level":
                    network_result.get(
                        "risk_level",
                        "High"
                    ),

                "confidence":
                    network_result.get(
                        "confidence",
                        0.0
                    ),

                "model_name":
                    network_result.get(
                        "model_name",
                        "CIC-IDS2017 Network RF"
                    ),

                "source_ip":
                    network_result.get(
                        "source_ip"
                    )
            }

            # -------------------------------------------------
            # Try to correlate this network event with recent
            # HTTP traffic.
            #
            # We examine recent HTTP records and ask the
            # existing CorrelationService whether the current
            # network flow is related.
            # -------------------------------------------------

            correlation = None

            recent_http_logs = (
                get_latest_traffic(100)
            )

            for http_log in recent_http_logs:

                http_traffic_id = (
                    http_log.get("id")
                )

                if not http_traffic_id:
                    continue

                candidate_correlation = (
                    correlation_service
                    .correlate_http_log(
                        http_traffic_id
                    )
                )

                if not candidate_correlation.get(
                    "matched"
                ):
                    continue

                matched_flow = (
                    candidate_correlation.get(
                        "network_flow"
                    )
                )

                if not matched_flow:
                    continue

                matched_flow_id = (
                    matched_flow.get("id")
                )

                if matched_flow_id != network_flow_id:
                    continue

                correlation = (
                    candidate_correlation
                )

                break

            # -------------------------------------------------
            # CORRELATED NETWORK + HTTP EVENT
            # -------------------------------------------------

            if correlation:

                http_log = (
                    correlation.get(
                        "http_log"
                    )
                )

                decision = (
                    decision_service.decide(
                        http_result=http_log,
                        network_result=network_evidence
                    )
                )

                alert_id = (
                    alert_service
                    .create_from_decision(
                        decision=decision,
                        correlation=correlation,
                        http_traffic_id=(
                            http_log.get("id")
                            if http_log
                            else None
                        ),
                        network_flow_id=(
                            network_flow_id
                        ),
                        source_ip=(
                            network_result.get(
                                "source_ip",
                                ""
                            )
                        )
                    )
                )

                print()
                print(
                    "[NETWORK] CORRELATED ALERT CREATED"
                )

                print(
                    f"  Alert ID:    {alert_id}"
                )

                print(
                    f"  HTTP ID:     "
                    f"{http_log.get('id')}"
                )

                print(
                    f"  Network ID:   "
                    f"{network_flow_id}"
                )

                print(
                    f"  HTTP Attack: "
                    f"{http_log.get('attack_type')}"
                )

                print(
                    f"  Network:     "
                    f"{attack_type}"
                )

                print(
                    f"  Score:       "
                    f"{correlation.get('correlation_score', 0)}"
                )

                return {
                    "alert_created": True,
                    "correlated": True,
                    "alert_id": alert_id
                }

            # -------------------------------------------------
            # NETWORK-ONLY EVENT
            # -------------------------------------------------

            decision = (
                decision_service.decide(
                    network_result=network_evidence
                )
            )

            alert_id = (
                alert_service
                .create_from_decision(
                    decision=decision,
                    correlation=None,
                    http_traffic_id=None,
                    network_flow_id=network_flow_id,
                    source_ip=(
                        network_result.get(
                            "source_ip",
                            ""
                        )
                    )
                )
            )

            print()
            print(
                "[NETWORK] NETWORK ALERT CREATED"
            )

            print(
                f"  Alert ID:    {alert_id}"
            )

            print(
                f"  Network ID:  {network_flow_id}"
            )

            print(
                f"  Attack:      {attack_type}"
            )

            print(
                f"  Risk:        "
                f"{decision.get('risk_level')}"
            )

            print(
                f"  Confidence:  "
                f"{network_result.get('confidence', 0):.6f}"
            )

            return {
                "alert_created": True,
                "correlated": False,
                "alert_id": alert_id
            }

        except Exception as exc:

            print()
            print(
                "[NETWORK] Alert integration failed"
            )

            print(
                f"  Error: {exc}"
            )

            return {
                "alert_created": False,
                "correlated": False,
                "alert_id": None
            }

    # -----------------------------------------------------
    # PROCESS ONE SCAN
    # -----------------------------------------------------

    def process_once(self):

        summary = {
            "rows": 0,
            "predicted": 0,
            "inserted": 0,
            "duplicates": 0,
            "skipped_memory": 0,
            "failed": 0,
            "alerts": 0,
            "correlated_alerts": 0
        }

        self.check_file_reset()

        try:

            df = self.read_csv()

        except RuntimeError as exc:

            print(
                f"[NETWORK] {exc}"
            )

            return summary

        if df.empty:
            return summary

        # -------------------------------------------------
        # Normalize headers using the exact same service
        # that passed the 65/65 contract test.
        # -------------------------------------------------

        df = (
            network_flow_service
            .normalize_dataframe(df)
        )

        # Validate the collector/model contract before
        # attempting any prediction.
        network_flow_service.validate_contract(
            df
        )

        summary["rows"] = len(df)

        # -------------------------------------------------
        # Process each complete flow
        # -------------------------------------------------

        for index, row in df.iterrows():

            try:

                # -----------------------------------------
                # Extract metadata first so we can create
                # flow_key BEFORE running ML inference.
                # -----------------------------------------

                metadata = (
                    network_flow_service
                    .extract_metadata(row)
                )

                flow_key = (
                    network_flow_service
                    .build_flow_key(metadata)
                )

                # -----------------------------------------
                # Fast in-memory duplicate skip
                # -----------------------------------------

                if (
                    flow_key
                    in self.seen_flow_keys
                ):

                    summary[
                        "skipped_memory"
                    ] += 1

                    continue

                # -----------------------------------------
                # ML prediction
                # -----------------------------------------

                result = (
                    network_flow_service
                    .predict_row(row)
                )

                summary["predicted"] += 1

                # -----------------------------------------
                # Persistent SQLite insert
                # -----------------------------------------

                result["created_at"] = (
                    datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                )

                database_id = (
                    insert_network_flow(
                        result
                    )
                )

                # Regardless of whether SQLite inserted
                # it, this process has now seen this key.
                self.seen_flow_keys.add(
                    flow_key
                )

                if database_id is None:

                    summary[
                        "duplicates"
                    ] += 1

                    print(
                        "[NETWORK] Duplicate skipped: "
                        f"{flow_key}"
                    )

                    continue

                summary["inserted"] += 1

                print()
                print(
                    "[NETWORK] New flow stored"
                )

                print(
                    f"  DB ID:       "
                    f"{database_id}"
                )

                print(
                    f"  Source:      "
                    f"{result.get('source_ip')}:"
                    f"{result.get('source_port')}"
                )

                print(
                    f"  Destination: "
                    f"{result.get('destination_ip')}:"
                    f"{result.get('destination_port')}"
                )

                print(
                    f"  Prediction:  "
                    f"{result.get('attack_type')}"
                )

                print(
                    f"  Confidence:  "
                    f"{result.get('confidence', 0):.6f}"
                )

                # -----------------------------------------
                # ALERT + CORRELATION INTEGRATION
                # -----------------------------------------

                alert_result = (
                    self.create_network_alert(
                        network_flow_id=database_id,
                        network_result=result
                    )
                )

                if alert_result.get(
                    "alert_created"
                ):

                    summary["alerts"] += 1

                if alert_result.get(
                    "correlated"
                ):

                    summary[
                        "correlated_alerts"
                    ] += 1

            except Exception as exc:

                summary["failed"] += 1

                print()
                print(
                    "[NETWORK] Flow processing "
                    f"failed at CSV row "
                    f"{index + 1}"
                )

                print(
                    f"  Error: {exc}"
                )

        return summary

    # -----------------------------------------------------
    # CONTINUOUS MONITOR
    # -----------------------------------------------------

    def run(self):

        self.running = True

        print("=" * 70)
        print(
            "NETWORK FLOW COLLECTOR STARTED"
        )
        print("=" * 70)

        print(
            f"CSV: {self.csv_path}"
        )

        print(
            f"Poll interval: "
            f"{self.poll_interval} seconds"
        )

        print()

        print(
            "Press Ctrl+C to stop."
        )

        try:

            while self.running:

                try:

                    summary = (
                        self.process_once()
                    )

                    # Only display activity when something
                    # actually required attention.
                    if (
                        summary["inserted"] > 0
                        or
                        summary["duplicates"] > 0
                        or
                        summary["failed"] > 0
                        or
                        summary["alerts"] > 0
                    ):

                        print()
                        print(
                            "[NETWORK] Scan summary"
                        )

                        print(
                            f"  CSV rows:          "
                            f"{summary['rows']}"
                        )

                        print(
                            f"  Predicted:         "
                            f"{summary['predicted']}"
                        )

                        print(
                            f"  Inserted:          "
                            f"{summary['inserted']}"
                        )

                        print(
                            f"  DB duplicates:     "
                            f"{summary['duplicates']}"
                        )

                        print(
                            f"  Memory skipped:    "
                            f"{summary['skipped_memory']}"
                        )

                        print(
                            f"  Alerts created:    "
                            f"{summary['alerts']}"
                        )

                        print(
                            f"  Correlated alerts: "
                            f"{summary['correlated_alerts']}"
                        )

                        print(
                            f"  Failed:            "
                            f"{summary['failed']}"
                        )

                except FileNotFoundError:

                    # CICFlowMeter may not have created
                    # its CSV yet.
                    pass

                except Exception as exc:

                    # Collector must survive a temporary
                    # CSV or processing problem.
                    print()
                    print(
                        "[NETWORK] Collector scan "
                        f"error: {exc}"
                    )

                time.sleep(
                    self.poll_interval
                )

        except KeyboardInterrupt:

            print()
            print()
            print(
                "NETWORK FLOW COLLECTOR STOPPED"
            )

        finally:

            self.running = False

    # -----------------------------------------------------
    # STOP
    # -----------------------------------------------------

    def stop(self):

        self.running = False