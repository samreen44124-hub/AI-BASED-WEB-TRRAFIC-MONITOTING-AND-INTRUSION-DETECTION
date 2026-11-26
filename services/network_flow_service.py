import json
import os

import numpy as np
import pandas as pd

from services.network_model_service import network_attack_model


BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

FEATURES_PATH = os.path.join(
    BASE_DIR,
    "models",
    "network_features.json"
)


# CICFlowMeter live column names -> CIC-IDS2017 training names
COLUMN_MAPPING = {
    "Dst Port": "Destination Port",

    "Total Fwd Packet": "Total Fwd Packets",
    "Total Bwd packets": "Total Backward Packets",

    "Total Length of Fwd Packet":
        "Total Length of Fwd Packets",

    "Total Length of Bwd Packet":
        "Total Length of Bwd Packets",

    "Packet Length Min": "Min Packet Length",
    "Packet Length Max": "Max Packet Length",

    "Fwd Segment Size Avg": "Avg Fwd Segment Size",
    "Bwd Segment Size Avg": "Avg Bwd Segment Size",

    "FWD Init Win Bytes": "Init_Win_bytes_forward",
    "Bwd Init Win Bytes": "Init_Win_bytes_backward",

    "Fwd Act Data Pkts": "act_data_pkt_fwd",
    "Fwd Seg Size Min": "min_seg_size_forward"
}


class NetworkFlowService:

    def __init__(self):

        self.required_features = (
            self._load_required_features()
        )

        if len(self.required_features) != 65:
            raise ValueError(
                "Network model feature contract must "
                f"contain 65 features, found "
                f"{len(self.required_features)}."
            )

    # -----------------------------------------------------
    # LOAD FEATURE CONTRACT
    # -----------------------------------------------------

    def _load_required_features(self):

        if not os.path.exists(FEATURES_PATH):
            raise FileNotFoundError(
                f"Network feature file not found: "
                f"{FEATURES_PATH}"
            )

        with open(
            FEATURES_PATH,
            "r",
            encoding="utf-8"
        ) as file:

            features = json.load(file)

        if not isinstance(features, list):
            raise ValueError(
                "network_features.json must "
                "contain a JSON list."
            )

        return features

    # -----------------------------------------------------
    # COLUMN NORMALIZATION
    # -----------------------------------------------------

    def normalize_dataframe(self, df):

        if not isinstance(df, pd.DataFrame):
            raise TypeError(
                "Expected a pandas DataFrame."
            )

        df = df.copy()

        # Remove whitespace around CICFlowMeter headers.
        df.columns = [
            str(column).strip()
            for column in df.columns
        ]

        # Convert live CICFlowMeter names to
        # CIC-IDS2017 training names.
        df = df.rename(
            columns=COLUMN_MAPPING
        )

        return df

    # -----------------------------------------------------
    # FEATURE CONTRACT VALIDATION
    # -----------------------------------------------------

    def validate_contract(self, df):

        missing = [
            feature
            for feature in self.required_features
            if feature not in df.columns
        ]

        if missing:
            raise ValueError(
                "Missing network model features: "
                + ", ".join(missing)
            )

        return True

    # -----------------------------------------------------
    # BUILD ONE MODEL INPUT
    # -----------------------------------------------------

    def build_flow_features(self, row):

        flow_data = {}

        for feature in self.required_features:

            if feature not in row.index:
                raise ValueError(
                    f"Required feature missing: "
                    f"{feature}"
                )

            value = pd.to_numeric(
                row[feature],
                errors="coerce"
            )

            if pd.isna(value):
                raise ValueError(
                    f"Invalid numeric value for "
                    f"'{feature}': {row[feature]}"
                )

            value = float(value)

            if not np.isfinite(value):
                raise ValueError(
                    f"Non-finite value for "
                    f"'{feature}': {value}"
                )

            flow_data[feature] = value

        return flow_data

    # -----------------------------------------------------
    # SAFE METADATA VALUE
    # -----------------------------------------------------

    @staticmethod
    def _safe_value(row, column, default=None):

        if column not in row.index:
            return default

        value = row[column]

        if pd.isna(value):
            return default

        return value

    # -----------------------------------------------------
    # INTEGER CONVERSION
    # -----------------------------------------------------

    @staticmethod
    def _safe_int(value):

        if value is None:
            return None

        try:
            return int(float(value))
        except (ValueError, TypeError):
            return None

    # -----------------------------------------------------
    # EXTRACT FLOW METADATA
    # -----------------------------------------------------

    def extract_metadata(self, row):

        return {
            "flow_id": self._safe_value(
                row,
                "Flow ID"
            ),

            "source_ip": self._safe_value(
                row,
                "Src IP"
            ),

            "source_port": self._safe_int(
                self._safe_value(
                    row,
                    "Src Port"
                )
            ),

            "destination_ip": self._safe_value(
                row,
                "Dst IP"
            ),

            # Dst Port has already been normalized.
            "destination_port": self._safe_int(
                self._safe_value(
                    row,
                    "Destination Port"
                )
            ),

            "protocol": self._safe_int(
                self._safe_value(
                    row,
                    "Protocol"
                )
            ),

            "timestamp": self._safe_value(
                row,
                "Timestamp"
            )
        }

    # -----------------------------------------------------
    # PREDICT ONE FLOW
    # -----------------------------------------------------

    def predict_row(self, row):

        flow_features = (
            self.build_flow_features(row)
        )

        prediction = (
            network_attack_model.predict(
                flow_features
            )
        )

        metadata = self.extract_metadata(row)
        flow_key = self.build_flow_key(
            metadata
        )

        result = {
            **metadata,

            "flow_key": flow_key,

            "attack_type":
                prediction["attack_type"],

            "class_id":
                prediction["class_id"],

            "confidence":
                float(
                    prediction["confidence"]
                ),

            "probabilities":
                prediction["probabilities"],

            "model_name":
                prediction["model_name"]
        }

        return result

    # -----------------------------------------------------
    # PROCESS DATAFRAME
    # -----------------------------------------------------

    def process_dataframe(self, df):

        df = self.normalize_dataframe(df)

        self.validate_contract(df)

        results = []

        for index, row in df.iterrows():

            try:
                result = self.predict_row(row)

                result["row_number"] = (
                    int(index) + 1
                )

                result["success"] = True

            except Exception as exc:

                result = {
                    "row_number": int(index) + 1,
                    "success": False,
                    "error": str(exc)
                }

            results.append(result)

        return results

    # -----------------------------------------------------
    # PROCESS CICFLOWMETER CSV
    # -----------------------------------------------------

    def process_csv(self, csv_path):

        if not os.path.exists(csv_path):
            raise FileNotFoundError(
                f"CICFlowMeter CSV not found: "
                f"{csv_path}"
            )

        df = pd.read_csv(csv_path)

        return self.process_dataframe(df)
    # -----------------------------------------------------
    # BUILD PERSISTENT FLOW KEY
    # -----------------------------------------------------

    @staticmethod
    def build_flow_key(metadata):

        flow_id = metadata.get(
            "flow_id"
        )

        timestamp = metadata.get(
            "timestamp"
        )

        if not flow_id:
            raise ValueError(
                "Cannot create flow key: "
                "flow_id is missing."
            )

        if not timestamp:
            raise ValueError(
                "Cannot create flow key: "
                "timestamp is missing."
            )

        return (
            f"{flow_id}|{timestamp}"
        )


# Singleton used throughout the IDS.
network_flow_service = NetworkFlowService()