import os
import sys
import warnings
from datetime import datetime

import pandas as pd


# ============================================================
# PROJECT PATH
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

DATASET_DIR = os.path.join(
    BASE_DIR,
    "CIC-IDS2017"
)


# ============================================================
# SUPPRESS ONLY THE SCIKIT-LEARN VERSION WARNING
# ============================================================

warnings.filterwarnings(
    "ignore",
    category=UserWarning,
    module="sklearn"
)


# ============================================================
# PROJECT SERVICES
# ============================================================

from services.network_flow_service import (
    network_flow_service
)

from services.database_service import (
    initialize_database,
    insert_network_flow
)

from services.decision_service import (
    decision_service
)

from services.alert_service import (
    alert_service
)


# ============================================================
# 7 MODEL CLASSES
# ============================================================

MODEL_CLASSES = [
    "Normal",
    "DoS",
    "DDoS",
    "Port Scan",
    "Network Brute Force",
    "Bot",
    "Web Attack"
]


# ============================================================
# KNOWN CIC-IDS2017 FILES
# ============================================================

CIC_FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
]


# ============================================================
# PREFERRED FILES FOR EACH CLASS
# ============================================================

PREFERRED_FILES = {
    "Normal": [
        "Monday-WorkingHours.pcap_ISCX.csv",
        "Tuesday-WorkingHours.pcap_ISCX.csv",
        "Wednesday-workingHours.pcap_ISCX.csv"
    ],

    "DoS": [
        "Wednesday-workingHours.pcap_ISCX.csv",
        "Monday-WorkingHours.pcap_ISCX.csv",
        "Tuesday-WorkingHours.pcap_ISCX.csv"
    ],

    "DDoS": [
        "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
    ],

    "Port Scan": [
        "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
    ],

    "Network Brute Force": [
        "Tuesday-WorkingHours.pcap_ISCX.csv",
        "Monday-WorkingHours.pcap_ISCX.csv",
        "Wednesday-workingHours.pcap_ISCX.csv"
    ],

    "Bot": [
        "Friday-WorkingHours-Morning.pcap_ISCX.csv",
        "Tuesday-WorkingHours.pcap_ISCX.csv",
        "Wednesday-workingHours.pcap_ISCX.csv",
        "Monday-WorkingHours.pcap_ISCX.csv"
    ],

    "Web Attack": [
        "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
    ]
}


# ============================================================
# DATASET LABEL NORMALIZATION
# ============================================================

def normalize_text(value):
    """
    Clean CIC-IDS2017 strings.

    Handles values such as:

        BENIGN
        'BENIGN'
        "BENIGN"
        ' Label'
        Label
    """

    if value is None:
        return ""

    value = str(value).strip()

    # Remove surrounding quotes.
    value = value.strip("'\"")

    return value.strip()


def normalize_label(value):
    return normalize_text(value).lower()


# ============================================================
# DATASET LABEL -> MODEL CLASS
# ============================================================

def label_matches(label, target_class):
    """
    Map raw CIC-IDS2017 labels to the
    7 classes used by the trained model.
    """

    raw = normalize_label(label)

    if not raw:
        return False

    # --------------------------------------------------------
    # NORMAL
    # --------------------------------------------------------

    if target_class == "Normal":
        return raw == "benign"

    # --------------------------------------------------------
    # DOS
    # --------------------------------------------------------

    if target_class == "DoS":
        return raw in (
            "dos hulk",
            "dos goldeneye",
            "dos slowloris",
            "dos slowhttptest"
        )

    # --------------------------------------------------------
    # DDOS
    # --------------------------------------------------------

    if target_class == "DDoS":
        return raw == "ddos"

    # --------------------------------------------------------
    # PORT SCAN
    # --------------------------------------------------------

    if target_class == "Port Scan":
        return raw in (
            "portscan",
            "port scan"
        )

    # --------------------------------------------------------
    # NETWORK BRUTE FORCE
    # --------------------------------------------------------

    if target_class == "Network Brute Force":
        return raw in (
            "ftp-patator",
            "ssh-patator"
        )

    # --------------------------------------------------------
    # BOT
    # --------------------------------------------------------

    if target_class == "Bot":
        return raw == "bot"

    # --------------------------------------------------------
    # WEB ATTACK
    # --------------------------------------------------------

    if target_class == "Web Attack":

        web_attack_prefixes = (
            "web attack -",
            "web attack –",
            "web attack —",
            "web attack"
        )

        return any(
            raw.startswith(prefix)
            for prefix in web_attack_prefixes
        )

    return False


# ============================================================
# COLUMN NORMALIZATION
# ============================================================

def clean_column_name(column):
    """
    CIC-IDS2017 downloaded CSV files can contain headers such as:

        ' Label'
        ' Destination Port'
        ' Flow Duration'

    Convert them to:

        Label
        Destination Port
        Flow Duration
    """

    value = str(column).strip()

    # Remove surrounding quotes.
    value = value.strip("'\"")

    # Remove whitespace again.
    value = value.strip()

    return value


def clean_dataframe_columns(df):
    """
    Clean every CSV column name.
    """

    df = df.copy()

    df.columns = [
        clean_column_name(column)
        for column in df.columns
    ]

    return df


# ============================================================
# FIND LABEL COLUMN
# ============================================================

def find_label_column(columns):
    """
    Find Label regardless of spaces or quote characters.
    """

    for column in columns:

        normalized = (
            str(column)
            .strip()
            .strip("'\"")
            .strip()
            .lower()
        )

        if normalized == "label":
            return column

    return None


# ============================================================
# FIND DATASET FILES
# ============================================================

def locate_dataset_files():
    print()
    print("=" * 70)
    print("LOCATING CIC-IDS2017 DATASET")
    print("=" * 70)

    print()
    print("Dataset directory:")
    print(DATASET_DIR)

    if not os.path.isdir(DATASET_DIR):
        raise FileNotFoundError(
            f"CIC-IDS2017 directory not found:\n{DATASET_DIR}"
        )

    files = []

    for filename in CIC_FILES:

        path = os.path.join(
            DATASET_DIR,
            filename
        )

        if os.path.isfile(path):

            size_mb = (
                os.path.getsize(path)
                / (1024 * 1024)
            )

            print(
                f"FOUND  {filename} "
                f"({size_mb:.1f} MB)"
            )

            files.append(path)

        else:

            print(
                f"MISSING {filename}"
            )

    if not files:
        raise RuntimeError(
            "No CIC-IDS2017 CSV files were found."
        )

    return files


# ============================================================
# SHOW LABEL INFORMATION
# ============================================================

def inspect_label_column(csv_path):
    """
    Read only a small portion of a CSV to determine
    the label column and confirm its values.
    """

    try:

        df = pd.read_csv(
            csv_path,
            nrows=5,
            low_memory=False
        )

        label_column = find_label_column(
            df.columns
        )

        if label_column is None:
            return None, []

        values = []

        for value in df[label_column].tolist():

            normalized = normalize_text(value)

            if normalized:
                values.append(normalized)

        return label_column, values

    except Exception:
        return None, []


# ============================================================
# FIND ONE SAMPLE FOR A CLASS
# ============================================================

def find_sample_for_class(
    target_class,
    csv_files,
    chunksize=50000
):
    """
    Search the real CIC-IDS2017 files for one
    valid sample belonging to target_class.

    The search is performed chunk-by-chunk so the
    entire 168 MB / 214 MB files are never loaded
    into memory at once.
    """

    print()
    print(f"[SEARCH] {target_class}")

    ordered_files = []

    # First search preferred files.
    preferred = PREFERRED_FILES.get(
        target_class,
        []
    )

    for filename in preferred:

        for path in csv_files:

            if os.path.basename(path) == filename:

                if path not in ordered_files:
                    ordered_files.append(path)

    # Then search remaining files.
    for path in csv_files:

        if path not in ordered_files:
            ordered_files.append(path)

    for csv_path in ordered_files:

        filename = os.path.basename(csv_path)

        print(
            f"  File: {filename}"
        )

        try:

            # ------------------------------------------------
            # Determine the actual label column.
            # ------------------------------------------------

            header = pd.read_csv(
                csv_path,
                nrows=1,
                low_memory=False
            )

            label_column = find_label_column(
                header.columns
            )

            if label_column is None:

                print(
                    "    Label column not detected."
                )

                continue

            print(
                f"    Label column: "
                f"{repr(label_column)}"
            )

            # ------------------------------------------------
            # Search chunks.
            # ------------------------------------------------

            chunk_number = 0

            for chunk in pd.read_csv(
                csv_path,
                chunksize=chunksize,
                low_memory=False
            ):

                chunk_number += 1

                # Clean column names.
                chunk = clean_dataframe_columns(
                    chunk
                )

                # Find cleaned label column.
                cleaned_label_column = find_label_column(
                    chunk.columns
                )

                if cleaned_label_column is None:
                    continue

                # Normalize labels.
                normalized_labels = (
                    chunk[cleaned_label_column]
                    .astype(str)
                    .str.strip()
                    .str.strip("'\"")
                    .str.strip()
                    .str.lower()
                )

                # ------------------------------------------------
                # Build matching mask.
                # ------------------------------------------------

                if target_class == "Normal":

                    mask = (
                        normalized_labels
                        == "benign"
                    )

                elif target_class == "DoS":

                    mask = normalized_labels.isin([
                        "dos hulk",
                        "dos goldeneye",
                        "dos slowloris",
                        "dos slowhttptest"
                    ])

                elif target_class == "DDoS":

                    mask = (
                        normalized_labels
                        == "ddos"
                    )

                elif target_class == "Port Scan":

                    mask = normalized_labels.isin([
                        "portscan",
                        "port scan"
                    ])

                elif target_class == "Network Brute Force":

                    mask = normalized_labels.isin([
                        "ftp-patator",
                        "ssh-patator"
                    ])

                elif target_class == "Bot":

                    mask = (
                        normalized_labels
                        == "bot"
                    )

                elif target_class == "Web Attack":

                    mask = (
                            normalized_labels.str.startswith(
                                "web attack -"
                            )
                            |
                            normalized_labels.str.startswith(
                                "web attack –"
                            )
                            |
                            normalized_labels.str.startswith(
                                "web attack —"
                            )
                            |
                            normalized_labels.str.startswith(
                                "web attack"
                            )
                    )

                else:

                    mask = pd.Series(
                        False,
                        index=chunk.index
                    )

                matching_rows = chunk.loc[mask]

                if not matching_rows.empty:

                    row = matching_rows.iloc[0].copy()

                    raw_label = row[
                        cleaned_label_column
                    ]

                    print()
                    print(
                        f"    FOUND: {target_class}"
                    )

                    print(
                        f"    Dataset label: "
                        f"{normalize_text(raw_label)}"
                    )

                    print(
                        f"    Chunk: "
                        f"{chunk_number}"
                    )

                    return {
                        "target_class": target_class,
                        "dataset_label": normalize_text(
                            raw_label
                        ),
                        "csv_file": csv_path,
                        "row": row
                    }

                if chunk_number % 10 == 0:

                    print(
                        f"    Chunk {chunk_number}: "
                        f"still searching..."
                    )

        except Exception as exc:

            print(
                f"    ERROR reading file: "
                f"{exc}"
            )

    print(
        f"    NOT FOUND: {target_class}"
    )

    return None


# ============================================================
# FIND ALL 7 SAMPLES
# ============================================================

def find_all_samples(csv_files):

    print()
    print("=" * 70)
    print("FINDING ONE REAL SAMPLE FOR EACH MODEL CLASS")
    print("=" * 70)

    samples = {}

    for target_class in MODEL_CLASSES:

        sample = find_sample_for_class(
            target_class,
            csv_files
        )

        if sample is not None:
            samples[target_class] = sample

    print()
    print("=" * 70)
    print("SAMPLE SEARCH SUMMARY")
    print("=" * 70)

    for target_class in MODEL_CLASSES:

        if target_class in samples:

            sample = samples[target_class]

            print(
                f"{target_class:<24} FOUND"
            )

            print(
                f"  Dataset label: "
                f"{sample['dataset_label']}"
            )

            print(
                f"  File: "
                f"{os.path.basename(sample['csv_file'])}"
            )

        else:

            print(
                f"{target_class:<24} NOT FOUND"
            )

    missing = [
        target_class
        for target_class in MODEL_CLASSES
        if target_class not in samples
    ]

    if missing:

        raise RuntimeError(
            "Missing classes: "
            + ", ".join(missing)
        )

    return samples


# ============================================================
# VALIDATE 65-FEATURE CONTRACT
# ============================================================

def prepare_sample_row(sample):
    """
    Convert a selected CIC-IDS2017 row into the dictionary
    expected by NetworkFlowService.

    CIC-IDS2017 does not contain Flow ID, so a deterministic
    Flow ID is generated for the controlled evidence record.
    """

    row = sample.copy()

    # CIC-IDS2017 metadata
    source_ip = str(
        row.get("Source IP", "127.0.0.1")
    ).strip()

    source_port = str(
        row.get("Source Port", "0")
    ).strip()

    destination_ip = str(
        row.get("Destination IP", "127.0.0.1")
    ).strip()

    destination_port = str(
        row.get("Destination Port", "0")
    ).strip()

    protocol = str(
        row.get("Protocol", "0")
    ).strip()

    # Required Flow ID
    row["Flow ID"] = (
        f"{source_ip}-"
        f"{destination_ip}-"
        f"{source_port}-"
        f"{destination_port}-"
        f"{protocol}"
    )

    # Metadata aliases expected by NetworkFlowService
    row["Src IP"] = source_ip
    row["Src Port"] = row.get(
        "Source Port",
        0
    )

    row["Dst IP"] = destination_ip

    # Keep Destination Port because network_flow_service.py
    # already maps Dst Port -> Destination Port.

    # Timestamp required for flow_key
    timestamp = row.get("Timestamp")

    if timestamp is None or not str(timestamp).strip():
        timestamp = "01/01/2026 12:00:00 PM"

    row["Timestamp"] = timestamp

    return row


# ============================================================
# PREDICT ONE SAMPLE
# PREDICT ONE SAMPLE
# ============================================================

# ============================================================
# PREDICT ONE SAMPLE
# ============================================================

def predict_sample(
    target_class,
    sample
):

    print()
    print("-" * 70)
    print(
        f"TESTING: {target_class}"
    )
    print("-" * 70)

    print(
        "Dataset label:",
        sample["dataset_label"]
    )

    print(
        "Source file:",
        os.path.basename(
            sample["csv_file"]
        )
    )

    # ---------------------------------------------------------
    # Prepare the selected CIC-IDS2017 row.
    # ---------------------------------------------------------

    row = prepare_sample_row(
        sample["row"]
    )

    # ---------------------------------------------------------
    # IMPORTANT:
    #
    # prepare_sample_row() returns a dictionary.
    # NetworkFlowService.predict_row() expects a pandas
    # Series because it uses row.index and row[feature].
    #
    # Convert the dictionary to a Series here.
    # ---------------------------------------------------------

    row = pd.Series(row)

    # ---------------------------------------------------------
    # Final Flow ID verification.
    # ---------------------------------------------------------

    if not str(
        row.get("Flow ID", "")
    ).strip():

        raise ValueError(
            "Controlled test could not create Flow ID."
        )

    # ---------------------------------------------------------
    # Existing network model service.
    # ---------------------------------------------------------

    result = network_flow_service.predict_row(
        row
    )

    print(
        "Expected model class:",
        target_class
    )

    print(
        "Predicted class:",
        result["attack_type"]
    )

    print(
        "Class ID:",
        result["class_id"]
    )

    print(
        "Confidence:",
        result["confidence"]
    )

    print(
        "Model:",
        result["model_name"]
    )

    # --------------------------------------------------------
    # Check whether model prediction agrees with the
    # expected grouped CIC-IDS2017 class.
    # --------------------------------------------------------

    if result["attack_type"] == target_class:

        print(
            "Prediction check: PASS"
        )

    else:

        print(
            "Prediction check: DIFFERENT"
        )

        print(
            "NOTE: The model produced a different "
            "class for this real dataset row."
        )

    return result


# ============================================================
# BUILD CONTROLLED NETWORK DATABASE RECORD
# ============================================================

# ============================================================
# BUILD CONTROLLED NETWORK DATABASE RECORD
# ============================================================

def build_network_record(
    target_class,
    prediction,
    test_number
):

    now = datetime.now()

    timestamp = now.strftime(
        "%d/%m/%Y %I:%M:%S %p"
    )

    # --------------------------------------------------------
    # Create a controlled-test Flow ID.
    #
    # This is NOT changing the dataset or model features.
    # It is only the identifier used for storing this
    # controlled network evidence in the IDS database.
    # --------------------------------------------------------

    flow_id = (
        f"CONTROLLED-7CLASS-"
        f"{test_number:02d}-"
        f"{target_class.replace(' ', '_')}"
    )

    flow_key = (
        f"{flow_id}|{timestamp}"
    )

    # --------------------------------------------------------
    # Network database status/risk follows the application's
    # normal network classification rules.
    # --------------------------------------------------------

    attack_type = prediction.get(
        "attack_type",
        "Normal"
    )

    if attack_type == "Normal":

        status = "Normal"
        risk_level = "Low"

    elif attack_type in (
        "DoS",
        "DDoS"
    ):

        status = "Intrusion"
        risk_level = "Critical"

    else:

        status = "Intrusion"
        risk_level = "High"

    # --------------------------------------------------------
    # Build database record.
    # --------------------------------------------------------

    record = {
        "flow_key": flow_key,

        "flow_id": flow_id,

        "source_ip": prediction.get(
            "source_ip"
        ) or "127.0.0.1",

        "source_port": prediction.get(
            "source_port"
        ),

        "destination_ip": prediction.get(
            "destination_ip"
        ) or "127.0.0.1",

        "destination_port": prediction.get(
            "destination_port"
        ),

        "protocol": prediction.get(
            "protocol"
        ),

        "flow_timestamp": timestamp,

        "status": status,

        "attack_type": attack_type,

        "risk_level": risk_level,

        "class_id": prediction.get(
            "class_id",
            0
        ),

        "confidence": prediction.get(
            "confidence",
            0.0
        ),

        "model_name": prediction.get(
            "model_name",
            "CIC-IDS2017 Network RF"
        ),

        "created_at": now.strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    }

    return record


# ============================================================
# STORE NETWORK EVIDENCE
# ============================================================

def store_network_evidence(
    target_class,
    prediction,
    test_number
):

    record = build_network_record(
        target_class,
        prediction,
        test_number
    )

    network_id = insert_network_flow(
        record
    )

    print()
    print(
        "Network DB ID:",
        network_id
    )

    print(
        "Flow ID:",
        record["flow_id"]
    )

    print(
        "Source:",
        f"{record['source_ip']}:"
        f"{record['source_port']}"
    )

    print(
        "Destination:",
        f"{record['destination_ip']}:"
        f"{record['destination_port']}"
    )

    print(
        "Stored status:",
        record["status"]
    )

    print(
        "Stored attack type:",
        record["attack_type"]
    )

    print(
        "Stored risk:",
        record["risk_level"]
    )

    # --------------------------------------------------------
    # Run DecisionService using the stored network prediction.
    # --------------------------------------------------------

    decision = decision_service.decide(
        network_result=prediction
    )

    print()
    print(
        "Decision:"
    )

    print(
        "  Status:",
        decision["status"]
    )

    print(
        "  Attack type:",
        decision["attack_type"]
    )

    print(
        "  Risk:",
        decision["risk_level"]
    )

    print(
        "  Confidence:",
        decision["confidence"]
    )

    print(
        "  Source:",
        decision["decision_source"]
    )

    # --------------------------------------------------------
    # Create alert for an actual network intrusion.
    # Normal traffic does not create an alert.
    # --------------------------------------------------------

    alert_id = None

    if decision["status"] in (
        "Intrusion",
        "Suspicious"
    ):

        alert_id = alert_service.create_from_decision(
            decision=decision,
            correlation=None,
            http_traffic_id=None,
            network_flow_id=network_id,
            source_ip=record["source_ip"]
        )

        print(
            "Alert ID:",
            alert_id
        )

    else:

        print(
            "Alert:",
            "Not created (Normal traffic)"
        )

    return {
        "network_id": network_id,
        "record": record,
        "decision": decision,
        "alert_id": alert_id
    }


# ============================================================
# TEST ONE CLASS
# ============================================================

def run_class_test(
    test_number,
    target_class,
    sample
):

    prediction = predict_sample(
        target_class,
        sample
    )

    stored = store_network_evidence(
        target_class,
        prediction,
        test_number
    )

    return {
        "target_class": target_class,
        "dataset_label": sample["dataset_label"],
        "predicted_class": prediction[
            "attack_type"
        ],
        "confidence": prediction[
            "confidence"
        ],
        "network_id": stored[
            "network_id"
        ],
        "decision_status": stored[
            "decision"
        ]["status"],
        "decision_attack_type": stored[
            "decision"
        ]["attack_type"],
        "risk_level": stored[
            "decision"
        ]["risk_level"],
        "alert_id": stored[
            "alert_id"
        ]
    }


# ============================================================
# FINAL SUMMARY
# ============================================================

def print_final_summary(results):

    print()
    print()
    print("=" * 90)
    print("FINAL 7-CLASS NETWORK IDS TEST SUMMARY")
    print("=" * 90)

    print()

    header = (
        f"{'Expected':<24}"
        f"{'Dataset Label':<28}"
        f"{'Predicted':<24}"
        f"{'Confidence':<12}"
        f"{'Status':<12}"
        f"{'Alert ID':<10}"
    )

    print(header)
    print("-" * 90)

    for result in results:

        alert_id = result["alert_id"]

        if alert_id is None:
            alert_text = "-"
        else:
            alert_text = str(alert_id)

        print(
            f"{result['target_class']:<24}"
            f"{result['dataset_label'][:27]:<28}"
            f"{result['predicted_class']:<24}"
            f"{result['confidence']:<12.4f}"
            f"{result['decision_status']:<12}"
            f"{alert_text:<10}"
        )

    print()
    print("=" * 90)

    expected_count = len(results)

    prediction_matches = sum(
        1
        for result in results
        if result["predicted_class"]
        == result["target_class"]
    )

    intrusion_count = sum(
        1
        for result in results
        if result["decision_status"]
        == "Intrusion"
    )

    alert_count = sum(
        1
        for result in results
        if result["alert_id"] is not None
    )

    print(
        f"Classes tested:       {expected_count}/7"
    )

    print(
        f"Expected predictions: "
        f"{prediction_matches}/7"
    )

    print(
        f"Intrusion decisions:  "
        f"{intrusion_count}/7"
    )

    print(
        f"Alerts created:        "
        f"{alert_count}"
    )

    print()

    if expected_count == 7:

        print(
            "CONTROLLED 7-CLASS TEST COMPLETED"
        )

    else:

        print(
            "CONTROLLED 7-CLASS TEST INCOMPLETE"
        )

    print("=" * 90)


# ============================================================
# MAIN TEST
# ============================================================

def run_tests():

    print()
    print("=" * 70)
    print("CONTROLLED 7-CLASS NETWORK IDS TEST")
    print("=" * 70)

    print()
    print("CICFlowMeter: NOT REQUIRED")
    print("Network Collector: NOT REQUIRED")
    print("Using real CIC-IDS2017 samples.")

    # --------------------------------------------------------
    # Initialize database.
    # --------------------------------------------------------

    print()
    print(
        "Initializing database..."
    )

    initialize_database()

    print(
        "Database ready."
    )

    # --------------------------------------------------------
    # Locate dataset.
    # --------------------------------------------------------

    csv_files = locate_dataset_files()

    # --------------------------------------------------------
    # Find one real row for each of the 7 classes.
    # --------------------------------------------------------

    samples = find_all_samples(
        csv_files
    )

    # --------------------------------------------------------
    # Run model + database + decision + alert tests.
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("RUNNING 7-CLASS NETWORK MODEL TESTS")
    print("=" * 70)

    results = []

    for test_number, target_class in enumerate(
        MODEL_CLASSES,
        start=1
    ):

        try:

            result = run_class_test(
                test_number,
                target_class,
                samples[target_class]
            )

            results.append(
                result
            )

        except Exception as exc:

            print()
            print(
                "ERROR TESTING:",
                target_class
            )

            print(
                "ERROR:",
                str(exc)
            )

            # Keep testing the remaining classes.
            results.append({
                "target_class": target_class,
                "dataset_label": samples[
                    target_class
                ]["dataset_label"],
                "predicted_class": "ERROR",
                "confidence": 0.0,
                "network_id": None,
                "decision_status": "ERROR",
                "decision_attack_type": "ERROR",
                "risk_level": "ERROR",
                "alert_id": None
            })

    # --------------------------------------------------------
    # Final report.
    # --------------------------------------------------------

    print_final_summary(
        results
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    try:

        run_tests()

    except KeyboardInterrupt:

        print()
        print(
            "Test interrupted by user."
        )

        sys.exit(1)

    except Exception as exc:

        print()
        print("=" * 70)
        print("TEST FAILED")
        print("=" * 70)

        print()
        print(
            type(exc).__name__,
            ":",
            str(exc)
        )

        print()

        sys.exit(1)