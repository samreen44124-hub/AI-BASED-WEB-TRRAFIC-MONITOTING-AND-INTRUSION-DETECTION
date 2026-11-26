import os
import sys


BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)


from services.decision_service import (
    decision_service
)


def show(title, result):

    print()
    print("=" * 70)
    print(title)
    print("=" * 70)

    print(
        f"Status:          "
        f"{result['status']}"
    )

    print(
        f"Attack Type:     "
        f"{result['attack_type']}"
    )

    print(
        f"Risk Level:      "
        f"{result['risk_level']}"
    )

    print(
        f"Confidence:      "
        f"{result['confidence']:.6f}"
    )

    print(
        f"Decision Source: "
        f"{result['decision_source']}"
    )


def main():

    # -------------------------------------------------
    # TEST 1
    # Both models normal
    # -------------------------------------------------

    result = decision_service.decide(

        http_result={
            "status": "Normal",
            "attack_type": "Normal",
            "risk_level": "Low",
            "confidence": 0.92,
            "model_name": "CSIC HTTP V2"
        },

        network_result={
            "attack_type": "Normal",
            "confidence": 0.996699,
            "model_name":
                "CIC-IDS2017 Network RF"
        }
    )

    show(
        "TEST 1 - BOTH NORMAL",
        result
    )

    assert result["status"] == "Normal"

    # -------------------------------------------------
    # TEST 2
    # HTTP suspicious, network normal
    # -------------------------------------------------

    result = decision_service.decide(

        http_result={
            "status": "Suspicious",
            "attack_type": "HTTP Anomaly",
            "risk_level": "High",
            "confidence": 0.91,
            "model_name": "CSIC HTTP V2"
        },

        network_result={
            "attack_type": "Normal",
            "confidence": 0.95,
            "model_name":
                "CIC-IDS2017 Network RF"
        }
    )

    show(
        "TEST 2 - HTTP SUSPICIOUS",
        result
    )

    assert (
        result["status"]
        ==
        "Suspicious"
    )

    assert (
        result["attack_type"]
        ==
        "HTTP Anomaly"
    )

    # -------------------------------------------------
    # TEST 3
    # Network DDoS
    # -------------------------------------------------

    result = decision_service.decide(

        http_result={
            "status": "Normal",
            "attack_type": "Normal",
            "risk_level": "Low",
            "confidence": 0.88,
            "model_name": "CSIC HTTP V2"
        },

        network_result={
            "attack_type": "DDoS",
            "confidence": 0.98,
            "model_name":
                "CIC-IDS2017 Network RF"
        }
    )

    show(
        "TEST 3 - NETWORK DDOS",
        result
    )

    assert (
        result["status"]
        ==
        "Intrusion"
    )

    assert (
        result["attack_type"]
        ==
        "DDoS"
    )

    assert (
        result["risk_level"]
        ==
        "Critical"
    )

    # -------------------------------------------------
    # TEST 4
    # HTTP suspicious + Network Web Attack
    # -------------------------------------------------

    result = decision_service.decide(

        http_result={
            "status": "Suspicious",
            "attack_type": "HTTP Anomaly",
            "risk_level": "High",
            "confidence": 0.94,
            "model_name": "CSIC HTTP V2"
        },

        network_result={
            "attack_type": "Web Attack",
            "confidence": 0.97,
            "model_name":
                "CIC-IDS2017 Network RF"
        }
    )

    show(
        "TEST 4 - COMBINED WEB EVIDENCE",
        result
    )

    assert (
        result["status"]
        ==
        "Intrusion"
    )

    assert (
        result["attack_type"]
        ==
        "Web Attack"
    )

    # -------------------------------------------------
    # TEST 5
    # Network evidence only
    # -------------------------------------------------

    result = decision_service.decide(

        network_result={
            "attack_type": "Port Scan",
            "confidence": 0.93,
            "model_name":
                "CIC-IDS2017 Network RF"
        }
    )

    show(
        "TEST 5 - NETWORK ONLY",
        result
    )

    assert (
        result["status"]
        ==
        "Intrusion"
    )

    assert (
        result["attack_type"]
        ==
        "Port Scan"
    )

    print()
    print("=" * 70)
    print(
        "DECISION SERVICE TEST PASSED"
    )
    print("=" * 70)


if __name__ == "__main__":
    main()