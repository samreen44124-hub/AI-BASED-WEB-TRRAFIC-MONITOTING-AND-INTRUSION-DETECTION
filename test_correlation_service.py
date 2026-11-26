from datetime import datetime, timedelta

from services.database_service import (
    get_connection,
    insert_network_flow
)

from services.correlation_service import (
    correlation_service
)


def create_test_http_log():

    conn = get_connection()
    cursor = conn.cursor()

    now = datetime.utcnow().replace(
        microsecond=0
    )

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
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        "127.0.0.1",
        "GET",
        "http://127.0.0.1:5001/test",
        "/test",
        "",
        "Correlation-Test",
        0,
        "Normal",
        "Normal",
        "Low",
        0.95,
        "Controlled HTTP Test",
        now.strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    ))

    traffic_id = cursor.lastrowid

    conn.commit()
    conn.close()

    return traffic_id, now


def create_test_network_flow(now):

    flow_time = now + timedelta(
        seconds=2
    )

    unique_suffix = now.strftime(
        "%Y%m%d%H%M%S"
    )

    data = {
        "flow_key": (
            f"correlation-test-{unique_suffix}"
            f"|{flow_time.strftime('%d/%m/%Y %I:%M:%S %p')}"
        ),
        "flow_id": (
            f"127.0.0.1-127.0.0.1-"
            f"55000-5001-6-{unique_suffix}"
        ),
        "source_ip": "127.0.0.1",
        "source_port": 55000,
        "destination_ip": "127.0.0.1",
        "destination_port": 5001,
        "protocol": 6,
        "timestamp": flow_time.strftime(
            "%d/%m/%Y %I:%M:%S %p"
        ),
        "attack_type": "Normal",
        "class_id": 0,
        "confidence": 0.98,
        "model_name": (
            "Controlled Network Test"
        )
    }

    return insert_network_flow(data)


def main():

    print("=" * 70)
    print("CONTROLLED CORRELATION TEST")
    print("=" * 70)

    traffic_id, now = (
        create_test_http_log()
    )

    network_id = (
        create_test_network_flow(now)
    )

    print()
    print("CONTROLLED RECORDS")
    print(f"HTTP ID:    {traffic_id}")
    print(f"Network ID: {network_id}")

    result = (
        correlation_service.correlate_http_log(
            traffic_id=traffic_id,
            target_port=5001
        )
    )

    print()
    print("CORRELATION RESULT")

    print(
        f"Matched:     "
        f"{result['matched']}"
    )

    print(
        f"Reason:      "
        f"{result['reason']}"
    )

    if result["matched"]:

        network_flow = result[
            "network_flow"
        ]

        print(
            f"HTTP ID:     "
            f"{result['http_log']['id']}"
        )

        print(
            f"Network ID:  "
            f"{network_flow['id']}"
        )

        print(
            f"Score:       "
            f"{result['correlation_score']}"
        )

        print(
            f"Time Diff:   "
            f"{result['time_difference_seconds']}"
            f" sec"
        )

        print(
            f"Attack Type: "
            f"{network_flow['attack_type']}"
        )

        assert result["matched"] is True

        assert (
            network_flow["id"]
            == network_id
        )

        assert (
            result["time_difference_seconds"]
            <= 2
        )

        print()
        print(
            "CONTROLLED CORRELATION "
            "TEST PASSED"
        )
        print()
        print("=" * 70)
        print("NEGATIVE CORRELATION TEST")
        print("=" * 70)

        negative_http_id, negative_time = (
            create_negative_test_http_log()
        )

        wrong_network_id = (
            create_wrong_network_flow(
                negative_time
            )
        )

        print()
        print("CONTROLLED WRONG RECORDS")

        print(
            f"HTTP ID:          "
            f"{negative_http_id}"
        )

        print(
            f"Wrong Network ID: "
            f"{wrong_network_id}"
        )

        negative_result = (
            correlation_service.correlate_http_log(
                traffic_id=negative_http_id,
                target_port=5001
            )
        )

        print()
        print("NEGATIVE RESULT")

        print(
            f"Matched: "
            f"{negative_result['matched']}"
        )

        print(
            f"Reason:  "
            f"{negative_result['reason']}"
        )

        assert (
                negative_result["matched"]
                is False
        )

        print()
        print(
            "NEGATIVE CORRELATION "
            "TEST PASSED"
        )
    else:

        raise AssertionError(
            "Controlled correlation failed."
        )

def create_wrong_network_flow(now):

    flow_time = now + timedelta(
        seconds=2
    )

    unique_suffix = (
        now.strftime("%Y%m%d%H%M%S")
        + "-wrong"
    )

    data = {
        "flow_key": (
            f"correlation-wrong-{unique_suffix}"
            f"|{flow_time.strftime('%d/%m/%Y %I:%M:%S %p')}"
        ),
        "flow_id": (
            f"10.10.10.10-10.20.20.20-"
            f"55001-9999-6-{unique_suffix}"
        ),
        "source_ip": "10.10.10.10",
        "source_port": 55001,
        "destination_ip": "10.20.20.20",
        "destination_port": 9999,
        "protocol": 6,
        "timestamp": flow_time.strftime(
            "%d/%m/%Y %I:%M:%S %p"
        ),
        "attack_type": "Normal",
        "class_id": 0,
        "confidence": 0.99,
        "model_name": (
            "Controlled Wrong Network Test"
        )
    }

    return insert_network_flow(data)
def create_negative_test_http_log():

    conn = get_connection()
    cursor = conn.cursor()

    now = datetime(
        2026,
        1,
        15,
        12,
        0,
        0
    )

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
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        "127.0.0.1",
        "GET",
        "http://127.0.0.1:5001/negative-test",
        "/negative-test",
        "",
        "Negative-Correlation-Test",
        0,
        "Normal",
        "Normal",
        "Low",
        0.95,
        "Controlled HTTP Negative Test",
        now.strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    ))

    traffic_id = cursor.lastrowid

    conn.commit()
    conn.close()

    return traffic_id, now
if __name__ == "__main__":
    main()