import os
import json

from services.network_model_service import (
    network_attack_model
)


BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

SAMPLE_PATH = os.path.join(
    BASE_DIR,
    "models",
    "network_test_sample.json"
)


with open(
    SAMPLE_PATH,
    "r",
    encoding="utf-8"
) as f:

    sample = json.load(f)


actual_class = sample[
    "actual_class"
]

flow_features = sample[
    "features"
]


print(
    "Actual class:",
    actual_class
)

print(
    "Input feature count:",
    len(flow_features)
)


result = network_attack_model.predict(
    flow_features
)


print(
    "\nPredicted class:",
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


print(
    "\nClass probabilities:"
)

for attack_type, probability in (
    result["probabilities"].items()
):

    print(
        f"{attack_type}: "
        f"{probability:.6f}"
    )


print(
    "\nActual:",
    actual_class
)

print(
    "Predicted:",
    result["attack_type"]
)


if (
    str(actual_class)
    ==
    str(result["attack_type"])
):

    print(
        "\nNETWORK MODEL TEST PASSED"
    )

else:

    print(
        "\nNETWORK MODEL PREDICTION "
        "DIFFERS FROM SAMPLE LABEL"
    )