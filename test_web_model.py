from services.model_service import (
    web_attack_model
)


test_request = {
    "Method": "GET",
    "URL":
        "http://127.0.0.1:5001/"
        "search?q=fish",

    "content": ""
}


result = web_attack_model.predict(
    test_request
)


print(
    "Anomaly probability:",
    result[
        "anomaly_probability"
    ]
)


print(
    "\nClass probabilities:"
)


for class_name, probability in (
    result["probabilities"].items()
):

    print(
        class_name,
        "=",
        probability
    )


print(
    "\nFeature count:",
    len(
        result["features"]
    )
)