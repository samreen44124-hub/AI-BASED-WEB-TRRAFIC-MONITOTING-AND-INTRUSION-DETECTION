from services.model_service import web_attack_model


tests = [

    {
        "name": "Normal Search",
        "Method": "GET",
        "URL": "/search?q=fish",
        "content": ""
    },

    {
        "name": "Normal Login",
        "Method": "POST",
        "URL": "/login",
        "content": "username=test&password=test"
    },

    {
        "name": "SQL Injection Test",
        "Method": "GET",
        "URL": "/search?q=%27%20OR%201%3D1--",
        "content": ""
    }
]


for test in tests:

    result = web_attack_model.predict(test)

    print()
    print("=" * 60)
    print(test["name"])
    print("=" * 60)

    print(
        "Anomaly probability:",
        result["anomaly_probability"]
    )

    print(
        "Probabilities:",
        result["probabilities"]
    )