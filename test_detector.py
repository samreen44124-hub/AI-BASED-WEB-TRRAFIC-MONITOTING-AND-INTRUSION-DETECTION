from services.intrusion_detector import (
    analyze_http_request
)


request_data = {
    "Method": "GET",
    "URL":
        "http://127.0.0.1:5001/"
        "search?q=fish",

    "content": ""
}


result = analyze_http_request(
    request_data
)


print(result)