import json
import joblib
import sklearn

model = joblib.load(
    "models/network_model.pkl"
)

with open(
    "models/network_features.json",
    "r",
    encoding="utf-8"
) as f:
    features = json.load(f)


print(
    "Scikit-learn:",
    sklearn.__version__
)

print(
    "Feature file:",
    len(features)
)

print(
    "Model expected:",
    model.n_features_in_
)

print(
    "Classes:",
    model.classes_
)

print(
    "\nFirst 10 features:"
)

for feature in features[:10]:
    print(feature)


if (
    len(features)
    ==
    model.n_features_in_
    ==
    65
):
    print(
        "\nNETWORK MODEL CONTRACT VALID"
    )
else:
    print(
        "\nNETWORK MODEL CONTRACT ERROR"
    )
