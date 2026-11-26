import os
import json
import joblib
import pandas as pd

from services.feature_extractor import (
    extract_http_features_v2
)


BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

MODEL_DIR = os.path.join(
    BASE_DIR,
    "models"
)

WEB_MODEL_PATH = os.path.join(
    MODEL_DIR,
    "web_attack_model.pkl"
)

WEB_FEATURE_PATH = os.path.join(
    MODEL_DIR,
    "web_features.json"
)


class WebAttackModel:

    def __init__(self):

        self.model = None
        self.features = None
        self.loaded = False

        self.load_model()


    def load_model(self):

        if not os.path.exists(
            WEB_MODEL_PATH
        ):
            raise FileNotFoundError(
                f"Web model not found: "
                f"{WEB_MODEL_PATH}"
            )

        if not os.path.exists(
            WEB_FEATURE_PATH
        ):
            raise FileNotFoundError(
                f"Feature file not found: "
                f"{WEB_FEATURE_PATH}"
            )

        self.model = joblib.load(
            WEB_MODEL_PATH
        )

        with open(
            WEB_FEATURE_PATH,
            "r",
            encoding="utf-8"
        ) as f:

            self.features = json.load(f)

        if (
            len(self.features)
            !=
            self.model.n_features_in_
        ):
            raise ValueError(
                "Web model feature contract mismatch."
            )

        self.loaded = True


    def predict(self, request_data):

        if not self.loaded:
            raise RuntimeError(
                "Web attack model is not loaded."
            )

        extracted = (
            extract_http_features_v2(
                request_data
            )
        )

        # Enforce exact training order.
        feature_values = {
            feature:
                extracted[feature]
            for feature in self.features
        }

        frame = pd.DataFrame(
            [feature_values],
            columns=self.features
        )

        probabilities = (
            self.model.predict_proba(
                frame
            )[0]
        )

        classes = list(
            self.model.classes_
        )

        probability_map = {
            str(class_name):
                float(probability)

            for class_name, probability
            in zip(
                classes,
                probabilities
            )
        }

        # Training contract:
        # 0 = Normal
        # 1 = Anomalous
        anomalous_index = (
            classes.index(1)
        )

        anomaly_probability = float(
            probabilities[
                anomalous_index
            ]
        )

        return {
            "anomaly_probability":
                anomaly_probability,

            "probabilities":
                probability_map,

            "features":
                feature_values
        }


web_attack_model = WebAttackModel()
