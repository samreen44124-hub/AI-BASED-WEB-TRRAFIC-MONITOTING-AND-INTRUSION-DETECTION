import os
import json
import joblib
import pandas as pd


BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

MODEL_DIR = os.path.join(
    BASE_DIR,
    "models"
)

NETWORK_MODEL_PATH = os.path.join(
    MODEL_DIR,
    "network_model.pkl"
)

NETWORK_FEATURE_PATH = os.path.join(
    MODEL_DIR,
    "network_features.json"
)


NETWORK_CLASS_NAMES = {
    0: "Normal",
    1: "DoS",
    2: "DDoS",
    3: "Port Scan",
    4: "Network Brute Force",
    5: "Bot",
    6: "Web Attack"
}


class NetworkAttackModel:

    def __init__(self):

        self.model = None
        self.features = None
        self.loaded = False

        self.load_model()


    def load_model(self):

        if not os.path.exists(
            NETWORK_MODEL_PATH
        ):
            raise FileNotFoundError(
                f"Network model not found: "
                f"{NETWORK_MODEL_PATH}"
            )


        if not os.path.exists(
            NETWORK_FEATURE_PATH
        ):
            raise FileNotFoundError(
                f"Network feature file not found: "
                f"{NETWORK_FEATURE_PATH}"
            )


        self.model = joblib.load(
            NETWORK_MODEL_PATH
        )


        with open(
            NETWORK_FEATURE_PATH,
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
                "Network model feature "
                "contract mismatch."
            )


        if len(self.features) != 65:
            raise ValueError(
                "Network model must contain "
                "exactly 65 features."
            )


        model_classes = {
            int(value)
            for value in self.model.classes_
        }

        expected_classes = set(
            NETWORK_CLASS_NAMES.keys()
        )


        if model_classes != expected_classes:
            raise ValueError(
                "Network model class "
                "contract mismatch."
            )


        self.loaded = True


    def validate_flow(
        self,
        flow_data
    ):

        if not isinstance(
            flow_data,
            dict
        ):
            raise ValueError(
                "Network flow data must "
                "be a dictionary."
            )


        missing_features = [
            feature
            for feature in self.features
            if feature not in flow_data
        ]


        if missing_features:

            raise ValueError(
                "Missing network features: "
                +
                ", ".join(
                    missing_features
                )
            )


    def predict(
        self,
        flow_data
    ):

        if not self.loaded:
            raise RuntimeError(
                "Network attack model "
                "is not loaded."
            )


        self.validate_flow(
            flow_data
        )


        feature_values = {
            feature:
                float(
                    flow_data[feature]
                )

            for feature
            in self.features
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


        classes = [
            int(value)
            for value
            in self.model.classes_
        ]


        probability_map = {

            NETWORK_CLASS_NAMES[
                class_id
            ]:
                float(probability)

            for class_id,
                probability
            in zip(
                classes,
                probabilities
            )
        }


        predicted_index = int(
            probabilities.argmax()
        )


        predicted_class_id = (
            classes[
                predicted_index
            ]
        )


        predicted_class = (
            NETWORK_CLASS_NAMES[
                predicted_class_id
            ]
        )


        confidence = float(
            probabilities[
                predicted_index
            ]
        )


        return {

            "class_id":
                predicted_class_id,

            "attack_type":
                predicted_class,

            "confidence":
                confidence,

            "probabilities":
                probability_map,

            "model_name":
                "CIC-IDS2017 Network RF"
        }


network_attack_model = (
    NetworkAttackModel()
)