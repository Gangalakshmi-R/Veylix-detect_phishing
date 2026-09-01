import os
import json
import joblib
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    classification_report,
    confusion_matrix
)


DATA_PATH = "data/PhiUSIIL_Phishing_URL_Dataset.csv"

MODEL_DIR = "models"

MODEL_PATH = "models/url_model.pkl"

META_PATH = "models/url_model_meta.json"


# ============================================================
# FEATURES AVAILABLE FROM URL STRUCTURE
# ============================================================

URL_FEATURES = [

    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "TLDLength",
    "NoOfSubDomain",
    "NoOfLettersInURL",
    "LetterRatioInURL",
    "NoOfDegitsInURL",
    "DegitRatioInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL",
    "IsHTTPS",
    "NoOfObfuscatedChar",
    "HasObfuscation",
    "ObfuscationRatio",
    "URLSimilarityIndex",
    "CharContinuationRate",
    "TLDLegitimateProb",
    "URLCharProb"
]


def main():

    print("=" * 75)
    print("       PHISHINTEL - URL PHISHING MODEL TRAINING")
    print("=" * 75)

    # --------------------------------------------------------
    # Load dataset
    # --------------------------------------------------------

    if not os.path.exists(DATA_PATH):

        raise FileNotFoundError(
            f"Dataset not found:\n{DATA_PATH}"
        )

    print("\nLoading PhiUSIIL dataset...")

    df = pd.read_csv(
        DATA_PATH,
        low_memory=False
    )

    print(
        f"Dataset shape: {df.shape}"
    )

    # --------------------------------------------------------
    # Validate label
    # --------------------------------------------------------

    if "label" not in df.columns:

        raise ValueError(
            "label column not found."
        )

    # --------------------------------------------------------
    # Validate features
    # --------------------------------------------------------

    missing = [
        feature
        for feature in URL_FEATURES
        if feature not in df.columns
    ]

    if missing:

        raise ValueError(
            "Missing features:\n"
            + "\n".join(missing)
        )

    # --------------------------------------------------------
    # Original distribution
    # --------------------------------------------------------

    print("\nOriginal class distribution:")

    print(
        df["label"].value_counts()
    )

    # --------------------------------------------------------
    # Remove duplicate URLs
    # --------------------------------------------------------

    if "URL" in df.columns:

        before = len(df)

        df = df.drop_duplicates(
            subset=["URL"]
        )

        print(
            f"\nDuplicate URLs removed: "
            f"{before - len(df):,}"
        )

    # --------------------------------------------------------
    # Features
    # --------------------------------------------------------

    X = df[
        URL_FEATURES
    ].copy()

    X = X.apply(
        pd.to_numeric,
        errors="coerce"
    )

    X = X.replace(
        [
            np.inf,
            -np.inf
        ],
        np.nan
    )

    X = X.fillna(0)

    # --------------------------------------------------------
    # Label mapping
    #
    # PhiUSIIL:
    # 0 = phishing
    # 1 = legitimate
    #
    # Application:
    # 0 = legitimate
    # 1 = phishing
    # --------------------------------------------------------

    y = (

        df["label"]
        .astype(int)
        .map({
            0: 1,
            1: 0
        })

    )

    if y.isna().any():

        raise ValueError(
            "Invalid labels found."
        )

    print("\nApplication class distribution:")

    print(
        y.value_counts()
        .rename(
            index={
                0: "Legitimate",
                1: "Phishing"
            }
        )
    )

    # --------------------------------------------------------
    # Split
    # --------------------------------------------------------

    X_train, X_test, y_train, y_test = (

        train_test_split(

            X,
            y,

            test_size=0.20,

            random_state=42,

            stratify=y

        )

    )

    print(
        f"\nTraining samples: {len(X_train):,}"
    )

    print(
        f"Testing samples: {len(X_test):,}"
    )

    print(
        f"Feature count: {len(URL_FEATURES)}"
    )

    # --------------------------------------------------------
    # Random Forest
    # --------------------------------------------------------

    print("\nTraining Random Forest...")

    model = RandomForestClassifier(

        n_estimators=400,

        max_features="sqrt",

        class_weight="balanced",

        random_state=42,

        n_jobs=-1,

        min_samples_leaf=2

    )

    model.fit(
        X_train,
        y_train
    )

    print(
        "Training completed."
    )

    # --------------------------------------------------------
    # Evaluation
    # --------------------------------------------------------

    predictions = model.predict(
        X_test
    )

    probabilities = (

        model.predict_proba(
            X_test
        )[:, 1]

    )

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    precision = precision_score(
        y_test,
        predictions,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        predictions,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        predictions,
        zero_division=0
    )

    roc_auc = roc_auc_score(
        y_test,
        probabilities
    )

    # --------------------------------------------------------
    # Results
    # --------------------------------------------------------

    print("\n")

    print("=" * 75)
    print("              URL MODEL PERFORMANCE")
    print("=" * 75)

    print(
        f"Accuracy : {accuracy:.4f}"
    )

    print(
        f"Precision: {precision:.4f}"
    )

    print(
        f"Recall   : {recall:.4f}"
    )

    print(
        f"F1 Score : {f1:.4f}"
    )

    print(
        f"ROC-AUC  : {roc_auc:.4f}"
    )

    print("\nClassification Report:")

    print(

        classification_report(

            y_test,

            predictions,

            target_names=[
                "Legitimate",
                "Phishing"
            ],

            zero_division=0

        )

    )

    print("\nConfusion Matrix:")

    print(
        confusion_matrix(
            y_test,
            predictions
        )
    )

    # --------------------------------------------------------
    # Feature importance
    # --------------------------------------------------------

    importance = dict(
        zip(
            URL_FEATURES,
            model.feature_importances_
        )
    )

    importance = dict(
        sorted(
            importance.items(),
            key=lambda item: item[1],
            reverse=True
        )
    )

    print("\nFeature Importance:")
    print("-" * 55)

    for feature, value in importance.items():

        print(
            f"{feature:<35}"
            f"{value:.6f}"
        )

    # --------------------------------------------------------
    # Save model
    # --------------------------------------------------------

    os.makedirs(
        MODEL_DIR,
        exist_ok=True
    )

    bundle = {

        "model":
            model,

        "features":
            URL_FEATURES,

        "label_mapping":
            {
                "0": "legitimate",
                "1": "phishing"
            }

    }

    joblib.dump(
        bundle,
        MODEL_PATH
    )

    # --------------------------------------------------------
    # Save metadata
    # --------------------------------------------------------

    metadata = {

        "model_type":
            "RandomForestClassifier",

        "dataset":
            DATA_PATH,

        "dataset_rows":
            int(len(df)),

        "feature_count":
            len(URL_FEATURES),

        "features":
            URL_FEATURES,

        "label_mapping":
            {
                "0":
                    "legitimate",

                "1":
                    "phishing"
            },

        "metrics":
            {
                "accuracy":
                    float(accuracy),

                "precision":
                    float(precision),

                "recall":
                    float(recall),

                "f1":
                    float(f1),

                "roc_auc":
                    float(roc_auc)
            },

        "feature_importance":
            {
                key:
                    float(value)

                for key, value
                in importance.items()
            }

    }

    with open(
        META_PATH,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            metadata,
            file,
            indent=4
        )

    print("\n")
    print("=" * 75)
    print("URL MODEL SAVED")
    print("=" * 75)

    print(
        f"Model    : {MODEL_PATH}"
    )

    print(
        f"Metadata : {META_PATH}"
    )

    print(
        "\nURL model training complete."
    )


if __name__ == "__main__":
    main()