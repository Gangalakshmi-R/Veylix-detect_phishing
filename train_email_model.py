import os
import json
import joblib
import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    classification_report,
    confusion_matrix
)


DATA_PATH = "data/phishing_email.csv"

MODEL_DIR = "models"

MODEL_PATH = "models/email_model.pkl"

META_PATH = "models/email_model_meta.json"


def main():

    print("=" * 75)
    print("EMAIL PHISHING MODEL TRAINING")
    print("=" * 75)

    if not os.path.exists(DATA_PATH):

        raise FileNotFoundError(
            f"\nDataset not found:\n{DATA_PATH}"
        )

    print("\nLoading dataset...")

    df = pd.read_csv(
        DATA_PATH,
        low_memory=False
    )

    print(
        f"Dataset shape: {df.shape}"
    )

    # ---------------------------------------------------------
    # Validate columns
    # ---------------------------------------------------------

    required_columns = [
        "text_combined",
        "label"
    ]

    for column in required_columns:

        if column not in df.columns:

            raise ValueError(
                f"Missing column: {column}"
            )

    # ---------------------------------------------------------
    # Keep only required columns
    # ---------------------------------------------------------

    df = df[
        [
            "text_combined",
            "label"
        ]
    ].copy()

    # ---------------------------------------------------------
    # Clean
    # ---------------------------------------------------------

    df["text_combined"] = (
        df["text_combined"]
        .fillna("")
        .astype(str)
        .str.strip()
    )

    df["label"] = pd.to_numeric(
        df["label"],
        errors="coerce"
    )

    df = df.dropna(
        subset=["label"]
    )

    df = df[
        df["text_combined"].str.len() > 0
    ]

    # ---------------------------------------------------------
    # Labels
    #
    # Dataset:
    # 0 = legitimate
    # 1 = phishing
    # ---------------------------------------------------------

    df["label"] = (
        df["label"]
        .astype(int)
    )

    invalid_labels = set(
        df["label"].unique()
    ) - {0, 1}

    if invalid_labels:

        raise ValueError(
            f"Unexpected labels: "
            f"{invalid_labels}"
        )

    # ---------------------------------------------------------
    # Remove duplicate messages
    # ---------------------------------------------------------

    before = len(df)

    df = df.drop_duplicates(
        subset=["text_combined"]
    )

    print(
        f"Duplicate messages removed: "
        f"{before - len(df)}"
    )

    # ---------------------------------------------------------
    # Dataset distribution
    # ---------------------------------------------------------

    print("\nClass distribution:")

    print(
        df["label"]
        .value_counts()
        .sort_index()
        .rename({
            0: "Legitimate",
            1: "Phishing"
        })
    )

    X = df["text_combined"]

    y = df["label"]

    # ---------------------------------------------------------
    # Train / test split
    # ---------------------------------------------------------

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

    # ---------------------------------------------------------
    # TF-IDF
    # ---------------------------------------------------------

    print(
        "\nBuilding TF-IDF features..."
    )

    word_vectorizer = TfidfVectorizer(

        lowercase=True,

        strip_accents="unicode",

        analyzer="word",

        ngram_range=(1, 2),

        min_df=2,

        max_df=0.98,

        sublinear_tf=True,

        max_features=120000
    )

    char_vectorizer = TfidfVectorizer(

        lowercase=True,

        analyzer="char",

        ngram_range=(3, 5),

        min_df=3,

        sublinear_tf=True,

        max_features=80000
    )

    features = FeatureUnion([

        (
            "word",
            word_vectorizer
        ),

        (
            "char",
            char_vectorizer
        )
    ])

    X_train_features = (
        features.fit_transform(
            X_train
        )
    )

    X_test_features = (
        features.transform(
            X_test
        )
    )

    print(
        "Feature matrix:",
        X_train_features.shape
    )

    # ---------------------------------------------------------
    # Logistic Regression
    # ---------------------------------------------------------

    print(
        "\nTraining Logistic Regression..."
    )

    model = LogisticRegression(

        C=4.0,

        max_iter=1000,

        class_weight="balanced",

        solver="liblinear",

        random_state=42
    )

    model.fit(
        X_train_features,
        y_train
    )

    # ---------------------------------------------------------
    # Predictions
    # ---------------------------------------------------------

    predictions = model.predict(
        X_test_features
    )

    probabilities = (
        model.predict_proba(
            X_test_features
        )[:, 1]
    )

    # ---------------------------------------------------------
    # Metrics
    # ---------------------------------------------------------

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

    print("\n")
    print("=" * 75)
    print("EMAIL MODEL PERFORMANCE")
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

    print(
        "\nConfusion Matrix:"
    )

    print(
        confusion_matrix(
            y_test,
            predictions
        )
    )

    # ---------------------------------------------------------
    # Save combined pipeline
    # ---------------------------------------------------------

    os.makedirs(
        MODEL_DIR,
        exist_ok=True
    )

    bundle = {

        "vectorizer": features,

        "model": model
    }

    joblib.dump(
        bundle,
        MODEL_PATH
    )

    metadata = {

        "dataset": DATA_PATH,

        "text_column": "text_combined",

        "label_column": "label",

        "label_mapping": {

            "0": "legitimate",

            "1": "phishing"
        },

        "accuracy": accuracy,

        "precision": precision,

        "recall": recall,

        "f1": f1,

        "roc_auc": roc_auc
    }

    with open(
        META_PATH,
        "w"
    ) as file:

        json.dump(
            metadata,
            file,
            indent=4
        )

    print(
        f"\nModel saved to: {MODEL_PATH}"
    )

    print(
        f"Metadata saved to: {META_PATH}"
    )

    print(
        "\nEmail model training complete."
    )


if __name__ == "__main__":

    main()