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


# ============================================================
# CONFIGURATION
# ============================================================

DATA_PATH = "data/PhiUSIIL_Phishing_URL_Dataset.csv"
MODEL_DIR = "models"

MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model.pkl")
FEATURE_PATH = os.path.join(MODEL_DIR, "features.json")
IMPORTANCE_PATH = os.path.join(MODEL_DIR, "feature_importance.json")


# ============================================================
# LOAD DATASET
# ============================================================

print("=" * 70)
print("PHISHING DETECTION MODEL - TRAINING")
print("=" * 70)

print("\nLoading dataset...")

if not os.path.exists(DATA_PATH):
    raise FileNotFoundError(
        f"\nDataset not found!\n"
        f"Expected location:\n{DATA_PATH}\n\n"
        f"Put PhiUSIIL_Phishing_URL_Dataset.csv inside the data folder."
    )

df = pd.read_csv(DATA_PATH)

print("\nDataset loaded successfully.")
print("Shape:", df.shape)


# ============================================================
# BASIC INFORMATION
# ============================================================

print("\nDataset columns:")
for column in df.columns:
    print(" -", column)


print("\nMissing values:")
print(df.isnull().sum().sum())


# ============================================================
# FIND TARGET COLUMN
# ============================================================

possible_targets = [
    "label",
    "Label",
    "LABEL",
    "target",
    "Target",
    "class",
    "Class"
]

target_column = None

for column in possible_targets:
    if column in df.columns:
        target_column = column
        break

if target_column is None:
    raise ValueError(
        "\nCould not find target column.\n"
        "Available columns:\n"
        + str(df.columns.tolist())
    )

print("\nTarget column:", target_column)


# ============================================================
# TARGET VALUES
# ============================================================

print("\nTarget distribution:")
print(df[target_column].value_counts())


# ============================================================
# NORMALIZE TARGET
# ============================================================

# PhiUSIIL normally uses:
#
# 1 = legitimate
# 0 = phishing
#
# For our model we want:
#
# 0 = legitimate
# 1 = phishing
#
# This makes predict_proba[:, 1]
# represent phishing probability.

unique_values = sorted(df[target_column].dropna().unique().tolist())

print("\nUnique target values:", unique_values)


def convert_target(value):

    # Numeric target
    if isinstance(value, (int, float, np.integer, np.floating)):

        if value == 1:
            return 0       # legitimate -> 0

        elif value == 0:
            return 1       # phishing -> 1

    # String target
    value_string = str(value).strip().lower()

    if value_string in [
        "phishing",
        "phish",
        "malicious",
        "1"
    ]:
        return 1

    if value_string in [
        "legitimate",
        "legit",
        "benign",
        "safe",
        "0"
    ]:
        return 0

    raise ValueError(
        f"Unknown target value: {value}"
    )


df["target"] = df[target_column].apply(convert_target)


print("\nConverted target distribution:")
print(
    df["target"]
    .value_counts()
    .rename({
        0: "Legitimate",
        1: "Phishing"
    })
)


# ============================================================
# REMOVE TARGET COLUMNS
# ============================================================

X = df.drop(
    columns=[
        target_column,
        "target"
    ],
    errors="ignore"
)


y = df["target"]


# ============================================================
# REMOVE RAW / NON-PREDICTIVE COLUMNS
# ============================================================

# These columns can contain raw strings or identifiers.
#
# We don't want the model simply memorizing URLs.
#
# Important engineered numerical URL/domain features
# are retained.

columns_to_remove = [
    "URL",
    "url",
    "Domain",
    "domain",
    "TLD",
    "tld",
    "Title",
    "title",
    "ID",
    "id"
]

existing_remove_columns = [
    column
    for column in columns_to_remove
    if column in X.columns
]

if existing_remove_columns:

    print("\nRemoving raw/string columns:")

    for column in existing_remove_columns:
        print(" -", column)

    X = X.drop(
        columns=existing_remove_columns
    )


# ============================================================
# HANDLE CATEGORICAL FEATURES
# ============================================================

categorical_columns = X.select_dtypes(
    include=["object", "category"]
).columns.tolist()

if categorical_columns:

    print("\nCategorical columns found:")

    for column in categorical_columns:
        print(" -", column)

    # One-hot encode categorical features
    X = pd.get_dummies(
        X,
        columns=categorical_columns,
        dummy_na=True
    )


# ============================================================
# CONVERT EVERYTHING TO NUMERIC
# ============================================================

X = X.apply(
    pd.to_numeric,
    errors="coerce"
)


# Replace infinity values
X = X.replace(
    [np.inf, -np.inf],
    np.nan
)


# Fill missing values
X = X.fillna(0)


# ============================================================
# FEATURE INFORMATION
# ============================================================

feature_names = X.columns.tolist()

print("\nNumber of ML features:", len(feature_names))

print("\nFeatures used for training:")

for feature in feature_names:
    print(" -", feature)


# ============================================================
# TRAIN / TEST SPLIT
# ============================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


print("\nTraining samples:", len(X_train))
print("Testing samples:", len(X_test))


# ============================================================
# RANDOM FOREST
# ============================================================

print("\nTraining Random Forest...")

model = RandomForestClassifier(
    n_estimators=300,
    max_depth=None,
    min_samples_split=2,
    min_samples_leaf=1,
    max_features="sqrt",
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)


model.fit(
    X_train,
    y_train
)


print("Training completed.")


# ============================================================
# PREDICTION
# ============================================================

y_pred = model.predict(X_test)

y_probability = model.predict_proba(X_test)[:, 1]


# ============================================================
# EVALUATION
# ============================================================

accuracy = accuracy_score(
    y_test,
    y_pred
)

precision = precision_score(
    y_test,
    y_pred,
    zero_division=0
)

recall = recall_score(
    y_test,
    y_pred,
    zero_division=0
)

f1 = f1_score(
    y_test,
    y_pred,
    zero_division=0
)

roc_auc = roc_auc_score(
    y_test,
    y_probability
)


print("\n")
print("=" * 70)
print("MODEL PERFORMANCE")
print("=" * 70)

print(f"\nAccuracy : {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall   : {recall:.4f}")
print(f"F1 Score : {f1:.4f}")
print(f"ROC-AUC  : {roc_auc:.4f}")


print("\nClassification Report:")
print(
    classification_report(
        y_test,
        y_pred,
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
        y_pred
    )
)


# ============================================================
# FEATURE IMPORTANCE
# ============================================================

print("\nCalculating feature importance...")

importance_values = model.feature_importances_

feature_importance = dict(
    zip(
        feature_names,
        importance_values
    )
)

feature_importance = dict(
    sorted(
        feature_importance.items(),
        key=lambda x: x[1],
        reverse=True
    )
)


print("\nTop 20 important features:")

for feature, importance in list(
    feature_importance.items()
)[:20]:

    print(
        f"{feature:<35} "
        f"{importance:.6f}"
    )


# ============================================================
# SAVE MODEL
# ============================================================

os.makedirs(
    MODEL_DIR,
    exist_ok=True
)


joblib.dump(
    model,
    MODEL_PATH
)


print(
    f"\nModel saved to: {MODEL_PATH}"
)


# ============================================================
# SAVE FEATURES
# ============================================================

with open(
    FEATURE_PATH,
    "w"
) as file:

    json.dump(
        feature_names,
        file,
        indent=4
    )


print(
    f"Feature list saved to: {FEATURE_PATH}"
)


# ============================================================
# SAVE FEATURE IMPORTANCE
# ============================================================

with open(
    IMPORTANCE_PATH,
    "w"
) as file:

    json.dump(
        feature_importance,
        file,
        indent=4
    )


print(
    f"Feature importance saved to: {IMPORTANCE_PATH}"
)


# ============================================================
# FINAL
# ============================================================

print("\n")
print("=" * 70)
print("TRAINING FINISHED SUCCESSFULLY")
print("=" * 70)

print("\nNext step:")
print("Run:")
print("python predict.py")