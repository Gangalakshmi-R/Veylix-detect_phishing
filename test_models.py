import joblib
import os

from services.message_analyzer import analyze_message
from services.url_analyzer import analyze_url


EMAIL_MODEL_PATH = "models/email_model.pkl"
URL_MODEL_PATH = "models/url_model.pkl"


def test_email(message):

    bundle = joblib.load(
        EMAIL_MODEL_PATH
    )

    vectorizer = bundle["vectorizer"]
    model = bundle["model"]

    X = vectorizer.transform(
        [message]
    )

    probability = (
        model.predict_proba(X)[0][1]
        * 100
    )

    prediction = (
        "PHISHING"
        if probability >= 50
        else "LEGITIMATE"
    )

    print("\nEMAIL MODEL")
    print("-" * 50)

    print(
        f"Prediction : {prediction}"
    )

    print(
        f"Phishing probability : "
        f"{probability:.2f}%"
    )

    print(
        f"Legitimate probability : "
        f"{100 - probability:.2f}%"
    )


def test_url(url):

    bundle = joblib.load(
        URL_MODEL_PATH
    )

    model = bundle["model"]

    features = bundle["features"]

    analysis = analyze_url(url)

    values = [

        analysis["features"].get(
            feature,
            0
        )

        for feature in features
    ]

    probability = (
        model.predict_proba(
            [values]
        )[0][1]
        * 100
    )

    prediction = (
        "PHISHING"
        if probability >= 50
        else "LEGITIMATE"
    )

    print("\nURL MODEL")
    print("-" * 50)

    print(
        f"URL : {url}"
    )

    print(
        f"Prediction : {prediction}"
    )

    print(
        f"Phishing probability : "
        f"{probability:.2f}%"
    )

    print(
        f"Legitimate probability : "
        f"{100 - probability:.2f}%"
    )


if __name__ == "__main__":

    print(
        "=" * 60
    )

    print(
        "PHISHING MODEL TEST"
    )

    print(
        "=" * 60
    )

    message = (
        "URGENT! Your account has been suspended. "
        "Verify your password immediately by clicking "
        "the link below."
    )

    test_email(
        message
    )

    test_url(
        "http://paypal-secure-login-example.com/verify"
    )