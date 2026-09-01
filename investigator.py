import os

import joblib
import pandas as pd

from services.message_analyzer import (
    analyze_message
)

from services.url_analyzer import (
    analyze_url
)

from services.dns_analyzer import (
    analyze_dns
)

from services.domain_analyzer import (
    analyze_domain
)

from services.threat_intelligence import (
    check_phishtank
)

from core.explanation_engine import (
    explain_message,
    explain_url
)


EMAIL_MODEL_PATH = (
    "models/email_model.pkl"
)

URL_MODEL_PATH = (
    "models/url_model.pkl"
)


# ============================================================
# MODEL LOADERS
# ============================================================

def load_email_model():

    if not os.path.exists(
        EMAIL_MODEL_PATH
    ):

        raise FileNotFoundError(
            "Email model not found. "
            "Run train_email_model.py first."
        )

    return joblib.load(
        EMAIL_MODEL_PATH
    )


def load_url_model():

    if not os.path.exists(
        URL_MODEL_PATH
    ):

        raise FileNotFoundError(
            "URL model not found. "
            "Run train_url_model.py first."
        )

    return joblib.load(
        URL_MODEL_PATH
    )


# ============================================================
# MESSAGE MODEL
# ============================================================

def predict_message(
    message
):

    bundle = load_email_model()

    vectorizer = (
        bundle["vectorizer"]
    )

    model = (
        bundle["model"]
    )

    transformed = (
        vectorizer.transform(
            [message]
        )
    )

    probabilities = (
        model.predict_proba(
            transformed
        )[0]
    )

    phishing_probability = (
        probabilities[1] * 100
    )

    legitimate_probability = (
        probabilities[0] * 100
    )

    return {

        "phishing_probability":
            round(
                phishing_probability,
                2
            ),

        "legitimate_probability":
            round(
                legitimate_probability,
                2
            ),

        "prediction":
            (
                "PHISHING"
                if phishing_probability >= 50
                else "LIKELY LEGITIMATE"
            )
    }


# ============================================================
# URL MODEL
# ============================================================

def predict_url(
    url
):

    bundle = load_url_model()

    model = (
        bundle["model"]
    )

    feature_names = (
        bundle["features"]
    )

    analysis = analyze_url(
        url
    )

    features = (
        analysis["features"]
    )

    # --------------------------------------------------------
    # Build a DataFrame with the same feature names used
    # during training.
    # --------------------------------------------------------

    model_input = pd.DataFrame(

        [
            {
                feature:
                    features.get(
                        feature,
                        0
                    )

                for feature
                in feature_names
            }
        ],

        columns=feature_names
    )

    probabilities = (
        model.predict_proba(
            model_input
        )[0]
    )

    phishing_probability = (
        probabilities[1] * 100
    )

    legitimate_probability = (
        probabilities[0] * 100
    )

    return {

        "phishing_probability":
            round(
                phishing_probability,
                2
            ),

        "legitimate_probability":
            round(
                legitimate_probability,
                2
            ),

        "prediction":
            (
                "PHISHING"
                if phishing_probability >= 50
                else "LIKELY LEGITIMATE"
            ),

        "analysis":
            analysis
    }


# ============================================================
# COMPLETE INVESTIGATION
# ============================================================

def investigate_message(
    message
):

    # --------------------------------------------------------
    # 1. MESSAGE ANALYSIS
    # --------------------------------------------------------

    message_analysis = (
        analyze_message(
            message
        )
    )

    # --------------------------------------------------------
    # 2. MESSAGE ML
    # --------------------------------------------------------

    message_prediction = (
        predict_message(
            message
        )
    )

    # --------------------------------------------------------
    # 3. MESSAGE EXPLANATION
    # --------------------------------------------------------

    message_reasons = (
        explain_message(
            message_analysis
        )
    )

    # --------------------------------------------------------
    # 4. URL INVESTIGATION
    # --------------------------------------------------------

    url_results = []

    all_reasons = list(
        message_reasons
    )

    for url in message_analysis[
        "urls"
    ]:

        # ----------------------------------------------------
        # URL ML
        # ----------------------------------------------------

        url_prediction = (
            predict_url(
                url
            )
        )

        url_analysis = (
            url_prediction[
                "analysis"
            ]
        )

        metadata = (
            url_analysis[
                "metadata"
            ]
        )

        # ----------------------------------------------------
        # DNS
        # ----------------------------------------------------

        dns_result = (
            analyze_dns(
                metadata[
                    "hostname"
                ]
            )
        )

        # ----------------------------------------------------
        # DOMAIN / RDAP
        # ----------------------------------------------------

        domain_result = (
            analyze_domain(
                metadata[
                    "registered_domain"
                ]
            )
        )

        # ----------------------------------------------------
        # THREAT INTELLIGENCE
        # ----------------------------------------------------

        threat_result = (
            check_phishtank(
                metadata[
                    "normalized_url"
                ]
            )
        )

        # ----------------------------------------------------
        # URL EXPLANATION
        # ----------------------------------------------------

        url_reasons = (
            explain_url(

                url_analysis,

                dns_result,

                domain_result,

                threat_result
            )
        )

        all_reasons.extend(
            url_reasons
        )

        url_results.append({

            "url":
                url,

            "machine_learning":
                url_prediction,

            "dns":
                dns_result,

            "domain":
                domain_result,

            "threat_intelligence":
                threat_result,

            "reasons":
                url_reasons
        })

    # ========================================================
    # ML SCORES
    # ========================================================

    message_score = (
        message_prediction[
            "phishing_probability"
        ]
    )

    url_scores = [

        item[
            "machine_learning"
        ][
            "phishing_probability"
        ]

        for item
        in url_results
    ]

    strongest_url_score = (

        max(url_scores)

        if url_scores

        else 0
    )

    strongest_ml_score = max(

        message_score,

        strongest_url_score
    )

    # ========================================================
    # THREAT INTELLIGENCE STATUS
    # ========================================================

    verified_threat = any(

        item[
            "threat_intelligence"
        ].get(
            "verified",
            False
        )

        for item
        in url_results
    )

    listed_threat = any(

        item[
            "threat_intelligence"
        ].get(
            "listed",
            False
        )

        for item
        in url_results
    )

    # ========================================================
    # EVIDENCE COUNTS
    # ========================================================

    critical = sum(

        1

        for reason
        in all_reasons

        if reason[
            "impact"
        ] == "CRITICAL"
    )

    high = sum(

        1

        for reason
        in all_reasons

        if reason[
            "impact"
        ] == "HIGH"
    )

    medium = sum(

        1

        for reason
        in all_reasons

        if reason[
            "impact"
        ] == "MEDIUM"
    )

    # ========================================================
    # INVESTIGATION RISK SCORE
    #
    # IMPORTANT:
    #
    # This is NOT a probability.
    #
    # ML probability and investigation risk score are
    # separate values.
    # ========================================================

    risk_score = strongest_ml_score

    # --------------------------------------------------------
    # Add evidence only when it provides additional support.
    # --------------------------------------------------------

    if critical > 0:

        risk_score += 5

    elif high >= 2:

        risk_score += 3

    elif high == 1:

        risk_score += 1

    if medium >= 3:

        risk_score += 1

    # --------------------------------------------------------
    # Threat intelligence
    # --------------------------------------------------------

    if verified_threat:

        risk_score = max(
            risk_score,
            98
        )

    elif listed_threat:

        risk_score = max(
            risk_score,
            90
        )

    risk_score = min(
        risk_score,
        100
    )

    # ========================================================
    # FINAL VERDICT
    # ========================================================

    if risk_score >= 80:

        verdict = "PHISHING"

        risk_level = "CRITICAL"

        recommendation = (
            "Do not click links, "
            "open attachments, or "
            "provide credentials."
        )

    elif risk_score >= 60:

        verdict = "SUSPICIOUS"

        risk_level = "HIGH"

        recommendation = (
            "Treat the message as potentially "
            "malicious and verify the sender "
            "through an independent channel."
        )

    elif risk_score >= 40:

        verdict = "SUSPICIOUS"

        risk_level = "MEDIUM"

        recommendation = (
            "Exercise caution and verify the "
            "message before taking action."
        )

    else:

        verdict = "LIKELY LEGITIMATE"

        risk_level = "LOW"

        recommendation = (
            "No strong phishing indicators "
            "were detected. Automated analysis "
            "cannot guarantee safety."
        )

    # ========================================================
    # FINAL RESULT
    # ========================================================

    return {

        "verdict":
            verdict,

        "risk_level":
            risk_level,

        "risk_score":
            round(
                risk_score,
                2
            ),

        "message_model":
            message_prediction,

        "message_analysis":
            message_analysis,

        "urls":
            url_results,

        "evidence_summary": {

            "critical":
                critical,

            "high":
                high,

            "medium":
                medium
        },

        "reasons":
            all_reasons,

        "recommendation":
            recommendation
    }