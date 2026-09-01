import json
import os

import joblib

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

from core.risk_engine import (
    calculate_final_risk
)


EMAIL_MODEL_PATH = (
    "models/email_model.pkl"
)

URL_MODEL_PATH = (
    "models/url_model.pkl"
)


def load_email_model():

    if not os.path.exists(
        EMAIL_MODEL_PATH
    ):

        raise FileNotFoundError(
            "Email model not found. "
            "Run train_email_model.py"
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
            "Run train_url_model.py"
        )

    return joblib.load(
        URL_MODEL_PATH
    )


def analyze_message_text(
    message
):

    email_bundle = (
        load_email_model()
    )

    message_analysis = (
        analyze_message(
            message
        )
    )

    # ---------------------------------------------------------
    # Email NLP model
    # ---------------------------------------------------------

    vectorizer = (
        email_bundle[
            "vectorizer"
        ]
    )

    model = (
        email_bundle[
            "model"
        ]
    )

    transformed = (
        vectorizer.transform(
            [message]
        )
    )

    email_probability = (

        model.predict_proba(
            transformed
        )[0][1]

        * 100
    )

    message_reasons = (
        explain_message(
            message_analysis
        )
    )

    # ---------------------------------------------------------
    # URL processing
    # ---------------------------------------------------------

    url_model = (
        load_url_model()
    )

    url_results = []

    url_probabilities = []

    all_reasons = list(
        message_reasons
    )

    threat_results = []

    for url in (
        message_analysis[
            "urls"
        ]
    ):

        url_analysis = (
            analyze_url(
                url
            )
        )

        features = (
            url_analysis[
                "features"
            ]
        )

        feature_names = (
            url_model[
                "features"
            ]
        )

        model_input = [

            [

                features.get(
                    feature,
                    0
                )

                for feature
                in feature_names
            ]
        ]

        probabilities = (
            url_model[
                "model"
            ].predict_proba(
                model_input
            )[0]
        )

        url_probability = (

            probabilities[1]
            * 100
        )

        url_probabilities.append(
            url_probability
        )

        metadata = (
            url_analysis[
                "metadata"
            ]
        )

        # -----------------------------------------------------
        # DNS
        # -----------------------------------------------------

        dns_analysis = (
            analyze_dns(
                metadata[
                    "hostname"
                ]
            )
        )

        # -----------------------------------------------------
        # Domain
        # -----------------------------------------------------

        domain_analysis = (
            analyze_domain(
                metadata[
                    "registered_domain"
                ]
            )
        )

        # -----------------------------------------------------
        # Threat intel
        # -----------------------------------------------------

        threat_analysis = (
            check_phishtank(
                metadata[
                    "normalized_url"
                ]
            )
        )

        threat_results.append(
            threat_analysis
        )

        # -----------------------------------------------------
        # Reasons
        # -----------------------------------------------------

        url_reasons = (
            explain_url(

                url_analysis,

                dns_analysis,

                domain_analysis,

                threat_analysis
            )
        )

        all_reasons.extend(
            url_reasons
        )

        url_results.append({

            "url":
                url,

            "ml_probability":
                round(
                    url_probability,
                    2
                ),

            "url_analysis":
                url_analysis,

            "dns_analysis":
                dns_analysis,

            "domain_analysis":
                domain_analysis,

            "threat_intelligence":
                threat_analysis,

            "reasons":
                url_reasons
        })

    # ---------------------------------------------------------
    # Strongest threat intelligence result
    # ---------------------------------------------------------

    strongest_threat = {

        "checked":
            False,

        "listed":
            False,

        "verified":
            False,

        "message":
            "No URLs detected."
    }

    for threat in (
        threat_results
    ):

        if threat[
            "verified"
        ]:

            strongest_threat = threat

            break

        if (
            threat["listed"]
            and not
            strongest_threat["listed"]
        ):

            strongest_threat = threat

    # ---------------------------------------------------------
    # Final risk
    # ---------------------------------------------------------

    final_risk = (
        calculate_final_risk(

            email_probability,

            url_probabilities,

            all_reasons,

            strongest_threat
        )
    )

    # ---------------------------------------------------------
    # Recommendation
    # ---------------------------------------------------------

    if final_risk[
        "risk_level"
    ] == "CRITICAL":

        recommendation = (
            "Do not click links, "
            "open attachments, or "
            "provide credentials."
        )

    elif final_risk[
        "risk_level"
    ] == "HIGH":

        recommendation = (
            "Treat this message as "
            "potentially malicious and "
            "verify the sender independently."
        )

    elif final_risk[
        "risk_level"
    ] == "MEDIUM":

        recommendation = (
            "Exercise caution and "
            "verify the message before "
            "taking any action."
        )

    else:

        recommendation = (
            "No strong phishing indicators "
            "were detected, but automated "
            "analysis cannot guarantee safety."
        )

    return {

        "message": message,

        "email_model": {

            "phishing_probability":
                round(
                    email_probability,
                    2
                ),

            "legitimate_probability":
                round(
                    100 -
                    email_probability,
                    2
                )
        },

        "message_analysis":
            message_analysis,

        "url_results":
            url_results,

        "final_risk":
            final_risk,

        "reasons":
            all_reasons,

        "recommendation":
            recommendation
    }


def print_report(
    result
):

    final = result[
        "final_risk"
    ]

    email = result[
        "email_model"
    ]

    print("\n")

    print("=" * 80)

    print(
        "        INTELLIGENT PHISHING INVESTIGATION"
    )

    print("=" * 80)

    print(
        "\nFINAL VERDICT:"
    )

    print(
        final["verdict"]
    )

    print(
        "\nFINAL RISK SCORE:"
    )

    print(
        f"{final['final_risk_score']}%"
    )

    print(
        "\nRISK LEVEL:"
    )

    print(
        final["risk_level"]
    )

    print(
        "\nMESSAGE MODEL:"
    )

    print(
        f"Phishing: "
        f"{email['phishing_probability']}%"
    )

    print(
        f"Legitimate: "
        f"{email['legitimate_probability']}%"
    )

    print(
        "\n"
        + "-" * 80
    )

    print(
        "EVIDENCE / REASONS"
    )

    print(
        "-" * 80
    )

    for index, reason in enumerate(
        result["reasons"],
        start=1
    ):

        print(
            f"\n{index}. "
            f"[{reason['impact']}] "
            f"{reason['factor']}"
        )

        print(
            f"   Category: "
            f"{reason['category']}"
        )

        print(
            f"   Why: "
            f"{reason['explanation']}"
        )

        print(
            f"   Evidence: "
            f"{reason['evidence']}"
        )

    print(
        "\n"
        + "-" * 80
    )

    print(
        "RECOMMENDATION"
    )

    print(
        "-" * 80
    )

    print(
        result[
            "recommendation"
        ]
    )

    print(
        "\n"
        + "=" * 80
    )


if __name__ == "__main__":

    print(
        "\nIntelligent Phishing Identification System"
    )

    print(
        "Paste any email/message/chat text."
    )

    print(
        "URLs inside the message will be "
        "automatically investigated."
    )

    message = input(
        "\nMessage:\n"
    )

    if not message.strip():

        print(
            "No message provided."
        )

        raise SystemExit

    try:

        result = (
            analyze_message_text(
                message
            )
        )

        print_report(
            result
        )

        print(
            "\nJSON OUTPUT:"
        )

        print(
            json.dumps(
                result,
                indent=4,
                default=str
            )
        )

    except Exception as exc:

        print(
            "\nAnalysis failed:"
        )

        print(
            str(exc)
        )