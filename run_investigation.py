import json

from investigator import investigate_message


def main():

    print("=" * 75)
    print("       PHISHINTEL - MESSAGE INVESTIGATOR")
    print("=" * 75)

    print()
    print(
        "Paste your complete email / SMS / WhatsApp / "
        "Telegram / chat message."
    )

    print()
    print(
        "When finished, type END on a new line."
    )

    print(
        "------------------------------------------------------------"
    )

    lines = []

    while True:

        try:
            line = input()

        except KeyboardInterrupt:

            print("\n\nAnalysis cancelled.")
            return

        if line.strip() == "END":

            break

        lines.append(line)

    message = "\n".join(lines).strip()

    if not message:

        print("\nNo message entered.")
        return

    print()
    print("Analyzing...")
    print()

    try:

        result = investigate_message(
            message
        )

    except Exception as exc:

        print("=" * 75)
        print("ANALYSIS ERROR")
        print("=" * 75)

        print(
            f"\n{type(exc).__name__}: {exc}"
        )

        return

    # =========================================================
    # FINAL VERDICT
    # =========================================================

    print("=" * 75)
    print("FINAL VERDICT")
    print("=" * 75)

    print(
        result["verdict"]
    )

    print(
        f"\nRisk Level: "
        f"{result['risk_level']}"
    )

    print(
        f"Final Risk Score: "
        f"{result['risk_score']}%"
    )

    # =========================================================
    # MESSAGE MODEL
    # =========================================================

    print()
    print("=" * 75)
    print("MESSAGE MODEL")
    print("=" * 75)

    message_model = result[
        "message_model"
    ]

    print(
        "Prediction:",
        message_model["prediction"]
    )

    print(
        "Phishing:",
        message_model[
            "phishing_probability"
        ],
        "%"
    )

    print(
        "Legitimate:",
        message_model[
            "legitimate_probability"
        ],
        "%"
    )

    # =========================================================
    # MESSAGE ANALYSIS
    # =========================================================

    print()
    print("=" * 75)
    print("MESSAGE ANALYSIS")
    print("=" * 75)

    analysis = result[
        "message_analysis"
    ]

    print(
        "Message length:",
        analysis[
            "message_length"
        ]
    )

    print(
        "URLs found:",
        analysis[
            "url_count"
        ]
    )

    print(
        "Urgency terms:",
        analysis[
            "urgency_terms"
        ]
    )

    print(
        "Credential terms:",
        analysis[
            "credential_terms"
        ]
    )

    print(
        "Financial terms:",
        analysis[
            "money_terms"
        ]
    )

    # =========================================================
    # URL INVESTIGATION
    # =========================================================

    print()
    print("=" * 75)
    print("URL INVESTIGATION")
    print("=" * 75)

    if not result["urls"]:

        print(
            "No URLs found."
        )

    for index, item in enumerate(
        result["urls"],
        start=1
    ):

        print()
        print(
            f"URL #{index}"
        )

        print(
            "-" * 60
        )

        print(
            "URL:",
            item["url"]
        )

        # -----------------------------------------------------
        # URL ML
        # -----------------------------------------------------

        ml = item[
            "machine_learning"
        ]

        print(
            "ML prediction:",
            ml["prediction"]
        )

        print(
            "Phishing probability:",
            ml[
                "phishing_probability"
            ],
            "%"
        )

        print(
            "Legitimate probability:",
            ml[
                "legitimate_probability"
            ],
            "%"
        )

        # -----------------------------------------------------
        # URL metadata
        # -----------------------------------------------------

        url_analysis = (
            ml["analysis"]
        )

        metadata = (
            url_analysis[
                "metadata"
            ]
        )

        print()
        print(
            "Hostname:",
            metadata[
                "hostname"
            ]
        )

        print(
            "Registered domain:",
            metadata[
                "registered_domain"
            ]
        )

        print(
            "TLD:",
            metadata[
                "tld"
            ]
        )

        print(
            "HTTPS:",
            metadata[
                "is_https"
            ]
        )

        print(
            "IP address URL:",
            metadata[
                "is_ip"
            ]
        )

        print(
            "Suspicious keywords:",
            metadata[
                "suspicious_keywords"
            ]
        )

        print(
            "Brand impersonation:",
            metadata[
                "impersonated_brand"
            ]
        )

        # -----------------------------------------------------
        # DNS
        # -----------------------------------------------------

        dns = item[
            "dns"
        ]

        print()
        print(
            "DNS"
        )

        print(
            "Resolved:",
            dns[
                "resolved"
            ]
        )

        print(
            "A records:",
            dns[
                "a_records"
            ]
        )

        print(
            "Reverse DNS:",
            dns[
                "reverse_dns"
            ]
        )

        # -----------------------------------------------------
        # DOMAIN / RDAP
        # -----------------------------------------------------

        domain = item[
            "domain"
        ]

        print()
        print(
            "DOMAIN / RDAP"
        )

        print(
            "RDAP available:",
            domain[
                "rdap_available"
            ]
        )

        print(
            "Registration date:",
            domain[
                "registration_date"
            ]
        )

        print(
            "Domain age:",
            domain[
                "domain_age_days"
            ],
            "days"
        )

        print(
            "Registrar:",
            domain[
                "registrar"
            ]
        )

        # -----------------------------------------------------
        # THREAT INTELLIGENCE
        # -----------------------------------------------------

        threat = item[
            "threat_intelligence"
        ]

        print()
        print(
            "THREAT INTELLIGENCE"
        )

        print(
            "PhishTank checked:",
            threat[
                "checked"
            ]
        )

        print(
            "Listed:",
            threat[
                "listed"
            ]
        )

        print(
            "Verified:",
            threat[
                "verified"
            ]
        )

        print(
            "Message:",
            threat[
                "message"
            ]
        )

    # =========================================================
    # REASONS
    # =========================================================

    print()
    print("=" * 75)
    print("WHY WAS IT FLAGGED?")
    print("=" * 75)

    if not result["reasons"]:

        print(
            "No explicit indicators detected."
        )

    for index, reason in enumerate(
        result["reasons"],
        start=1
    ):

        print()

        print(
            f"{index}. "
            f"[{reason['impact']}] "
            f"{reason['factor']}"
        )

        print(
            "Category:",
            reason["category"]
        )

        print(
            "Why:",
            reason["explanation"]
        )

        print(
            "Evidence:",
            reason["evidence"]
        )

    # =========================================================
    # RECOMMENDATION
    # =========================================================

    print()
    print("=" * 75)
    print("RECOMMENDATION")
    print("=" * 75)

    print(
        result["recommendation"]
    )

    # =========================================================
    # JSON
    # =========================================================

    print()
    print("=" * 75)
    print("JSON OUTPUT")
    print("=" * 75)

    print(
        json.dumps(
            result,
            indent=4,
            default=str
        )
    )


if __name__ == "__main__":

    main()