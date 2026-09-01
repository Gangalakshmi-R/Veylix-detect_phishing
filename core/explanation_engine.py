def add_reason(
    reasons,
    category,
    factor,
    impact,
    explanation,
    evidence=None
):

    reasons.append({

        "category":
            category,

        "factor":
            factor,

        "impact":
            impact,

        "explanation":
            explanation,

        "evidence":
            evidence

    })


# ============================================================
# MESSAGE EXPLANATION
# ============================================================

def explain_message(
    message_analysis
):

    reasons = []

    urgency = (
        message_analysis[
            "urgency_terms"
        ]
    )

    credentials = (
        message_analysis[
            "credential_terms"
        ]
    )

    money = (
        message_analysis[
            "money_terms"
        ]
    )

    # --------------------------------------------------------
    # Urgency
    # --------------------------------------------------------

    if urgency:

        add_reason(

            reasons,

            "MESSAGE",

            "Urgency Language",

            "HIGH",

            (
                "The message uses pressure, "
                "deadlines or time-limited language "
                "that may encourage the recipient "
                "to act without verification."
            ),

            urgency

        )

    # --------------------------------------------------------
    # Credentials
    # --------------------------------------------------------

    if credentials:

        add_reason(

            reasons,

            "MESSAGE",

            "Credential Request",

            "HIGH",

            (
                "The message contains terms "
                "associated with passwords, OTPs, "
                "verification codes or account "
                "credentials."
            ),

            credentials

        )

    # --------------------------------------------------------
    # Financial language
    # --------------------------------------------------------

    if money:

        add_reason(

            reasons,

            "MESSAGE",

            "Financial Language",

            "MEDIUM",

            (
                "The message contains payment, "
                "money, reward, fee or other "
                "financial language."
            ),

            money

        )

    # --------------------------------------------------------
    # Exclamation marks
    # --------------------------------------------------------

    if (
        message_analysis[
            "exclamation_count"
        ] >= 3
    ):

        add_reason(

            reasons,

            "MESSAGE",

            "Excessive Urgency Formatting",

            "MEDIUM",

            (
                "The message uses multiple "
                "exclamation marks, which can "
                "be used to create urgency."
            ),

            message_analysis[
                "exclamation_count"
            ]

        )

    # --------------------------------------------------------
    # Capitalization
    # --------------------------------------------------------

    if (
        message_analysis[
            "uppercase_ratio"
        ] > 0.45
    ):

        add_reason(

            reasons,

            "MESSAGE",

            "Excessive Capitalization",

            "LOW",

            (
                "A high proportion of alphabetic "
                "characters are uppercase."
            ),

            message_analysis[
                "uppercase_ratio"
            ]

        )

    return reasons


# ============================================================
# URL EXPLANATION
# ============================================================

def explain_url(

    url_analysis,

    dns_analysis,

    domain_analysis,

    threat_analysis

):

    reasons = []

    features = (
        url_analysis[
            "features"
        ]
    )

    metadata = (
        url_analysis[
            "metadata"
        ]
    )

    # --------------------------------------------------------
    # Raw IP
    # --------------------------------------------------------

    if metadata["is_ip"]:

        add_reason(

            reasons,

            "URL",

            "IP Address",

            "HIGH",

            (
                "The URL uses a raw IP address "
                "instead of a conventional domain."
            ),

            metadata["hostname"]

        )

    # --------------------------------------------------------
    # HTTPS
    # --------------------------------------------------------

    if not metadata["is_https"]:

        add_reason(

            reasons,

            "URL",

            "HTTPS",

            "MEDIUM",

            (
                "The URL uses HTTP instead of HTTPS. "
                "This means the connection does not "
                "provide the protections normally "
                "associated with HTTPS."
            ),

            metadata["scheme"]

        )

    # --------------------------------------------------------
    # URL length
    # --------------------------------------------------------

    if features["URLLength"] > 100:

        add_reason(

            reasons,

            "URL",

            "URL Length",

            "MEDIUM",

            (
                "The URL is unusually long and "
                "contains a large amount of structure."
            ),

            features["URLLength"]

        )

    # --------------------------------------------------------
    # Subdomains
    # --------------------------------------------------------

    if features["NoOfSubDomain"] >= 3:

        add_reason(

            reasons,

            "DOMAIN",

            "Multiple Subdomains",

            "MEDIUM",

            (
                "The hostname contains multiple "
                "subdomain levels."
            ),

            features["NoOfSubDomain"]

        )

    # --------------------------------------------------------
    # Suspicious keywords
    # --------------------------------------------------------

    keywords = (
        metadata[
            "suspicious_keywords"
        ]
    )

    if keywords:

        add_reason(

            reasons,

            "URL",

            "Suspicious Keywords",

            "HIGH",

            (
                "The URL contains terms commonly "
                "associated with login, verification, "
                "account, payment or credential lures."
            ),

            keywords

        )

    # --------------------------------------------------------
    # Obfuscation
    # --------------------------------------------------------

    if features["HasObfuscation"]:

        add_reason(

            reasons,

            "URL",

            "URL Obfuscation",

            "MEDIUM",

            (
                "The URL contains percent-encoded "
                "characters that may obscure its structure."
            ),

            features[
                "NoOfObfuscatedChar"
            ]

        )

    # --------------------------------------------------------
    # @ character
    # --------------------------------------------------------

    if metadata["at_symbol"] > 0:

        add_reason(

            reasons,

            "URL",

            "@ Character",

            "HIGH",

            (
                "The URL contains an @ character, "
                "which can be abused to make a "
                "destination appear misleading."
            ),

            metadata["at_symbol"]

        )

    # --------------------------------------------------------
    # Brand impersonation
    # --------------------------------------------------------

    brand = (
        metadata[
            "impersonated_brand"
        ]
    )

    if brand:

        add_reason(

            reasons,

            "DOMAIN",

            "Brand Impersonation",

            "CRITICAL",

            (
                f"The URL contains the brand "
                f"'{brand}', but the registered "
                f"domain does not match the known "
                f"official domain."
            ),

            brand

        )

    # --------------------------------------------------------
    # URL shortener
    # --------------------------------------------------------

    if metadata.get(
        "is_shortened",
        False
    ):

        add_reason(

            reasons,

            "URL",

            "URL Shortener",

            "MEDIUM",

            (
                "The URL uses a URL-shortening "
                "service. The visible URL does not "
                "directly reveal the final destination."
            ),

            metadata["registered_domain"]

        )

    # --------------------------------------------------------
    # Suspicious TLD
    # --------------------------------------------------------

    if metadata.get(
        "suspicious_tld",
        False
    ):

        add_reason(

            reasons,

            "DOMAIN",

            "Suspicious TLD",

            "MEDIUM",

            (
                "The domain uses a TLD that is "
                "frequently observed in suspicious "
                "or abusive registrations."
            ),

            metadata["tld"]

        )

    # --------------------------------------------------------
    # DNS
    # --------------------------------------------------------

    if dns_analysis["resolved"]:

        add_reason(

            reasons,

            "DNS",

            "DNS Resolution",

            "INFO",

            (
                "The domain successfully resolved "
                "to one or more IPv4 addresses."
            ),

            dns_analysis["a_records"]

        )

    else:

        add_reason(

            reasons,

            "DNS",

            "DNS Status",

            "INFO",

            (
                "The domain did not resolve to an "
                "IPv4 address during this investigation. "
                "This may indicate that the domain is "
                "inactive, unavailable or temporarily "
                "unresolvable. It is not by itself "
                "evidence of phishing."
            ),

            None

        )

    # --------------------------------------------------------
    # Domain age
    # --------------------------------------------------------

    age = (
        domain_analysis[
            "domain_age_days"
        ]
    )

    if age is not None:

        if age < 7:

            add_reason(

                reasons,

                "DOMAIN",

                "Very New Domain",

                "HIGH",

                (
                    "The domain appears to have "
                    "been registered very recently."
                ),

                f"{age} days"

            )

        elif age < 30:

            add_reason(

                reasons,

                "DOMAIN",

                "New Domain",

                "MEDIUM",

                (
                    "The domain is relatively new."
                ),

                f"{age} days"

            )

        elif age > 3650:

            add_reason(

                reasons,

                "DOMAIN",

                "Established Domain",

                "INFO",

                (
                    "The domain has been registered "
                    "for many years. Domain age alone "
                    "does not prove legitimacy, but "
                    "it provides useful context."
                ),

                f"{age} days"

            )

    else:

        add_reason(

            reasons,

            "DOMAIN",

            "Domain Registration Data",

            "INFO",

            (
                "Registration information could not "
                "be retrieved for this domain. "
                "Unavailable registration data is "
                "not by itself evidence of phishing."
            ),

            None

        )

    # --------------------------------------------------------
    # Threat intelligence
    # --------------------------------------------------------

    if threat_analysis["verified"]:

        add_reason(

            reasons,

            "THREAT_INTELLIGENCE",

            "PhishTank",

            "CRITICAL",

            (
                "The URL is listed as a verified "
                "phishing URL."
            ),

            True

        )

    elif threat_analysis["listed"]:

        add_reason(

            reasons,

            "THREAT_INTELLIGENCE",

            "PhishTank",

            "HIGH",

            (
                "The URL is present in the "
                "PhishTank database."
            ),

            True

        )

    elif not threat_analysis["checked"]:

        add_reason(

            reasons,

            "THREAT_INTELLIGENCE",

            "Threat Intelligence Status",

            "INFO",

            (
                "The threat-intelligence lookup "
                "could not be completed. No conclusion "
                "about the URL's reputation should be "
                "drawn from an unavailable lookup."
            ),

            threat_analysis.get(
                "message"
            )

        )

    return reasons