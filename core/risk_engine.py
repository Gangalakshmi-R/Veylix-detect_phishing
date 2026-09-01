def calculate_final_risk(

    message_probability,

    url_probabilities,

    reasons,

    threat_intelligence

):

    # ---------------------------------------------------------
    # Base score
    # ---------------------------------------------------------

    scores = []

    if message_probability is not None:

        scores.append(
            message_probability
        )

    scores.extend(
        url_probabilities
    )

    if scores:

        base_score = max(
            scores
        )

    else:

        base_score = 0

    # ---------------------------------------------------------
    # Evidence
    # ---------------------------------------------------------

    critical = sum(

        1

        for reason
        in reasons

        if reason["impact"]
        == "CRITICAL"
    )

    high = sum(

        1

        for reason
        in reasons

        if reason["impact"]
        == "HIGH"
    )

    medium = sum(

        1

        for reason
        in reasons

        if reason["impact"]
        == "MEDIUM"
    )

    evidence_bonus = (

        critical * 7

        + high * 3

        + medium * 1
    )

    score = (
        base_score
        + evidence_bonus
    )

    # ---------------------------------------------------------
    # Threat intelligence overrides
    # ---------------------------------------------------------

    if threat_intelligence[
        "verified"
    ]:

        score = max(
            score,
            98
        )

    elif threat_intelligence[
        "listed"
    ]:

        score = max(
            score,
            90
        )

    # ---------------------------------------------------------
    # Cap
    # ---------------------------------------------------------

    score = min(
        score,
        99.9
    )

    # ---------------------------------------------------------
    # Verdict
    # ---------------------------------------------------------

    if score >= 80:

        verdict = "PHISHING"

        risk_level = "CRITICAL"

    elif score >= 60:

        verdict = "SUSPICIOUS"

        risk_level = "HIGH"

    elif score >= 40:

        verdict = "SUSPICIOUS"

        risk_level = "MEDIUM"

    else:

        verdict = "LIKELY LEGITIMATE"

        risk_level = "LOW"

    return {

        "final_risk_score":
            round(
                score,
                2
            ),

        "verdict":
            verdict,

        "risk_level":
            risk_level,

        "evidence_summary": {

            "critical":
                critical,

            "high":
                high,

            "medium":
                medium
        }
    }