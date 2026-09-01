import re


URGENCY_TERMS = [

    "urgent",
    "immediately",
    "immediate",
    "act now",
    "action required",
    "final warning",
    "last warning",
    "within 24 hours",
    "within 48 hours",
    "expires",
    "expired",
    "suspended",
    "blocked",
    "locked",
    "verify now",
    "confirm now",
    "deadline",
    "last chance",
    "registrations close",
    "registration closes",
    "respond immediately"

]


CREDENTIAL_TERMS = [

    "password",
    "username",
    "login",
    "signin",
    "sign in",
    "otp",
    "verification code",
    "pin",
    "cvv",
    "card number",
    "account number",
    "bank details",
    "credentials",
    "passcode",
    "security code"

]


MONEY_TERMS = [

    "payment",
    "refund",
    "prize",
    "reward",
    "lottery",
    "cash",
    "money",
    "transfer",
    "invoice",
    "gift",
    "bonus",
    "crypto",
    "bitcoin",
    "fee",
    "fees",
    "stipend",
    "tuition",
    "payment required"

]


def extract_urls(text):

    if not text:
        return []

    # Handles normal URLs and Markdown URLs.

    pattern = (

        r"(?:https?://|www\.)"
        r"[^\s<>\"'()]+"

    )

    urls = re.findall(
        pattern,
        text,
        flags=re.IGNORECASE
    )

    cleaned = []

    for url in urls:

        url = url.rstrip(
            ".,!?;:]}"
        )

        if url.startswith(
            "www."
        ):

            url = (
                "http://"
                + url
            )

        cleaned.append(
            url
        )

    # --------------------------------------------------------
    # Also detect Markdown links where the regex can leave
    # formatting artifacts.
    # --------------------------------------------------------

    markdown_urls = re.findall(

        r"\[[^\]]+\]"
        r"\((https?://[^)]+)\)",

        text,

        flags=re.IGNORECASE

    )

    for url in markdown_urls:

        url = url.rstrip(
            ".,!?;:]}"
        )

        cleaned.append(
            url
        )

    return list(
        dict.fromkeys(
            cleaned
        )
    )


def find_terms(
    text,
    terms
):

    found = []

    for term in terms:

        pattern = (
            r"(?<!\w)"
            + re.escape(term)
            + r"(?!\w)"
        )

        if re.search(
            pattern,
            text,
            flags=re.IGNORECASE
        ):

            found.append(
                term
            )

    return found


def analyze_message(message):

    message = str(
        message
    ).strip()

    lower = message.lower()

    urls = extract_urls(
        message
    )

    urgency = find_terms(
        message,
        URGENCY_TERMS
    )

    credentials = find_terms(
        message,
        CREDENTIAL_TERMS
    )

    money = find_terms(
        message,
        MONEY_TERMS
    )

    exclamation_count = (
        message.count("!")
    )

    uppercase_letters = sum(

        character.isupper()

        for character
        in message

        if character.isalpha()

    )

    alphabetic_count = sum(

        character.isalpha()

        for character
        in message

    )

    uppercase_ratio = (

        uppercase_letters
        / alphabetic_count

        if alphabetic_count

        else 0

    )

    return {

        "message_length":
            len(message),

        "urls":
            urls,

        "url_count":
            len(urls),

        "urgency_terms":
            urgency,

        "credential_terms":
            credentials,

        "money_terms":
            money,

        "exclamation_count":
            exclamation_count,

        "uppercase_ratio":
            round(
                uppercase_ratio,
                4
            ),

        "has_credential_request":
            len(credentials) > 0,

        "has_money_language":
            len(money) > 0,

        "has_urgency":
            len(urgency) > 0

    }