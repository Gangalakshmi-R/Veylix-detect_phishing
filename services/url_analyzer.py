import re
import ipaddress

from urllib.parse import urlparse

import tldextract


SUSPICIOUS_KEYWORDS = [

    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "update",
    "confirm",
    "password",
    "bank",
    "banking",
    "paypal",
    "amazon",
    "microsoft",
    "apple",
    "google",
    "facebook",
    "instagram",
    "netflix",
    "wallet",
    "payment",
    "invoice",
    "suspended",
    "suspend",
    "unlock",
    "recover",
    "authenticate",
    "credential",
]


BRANDS = {

    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "netflix": "netflix.com",

}


def normalize_url(url):
    """
    Normalize a URL before analysis.

    Handles:

        https://example.com

        http://example.com

        www.example.com

        [https://example.com](https://example.com)

    """

    if not url:
        return ""

    url = str(url).strip()

    # ========================================================
    # MARKDOWN LINK
    #
    # [visible text](https://example.com)
    # ========================================================

    markdown_match = re.search(
        r"\[[^\]]*\]\(\s*"
        r"(https?://[^\s\)]+|www\.[^\s\)]+)"
        r"\s*\)",
        url,
        flags=re.IGNORECASE
    )

    if markdown_match:

        url = markdown_match.group(1)

    else:

        # ----------------------------------------------------
        # Sometimes the entire URL may be wrapped in Markdown
        # or punctuation.
        # ----------------------------------------------------

        raw_match = re.search(
            r"(https?://[^\s<>\[\]\(\)\"']+|"
            r"www\.[^\s<>\[\]\(\)\"']+)",
            url,
            flags=re.IGNORECASE
        )

        if raw_match:

            url = raw_match.group(1)

    # ========================================================
    # Remove trailing punctuation
    # ========================================================

    url = url.strip()

    url = url.rstrip(
        ".,!?;:'\""
    )

    url = url.rstrip(
        ")]}"
    )

    # ========================================================
    # www.example.com
    # ========================================================

    if url.lower().startswith(
        "www."
    ):

        url = (
            "http://"
            + url
        )

    # ========================================================
    # Missing scheme
    # ========================================================

    elif not url.lower().startswith(
        (
            "http://",
            "https://"
        )
    ):

        url = (
            "http://"
            + url
        )

    return url


def is_ip(hostname):

    if not hostname:

        return False

    try:

        ipaddress.ip_address(
            hostname
        )

        return True

    except ValueError:

        return False


def analyze_url(url):

    # ========================================================
    # NORMALIZE
    # ========================================================

    normalized = normalize_url(
        url
    )

    parsed = urlparse(
        normalized
    )

    hostname = (
        parsed.hostname
        or ""
    )

    path = (
        parsed.path
        or ""
    )

    query = (
        parsed.query
        or ""
    )

    # ========================================================
    # DOMAIN EXTRACTION
    # ========================================================

    extracted = tldextract.extract(
        hostname
    )

    registered_domain = (
        extracted.registered_domain
    )

    subdomain = (
        extracted.subdomain
    )

    suffix = (
        extracted.suffix
    )

    lower_url = (
        normalized.lower()
    )

    # ========================================================
    # URL MEASUREMENTS
    # ========================================================

    url_length = len(
        normalized
    )

    domain_length = len(
        hostname
    )

    letters = sum(

        character.isalpha()

        for character
        in normalized

    )

    digits = sum(

        character.isdigit()

        for character
        in normalized

    )

    special_chars = sum(

        not character.isalnum()

        for character
        in normalized

    )

    # ========================================================
    # URL COUNTS
    # ========================================================

    at_count = normalized.count(
        "@"
    )

    equals_count = normalized.count(
        "="
    )

    question_count = normalized.count(
        "?"
    )

    ampersand_count = normalized.count(
        "&"
    )

    other_special = sum(

        normalized.count(
            character
        )

        for character
        in [
            "-",
            "_",
            "%",
            "#"
        ]

    )

    # ========================================================
    # RATIOS
    # ========================================================

    letter_ratio = (

        letters / url_length

        if url_length

        else 0

    )

    digit_ratio = (

        digits / url_length

        if url_length

        else 0

    )

    special_ratio = (

        special_chars / url_length

        if url_length

        else 0

    )

    # ========================================================
    # IP
    # ========================================================

    domain_is_ip = is_ip(
        hostname
    )

    # ========================================================
    # HTTPS
    # ========================================================

    is_https = (

        parsed.scheme.lower()

        == "https"

    )

    # ========================================================
    # SUBDOMAINS
    # ========================================================

    subdomain_count = (

        len(

            [
                item

                for item
                in subdomain.split(".")

                if item
            ]

        )

        if subdomain

        else 0

    )

    # ========================================================
    # OBFUSCATION
    # ========================================================

    encoded_chars = re.findall(

        r"%[0-9a-fA-F]{2}",

        normalized

    )

    has_obfuscation = (

        len(encoded_chars) > 0

    )

    # ========================================================
    # SUSPICIOUS KEYWORDS
    # ========================================================

    suspicious_keywords = [

        keyword

        for keyword
        in SUSPICIOUS_KEYWORDS

        if keyword
        in lower_url

    ]

    # ========================================================
    # BRAND IMPERSONATION
    # ========================================================

    impersonated_brand = None

    if registered_domain:

        for brand, official in BRANDS.items():

            if brand in lower_url:

                if registered_domain != official:

                    impersonated_brand = brand

                break

    # ========================================================
    # ML FEATURES
    # ========================================================

    features = {

        "URLLength":
            url_length,

        "DomainLength":
            domain_length,

        "IsDomainIP":
            int(domain_is_ip),

        "TLDLength":
            len(suffix),

        "NoOfSubDomain":
            subdomain_count,

        "NoOfLettersInURL":
            letters,

        "LetterRatioInURL":
            letter_ratio,

        "NoOfDegitsInURL":
            digits,

        "DegitRatioInURL":
            digit_ratio,

        "NoOfEqualsInURL":
            equals_count,

        "NoOfQMarkInURL":
            question_count,

        "NoOfAmpersandInURL":
            ampersand_count,

        "NoOfOtherSpecialCharsInURL":
            other_special,

        "SpacialCharRatioInURL":
            special_ratio,

        "IsHTTPS":
            int(is_https),

        "NoOfObfuscatedChar":
            len(encoded_chars),

        "HasObfuscation":
            int(has_obfuscation)

    }

    # ========================================================
    # METADATA
    # ========================================================

    metadata = {

        "normalized_url":
            normalized,

        "scheme":
            parsed.scheme,

        "hostname":
            hostname,

        "registered_domain":
            registered_domain,

        "subdomain":
            subdomain,

        "tld":
            suffix,

        "path":
            path,

        "query":
            query,

        "is_https":
            is_https,

        "is_ip":
            domain_is_ip,

        "suspicious_keywords":
            suspicious_keywords,

        "impersonated_brand":
            impersonated_brand,

        "at_symbol":
            at_count,

        "equals":
            equals_count,

        "question_mark":
            question_count,

        "ampersand":
            ampersand_count,

        "special_characters":
            special_chars,

        "encoded_characters":
            len(encoded_chars)

    }

    return {

        "features":
            features,

        "metadata":
            metadata

    }