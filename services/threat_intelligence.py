import os
import requests


PHISHTANK_ENDPOINT = (
    "https://checkurl.phishtank.com/checkurl/"
)


def check_phishtank(url):

    result = {

        "checked":
            False,

        "listed":
            False,

        "verified":
            False,

        "online":
            False,

        "target":
            None,

        "message":
            "Not checked."

    }

    if not url:

        result[
            "message"
        ] = "No URL supplied."

        return result

    try:

        payload = {

            "url":
                url,

            "format":
                "json"

        }

        app_key = os.getenv(
            "PHISHTANK_APP_KEY",
            ""
        )

        if app_key:

            payload[
                "app_key"
            ] = app_key

        response = requests.post(

            PHISHTANK_ENDPOINT,

            data=payload,

            headers={

                "User-Agent":
                    "PhishIntel/1.0"

            },

            timeout=10

        )

        # ----------------------------------------------------
        # IMPORTANT:
        # A failed lookup is NOT the same as "not listed".
        # ----------------------------------------------------

        if response.status_code != 200:

            result[
                "message"
            ] = (

                "Threat intelligence lookup "
                "unavailable: HTTP "

                + str(
                    response.status_code
                )

            )

            return result

        data = response.json()

        result[
            "checked"
        ] = True

        results = data.get(
            "results"
        )

        if not results:

            result[
                "message"
            ] = (
                "No PhishTank result."
            )

            return result

        result[
            "listed"
        ] = bool(
            results.get(
                "in_database",
                False
            )
        )

        result[
            "verified"
        ] = bool(
            results.get(
                "verified",
                False
            )
        )

        result[
            "online"
        ] = bool(
            results.get(
                "online",
                False
            )
        )

        result[
            "target"
        ] = results.get(
            "target"
        )

        if result["verified"]:

            result[
                "message"
            ] = (
                "Verified phishing URL "
                "found in PhishTank."
            )

        elif result["listed"]:

            result[
                "message"
            ] = (
                "URL is present in "
                "PhishTank."
            )

        else:

            result[
                "message"
            ] = (
                "URL was not found as "
                "a known phishing URL."
            )

    except Exception as exc:

        result[
            "message"
        ] = (
            "Threat intelligence lookup "
            "failed: "
            + str(exc)
        )

    return result