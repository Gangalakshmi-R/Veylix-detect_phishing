import requests
from datetime import datetime, timezone


IANA_RDAP_BOOTSTRAP = (
    "https://data.iana.org/rdap/dns.json"
)


def find_rdap_server(domain):
    """
    Find the authoritative RDAP server for the domain's TLD.
    """

    if not domain:
        return None

    try:

        response = requests.get(
            IANA_RDAP_BOOTSTRAP,
            timeout=10
        )

        response.raise_for_status()

        data = response.json()

        # Remove trailing dot if present
        domain = domain.lower().rstrip(".")

        # Extract TLD
        tld = domain.split(".")[-1]

        for service in data.get(
            "services",
            []
        ):

            if len(service) != 2:
                continue

            tlds = service[0]
            servers = service[1]

            for registered_tld in tlds:

                if (
                    registered_tld.lower()
                    == tld
                ):

                    if servers:

                        return servers[0].rstrip(
                            "/"
                        )

    except Exception as exc:

        print(
            f"RDAP bootstrap error: {exc}"
        )

    return None


def calculate_domain_age(
    registration_date
):
    """
    Calculate domain age in days from
    an RDAP registration timestamp.
    """

    if not registration_date:
        return None

    try:

        registered = datetime.fromisoformat(
            registration_date.replace(
                "Z",
                "+00:00"
            )
        )

        now = datetime.now(
            timezone.utc
        )

        return max(
            0,
            (now - registered).days
        )

    except Exception:

        return None


def analyze_domain(domain):
    """
    Perform RDAP-based domain investigation.

    RDAP failure or unavailable registration
    information is treated as unavailable
    intelligence, NOT as phishing evidence.
    """

    result = {

        "domain":
            domain,

        "rdap_available":
            False,

        "registration_date":
            None,

        "expiration_date":
            None,

        "domain_age_days":
            None,

        "registrar":
            None,

        "status":
            [],

        "rdap_server":
            None
    }

    if not domain:
        return result

    # ========================================================
    # FIND RDAP SERVER
    # ========================================================

    server = find_rdap_server(
        domain
    )

    if not server:

        return result

    result[
        "rdap_server"
    ] = server

    # ========================================================
    # QUERY RDAP
    # ========================================================

    try:

        domain_clean = (
            domain
            .lower()
            .rstrip(".")
        )

        url = (
            f"{server}/domain/"
            f"{domain_clean}"
        )

        response = requests.get(

            url,

            timeout=10,

            headers={
                "Accept":
                    "application/rdap+json"
            }
        )

        # 404 means the domain is not
        # available in this registry.
        if response.status_code == 404:

            print(
                f"RDAP domain not found: "
                f"{domain_clean}"
            )

            return result

        if response.status_code != 200:

            print(
                f"RDAP request failed: "
                f"{response.status_code}"
            )

            return result

        data = response.json()

        result[
            "rdap_available"
        ] = True

        # ====================================================
        # EVENTS
        # ====================================================

        for event in data.get(
            "events",
            []
        ):

            action = event.get(
                "eventAction"
            )

            event_date = event.get(
                "eventDate"
            )

            if action == "registration":

                result[
                    "registration_date"
                ] = event_date

            elif action == "expiration":

                result[
                    "expiration_date"
                ] = event_date

        # ====================================================
        # DOMAIN AGE
        # ====================================================

        result[
            "domain_age_days"
        ] = calculate_domain_age(

            result[
                "registration_date"
            ]
        )

        # ====================================================
        # STATUS
        # ====================================================

        result[
            "status"
        ] = data.get(
            "status",
            []
        )

        # ====================================================
        # REGISTRAR
        # ====================================================

        for entity in data.get(
            "entities",
            []
        ):

            roles = entity.get(
                "roles",
                []
            )

            if "registrar" not in roles:

                continue

            vcard = entity.get(
                "vcardArray"
            )

            if not vcard:

                continue

            if len(vcard) < 2:

                continue

            for item in vcard[1]:

                if (
                    len(item) >= 4
                    and item[0] == "fn"
                ):

                    result[
                        "registrar"
                    ] = item[3]

                    break

            if result[
                "registrar"
            ]:

                break

    except requests.RequestException as exc:

        print(
            f"RDAP connection error: "
            f"{exc}"
        )

    except Exception as exc:

        print(
            f"RDAP domain lookup error: "
            f"{exc}"
        )

    return result