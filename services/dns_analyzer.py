import socket


def resolve_a_records(domain):
    """
    Resolve a domain to IPv4 addresses.
    Uses Python's built-in socket library.
    """

    if not domain:
        return []

    try:
        results = socket.getaddrinfo(
            domain,
            None,
            socket.AF_INET
        )

        ips = []

        for result in results:

            ip = result[4][0]

            if ip not in ips:
                ips.append(ip)

        return ips

    except Exception:
        return []


def reverse_dns(ip):
    """
    Perform reverse DNS lookup for an IP address.
    """

    if not ip:
        return None

    try:

        return socket.gethostbyaddr(
            ip
        )[0]

    except Exception:

        return None


def analyze_dns(domain):
    """
    Complete DNS investigation.

    Currently uses Python's built-in socket
    functionality, so dnspython is not required.
    """

    if not domain:

        return {
            "domain": None,
            "a_records": [],
            "mx_records": [],
            "ns_records": [],
            "reverse_dns": [],
            "resolved": False
        }

    # ---------------------------------------------
    # A records
    # ---------------------------------------------

    a_records = resolve_a_records(
        domain
    )

    # ---------------------------------------------
    # Reverse DNS
    # ---------------------------------------------

    reverse_records = []

    for ip in a_records:

        hostname = reverse_dns(
            ip
        )

        if hostname:

            reverse_records.append(
                hostname
            )

    # ---------------------------------------------
    # Result
    # ---------------------------------------------

    return {

        "domain":
            domain,

        "a_records":
            a_records,

        # These require dedicated DNS querying.
        # We will add them later.
        "mx_records":
            [],

        "ns_records":
            [],

        "reverse_dns":
            reverse_records,

        "resolved":
            len(a_records) > 0
    }