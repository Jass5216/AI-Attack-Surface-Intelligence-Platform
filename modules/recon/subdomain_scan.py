import socket
import requests
from concurrent.futures import ThreadPoolExecutor

requests.packages.urllib3.disable_warnings()

# =====================================================
# DNS CHECK
# =====================================================

def is_alive(subdomain):

    try:
        socket.gethostbyname(subdomain)
        return True

    except:
        return False


# =====================================================
# CRT.SH CERTIFICATE TRANSPARENCY SEARCH
# =====================================================

def get_crtsh_subdomains(domain):

    found = []

    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"

        response = requests.get(
            url,
            timeout=15,
            headers={
                "User-Agent": "Mozilla/5.0"
            }
        )

        if response.status_code == 200:

            data = response.json()

            for item in data:

                name_value = item.get(
                    "name_value",
                    ""
                )

                names = name_value.split(
                    "\n"
                )

                for name in names:

                    name = name.strip().lower()

                    name = name.replace(
                        "*.",
                        ""
                    )

                    if name.endswith(
                        domain
                    ):

                        if name not in found:

                            found.append(
                                name
                            )

    except:
        pass

    return found


# =====================================================
# WORDLIST DNS BRUTEFORCE
# =====================================================

def get_wordlist_subdomains(domain):

    wordlist = [
        "www",
        "api",
        "mail",
        "vpn",
        "dev",
        "admin",
        "test",
        "portal",
        "dashboard",
        "blog",
        "support",
        "cdn",
        "m",
        "shop",
        "app",
        "secure",
        "login",
        "beta",
        "staging",
        "static",
        "assets",
        "images",
        "media",
        "seller",
        "partner",
        "business",
        "careers",
        "help",
        "news",
        "mobile"
    ]

    discovered = []

    def check_subdomain(sub):

        subdomain = f"{sub}.{domain}"

        if is_alive(
            subdomain
        ):

            return subdomain

        return None

    with ThreadPoolExecutor(
        max_workers=20
    ) as executor:

        results = executor.map(
            check_subdomain,
            wordlist
        )

    for result in results:

        if result:

            discovered.append(
                result
            )

    return discovered


# =====================================================
# FINAL SUBDOMAIN SCANNER
# =====================================================

def scan_subdomains(domain):

    all_subdomains = []

    crtsh_results = get_crtsh_subdomains(
        domain
    )

    wordlist_results = get_wordlist_subdomains(
        domain
    )

    combined = (
        crtsh_results
        +
        wordlist_results
    )

    for subdomain in combined:

        subdomain = subdomain.strip().lower()

        if subdomain not in all_subdomains:

            all_subdomains.append(
                subdomain
            )

    return all_subdomains[:100]