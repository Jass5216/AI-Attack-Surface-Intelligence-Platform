import requests

from concurrent.futures import (
    ThreadPoolExecutor
)

# =====================================================
# DISABLE SSL WARNINGS
# =====================================================

requests.packages.urllib3.disable_warnings()

# =====================================================
# DIRECTORY SCANNER
# =====================================================

def scan_directories(domain):

    directories = [

        "admin",
        "dashboard",
        "api",
        "uploads",
        "login",
        "portal",
        "test",
        "dev",
        "backup",
        "config",
        "private",
        "db",
        "server-status",
        "panel",
        "user",
        "users",
        "administrator",
        "console",
        "manage",
        "cpanel"
    ]

    found = []

    headers = {

        "User-Agent":
        (
            "Mozilla/5.0 "
            "(Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 "
            "(KHTML, like Gecko) "
            "Chrome/120.0.0.0 "
            "Safari/537.36"
        )
    }

    # =================================================
    # SINGLE DIRECTORY CHECK
    # =================================================

    def check_directory(directory):

        url = (
            f"https://{domain}/{directory}"
        )

        try:

            response = requests.get(

                url,

                headers=headers,

                timeout=5,

                verify=False,

                allow_redirects=True
            )

            if response.status_code in [

                200,
                301,
                302,
                403
            ]:

                return {

                    "url": url,

                    "status":
                    response.status_code
                }

        except:

            return None

    # =================================================
    # MULTITHREADED SCANNING
    # =================================================

    with ThreadPoolExecutor(
        max_workers=10
    ) as executor:

        results = executor.map(

            check_directory,
            directories
        )

    # =================================================
    # FILTER RESULTS
    # =================================================

    for result in results:

        if result:

            found.append(result)

    # =================================================
    # REMOVE DUPLICATES
    # =================================================

    unique_results = []

    seen = set()

    for item in found:

        if item["url"] not in seen:

            unique_results.append(item)

            seen.add(item["url"])

    return unique_results