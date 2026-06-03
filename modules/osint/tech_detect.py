import requests
import builtwith

# =====================================================
# TECHNOLOGY DETECTION
# =====================================================

def detect_technology(domain):

    technologies = []

    try:

        url = f"https://{domain}"

        # =================================================
        # BUILTWITH DETECTION
        # =================================================

        result = builtwith.parse(
            url
        )

        for category in result:

            tech_list = result[category]

            for tech in tech_list:

                if tech not in technologies:

                    technologies.append(
                        tech
                    )

        # =================================================
        # HEADER ANALYSIS
        # =================================================

        response = requests.get(
            url,
            timeout=10,
            headers={
                "User-Agent":
                "Mozilla/5.0"
            }
        )

        headers = response.headers

        server = headers.get(
            "Server"
        )

        powered_by = headers.get(
            "X-Powered-By"
        )

        if server:

            technologies.append(
                f"Server: {server}"
            )

        if powered_by:

            technologies.append(
                f"Powered-By: {powered_by}"
            )

        # =================================================
        # HTML CONTENT CHECKS
        # =================================================

        html = response.text.lower()

        checks = {

            "WordPress":
            "wp-content",

            "React":
            "react",

            "Angular":
            "angular",

            "Vue":
            "vue",

            "Bootstrap":
            "bootstrap",

            "jQuery":
            "jquery",

            "Cloudflare":
            "cloudflare",

            "PHP":
            ".php",

            "Node.js":
            "node.js"
        }

        for tech, keyword in checks.items():

            if keyword in html:

                if tech not in technologies:

                    technologies.append(
                        tech
                    )

    except Exception as error:

        technologies.append(
            f"Detection Error: {error}"
        )

    return list(
        set(technologies)
    )