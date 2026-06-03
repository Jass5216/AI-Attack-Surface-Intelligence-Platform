import os
import json
from datetime import datetime

from modules.recon.subdomain_scan import scan_subdomains
from modules.recon.port_scan import scan_ports
from modules.recon.dir_scan import scan_directories
from modules.osint.tech_detect import detect_technology
from modules.ai.ensemble_model import predict_ai_risk
from modules.ai.llm_analyzer import generate_ai_summary

BASE_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        ".."
    )
)

DATA_DIR = os.path.join(
    BASE_DIR,
    "data"
)

RESULT_FILE = os.path.join(
    DATA_DIR,
    "scan_results.json"
)

os.makedirs(
    DATA_DIR,
    exist_ok=True
)


def save_results(data):
    with open(
        RESULT_FILE,
        "w"
    ) as file:
        json.dump(
            data,
            file,
            indent=4
        )


def load_old_results():
    if not os.path.exists(
        RESULT_FILE
    ):
        return {
            "subdomains": [],
            "ports": [],
            "directories": [],
            "technologies": []
        }

    try:
        with open(
            RESULT_FILE,
            "r"
        ) as file:
            return json.load(file)

    except Exception:
        return {
            "subdomains": [],
            "ports": [],
            "directories": [],
            "technologies": []
        }


def generate_alerts(
    old_data,
    new_data
):
    alerts = []

    old_subdomains = set(
        old_data.get(
            "subdomains",
            []
        )
    )

    new_subdomains = set(
        new_data.get(
            "subdomains",
            []
        )
    )

    for subdomain in new_subdomains - old_subdomains:
        alerts.append(
            f"New subdomain detected: {subdomain}"
        )

    old_ports = set(
        old_data.get(
            "ports",
            []
        )
    )

    new_ports = set(
        new_data.get(
            "ports",
            []
        )
    )

    for port in new_ports - old_ports:
        alerts.append(
            f"New open port detected: {port}"
        )

    severity = new_data.get(
        "ai_results",
        {}
    ).get(
        "Severity",
        ""
    )

    if severity in [
        "HIGH",
        "CRITICAL"
    ]:
        alerts.append(
            f"High risk threat level detected: {severity}"
        )

    return alerts


def run_realtime_scan(
    domain,
    use_ollama=False
):
    old_data = load_old_results()

    subdomains = scan_subdomains(
        domain
    )

    ports = scan_ports(
        domain
    )

    directories = scan_directories(
        domain
    )

    technologies = detect_technology(
        domain
    )

    ai_results = predict_ai_risk(
        subdomains,
        ports,
        technologies,
        directories
    )

    if use_ollama:
        llm_summary = generate_ai_summary(
            domain,
            subdomains,
            ports,
            directories,
            technologies,
            ai_results
        )
    else:
        llm_summary = ""

    new_data = {
        "domain": domain,
        "subdomains": subdomains,
        "ports": ports,
        "directories": directories,
        "technologies": technologies,
        "ai_results": ai_results,
        "llm_summary": llm_summary,
        "alerts": [],
        "last_updated": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    }

    new_data["alerts"] = generate_alerts(
        old_data,
        new_data
    )

    save_results(
        new_data
    )

    return new_data