import os
import joblib
import pandas as pd

# =====================================================
# BASE DIRECTORY
# =====================================================

BASE_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        ".."
    )
)

# =====================================================
# MODEL PATHS
# =====================================================

RF_MODEL_PATH = os.path.join(
    BASE_DIR,
    "models",
    "random_forest.pkl"
)

XGB_MODEL_PATH = os.path.join(
    BASE_DIR,
    "models",
    "xgboost.pkl"
)

# =====================================================
# LOAD MODELS
# =====================================================

rf_model = joblib.load(
    RF_MODEL_PATH
)

xgb_model = joblib.load(
    XGB_MODEL_PATH
)

# =====================================================
# AI RISK PREDICTION
# =====================================================

def predict_ai_risk(
    subdomains,
    ports,
    technologies,
    directories
):

    features = pd.DataFrame(
        [[
            len(subdomains),
            len(ports),
            len(technologies),
            len(directories)
        ]],
        columns=[
            "subdomains",
            "ports",
            "technologies",
            "directories"
        ]
    )

    rf_score = rf_model.predict_proba(
        features
    )[0][1]

    xgb_score = xgb_model.predict_proba(
        features
    )[0][1]

    final_score = (
        rf_score +
        xgb_score
    ) / 2

    risk_score = int(
        final_score * 100
    )

    if risk_score >= 75:

        severity = "CRITICAL"

    elif risk_score >= 50:

        severity = "HIGH"

    else:

        severity = "LOW"

    return {

        "Severity": severity,

        "Confidence": f"{risk_score}%",

        "Risk Score": risk_score,

        "Findings": [

            f"Detected {len(subdomains)} real DNS-resolvable subdomains",

            f"Detected {len(ports)} open ports",

            f"Detected {len(directories)} restricted or accessible paths",

            f"Detected {len(technologies)} technologies"
        ],

        "Recommendations": [

            "Restrict unnecessary public services",

            "Review restricted paths and verify they do not expose sensitive information",

            "Patch outdated technologies and server components",

            "Enable Web Application Firewall",

            "Continuously monitor attack surface"
        ]
    }