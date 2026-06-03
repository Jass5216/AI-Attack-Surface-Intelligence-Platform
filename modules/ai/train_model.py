import os
import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier

from xgboost import XGBClassifier

# ====================================================
# CREATE MODELS DIRECTORY
# ====================================================

BASE_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        ".."
    )
)

MODELS_DIR = os.path.join(
    BASE_DIR,
    "models"
)

os.makedirs(
    MODELS_DIR,
    exist_ok=True
)

# ====================================================
# SAMPLE TRAINING DATA
# ====================================================

data = {

    "subdomains": [
        5,
        10,
        50,
        100,
        150,
        250,
        300,
        400
    ],

    "ports": [
        1,
        2,
        5,
        8,
        10,
        15,
        20,
        25
    ],

    "technologies": [
        1,
        2,
        4,
        5,
        6,
        8,
        10,
        12
    ],

    "directories": [
        0,
        1,
        2,
        3,
        5,
        7,
        10,
        15
    ],

    "risk": [
        0,
        0,
        0,
        1,
        1,
        1,
        1,
        1
    ]
}

dataset = pd.DataFrame(data)

# ====================================================
# FEATURES
# ====================================================

X = dataset[[
    "subdomains",
    "ports",
    "technologies",
    "directories"
]]

y = dataset["risk"]

# ====================================================
# RANDOM FOREST MODEL
# ====================================================

rf_model = RandomForestClassifier()

rf_model.fit(X, y)

# ====================================================
# XGBOOST MODEL
# ====================================================

xgb_model = XGBClassifier()

xgb_model.fit(X, y)

# ====================================================
# SAVE MODELS
# ====================================================

rf_path = os.path.join(
    MODELS_DIR,
    "random_forest.pkl"
)

xgb_path = os.path.join(
    MODELS_DIR,
    "xgboost.pkl"
)

joblib.dump(
    rf_model,
    rf_path
)

joblib.dump(
    xgb_model,
    xgb_path
)

print("AI Models Trained Successfully")
print(f"Random Forest Saved: {rf_path}")
print(f"XGBoost Saved: {xgb_path}")