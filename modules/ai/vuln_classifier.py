
def classify_vulnerability(text):
    if "apache" in text.lower():
        return {"severity":"medium","note":"possible outdated apache"}
    return {"severity":"unknown"}
