import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3.2:1b"


def generate_ai_summary(
    domain,
    subdomains,
    ports,
    directories,
    technologies,
    ai_results
):
    prompt = f"""
You are a cybersecurity analyst.

Write a short realistic security summary based ONLY on this scan data.
Do not exaggerate.
Do not say confirmed vulnerability.
Do not invent CVEs.
Do not mention hacking.
Use simple professional language.

Target: {domain}

Scan Data:
- Subdomains found: {len(subdomains)}
- Open ports: {ports}
- Restricted/access paths: {len(directories)}
- Technologies: {technologies}
- Risk score: {ai_results.get("Risk Score", "N/A")}
- Severity: {ai_results.get("Severity", "N/A")}

Return only this format:

Summary:
one short paragraph

Key Points:
- point 1
- point 2
- point 3

Next Actions:
- action 1
- action 2
- action 3
"""

    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.2,
                    "num_predict": 160
                }
            },
            timeout=45
        )

        if response.status_code != 200:
            return "Ollama is not responding correctly."

        data = response.json()

        return data.get(
            "response",
            "No AI summary generated."
        )

    except requests.exceptions.ConnectionError:
        return "Ollama is not running. Start it with: ollama serve"

    except requests.exceptions.Timeout:
        return "Ollama response timed out. Use smaller model: llama3.2:1b"

    except Exception as error:
        return f"Ollama error: {error}"