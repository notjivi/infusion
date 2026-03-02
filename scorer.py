import json

def calculate_risk_score(trivy_json: str) -> dict:
    try:
        data = json.loads(trivy_json) if isinstance(trivy_json, str) else trivy_json
    except json.JSONDecodeError as e:
        return {
            "score": 0,
            "breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "risk_level": "UNKNOWN",
            "error": f"Invalid JSON: {str(e)}"
        }

    critical = high = medium = low = 0

    for result in data.get("Results", []):
        # Handle both Vulnerabilities and Misconfigurations
        items = result.get("Vulnerabilities", []) + result.get("Misconfigurations", [])
        
        for item in items:
            severity = item.get("Severity", "").upper()
            if severity == "CRITICAL":
                critical += 1
            elif severity == "HIGH":
                high += 1
            elif severity == "MEDIUM":
                medium += 1
            elif severity == "LOW":
                low += 1

    score = (critical * 10) + (high * 5) + (medium * 2) + (low * 1)

    return {
        "score": score,
        "breakdown": {"critical": critical, "high": high, "medium": medium, "low": low},
        "risk_level": "CRITICAL" if score > 50 else "HIGH" if score > 20 else "MEDIUM" if score > 10 else "LOW"
    }