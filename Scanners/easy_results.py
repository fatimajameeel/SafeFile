def format_verdict(verdict: str) -> dict:
    # Convert whatever we got into lowercase text (safer)
    verdict = (verdict or "").lower()

    # If scanner says benign → user sees Safe + green icon + friendly message
    if verdict == "benign":
        return {
            "label": "Safe",
            "icon": "img/icons/checked.png",
            "css": "verdict-safe",
            "message": "No threats detected. This file is safe to use."
        }

    # If suspicious → show warning style
    if verdict == "suspicious":
        return {
            "label": "Suspicious",
            "icon": "img/icons/warning.png",
            "css": "verdict-warning",
            "message": "Something unusual was found. Use caution before opening."
        }

    # If malicious → show danger style
    if verdict == "malicious":
        return {
            "label": "Malicious",
            "icon": "img/icons/cross.png",
            "css": "verdict-danger",
            "message": "This file is harmful. Do not open it."
        }

    # If unknown or missing → fallback
    return {
        "label": "Unknown",
        "icon": "img/warning.png",
        "css": "verdict-unknown",
        "message": "We could not fully analyze this file."
    }
