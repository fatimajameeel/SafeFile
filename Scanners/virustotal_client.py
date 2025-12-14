import hashlib
from pathlib import Path
from typing import Optional, Dict, Any
import requests

VT_FILE_URL = "https://www.virustotal.com/api/v3/files/{}"


"""
    Calculate the SHA-256 hash of a file on disk.

    Parameters
    ----------
    path : str
        Full path to the file.

    Returns
    -------
    str
        Hex-encoded SHA-256 digest, e.g. 'a9f4...'.
"""


def file_sha256(path: str) -> str:

    # 1) convert the input string to a path object
    file_path = Path(path)

    # 2) Create the SHA-256 hasher
    hasher = hashlib.sha256()

    # 3) Open the file in binary mode ('rb') and read it in chunks
    with file_path.open("rb") as f:

        # 4) iter with a lambda creates a loop that reads 8192 bytes until b (the end)
        for chunk in iter(lambda: f.read(8192), b""):
            # 5) Feed the chunk into the hasher object
            hasher.update(chunk)
    # 6) Return the hex string in lowercase
    return hasher.hexdigest()


def vt_lookup_file(sha256: str, api_key: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Look up a file hash on VirusTotal (v3 API).

    Returns a simplified dict with detection stats and verdict.
    """
    headers = {
        "x-apikey": api_key
    }
    url = VT_FILE_URL.format(sha256)

    resp = requests.get(url, headers=headers, timeout=timeout)

    # 404 = VT has never seen this hash
    if resp.status_code == 404:
        return {
            "found": False,
            "error": None,
        }

    # Common error cases: bad key, rate limit, etc.
    if resp.status_code == 401:
        return {
            "found": False,
            "error": "Unauthorized (check API key)",
        }

    if resp.status_code == 429:
        return {
            "found": False,
            "error": "Rate limit exceeded",
        }

    if resp.status_code != 200:
        return {
            "found": False,
            "error": f"HTTP {resp.status_code}",
        }

    data = resp.json()
    attrs = data.get("data", {}).get("attributes", {})

    stats = attrs.get("last_analysis_stats", {}) or {}
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)
    timeout_count = int(stats.get("timeout", 0) or 0)

    total = malicious + suspicious + harmless + undetected + timeout_count

    threat_cat = attrs.get("popular_threat_classification") or attrs.get(
        "popular_threat_category") or {}
    threat_label = None
    if isinstance(threat_cat, dict):
        threat_label = (
            threat_cat.get("suggested_threat_label")
            or threat_cat.get("label")
            or threat_cat.get("value")
            or threat_cat.get("type")
        )

    # Type tag as fallback
    type_tag = attrs.get("type_tag")
    if not threat_label and type_tag:
        threat_label = type_tag

    vt_tags = attrs.get("tags") or []

    # Simple verdict logic
    if malicious > 0 or suspicious > 0:
        verdict = "malicious"
    elif harmless > 0 and malicious == 0 and suspicious == 0:
        verdict = "clean"
    else:
        verdict = "unknown"

    permalink = f"https://www.virustotal.com/gui/file/{sha256}"

    return {
        "found": True,
        "error": None,
        "harmless": harmless,
        "malicious": malicious,
        "suspicious": suspicious,
        "undetected": undetected,
        "timeout": timeout_count,
        "total_engines": total,
        "verdict": verdict,
        "permalink": permalink,
        "threat_label": threat_label,
        "tags": vt_tags,

    }


def get_virustotal_report(path: str, api_key: Optional[str]) -> Dict[str, Any]:
    """
    High-level helper:
    - If no API key: mark VT as disabled.
    - If key exists: hash the file, query VT, and attach sha256.
    - Always returns a stable dict so templates don't break.
    """
    if not api_key:
        return {
            "enabled": False,
            "found": False,
            "error": "API key not configured",
        }

    try:
        sha256 = file_sha256(path)
        vt_data = vt_lookup_file(sha256, api_key)
        vt_data["enabled"] = True
        vt_data["sha256"] = sha256
        return vt_data
    except Exception as e:
        # Any network/JSON error is caught here so the rest of the analysis still works.
        return {
            "enabled": True,
            "found": False,
            "error": str(e),
        }
