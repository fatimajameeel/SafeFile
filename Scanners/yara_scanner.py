import yara
from pathlib import Path

# Global variable where we keep the compiled rules
_RULES = None


def _load_yara_rules():
    """
    Find and compile all YARA rule files from SafeFile/yara_rules.

    This function is called lazily (only when needed).
    """
    global _RULES

    if _RULES is not None:
        # Already loaded once; just reuse them
        return _RULES

    # BASE_DIR = .../SafeFile
    base_dir = Path(__file__).resolve().parent.parent
    rules_dir = base_dir / "yara_rules"

    if not rules_dir.exists():
        print(f"[YARA] Rules directory not found: {rules_dir}")
        _RULES = None
        return None

    # Find all *.yar and *.yara files
    yar_files = list(rules_dir.glob("*.yar")) + list(rules_dir.glob("*.yara"))

    if not yar_files:
        print(
            f"[YARA] No .yar files found in {rules_dir}, YARA will be disabled.")
        _RULES = None
        return None

    # Build a dict: { "filename_without_extension": "/full/path/to/file.yar", ... }
    filepaths = {f.stem: str(f) for f in yar_files}

    try:
        _RULES = yara.compile(filepaths=filepaths)
        print(f"[YARA] Loaded {len(filepaths)} rule file(s) from {rules_dir}")
    except Exception as e:
        print(f"[YARA] Failed to compile rules: {e}")
        _RULES = None

    return _RULES


def scan_file_with_yara(file_path: str) -> dict:
    """
    Scan a single file with all loaded YARA rules.

    Returns a dictionary like:
    {
        "enabled": bool,
        "error": Optional[str],
        "matches": [
            {
                "rule": str,
                "namespace": str,
                "tags": [str, ...],
                "meta": { ... }
            },
            ...
        ]
    }
    """
    rules = _load_yara_rules()

    # If we couldn't load rules, just say YARA is disabled
    if rules is None:
        return {
            "enabled": False,
            "error": None,
            "matches": []
        }
    # YARA ruleset is applied to each uploaded file
    try:
        matches = rules.match(filepath=file_path)
    except Exception as e:
        print(f"[YARA] Error while scanning {file_path}: {e}")
        return {
            "enabled": True,
            "error": str(e),
            "matches": []
        }

    # Convert matches to a JSON-friendly structure
    result_matches = []
    for m in matches:
        result_matches.append(
            {
                "rule": m.rule,               # rule name
                "namespace": m.namespace,     # the filename group
                "tags": list(m.tags),         # any tags defined in the rule
                # meta fields like description, author, score, ...
                "meta": dict(m.meta),
            }
        )

    return {
        "enabled": True,
        "error": None,
        "matches": result_matches
    }
