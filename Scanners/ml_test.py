from pathlib import Path
from .static_analysis import analyze_file

SEARCH_DIR = Path(r"C:\Windows\System32")


def main():
    vt_api_key = None
    count_scanned = 0
    found = []

    for exe_path in SEARCH_DIR.glob("*.exe"):
        try:
            count_scanned += 1
            print(f"[{count_scanned}] Scanning {exe_path}")

            result = analyze_file(str(exe_path), vt_api_key=vt_api_key)
            ml = result.get("ml")

            if ml and ml.get("ml_verdict") == "malware":
                score = ml.get("ml_score")
                print(f"  >>> ML flagged as malware! score={score:.3f}")
                found.append((exe_path, score))

            if len(found) >= 3:
                break

        except Exception as e:
            print(f"  !! Error scanning {exe_path}: {e}")

    print("\nSummary of files flagged as malware by ML:")
    for path, score in found:
        print(f" - {path} (score={score:.3f})")


if __name__ == "__main__":
    main()
