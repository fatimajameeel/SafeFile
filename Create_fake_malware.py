import os
from pathlib import Path

OUT_DIR = Path("test_samples")
OUT_DIR.mkdir(exist_ok=True)


def make_high_entropy_sample(filename: str, marker: str, banner: str, size_bytes: int) -> Path:
    """
    Create a fake 'malware-ish' sample:
      - Text header with explanation + marker (for YARA)
      - Large block of random bytes (high entropy)
    """
    header = (
        "SAFEFILE DEMO SAMPLE\n"
        f"{banner}\n"
        f"MARKER: {marker}\n"
        "This file is generated for testing YARA + entropy only. "
        "It does NOT contain real malware.\n\n"
    ).encode("utf-8")

    payload = os.urandom(size_bytes)

    path = OUT_DIR / filename
    with open(path, "wb") as f:
        f.write(header)
        f.write(payload)

    print(f"Created {path} ({path.stat().st_size} bytes)")
    return path


def main():
    # 1) Ransomware – critical, high entropy → very likely MALICIOUS
    make_high_entropy_sample(
        filename="demo_ransomware_critical.bin",
        marker="SAFEFILE_DEMO_RANSOMWARE_CRITICAL",
        banner="[DEMO] Ransomware high-entropy sample (critical severity)",
        size_bytes=120_000,
    )

    # 2) Trojan – high severity → likely MALICIOUS
    make_high_entropy_sample(
        filename="demo_trojan_high.bin",
        marker="SAFEFILE_DEMO_TROJAN_HIGH",
        banner="[DEMO] Trojan horse banking sample (high severity)",
        size_bytes=90_000,
    )

    # 3) Worm – medium severity → often SUSPICIOUS
    make_high_entropy_sample(
        filename="demo_worm_medium.bin",
        marker="SAFEFILE_DEMO_WORM_MEDIUM",
        banner="[DEMO] Worm-like sample (medium severity)",
        size_bytes=80_000,
    )

    # 4) Virus – medium severity → often SUSPICIOUS
    make_high_entropy_sample(
        filename="demo_virus_medium.bin",
        marker="SAFEFILE_DEMO_VIRUS_MEDIUM",
        banner="[DEMO] File-virus style sample (medium severity)",
        size_bytes=80_000,
    )

    # 5) Backdoor – high severity → likely MALICIOUS
    make_high_entropy_sample(
        filename="demo_backdoor_high.bin",
        marker="SAFEFILE_DEMO_BACKDOOR_HIGH",
        banner="[DEMO] Backdoor / RAT-style sample (high severity)",
        size_bytes=90_000,
    )


if __name__ == "__main__":
    main()
