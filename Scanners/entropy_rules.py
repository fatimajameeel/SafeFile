def interpret_pe_entropy(report: dict) -> dict:
    """
    Takes the output from analyze_pe_entropy() and adds interpretation flags.

    Returns:
    {
        "flags": [...],
        "risk_score": 0-100,
        "notes": [...]
    }
    """

    flags = []
    notes = []
    risk_score = 0

    # 1) If it's not a PE file
    if not report.get("is_pe"):
        return {
            "flags": ["NOT_A_PE_FILE"],
            "risk_score": 0,
            "notes": ["Entropy interpretation skipped: file is not PE"]
        }

    # 2) Check overall entropy
    overall = report.get("overall_entropy", None)
    if overall is not None:
        if overall > 7.3:
            flags.append("VERY_HIGH_OVERALL_ENTROPY")
            notes.append(f"Overall entropy {overall:.2f} is unusually high.")
            risk_score += 30
        elif overall > 6.8:
            flags.append("HIGH_OVERALL_ENTROPY")
            risk_score += 15

    # 3) Check section entropy
    for sec in report.get("sections", []):
        name = sec["name"]
        ent = sec["entropy"]

        if ent is None:
            continue

        # Very high entropy -> packed or encrypted
        if ent > 7.2:
            flags.append(f"HIGH_ENTROPY_SECTION:{name}")
            notes.append(f"Section {name} has high entropy ({ent:.2f}).")
            risk_score += 20

        # Suspicious section names (common in malware)
        suspicious_names = [".asdf", ".xyz", ".shit", ".evil", ".packed"]
        if name.lower() in suspicious_names:
            flags.append(f"SUSPICIOUS_SECTION_NAME:{name}")
            notes.append(f"Section {name} has a suspicious name.")
            risk_score += 10

        # UPX sections
        if "UPX" in name.upper():
            flags.append("UPX_PACKED")
            notes.append("File contains UPX sections; likely packed.")
            risk_score += 25

    # 4) Risk normalization
    risk_score = min(risk_score, 100)

    return {
        "flags": list(set(flags)),  # deduplicate
        "risk_score": risk_score,
        "notes": notes
    }
