# DB_helpers/top_yara_rules.py

from collections import Counter
import json
from typing import Dict, List
from db import get_db


def get_top_yara_rules(limit: int = 5) -> Dict[str, List]:
    """
    Read the yara_hits column from the file table count how often
    each YARA rule appears and return the top N rules.

    Returns a dict like:
    {
      "labels": ["TEST_Emotet_Demo", "GEN_PowerShell", ...],
      "counts": [12, 7, ...]
    }
    """

    db = get_db()
    cursor = db.cursor()

    # 1) Get all yara_hits values that are not NULL / empty
    cursor.execute(
        """
        SELECT yara_hits
        FROM file
        WHERE yara_hits IS NOT NULL
          AND yara_hits <> ''
        """
    )
    rows = cursor.fetchall()

    # 2) Counter to accumulate rule frequencies
    rule_counter: Counter = Counter()

    for row in rows:
        raw_hits = row["yara_hits"]

        if not raw_hits:
            continue

        try:
            # yara_hits is stored as JSON string, e.g. '["Rule1", "Rule2"]'
            hits = json.loads(raw_hits)
        except json.JSONDecodeError:
            # If someone stored bad JSON by mistake, skip this row
            continue

        # We expect hits to be a list
        if not isinstance(hits, list):
            continue

        # Count each rule name
        for rule_name in hits:
            if not rule_name:
                continue
            rule_counter[str(rule_name)] += 1

    # 3) If there were no matches at all, return empty data
    if not rule_counter:
        return {"labels": [], "counts": []}

    # 4) Get the top N most common rules
    top_rules = rule_counter.most_common(limit)

    labels = [name for (name, count) in top_rules]
    counts = [count for (name, count) in top_rules]

    return {
        "labels": labels,
        "counts": counts,
    }
