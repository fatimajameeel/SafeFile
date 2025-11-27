import math


def shannon_entropy(data: bytes) -> float:
    """
    Calculate Shannon etnropy (in bits per byte) for a bytes object

    - Input:  data -> raw bytes (b"...")
    - Output: entropy value between 0.0 and 8.0
    """
    # If there is no data entropy is 0 by definition
    if not data:
        return 0.0

    # 1) Creating a list to count how many times each byte value appears (0–255)
    freq = [0] * 256  # index = byte value, value = count

    # 2) Count the occurrences of each byte
    for b in data:
        freq[b] += 1

    # 3) Convert counts to probabilities and apply Shannon formula
    entropy = 0.0
    length = len(data)

    for count in freq:
        if count == 0:
            # If a byte value never appears it doesn't contribute to entropy
            continue

        p = count / length  # probability of this byte value
        entropy -= p * math.log2(p)

    return entropy
