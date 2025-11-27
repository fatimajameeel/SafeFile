from .entropy import shannon_entropy

"""
    Calculates the entropy of an entire file.
    
    - Input: path to a file on disk
    - Output: Shannon entropy (0.0-8.0)
"""


def file_entropy(file_path: str) -> float:

    try:
        with open(file_path, "rb") as f:
            data = f.read()

        return shannon_entropy(data)

    except Exception as e:
        print(f"[Entropy] Failed to read file{e}")
        return 0.0
