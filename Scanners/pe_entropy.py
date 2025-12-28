import os
import pefile

from .entropy import shannon_entropy


def analyze_pe_entropy(file_path: str) -> dict:
    """
    Analyze entropy for a PE file (EXE/DLL).

    Returns a dictionary like:
    {
        "is_pe": True/False,
        "overall_entropy": float or None,
        "sections": [
            {
                "name": ".text",
                "raw_size": 12345,
                "virtual_address": 4096,
                "entropy": 5.3
            },
            ...
        ],
        "errors": [ "any error messages" ]
    }
    """

    result = {
        "is_pe": False,
        "overall_entropy": None,
        "sections": [],
        "errors": [],
        "file_path": file_path,
        "file_name": os.path.basename(file_path),
    }

    pe = None

    # 1) Try to parse the file as a PE
    try:
        pe = pefile.PE(file_path)
        result["is_pe"] = True
    except pefile.PEFormatError as e:
        # Not a PE file
        result["errors"].append(f"Not a PE file: {e}")
        return result

    except Exception as e:
        # Some other unexpected problem
        result["errors"].append(f"Error opening PE file: {e}")
        return result

    # 2) Calculate entropy of the whole file
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        result["overall_entropy"] = shannon_entropy(data)

    except Exception as e:
        result["errors"].append(
            f"Failed to read file for overall entropy: {e}")

    # 3) Calculate entropy for each PE section
    for section in pe.sections:
        # Section names are stored as bytes, e.g. b'.text\x00\x00'
        raw_name = section.Name.rstrip(b"\x00")
        try:
            name = raw_name.decode(errors="ignore")
        except Exception:
            name = "<unknown>"

        raw_size = int(section.SizeOfRawData)
        virtual_address = int(section.VirtualAddress)

        try:
            section_data = section.get_data()
            section_entropy = shannon_entropy(section_data)

        except Exception as e:
            section_entropy = None
            result["errors"].append(
                f"Failed to get data for section {name}: {e}")

        result["sections"].append(
            {
                "name": name or "<noname>",
                "raw_size": raw_size,
                "virtual_address": virtual_address,
                "entropy": section_entropy,
            }
        )

    # IMPORTANT: explicitly close the PE file to avoid Windows file locks
    if pe is not None:
        pe.close()

    return result
