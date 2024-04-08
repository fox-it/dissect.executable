from pathlib import Path


def data_file(path: str) -> Path:
    return Path(__file__).parent / "data" / path
