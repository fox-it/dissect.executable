from pathlib import Path


def absolute_path(path: str) -> Path:
    return (Path(__file__).parent / path).resolve()
