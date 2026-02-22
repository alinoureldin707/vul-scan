import os
from models import CodeChunk, CodeChunkList
from agent import agent_splitter
from printer import print_info, print_warning, print_error

# Binary file signatures to skip (magic bytes)
_BINARY_SIGNATURES = [
    b"\x7fELF",   # ELF
    b"MZ",        # PE/DOS
    b"PK\x03\x04", # ZIP
    b"\x89PNG",   # PNG
    b"\xff\xd8\xff", # JPEG
    b"\x47\x49\x46", # GIF
    b"\x25PDF",   # PDF
]

SKIP_DIRS = {"__pycache__", ".git", ".github", "node_modules", ".venv", "venv", "dist", "build"}


def _is_binary(file_path: str) -> bool:
    """Quick binary detection: check magic bytes then null-byte scan."""
    try:
        with open(file_path, "rb") as fh:
            header = fh.read(8)
        if any(header.startswith(sig) for sig in _BINARY_SIGNATURES):
            return True
        # Null-byte heuristic
        with open(file_path, "rb") as fh:
            chunk = fh.read(1024)
        return b"\x00" in chunk
    except Exception:
        return True


def get_all_code_tasks(input_path: str) -> list[CodeChunk]:
    """
    Scans a directory OR a single file and returns a list of CodeChunk objects.
    Accepts any readable text file — language detection is handled by the splitter agent.
    Splitting is performed by the splitter agent (LLM-based).
    """
    if not os.path.exists(input_path):
        print_error(f"Path not found: '{input_path}'")
        return []

    if os.path.isfile(input_path):
        files_to_process = [input_path]
    else:
        files_to_process = [
            os.path.join(root, f)
            for root, dirs, files in os.walk(input_path)
            for f in files
            if not any(skip in root.split(os.sep) for skip in SKIP_DIRS)
        ]
        # Sort for deterministic ordering
        files_to_process.sort()

    all_tasks: list[CodeChunk] = []
    for file_path in files_to_process:
        if _is_binary(file_path):
            print_warning(f"Skipping binary file: {file_path}")
            continue
        chunks = _split_file_with_agent(file_path)
        if chunks:
            print_info(f"{len(chunks)} chunk(s) extracted from {file_path}")
            all_tasks.extend(chunks)

    return all_tasks


def _split_file_with_agent(file_path: str) -> list[CodeChunk]:
    """Reads a source file and uses the splitter agent to divide it into CodeChunk objects."""
    try:
        with open(file_path, "r", encoding="utf-8") as fh:
            source_code = fh.read()
    except Exception as exc:
        print_error(f"Cannot read {file_path}: {exc}")
        return []

    if not source_code.strip():
        print_warning(f"Skipping empty file: {file_path}")
        return []

    prompt = (
        f"File path: {file_path}\n\n"
        f"Source code:\n```\n{source_code}\n```"
    )

    try:
        raw = agent_splitter.invoke({"messages": [{"role": "user", "content": prompt}]})
    except Exception as exc:
        print_error(f"Splitter agent failed for {file_path}: {exc}")
        return []

    # Normalise the response into a CodeChunkList
    result: CodeChunkList | None = None
    if isinstance(raw, CodeChunkList):
        result = raw
    elif isinstance(raw, dict) and "structured_response" in raw:
        result = raw["structured_response"]
    elif hasattr(raw, "structured_response"):
        result = raw.structured_response
    elif isinstance(raw, dict):
        try:
            result = CodeChunkList.model_validate(raw)
        except Exception:
            pass

    if result is None or not result.chunks:
        print_warning(f"Splitter returned no chunks for {file_path} — using whole file as one chunk.")
        return [CodeChunk(file=file_path, context="", code_segment=source_code)]

    return result.chunks
