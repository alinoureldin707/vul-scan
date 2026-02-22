import os
from .models import CodeChunk, CodeChunkList
from .agent import agent_splitter
from .printer import print_info, print_warning, print_error
from .utils import invoke_with_retry

# Binary file signatures to skip (magic bytes)
_BINARY_SIGNATURES = (
    b"\x7fELF",      # ELF
    b"MZ",           # PE/DOS
    b"PK\x03\x04",   # ZIP
    b"\x89PNG",      # PNG
    b"\xff\xd8\xff", # JPEG
    b"GIF",          # GIF
    b"%PDF",         # PDF
)

SKIP_DIRS = frozenset({
    "__pycache__", ".git", ".github", "node_modules",
    ".venv", "venv", "dist", "build", ".idea", ".vscode",
    "coverage", ".nyc_output", "__snapshots__"
})

# Supported source code extensions
SOURCE_EXTENSIONS = frozenset({
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".c", ".cpp", ".h", ".hpp",
    ".cs", ".go", ".rb", ".php", ".rs", ".swift", ".kt", ".kts", ".scala",
    ".sql", ".sh", ".bash", ".ps1", ".yaml", ".yml", ".json", ".xml",
    ".html", ".vue", ".svelte", ".astro", ".lua", ".pl", ".pm", ".r",
})


def _is_supported_source(file_path: str) -> bool:
    """Check if file extension is in the supported source code list."""
    ext = os.path.splitext(file_path)[1].lower()
    return ext in SOURCE_EXTENSIONS


def _is_binary(file_path: str) -> bool:
    """Quick binary detection: check magic bytes then null-byte scan."""
    try:
        with open(file_path, "rb") as fh:
            header = fh.read(8)
            if any(header.startswith(sig) for sig in _BINARY_SIGNATURES):
                return True
            fh.seek(0)
            return b"\x00" in fh.read(1024)
    except Exception:
        return True


def _collect_files(input_path: str) -> list[str]:
    """Collect all processable files from directory or single file."""
    if os.path.isfile(input_path):
        return [input_path]

    files = []
    for root, dirs, filenames in os.walk(input_path):
        # Skip excluded directories in-place for efficiency
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in filenames:
            files.append(os.path.join(root, f))
    return sorted(files)


def _parse_agent_response(raw) -> CodeChunkList | None:
    """Extract CodeChunkList from various agent response formats."""
    if isinstance(raw, CodeChunkList):
        return raw
    if isinstance(raw, dict):
        if "structured_response" in raw:
            return raw["structured_response"]
        try:
            return CodeChunkList.model_validate(raw)
        except Exception:
            return None
    if hasattr(raw, "structured_response"):
        return raw.structured_response
    return None


def _split_file_with_agent(file_path: str, source_code: str) -> list[CodeChunk]:
    """Use the splitter agent to divide source code into CodeChunk objects with retry logic."""
    prompt = f"File path: {file_path}\n\nSource code:\n```\n{source_code}\n```"
    
    def invoke():
        return agent_splitter.invoke({"messages": [{"role": "user", "content": prompt}]})
    
    def normalize(raw) -> CodeChunkList | None:
        result = _parse_agent_response(raw)
        return result if result and result.chunks else None
    
    result = invoke_with_retry(invoke, normalize, f"splitter:{file_path}")
    
    if result:
        return _fix_chunk_line_numbers(result.chunks, source_code, file_path)
    
    print_warning(f"Splitter returned no chunks for {file_path} — using whole file as fallback.")
    return _create_fallback_chunk(file_path, source_code)


def _fix_chunk_line_numbers(chunks: list[CodeChunk], source_code: str, file_path: str) -> list[CodeChunk]:
    """Calculate accurate line_start/line_end by finding code_segment position in source."""
    source_lines = source_code.splitlines()
    fixed_chunks = []
    
    for chunk in chunks:
        segment_lines = chunk.code_segment.strip().splitlines()
        if not segment_lines:
            continue
            
        # Find the first line of the segment in the source
        first_line = segment_lines[0].strip()
        line_start = None
        
        for i, src_line in enumerate(source_lines, start=1):
            if src_line.strip() == first_line:
                line_start = i
                break
        
        if line_start is None:
            # Fallback: use LLM's value or default to 1
            line_start = chunk.line_start if chunk.line_start > 0 else 1
        
        line_end = line_start + len(segment_lines) - 1
        
        fixed_chunks.append(CodeChunk(
            file=chunk.file or file_path,
            context=chunk.context,
            code_segment=chunk.code_segment,
            line_start=line_start,
            line_end=line_end,
        ))
    
    return fixed_chunks


def _create_fallback_chunk(file_path: str, source_code: str) -> list[CodeChunk]:
    """Create a single chunk containing the entire file as fallback."""
    line_count = source_code.count("\n") + 1
    return [CodeChunk(
        file=file_path,
        context=f"// File: {file_path}",
        code_segment=source_code,
        line_start=1,
        line_end=line_count,
    )]


def get_all_code_tasks(input_path: str) -> list[CodeChunk]:
    """
    Scans a directory or single file and returns a list of CodeChunk objects.
    Uses LLM-based splitting with retry logic and fallback to whole-file chunks.
    """
    if not os.path.exists(input_path):
        print_error(f"Path not found: '{input_path}'")
        return []

    files_to_process = _collect_files(input_path)
    all_tasks: list[CodeChunk] = []
    
    for file_path in files_to_process:
        # Skip unsupported file types
        if not _is_supported_source(file_path):
            continue
        
        if _is_binary(file_path):
            print_warning(f"Skipping binary file: {file_path}")
            continue
        
        try:
            with open(file_path, "r", encoding="utf-8") as fh:
                source_code = fh.read()
        except UnicodeDecodeError:
            print_warning(f"Skipping non-UTF-8 file: {file_path}")
            continue
        except Exception as exc:
            print_error(f"Cannot read {file_path}: {exc}")
            continue
        
        if not source_code.strip():
            print_warning(f"Skipping empty file: {file_path}")
            continue
        
        chunks = _split_file_with_agent(file_path, source_code)
        if chunks:
            print_info(f"{len(chunks)} chunk(s) extracted from {file_path}")
            all_tasks.extend(chunks)

    return all_tasks
