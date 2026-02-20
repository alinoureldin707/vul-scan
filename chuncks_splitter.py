import os
import tree_sitter_python as tspython
from tree_sitter import Language, Parser
import tree_sitter_javascript as tsjs
import tree_sitter_typescript as tsts
from models import CodeChunk
from printer import print_info, print_warning, print_error


def get_language_from_extension(file_extension):
    """Returns the programming language based on file extension."""
    if file_extension == ".py":
        return "python"
    elif file_extension in [".js", ".jsx"]:
        return "javascript"
    elif file_extension in [".ts", ".tsx"]:
        return "typescript"
    else:
        return None


def get_all_code_tasks(input_path: str) -> list[CodeChunk]:
    """
    Scans a directory OR a single file and returns a list of CodeChunk objects.
    Splitting is done with tree-sitter (no LLM agent required).
    """
    all_tasks: list[CodeChunk] = []

    if not os.path.exists(input_path):
        print_error(f"Path not found: '{input_path}'")
        return []

    supported_extensions = {".py", ".js", ".jsx", ".ts", ".tsx"}

    if os.path.isfile(input_path):
        files_to_process = [input_path]
    else:
        files_to_process = [
            os.path.join(root, f)
            for root, _, files in os.walk(input_path)
            for f in files
            if os.path.splitext(f)[1] in supported_extensions
        ]

    for file_path in files_to_process:
        file_lang = get_language_from_extension(os.path.splitext(file_path)[1])
        if not file_lang:
            continue

        header, chunks = _parse_file_to_chunks(file_path, file_lang)

        if not chunks:
            # Fallback: treat the entire file as one chunk so it still gets analysed
            try:
                with open(file_path, "r", encoding="utf-8") as fh:
                    source_code = fh.read()
                print_warning(f"No logic blocks found in {file_path} — using whole file as one chunk.")
                all_tasks.append(CodeChunk(file=file_path, context=header, code_segment=source_code))
            except Exception as exc:
                print_error(f"Cannot read {file_path}: {exc}")
            continue

        print_info(f"{len(chunks)} chunk(s) extracted from {file_path}")
        for chunk in chunks:
            all_tasks.append(CodeChunk(file=file_path, context=header, code_segment=chunk))

    return all_tasks


def _parse_file_to_chunks(file_path, language):
    # --- Setup ---
    if language == "python":
        lang_obj = Language(tspython.language())
        logic_types = ["function_definition", "class_definition"]
        context_types = ["import_statement", "import_from_statement"]
    elif language == "javascript":
        lang_obj = Language(tsjs.language())
        # JS uses 'declaration' instead of 'definition'
        logic_types = [
            "function_declaration",
            "class_declaration",
            "method_definition",
            "export_statement",
        ]
        context_types = [
            "import_statement",
        ]
    elif language == "typescript":
        lang_obj = Language(tsts.language_typescript())
        logic_types = [
            "function_declaration",
            "class_declaration",
            "method_definition",
            "export_statement",
        ]
        context_types = [
            "import_statement",
        ]

    parser = Parser(lang_obj)

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            source_code = f.read()
    except Exception as e:
        return f"# Error reading {file_path}: {e}", []

    source_bytes = bytes(source_code, "utf8")
    tree = parser.parse(source_bytes)

    header_lines = [f"# File Path: {file_path}"]
    chunks = []

    for child in tree.root_node.children:
        # 1. Capture Comments (Works for both)
        if child.type == "comment":
            header_lines.append(child.text.decode("utf8"))

        # 2. Capture Context (Imports)
        elif child.type in context_types:
            header_lines.append(child.text.decode("utf8"))

        # 3. Capture Assignments
        elif child.type in [
            "expression_statement",
            "lexical_declaration",
            "variable_declaration",
        ]:
            # Python assignments are usually inside expression_statements
            # JS 'const x = 1' is a lexical_declaration
            if b"=" in child.text:
                header_lines.append(child.text.decode("utf8"))

        # 4. Capture Logic Blocks (Functions and Classes)
        elif child.type in logic_types:
            chunks.append(child.text.decode("utf8"))

    return "\n".join(header_lines), chunks
