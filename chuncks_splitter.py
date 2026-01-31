import os
import tree_sitter_python as tspython
from tree_sitter import Language, Parser

# --- Setup ---
PY_LANGUAGE = Language(tspython.language())
parser = Parser(PY_LANGUAGE)

def get_all_code_tasks(root_path):
    """
    Scans a directory and returns a flat list of 'task' dictionaries.
    Each task contains the file path, global context (imports/globals), and a code chunk.
    """
    all_tasks = []

    if not os.path.exists(root_path):
        print(f"Error: Path '{root_path}' does not exist.")
        return []

    for root, _, files in os.walk(root_path):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                
                # Extract chunks from individual file
                header, chunks = _parse_file_to_chunks(file_path)
                
                for chunk in chunks:
                    all_tasks.append({
                        "file": file_path,
                        "context": header,
                        "code_segment": chunk
                    })
    
    return all_tasks

def _parse_file_to_chunks(file_path):
    """Internal helper to parse a file into context and logical blocks."""
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
        # 1. Capture Context (Imports and Global Assignments)
        if child.type in ['import_statement', 'import_from_statement']:
            header_lines.append(child.text.decode('utf8'))
        
        elif child.type == 'expression_statement':
            # Capturing top-level assignments like: API_KEY = "123"
            if b'=' in child.text: 
                header_lines.append(child.text.decode('utf8'))
        
        # 2. Capture Logic Blocks (Functions and Classes)
        elif child.type in ['function_definition', 'class_definition']:
            chunks.append(child.text.decode('utf8'))

    return "\n".join(header_lines), chunks