import ast
from pathlib import Path

def get_chunks_from_file(file_path: Path):
    """
    Parse a Python file and return semantic chunks:
    - functions
    - classes
    - imports
    - top-level code
    """
    chunks = []
    code = file_path.read_text(encoding="utf-8")
    
    # Parse the file into an AST
    tree = ast.parse(code, filename=str(file_path))

    # Helper function to extract code snippet by line numbers
    def get_code(node):
        start = node.lineno - 1
        end = node.end_lineno
        lines = code.splitlines()[start:end]
        return "\n".join(lines)

    # Walk through top-level nodes
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            chunks.append({
                "file": str(file_path),
                "chunk_type": "function",
                "name": node.name,
                "start_line": node.lineno,
                "end_line": node.end_lineno,
                "code": get_code(node)
            })
        elif isinstance(node, ast.ClassDef):
            chunks.append({
                "file": str(file_path),
                "chunk_type": "class",
                "name": node.name,
                "start_line": node.lineno,
                "end_line": node.end_lineno,
                "code": get_code(node)
            })
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            chunks.append({
                "file": str(file_path),
                "chunk_type": "import",
                "name": None,
                "start_line": node.lineno,
                "end_line": node.end_lineno,
                "code": get_code(node)
            })
        else:
            chunks.append({
                "file": str(file_path),
                "chunk_type": "top_level",
                "name": None,
                "start_line": node.lineno,
                "end_line": getattr(node, "end_lineno", node.lineno),
                "code": get_code(node)
            })
    return chunks

# --- Example: scan an entire project folder ---
def chunk_project(project_dir: Path):
    all_chunks = []
    for py_file in project_dir.rglob("*.py"):
        all_chunks.extend(get_chunks_from_file(py_file))
    return all_chunks

# --- Example usage ---
if __name__ == "__main__":
    project_path = input("Enter path to your Python project: ")
    chunks = chunk_project(Path(project_path))
    for c in chunks:
        print(f"File: {c['file']}")
        print(f"Type: {c['chunk_type']}")
        if c["name"]:
            print(f"Name: {c['name']}")
        print(f"Lines: {c['start_line']}-{c['end_line']}")
        print("Code:")
        print(c["code"])
        print("-" * 50)
