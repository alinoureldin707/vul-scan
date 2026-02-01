import os
import tree_sitter_python as tspython
from tree_sitter import Language, Parser
import tree_sitter_javascript as tsjs
import tree_sitter_typescript as tsts

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

def get_all_code_tasks(input_path):
    """
    Scans a directory OR a single file and returns a list of 'task' dictionaries.
    """
    all_tasks = []

    if not os.path.exists(input_path):
        print(f"Error: Path '{input_path}' does not exist.")
        return []

    # 1. Determine if we are dealing with a single file or a directory
    if os.path.isfile(input_path):
        # Process just this one file
        files_to_process = [(os.path.dirname(input_path), [os.path.basename(input_path)])]
    else:
        # Process the directory tree as before
        files_to_process = [(root, files) for root, _, files in os.walk(input_path)]

    # 2. Iterate through the identified file(s)
    for root, files in files_to_process:
        for file in files:
            file_lang = get_language_from_extension(os.path.splitext(file)[1])
            if file_lang:
                file_path = os.path.join(root, file)
                
                header, chunks = _parse_file_to_chunks(file_path,file_lang)
                print(f"Parsed {len(chunks)} chunks from {file_path}")
                
                for chunk in chunks:
                    all_tasks.append({
                        "file": file_path,
                        "context": header,
                        "code_segment": chunk
                    })
    
    return all_tasks

def _parse_file_to_chunks(file_path, language):
    # --- Setup ---
    if language == "python":
        lang_obj = Language(tspython.language())
        logic_types = ['function_definition', 'class_definition']
        context_types = ['import_statement', 'import_from_statement']
    elif language == "javascript":
        lang_obj = Language(tsjs.language())
        # JS uses 'declaration' instead of 'definition'
        logic_types = ['function_declaration', 'class_declaration', 'method_definition','export_statement']
        context_types = ['import_statement', ]
    elif language == "typescript":
        lang_obj = Language(tsts.language_typescript())
        logic_types = ['function_declaration', 'class_declaration', 'method_definition','export_statement']
        context_types = ['import_statement', ]
        
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
        print(child.type)
        # 1. Capture Comments (Works for both)
        if child.type == 'comment':
            header_lines.append(child.text.decode('utf8'))

        # 2. Capture Context (Imports)
        elif child.type in context_types:
            header_lines.append(child.text.decode('utf8'))
        
        # 3. Capture Assignments
        elif child.type in ['expression_statement', 'lexical_declaration', 'variable_declaration']:
            # Python assignments are usually inside expression_statements
            # JS 'const x = 1' is a lexical_declaration
            if b'=' in child.text: 
                header_lines.append(child.text.decode('utf8'))
        
        # 4. Capture Logic Blocks (Functions and Classes)
        elif child.type in logic_types:
            chunks.append(child.text.decode('utf8'))

    return "\n".join(header_lines), chunks