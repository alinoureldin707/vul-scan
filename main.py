import os
import tree_sitter_python as tspython
from tree_sitter import Language, Parser

# Initialize the Parser
PY_LANGUAGE = Language(tspython.language())
parser = Parser(PY_LANGUAGE)

def analyze_file_for_agent(file_path):
    if not os.path.exists(file_path):
        return "File not found.", []

    with open(file_path, "r", encoding="utf-8") as f:
        source_code = f.read()
    
    source_bytes = bytes(source_code, "utf8")
    tree = parser.parse(source_bytes)
    root = tree.root_node
    
    context_lines = []
    function_chunks = []

    for child in root.children:
        # 1. Capture Imports and Globals for the Header
        if child.type in ['import_statement', 'import_from_statement']:
            context_lines.append(child.text.decode('utf8'))
        
        elif child.type == 'expression_statement':
            # Checks for top-level assignments like: API_KEY = "..."
            if child.children and child.children[0].type == 'assignment':
                context_lines.append(child.text.decode('utf8'))

        # 2. Capture Function Signatures (The "Map")
        elif child.type == 'function_definition':
            # Extract just the first line (the def line)
            # This prevents hallucinations about what functions are available
            sig_end = child.named_child(1).end_byte # End of parameters
            sig = source_bytes[child.start_byte:sig_end].decode('utf8') + ":"
            context_lines.append(f"# Available function: {sig} ...")
            
            # Store the full body as a chunk for analysis
            function_chunks.append(child.text.decode('utf8'))

    header = "\n".join(context_lines)
    return header, function_chunks

# --- Execution ---
file_name = "vulnerable_app.py" # Replace with your target file
header_info, chunks = analyze_file_for_agent(file_name)

for idx, chunk in enumerate(chunks):
    prompt = f"""
    SYSTEM: You are a vulnerability research agent.
    
    FILE CONTEXT:
    {header_info}
    
    TARGET CODE BLOCK:
    {chunk}
    
    TASK: Analyze the TARGET CODE BLOCK for vulnerabilities (SQLi, XSS, RCE, etc).
    Use the FILE CONTEXT to understand where variables and imports come from.
    """
    print(f"--- PREPARED PROMPT FOR CHUNK {idx+1} ---")
    print(prompt)