import os
import tree_sitter_python as tspython
from tree_sitter import Language, Parser

# Initialize Parser
PY_LANGUAGE = Language(tspython.language())
parser = Parser(PY_LANGUAGE)

def get_file_chunks(file_path):
    """Parses a single file and returns (header, list_of_function_bodies)"""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            source_code = f.read()
    except Exception as e:
        return f"# Error reading file: {file_path}: {e}", []

    source_bytes = bytes(source_code, "utf8")
    tree = parser.parse(source_bytes)
    
    header_lines = [f"# File Path: {file_path}"]
    chunks = []

    for child in tree.root_node.children:
        # 1. Capture Context (Imports and Globals)
        if child.type in ['import_statement', 'import_from_statement']:
            header_lines.append(child.text.decode('utf8'))
        
        elif child.type == 'expression_statement':
            # Check if it's an assignment (e.g., DEBUG = True)
            if child.children and child.children[0].type == 'assignment':
                header_lines.append(child.text.decode('utf8'))
        
        # 2. Capture Logic Blocks (Functions and Classes)
        elif child.type in ['function_definition', 'class_definition']:
            chunks.append(child.text.decode('utf8'))

    return "\n".join(header_lines), chunks

def scan_directory(path):
    """Walks through the directory and prepares prompts for all python files"""
    all_tasks = [] # The list is initialized here
    
    for root, dirs, files in os.walk(path):
        for file in files:
            if file.endswith(".py"):
                full_path = os.path.join(root, file)
                header, chunks = get_file_chunks(full_path)
                
                for chunk in chunks:
                    # Create a structured task for the AI Agent
                    task = {
                        "file": full_path,
                        "context": header,
                        "code_segment": chunk
                    }
                    all_tasks.append(task)
    
    return all_tasks

# --- Execution ---
target_folder = "./" # <--- Change this to your folder
if os.path.exists(target_folder):
    analysis_queue = scan_directory(target_folder)
    print(f"Successfully processed {target_folder}")
    print(f"Total logical chunks ready for AI analysis: {len(analysis_queue)}")
else:
    print(f"Folder '{target_folder}' not found. Please update the path.")

for task in analysis_queue:
    # Example prompt construction
    prompt = f"""
    ANALYSIS TASK:
    {task['context']}
    
    CODE TO CHECK:
    {task['code_segment']}
    
    Identify any security flaws in the CODE TO CHECK based on the CONTEXT.
    """
    # response = ai_agent.ask(prompt)
    print(f"Results for {task['file']}: {prompt}")