from Agent_OWASP import OWASPFunctionReport
from chuncks_splitter import get_all_code_tasks
from models import CodeChunk
from agent import agent_analyzer

def analyze_code_chunk(code_chunk: CodeChunk) -> OWASPFunctionReport:
    """
    Takes a CodeChunk and returns an OWASPFunctionReport.
    """
    # --- Extract info from the chunk ---
    file_path = code_chunk['file']
    context = code_chunk['context']
    code_segment = code_chunk['code_segment']

    # --- Build the prompt for the agent ---
    prompt = f"""Analyze the following code segment for OWASP vulnerabilities. Provide a structured report based on the OWASP Top 10.
File: {file_path}
Context: {context}
```
{code_segment}
```
    """
    # --- Invoke the agent ---
    report = agent_analyzer.invoke({
        "messages": [
            {"role": "user", "content": prompt}
        ]
    })
    return report


if __name__ == "__main__":
# 1. Configuration
    project_path = "./project/vulnerable_app.py" 
    report_file = f"vulnerability_report_.txt"

    # 2. Extract tasks using our Tree-sitter logic
    tasks = get_all_code_tasks(project_path)

    print(f"Found {len(tasks)} chunks to analyze. Saving results to: {report_file}")

    # 3. Open file and iterate through tasks
    with open(report_file, "w", encoding="utf-8") as f:
        for i, task in enumerate(tasks):
            print(f"[{i+1}/{len(tasks)}] Analyzing: {task['file']}")
            report = analyze_code_chunk(task)
            response: OWASPFunctionReport = report['structured_response']
            for vulnerability in response.vulnerabilities:
                f.write(f"File: {task['file']}\n")
                f.write(f"Context: {task['context']}\n")
                f.write(f"Vulnerability: {vulnerability.name}\n")
                f.write(f"Description: {vulnerability.description}\n")
                f.write(f"Evidence: {vulnerability.evidence}\n")
                f.write("Exploitation Steps:\n")
                for step in vulnerability.exploitation_steps:
                    f.write(f"  - {step}\n")
                f.write(f"Impact: {vulnerability.impact}\n")
                f.write(f"Mitigation: {vulnerability.mitigation}\n")
                f.write("-" * 80 + "\n")
            f.write("-" * 80 + "\n")

    print(f"\nAudit complete. Results saved to {report_file}")