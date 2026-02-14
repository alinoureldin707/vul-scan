from chuncks_splitter import get_all_code_tasks
from models import CodeChunk, OWASPFunctionReport
from agent import agent_analyzer
from printer import print_header, print_vulnerability, print_summary
import sys

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
    project_path = "./project/no_vulnerable.py" 
    report_file = f"vulnerability_report_.txt"

    # 2. Extract tasks using our Tree-sitter logic
    tasks = get_all_code_tasks(project_path)

    print(f"Found {len(tasks)} chunks to analyze.")

    summary = {}

    # 3. Iterate through tasks and print to console sequentially
    for i, task in enumerate(tasks):
        file_path = task.get("file")
        print_header(i + 1, len(tasks), file_path)

        try:
            report_raw = analyze_code_chunk(task)
        except Exception as e:
            print(f"Agent invocation failed for {file_path}: {e}")
            summary[file_path] = summary.get(file_path, 0)
            continue

        # Normalize response shapes
        structured = None
        if isinstance(report_raw, OWASPFunctionReport):
            structured = report_raw
        elif isinstance(report_raw, dict) and "structured_response" in report_raw:
            structured = report_raw["structured_response"]
        elif hasattr(report_raw, "structured_response"):
            structured = report_raw.structured_response
        elif isinstance(report_raw, dict) and "vulnerabilities" in report_raw:
            # sometimes agent returns raw dict
            try:
                if hasattr(OWASPFunctionReport, "model_validate"):
                    structured = OWASPFunctionReport.model_validate(report_raw)
                else:
                    structured = OWASPFunctionReport.parse_obj(report_raw)
            except Exception:
                structured = None

        if structured is None:
            print("Could not parse structured response from agent. Raw output:\n", report_raw)
            summary[file_path] = summary.get(file_path, 0)
            continue

        vulns = getattr(structured, "vulnerabilities", None)
        if vulns is None:
            # If pydantic model; try dict access
            try:
                vulns = structured.get("vulnerabilities", [])
            except Exception:
                vulns = []

        count = 0
        if not vulns:
            print("No OWASP Top-10 vulnerabilities found in this chunk.")
        else:
            for v in vulns:
                print_vulnerability(v)
                count += 1

        summary[file_path] = summary.get(file_path, 0) + count

    # Print summary table
    print_summary(summary)

    total_vulnerabilities= sum(summary.values())
    if total_vulnerabilities>0:
        print (f"\n {total_vulnerabilities} vulnerabilities detected. Blocking deployment.")
        sys.exit(1) #makes CI fail
    else:
        print("\n No vulnerabilities detected. Safe to deploy.")
        sys.exit(0) #allow CI to pass