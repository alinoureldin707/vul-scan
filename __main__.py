from chuncks_splitter import get_all_code_tasks
import os
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
import datetime
from config import MODEL_NAME, TEMPERATURE, GROQ_API_KEY
from langchain.agents import create_agent
from pydantic import BaseModel, Field
from typing import List

# 1. Initialize Groq LLM via LangChain
# Set your GROQ_API_KEY as an environment variable or pass it here
llm = ChatGroq(
    model_name=MODEL_NAME,
    temperature=TEMPERATURE, # Low temperature for consistent security analysis
    groq_api_key=GROQ_API_KEY 
)

# 2. Define the Security Prompt Template
prompt_template = ChatPromptTemplate.from_messages([
    ("system", "You are an expert security researcher. Analyze the following Python code for vulnerabilities like SQL injection, RCE, or insecure data handling."),
    ("user", "CONTEXT (Imports & Globals):\n{context}\n\nTARGET CODE BLOCK:\n{code_segment}\n\nAnalyze the code segment above. If a vulnerability exists, explain why and provide a fix.")
])

# 3. Create the Chain
chain = prompt_template | llm | StrOutputParser()

def run_agent_test(analysis_queue):
    """Processes the queue through the Groq-powered LangChain"""
    for task in analysis_queue:
        print(f"\n--- Testing File: {task['file']} ---")
        
        # Invoke the chain using the dictionary from our previous script
        response = chain.invoke({
            "context": task['context'],
            "code_segment": task['code_segment']
        })
        
        print(response)
        print("-" * 50)

# --- Integration Example ---
# Assuming 'analysis_queue' comes from the scan_directory function
# run_agent_test(analysis_queue)

if __name__ == "__main__":
# 1. Configuration
    project_path = "./project"
    report_file = f"vulnerability_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    
    # 2. Extract tasks using our Tree-sitter logic
    tasks = get_all_code_tasks(project_path) 

    print(f"Found {len(tasks)} chunks to analyze. Saving results to: {report_file}")

    # 3. Open file and iterate through tasks
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(f"VULNERABILITY AUDIT REPORT\nDATE: {datetime.datetime.now()}\n")
        f.write("="*50 + "\n\n")

        for i, task in enumerate(tasks):
            print(f"[{i+1}/{len(tasks)}] Analyzing: {task['file']}")
            
            print(task['context'])
            print(task['code_segment'])

            # Also print to console so you can track progress
            print("Done.")

    print(f"\nAudit complete. Results saved to {report_file}")
        

def build_agent(name, tools, system_prompt, response_format=None):
    """Constructs a LangChain agent bound to a small set of tools."""
    model = ChatGroq(model=MODEL_NAME, temperature=TEMPERATURE)
    agent = create_agent(
        name=name,
        model=model,
        tools=tools,
        system_prompt=system_prompt,
        response_format=response_format,
    )
    return agent


class CVEItem(BaseModel):
    cve_id: str = Field(alias="CVE ID", description="The CVE ID")
    severity: str
    score: float
    vectors: str
    affected_products: List[str]
    published_date: str
    description: str
    source_bias_note: str = Field(description="Note on potential source bias (e.g., legacy system scarcity)")

build_agent("name", tools=[], system_prompt="You are a security analysis agent.", response_format=CVEItem)