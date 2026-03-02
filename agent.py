from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.agents import AgentExecutor, create_react_agent
from langchain import hub
from tools import read_trivy_log, write_yaml_patch, test_kubernetes_config
from scorer import calculate_risk_score
import os
import json

# ── Setup ──────────────────────────────────────────────────────────────────
from dotenv import load_dotenv
load_dotenv()

# Use a stable model that has quota on the free tier
llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0)
# llm = ChatGoogleGenerativeAI(model="gemini-pro", temperature=0)
# llm = ChatGoogleGenerativeAI(model="gemini-1.5-flash", temperature=0)

tools = [read_trivy_log, write_yaml_patch, test_kubernetes_config]

prompt = hub.pull("hwchase17/react")

agent = create_react_agent(llm, tools, prompt)

agent_executor = AgentExecutor(
    agent=agent,
    tools=tools,
    verbose=True,
    max_iterations=10,
    handle_parsing_errors=True
)

# ── Main Function ──────────────────────────────────────────────────────────
def run_agent(trivy_json: str, vulnerable_yaml: str):
    fixed_yaml = "" # Initialize early to avoid UnboundLocalError

    # Step 1: Risk Score
    print("\n" + "="*60, flush=True)
    print("🔍 STEP 1: CALCULATING RISK SCORE", flush=True)
    print("="*60, flush=True)
    risk = calculate_risk_score(trivy_json)
    print(f"⚠️  Risk Score  : {risk['score']}", flush=True)
    print(f"🚨 Risk Level  : {risk['risk_level']}", flush=True)
    print(f"📊 Breakdown   : {risk['breakdown']}", flush=True)

    # Step 2: Attacker Story (Red Team Analysis)
    print("\n" + "="*60, flush=True)
    print("💀 STEP 2: GENERATING RED TEAM ANALYSIS", flush=True)
    print("="*60, flush=True)
    
    attacker_story = ""
    try:
        attacker_result = agent_executor.invoke({
            "input": f"""
            You are a Threat Modeling Expert performing a red-team analysis. 
            Analyze the following vulnerabilities from a technical perspective and explain the hypothetical exploitation path an attacker might take.
            
            Vulnerabilities found:
            {trivy_json}
            
            Explain the scenario step by step:
            1. Entry point: Which vulnerability provides the initial foothold and why?
            2. Lateral movement: How would an attacker move from the initial entry to further compromise the system?
            3. Impact: What is the maximum damage (data loss, persistence, breakout) this specific combination allows?
            
            Use read_trivy_log tool first to understand the vulnerabilities.
            Provide your analysis as the final answer.
            """
        })
        attacker_story = attacker_result["output"]
        print("\n🔴 RED TEAM ANALYSIS:", flush=True)
        print("-"*60, flush=True)
        print(attacker_story, flush=True)
    except Exception as e:
        attacker_story = f"Error in Step 2: {str(e)}"
        print(f"\n❌ ERROR in Step 2: {attacker_story}", flush=True)

    # Step 3: Fix the YAML
    print("\n" + "="*60, flush=True)
    print("🔧 STEP 3: AGENT FIXING THE VULNERABLE YAML", flush=True)
    print("="*60, flush=True)
    print("👀 Watch the AI think, act, and self-correct in real time:\n", flush=True)
    
    fix_summary = ""
    try:
        fix_result = agent_executor.invoke({
            "input": f"""
            You are an expert DevSecOps engineer. Fix the vulnerable Kubernetes YAML below.
            
            Vulnerable YAML:
            {vulnerable_yaml}
            
            Vulnerabilities to fix:
            {trivy_json}
            
            Instructions:
            1. Use read_trivy_log to understand what needs fixing
            2. Write the fully secure fixed YAML using write_yaml_patch
            3. Use test_kubernetes_config to verify your fix
            4. If the test FAILS, read the error carefully, fix the YAML and test again
            5. Keep retrying until test_kubernetes_config returns SUCCESS
            
            Provide the final summary of changes and the verification status as the final answer.
            """
        })
        fix_summary = fix_result["output"]
    except Exception as e:
        fix_summary = f"Error in Step 3: {str(e)}"
        print(f"\n❌ ERROR in Step 3: {fix_summary}", flush=True)

    # Try to read the fixed YAML from the temp file if it exists
    try:
        with open("temp_patch.yaml", "r") as f:
            fixed_yaml = f.read()
    except:
        fixed_yaml = "Error: Fixed YAML could not be retrieved from temp file."

    return {
        "risk_score": risk,
        "attacker_story": attacker_story,
        "fix_summary": fix_summary,
        "fixed_yaml": fixed_yaml if 'fixed_yaml' in locals() else ""
    }


# ── Test Run ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    # Automatically read JSON file from command line argument
    # Usage: python agent.py cluster.json vulnerable.yaml
    
    if len(sys.argv) >= 2:
        json_file = sys.argv[1]
        try:
            with open(json_file, "r") as f:
                trivy_data = json.load(f)
            trivy_json = json.dumps(trivy_data)
            print(f"✅ Loaded {json_file}")
        except FileNotFoundError:
            print(f"❌ File {json_file} not found!")
            sys.exit(1)
    else:
        print("❌ Please provide a Trivy JSON file!")
        print("Usage: python agent.py <trivy_json_file> <vulnerable_yaml_file>")
        sys.exit(1)

    if len(sys.argv) >= 3:
        yaml_file = sys.argv[2]
        try:
            with open(yaml_file, "r") as f:
                sample_yaml = f.read()
            print(f"✅ Loaded {yaml_file}")
        except FileNotFoundError:
            print(f"❌ File {yaml_file} not found!")
            sys.exit(1)
    else:
        print("❌ Please provide a vulnerable YAML file!")
        print("Usage: python agent.py <trivy_json_file> <vulnerable_yaml_file>")
        sys.exit(1)

    run_agent(trivy_json, sample_yaml)
