from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_classic.agents import AgentExecutor, create_react_agent
from langchain_classic import hub
from tools import read_trivy_log, write_yaml_patch, test_kubernetes_config
from scorer import calculate_risk_score
import os
import json
os.environ["GOOGLE_API_KEY"] = "AIzaSyAbDqSEQzPrVA-mx0rDzFpBHkRfrnCtnP8"
# ── Setup ──────────────────────────────────────────────────────────────────
from dotenv import load_dotenv
load_dotenv()

# Using 1.5-flash as it is lightning fast and highly stable for free tier
llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0)

tools = [read_trivy_log, write_yaml_patch, test_kubernetes_config]
prompt = hub.pull("hwchase17/react")
agent = create_react_agent(llm, tools, prompt)

agent_executor = AgentExecutor(
    agent=agent,
    tools=tools,
    verbose=True, # Keeps the "Thought Process" but won't print raw JSON anymore
    max_iterations=10,
    handle_parsing_errors=True
)

# ── Optimization Helper ────────────────────────────────────────────────────
def compress_trivy_data(raw_json_str):
    """
    Strips the bloated JSON down to just the essential CVE IDs and Titles.
    Saves massive amounts of API tokens and keeps the terminal clean.
    """
    try:
        data = json.loads(raw_json_str)
        summary = []
        for result in data.get("Results", []):
            # Grab vulnerabilities or misconfigurations
            issues = result.get("Vulnerabilities", []) + result.get("Misconfigurations", [])
            for issue in issues:
                vid = issue.get("VulnerabilityID", issue.get("ID", "Unknown"))
                sev = issue.get("Severity", "Unknown")
                title = issue.get("Title", issue.get("Description", "No Title"))
                summary.append(f"- [{sev}] {vid}: {title}")
        
        if not summary:
            return "No vulnerabilities found."
        return "\n".join(summary)
    except Exception as e:
        return "Failed to parse Trivy JSON."

# ── Main Function ──────────────────────────────────────────────────────────
def run_agent(trivy_json: str, vulnerable_yaml: str):
    fixed_yaml = "" 

    # Compress the JSON to save API Quota
    compact_trivy = compress_trivy_data(trivy_json)

    # Step 1: Risk Score
    print("\n" + "="*60, flush=True)
    print("🔍 STEP 1: CALCULATING RISK SCORE", flush=True)
    print("="*60, flush=True)
    risk = calculate_risk_score(trivy_json) # Scorer can use raw JSON internally
    print(f"⚠️  Risk Score  : {risk['score']}", flush=True)
    print(f"🚨 Risk Level  : {risk['risk_level']}", flush=True)
    print(f"📊 Breakdown   : {risk['breakdown']}", flush=True)

    # Step 2: Attacker Story (Red Team Analysis)
    print("\n" + "="*60, flush=True)
    print("💀 STEP 2: GENERATING RED TEAM ANALYSIS", flush=True)
    print("="*60, flush=True)
    
    attacker_story = ""
    try:
        # We pass compact_trivy instead of trivy_json
        attacker_result = agent_executor.invoke({
            "input": f"""
            You are a Threat Modeling Expert. 
            Vulnerabilities: {compact_trivy}
            
            Do NOT write a long paragraph. Provide a brutally concise, 3-bullet-point attack chain:
            🔥 Initial Access: [1 sentence explaining the foothold]
            🕵️ Lateral Movement: [1 sentence explaining the pivot]
            💥 Critical Impact: [1 sentence explaining the maximum damage]
            
            Output ONLY those three bullet points.
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
        # We pass compact_trivy instead of trivy_json
        fix_result = agent_executor.invoke({
            "input": f"""
            You are an expert DevSecOps engineer. Fix the vulnerable Kubernetes YAML below.
            
            Vulnerable YAML:
            {vulnerable_yaml}
            
            Security Issues to fix:
            {compact_trivy}
            
            Instructions:
            1. Write the fully secure fixed YAML using the write_yaml_patch tool.
            2. Use the test_kubernetes_config tool to verify your fix.
            3. If the test FAILS, read the error carefully, fix the YAML and test again.
            4. Keep retrying until test_kubernetes_config returns SUCCESS.
            
            Provide the final summary of changes as the final answer.
            """
        })
        fix_summary = fix_result["output"]
    except Exception as e:
        fix_summary = f"Error in Step 3: {str(e)}"
        print(f"\n❌ ERROR in Step 3: {fix_summary}", flush=True)

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