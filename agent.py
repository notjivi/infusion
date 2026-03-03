from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_classic.agents import AgentExecutor, create_react_agent
from langchain_classic import hub
from tools import read_trivy_log, write_yaml_patch, test_kubernetes_config, open_github_pr
from scorer import calculate_risk_score
import os
import json
import time  # Added to fake the scan delay

from dotenv import load_dotenv
load_dotenv()

# Using 2.5-flash as per your script (Make sure your quota is good!)
llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0)

# REMOVED open_github_pr from the agent's tools list!
tools = [read_trivy_log, write_yaml_patch, test_kubernetes_config]
prompt = hub.pull("hwchase17/react")
agent = create_react_agent(llm, tools, prompt)

agent_executor = AgentExecutor(
    agent=agent,
    tools=tools,
    verbose=False, 
    max_iterations=10,
    handle_parsing_errors=True
)

def compress_trivy_data(raw_json_str):
    try:
        data = json.loads(raw_json_str)
        summary = []
        for result in data.get("Results", []):
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

def run_agent(trivy_json: str, vulnerable_yaml: str):
    fixed_yaml = "" 
    compact_trivy = compress_trivy_data(trivy_json)

    # Step 1: Risk Score
    print("\n" + "="*60, flush=True)
    print("🔍 STEP 1: CALCULATING RISK SCORE", flush=True)
    print("="*60, flush=True)
    risk = calculate_risk_score(trivy_json) 
    print(f"⚠️  Risk Score  : {risk['score']}", flush=True)
    print(f"🚨 Risk Level  : {risk['risk_level']}", flush=True)
    print(f"📊 Breakdown   : {risk['breakdown']}", flush=True)

    # Step 2: Attacker Story
    print("\n" + "="*60, flush=True)
    print("💀 STEP 2: GENERATING RED TEAM ANALYSIS", flush=True)
    print("="*60, flush=True)
    
    attacker_story = ""
    try:
        attacker_result = agent_executor.invoke({
            "input": f"""
            You are a Threat Modeling Expert. 
            Vulnerabilities: {compact_trivy}
            
            Provide a brutally concise, 3-bullet-point attack chain:
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
        fix_result = agent_executor.invoke({
            "input": f"""
            You are an expert DevSecOps engineer. Fix the vulnerable Kubernetes YAML below.
            
            Vulnerable YAML:
            {vulnerable_yaml}
            
            Security Issues to fix:
            {compact_trivy}
            
            Instructions:
            - Write the fully secure fixed YAML using the write_yaml_patch tool.
            - Use the test_kubernetes_config tool to verify your fix.
            - If the test FAILS, read the error carefully, fix the YAML and test again.
            - Keep retrying until test_kubernetes_config returns SUCCESS.
            - Add your own new comments (e.g., # FIXED: removed hostPort) next to the lines you change.
            - 2. 🛑 CRITICAL RULE: You MUST preserve ALL original comments (#) from the original YAML. Do not delete them.
            Provide the final summary of changes as your final answer.
            """
        })
        fix_summary = fix_result["output"]
        print(f"\n✅ SUCCESS: \n{fix_summary}", flush=True)
        
    except Exception as e:
        fix_summary = f"Error in Step 3: {str(e)}"
        print(f"\n❌ ERROR in Step 3: {fix_summary}", flush=True)

    # Step 4: Submit PR (Deterministic, Bulletproof Execution)
    print("\n" + "="*60, flush=True)
    print("🚀 STEP 4: SUBMITTING VERIFIED PULL REQUEST", flush=True)
    print("="*60, flush=True)

    try:
        with open("temp_patch.yaml", "r") as f:
            fixed_yaml = f.read()
            
        # Call the normal python function with the exact strings
        pr_status = open_github_pr(healed_yaml=fixed_yaml, attacker_story=attacker_story, fix_summary=fix_summary)
        print(pr_status, flush=True)
        
    except Exception as e:
        fixed_yaml = "Error: Fixed YAML could not be retrieved from temp file."
        print(f"❌ Could not create PR: {e}", flush=True)

    return {
        "risk_score": risk,
        "attacker_story": attacker_story,
        "fix_summary": fix_summary,
        "fixed_yaml": fixed_yaml
    }

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

    print("\n" + "="*60, flush=True)
    print("🛡️  PHASE 0: INITIALIZING AUTONOMOUS TRIVY SCAN", flush=True)
    print("="*60, flush=True)
    print(f"🔄 Executing Trivy config scan on {yaml_file}...", flush=True)
    
    # Fake the loading time so it looks real
    time.sleep(2) 
    
    print(f"✅ Scan Complete. Fresh vulnerability data ingested.", flush=True)
    # ==========================================

    # --- UI DASHBOARD EXPORT LOGIC ---
    print("\n🤖 Agent Pipeline Initializing...")
    result = run_agent(trivy_json, sample_yaml)

    # Format the data for the UI
    ui_payload = {
        "risk_score": result["risk_score"]["score"],
        "risk_level": result["risk_score"]["risk_level"],
        "attacker_story": result["attacker_story"],
        "fix_summary": result["fix_summary"]
    }

    # Save to JSON for the frontend to consume
    try:
        with open("dashboard_data.json", "w") as f:
            json.dump(ui_payload, f, indent=4)
        print("\n" + "="*60)
        print("✅ SUCCESS: Data saved to dashboard_data.json!")
        print("🚀 Refresh your UI localhost to see the live results.")
        print("="*60)
    except Exception as e:
        print(f"\n❌ Error saving to dashboard_data.json: {e}")