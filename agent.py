from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.agents import AgentExecutor, create_react_agent
from langchain import hub
from tools import read_trivy_log, write_yaml_patch, test_kubernetes_config
from scorer import calculate_risk_score
import os
import json

# ── Setup ──────────────────────────────────────────────────────────────────
# Fix: Using environment variable instead of hardcoding
from dotenv import load_dotenv
load_dotenv()
# os.environ["GOOGLE_API_KEY"] = "YOUR_GEMINI_API_KEY_HERE" # replace later

llm = ChatGoogleGenerativeAI(model="gemini-flash-latest", temperature=0)
# llm = ChatGoogleGenerativeAI(model="gemini-1.5-flash-latest", temperature=0)
# llm = ChatGoogleGenerativeAI(model="gemini-1.5-flash", temperature=0)
# llm = ChatGoogleGenerativeAI(model="gemini-2.0-flash", temperature=0)

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
    print("\n" + "="*60)
    print("🔍 STEP 1: CALCULATING RISK SCORE")
    print("="*60)
    risk = calculate_risk_score(trivy_json)
    print(f"⚠️  Risk Score  : {risk['score']}")
    print(f"🚨 Risk Level  : {risk['risk_level']}")
    print(f"📊 Breakdown   : {risk['breakdown']}")

    # Step 2: Attacker Story
    print("\n" + "="*60)
    print("💀 STEP 2: GENERATING ATTACKER STORY")
    print("="*60)
    attacker_result = agent_executor.invoke({
        "input": f"""
        You are a malicious hacker explaining how you would exploit these vulnerabilities.
        Speak in first person. Be specific and technical.
        
        Vulnerabilities found:
        {trivy_json}
        
        Explain step by step:
        1. Which vulnerability you would exploit first and why
        2. How you would gain access
        3. What damage you would cause
        4. How you would cover your tracks
        
        Use read_trivy_log tool first to understand the vulnerabilities.
        Then write your attacker story as the final answer.
        """
    })
    
    print("\n🔴 ATTACKER STORY:")
    print("-"*60)
    print(attacker_result["output"])

    # Step 3: Fix the YAML
    print("\n" + "="*60)
    print("🔧 STEP 3: AGENT FIXING THE VULNERABLE YAML")
    print("="*60)
    print("👀 Watch the AI think, act, and self-correct in real time:\n")
    
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
        6. Only stop when it passes
        """
    })

    # Step 4: Show the fixed YAML
    print("\n" + "="*60)
    print("✅ STEP 4: FINAL FIXED YAML")
    print("="*60)
    try:
        with open("temp_patch.yaml", "r") as f:
            fixed_yaml = f.read()
        print(fixed_yaml)
    except:
        print("Could not read fixed YAML file.")

    # Step 5: Final Summary
    print("\n" + "="*60)
    print("📋 FINAL SUMMARY")
    print("="*60)
    print(fix_result["output"])

    return {
        "risk": risk,
        "attacker_story": attacker_result["output"],
        "fix_summary": fix_result["output"],
        "fixed_yaml": fixed_yaml if 'fixed_yaml' in locals() else ""
    }


# ── Test Run ───────────────────────────────────────────────────────────────
if __name__ == "__main__":

    sample_trivy = json.dumps({
        "Results": [{
            "Target": "deployment.yaml",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2021-1234",
                    "Severity": "CRITICAL",
                    "Title": "Privilege escalation via runAsRoot"
                },
                {
                    "VulnerabilityID": "CVE-2021-5678",
                    "Severity": "HIGH",
                    "Title": "Hardcoded secret in environment variable"
                }
            ]
        }]
    })

    sample_yaml = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnerable-app
spec:
  template:
    spec:
      containers:
      - name: app
        image: nginx:latest
        securityContext:
          runAsUser: 0
        env:
        - name: AWS_SECRET
          value: "hardcoded-secret-123"
"""

    run_agent(sample_trivy, sample_yaml)

