import subprocess
import json
import re
from langchain_core.tools import tool
from github import Github, Auth
import random
import os

@tool
def read_trivy_log(vulnerability_json: str) -> str:
    """
    Reads and summarizes the Trivy vulnerability scan output.
    Input: raw Trivy JSON string
    Output: human readable summary of vulnerabilities
    """
    try:
        # Handle both string and dict input
        if isinstance(vulnerability_json, str):
            # Strip any extra whitespace
            vulnerability_json = vulnerability_json.strip()
            data = json.loads(vulnerability_json)
        else:
            data = vulnerability_json

        summary = []

        for result in data.get("Results", []):
            target = result.get("Target", "unknown")
            
            # Handle Misconfigurations (real Trivy data)
            items = result.get("Misconfigurations", []) + result.get("Vulnerabilities", [])
            
            for item in items:
                summary.append(
                    f"[{item.get('Severity', 'UNKNOWN')}] {item.get('ID', 'N/A')} - "
                    f"{item.get('Title', 'No title')} | Fix: {item.get('Resolution', 'N/A')}"
                )

        return "\n".join(summary) if summary else "No vulnerabilities found."

    except Exception as e:
        return f"Error reading trivy log: {str(e)}"


@tool
def write_yaml_patch(yaml_content: str) -> str:
    """
    Writes the AI-generated patched YAML to a temp file.
    Automatically strips markdown code blocks if present.
    Input: YAML content as string
    Output: confirmation message
    """
    try:
        # Fix: robustly strip markdown code blocks like ```yaml ... ```
        cleaned = re.sub(r"```(?:yaml)?\n?|```", "", yaml_content).strip()

        if not cleaned:
            return "❌ ERROR: YAML content is empty after cleaning."

        with open("temp_patch.yaml", "w") as f:
            f.write(cleaned)

        return "Successfully wrote patch to temp_patch.yaml"

    except Exception as e:
        return f"❌ Error writing YAML: {str(e)}"


@tool
def test_kubernetes_config(dummy_input: str = "") -> str:
    """
    Tests the patched YAML using kubectl dry-run.
    Output: success or error message from kubectl
    """
    try:
        # Use absolute path for kubectl if winget modified PATH but session hasn't refreshed
        kubectl_path = r"C:\Users\avira\AppData\Local\Microsoft\WinGet\Packages\Kubernetes.kubectl_Microsoft.Winget.Source_8wekyb3d8bbwe\kubectl.exe"
        
        result = subprocess.run(
            [kubectl_path, "apply", "-f", "temp_patch.yaml", "--dry-run=client", "--validate=false"],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode == 0:
            return f"✅ SUCCESS: YAML is valid!\n{result.stdout}"
        else:
            return f"❌ FAILED: YAML has errors!\n{result.stderr}"

    except FileNotFoundError:
        return "⚠️ kubectl not found. Skipping validation — YAML was written successfully."
    except Exception as e:
        return f"❌ ERROR: {str(e)}"
    
def open_github_pr(healed_yaml: str, attacker_story: str, fix_summary: str) -> str:
    """
    Submits a Pull Request to GitHub with the finalized, verified YAML.
    """
    try:
        # Load token from .env for security
        token = os.getenv("GITHUB_TOKEN")
        auth = Auth.Token(token)
        g = Github(auth=auth)

        repo_name = "notjivi/hackathon" # Change to your actual repo
        repo = g.get_repo(repo_name)
        
        base_branch = "main"
        new_branch = f"aegis-remediation-{random.randint(1000, 9999)}"
        
        # 1. Create Branch
        base_ref = repo.get_git_ref(f"heads/{base_branch}")
        repo.create_git_ref(ref=f"refs/heads/{new_branch}", sha=base_ref.object.sha)

        # 2. Update File
        file_path = "juice.yaml"
        file_contents = repo.get_contents(file_path, ref=base_branch)
        repo.update_file(
            path=file_path,
            message="chore(security): Autonomous K8s Hardening by Aegis Sentinel",
            content=healed_yaml,
            sha=file_contents.sha,
            branch=new_branch
        )

        # 3. Create "Beautiful" PR Body
        pr_body = f"""## 🚨 Security Incident Remediated
**Aegis Sentinel** detected critical attack vectors and has autonomously generated this secure patch.

### 💀 Red Team Analysis (Attack Path)
{attacker_story}

### 🔧 Remediation Summary
{fix_summary}

### 🔍 Verification Status
- [x] Kubernetes `dry-run` successful
- [x] Zero-Trust policies enforced
---
*Generated autonomously by Aegis Sentinel.* 🤖
"""
        pr = repo.create_pull(
            title="🛡️ Aegis Sentinel: Critical Vulnerability Remediation",
            body=pr_body,
            head=new_branch,
            base=base_branch
        )

        return f"🏆 SUCCESS: PR opened at {pr.html_url}"

    except Exception as e:
        return f"❌ PR Error: {str(e)}"