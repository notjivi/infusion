# 🛡️ Infusion (Aegis Sentinel) 
**Autonomous DevSecOps & K8s Auto-Remediation Agent**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![LangChain](https://img.shields.io/badge/🦜🔗-LangChain-green)](https://github.com/langchain-ai/langchain)
[![Gemini](https://img.shields.io/badge/Gemini-2.5_Flash-orange)](https://deepmind.google/technologies/gemini/)
[![Kubernetes](https://img.shields.io/badge/kubernetes-%23326ce5.svg?logo=kubernetes&logoColor=white)](https://kubernetes.io/)

**Infusion** is an autonomous DevSecOps pipeline. It doesn't just alert you to vulnerabilities—it **understands them, fixes them, tests the fixes, and submits a Pull Request** completely autonomously.

---

## 🌟 What It Does

Infusion ingests Kubernetes manifest files and their corresponding [Trivy](https://trivy.dev/) vulnerability scan reports. Using Google's **Gemini 2.5 Flash** and **LangChain**, it creates an autonomous agent that acts as a Senior Security Engineer:

1. **Calculates Risk:** Parses the Trivy JSON to compute a custom risk score and threat level.
2. **Threat Modeling:** Generates a concise Red Team "Attacker Story" outlining how a threat actor could exploit the found vulnerabilities (Initial Access -> Lateral Movement -> Critical Impact).
3. **Autonomous Remediation:** The LangChain agent analyzes the vulnerable YAML, writes a patched version to resolve specific CVEs/misconfigurations, and intelligently preserves original comments.
4. **Validation:** Automatically runs `kubectl apply --dry-run=client` against the patched YAML to ensure syntax validity and prevent cluster-breaking changes.
5. **Auto-PR Generation:** Submits a beautifully formatted Pull Request to GitHub containing the security patch, the threat model, and a summary of the fixes.
6. **Live Dashboard:** Outputs telemetry to a sleek, cyberpunk-styled HTML/JS dashboard (`Heal Nexus`).

---

## 🏗️ Architecture & Pipeline

```text
[ Trivy Scan (JSON) ] + [ Vulnerable YAML ] 
          │                      │
          └──────────► 🤖 LangChain Agent (Gemini 2.5 Flash)
                                 │
                                 ├─► 📊 Risk Scorer (Computes Threat Level)
                                 ├─► 💀 Threat Modeler (Generates Attack Vector)
                                 │
                                 ▼
                    🔧 YAML Remediation Tool (Iterative Fixing)
                                 │
                                 ▼
                    ✅ Kubectl Dry-Run Validation (Self-Correction Loop)
                                 │
                                 ▼
                     🚀 GitHub API (Creates Branch -> Commits -> Opens PR)
```

---

## 🗂️ Project Structure

* `agent.py`: The core LangChain ReAct agent orchestrator. Handles the pipeline flow from ingestion to UI data export.
* `tools.py`: Custom LangChain tools allowing the LLM to read logs, write YAML patches, test with `kubectl`, and interact with GitHub.
* `scorer.py`: Logic for parsing Trivy JSON and calculating a weighted numerical risk score based on severity (Critical/High/Medium/Low).
* `f.py`: A standalone GitHub integration script to programmatically create secure branches, commit healed YAMLs, and open detailed PRs.
* `index.html`: The **Heal Nexus** frontend. A fully responsive, high-contrast dashboard that polls `dashboard_data.json` for live agent updates.
* `cluster_scan.json`: Example Trivy vulnerability data.
* `deployment.yaml` / `juice.yaml`: Example vulnerable Kubernetes manifests (like OWASP Juice Shop).

---

## 🚀 Getting Started

### Prerequisites

* **Python 3.8+**
* **kubectl** installed and configured in your system `PATH`.
* **GitHub Personal Access Token** (with `repo` permissions to create branches and PRs).
* **Google Gemini API Key** (for `gemini-2.5-flash`).

### 1. Installation

Clone the repository and install the required dependencies:

```bash
git clone https://github.com/notjivi/infusion.git
cd infusion
pip install langchain langchain-google-genai langchain-classic PyGithub python-dotenv
```

### 2. Configuration

Create a `.env` file in the root directory and add your API keys:

```env
GOOGLE_API_KEY="your_gemini_api_key_here"
GITHUB_TOKEN="your_github_personal_access_token_here"
```

*Note: Update the `repo_name = "notjivi/hackathon"` line in `tools.py` and `f.py` to point to your actual target GitHub repository.*

---

## 💻 Usage

### Running the Agent

To launch the autonomous DevSecOps pipeline, run `agent.py` and pass the Trivy scan results and the vulnerable YAML as arguments:

```bash
python agent.py cluster_scan.json deployment.yaml
```

**What happens next:**
1. You will see the agent's "thought process" in the console as it calculates risk and generates a red-team analysis.
2. It will write the fixed YAML to `temp_patch.yaml`.
3. It validates the file using local `kubectl`.
4. It exports the session data to `dashboard_data.json`.
5. It automatically pushes a new branch and opens a PR on GitHub.

### Viewing the Dashboard (Heal Nexus)

The agent automatically generates a `dashboard_data.json` file. To view the live results in the cyberpunk UI:

1. Open a local web server (optional but recommended to avoid CORS issues):
   ```bash
   python -m http.server 8000
   ```
2. Navigate to `http://localhost:8000/index.html` in your web browser.
3. The dashboard will automatically poll and display the Risk Score, Attack Vector, and Agent reasoning logs in real-time.

---

## 🛡️ Security & Disclaimers

* **Quota:** This tool uses Google's Gemini API. Ensure you have sufficient quota/billing enabled.
* **Testing:** The `kubectl` dry-run tool executes commands locally. Ensure your local `kubectl` context is safe or appropriately sandboxed, even though `dry-run=client` prevents actual cluster modifications.
* **Intended Use:** This project is intended for educational purposes, hackathons, and internal DevSecOps experimentation. Always manually review AI-generated code before merging to production.

---

