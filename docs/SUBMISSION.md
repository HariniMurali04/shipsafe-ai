# ShipSafe AI &mdash; Hackathon Submission Package
## Build, Ship, Shape: Amazon Developer Hackathon 2026

> **Project Name:** ShipSafe AI  
> **Tagline:** Secure Every Change Before It Ships.  
> **Repository:** https://github.com/YOUR_GITHUB_USERNAME/shipsafe-ai  
> **License:** MIT Open Source License  
> **Primary Track:** Alexa+ Track (Simulated Voice-First Developer Experience)  
> **Eligible Mini-Challenges:** Open Source, AWS Builder (via Amazon Bedrock `boto3` runtime SDK integration)

---

### 1. Concise Project Description
**ShipSafe AI** is an intelligent, developer-first AWS configuration security and deployment-readiness advisor. Operating locally with zero required cloud credentials, it statically audits AWS S3 configuration JSON files against 14 baseline security checks, explains risk rationales using concrete extracted evidence, and verifies whether developer remediations resolve targeted vulnerabilities through true deterministic rule re-execution. It features an interactive **Simulated Alexa+** conversational assistant and an optional **Amazon Bedrock** explanation layer with transparent zero-cost fallback.

---

### 2. The Problem Being Solved
Cloud misconfigurations remain the leading root cause of public data breaches and accidental exposures in AWS environments. However:
- **Late Discovery:** Security scanners typically run after deployment or rely on expensive cloud security posture management (CSPM) suites connected to live infrastructure.
- **Opaque Rationale & Hallucination:** Traditional tools flag warnings without citing concrete evidence from the input payload, while unconstrained LLMs hallucinate phantom vulnerabilities or claim non-compliant configs are secure.
- **No Remediation Verification:** Developers modify a configuration but have no fast, offline mechanism to re-test the updated file and prove that previous violations are genuinely resolved before shipping to production.
- **Credential Overhead:** Developers often cannot run pre-commit security audits because scanners require active IAM credentials or network access.

---

### 3. Target Users
- **Cloud & DevOps Engineers:** Auditing AWS CloudFormation, Terraform JSON outputs, or bucket definitions before deployment.
- **Backend & Full-Stack Developers:** Working with cloud storage who need fast, offline, and explainable pre-flight security feedback.
- **Security & Platform Engineers:** Setting up baseline pre-deployment quality gates for engineering teams.
- **Hackathon Judges & Reviewers:** Evaluating deterministic cloud security paired with voice-first conversational AI patterns.

---

### 4. Key Differentiators
1. **Zero AWS Credentials Required:** Evaluates static configurations locally; no IAM keys or network access needed.
2. **Grounded Determinism (Zero Hallucination):** Findings and finding IDs are 100% deterministic. Identical payloads always produce identical findings.
3. **True Rule Re-execution Verification:** Fixes are verified by re-executing actual Python security rules against updated configurations (`Resolved` vs `Still present`).
4. **Resilient AI Fallback Architecture:** Optional Amazon Bedrock integration automatically falls back to deterministic template explanations on socket timeout, `AccessDeniedException`, or missing credentials without throwing HTTP 500 errors.
5. **Interactive Simulated Alexa+ Experience:** Natural language interaction following a structured 9-step agentic workflow.
6. **Zero-Build Lightweight Frontend:** Responsive SPA built with pure HTML5, CSS3, and Vanilla JavaScript &mdash; zero npm dependencies.

---

### 5. Technical Architecture Summary

```text
+---------------------------------------------------------------------------------+
|                         ShipSafe AI Frontend (Web UI)                           |
|        - Overview Dashboard          - Static S3 Config Analyzer                |
|        - Security Findings Detail    - Remediation Verifier                     |
|        - Browser-Local History       - Simulated Alexa+ Assistant Experience    |
+---------------------------------------------------------------------------------+
                                       |
                              REST JSON HTTP API
                                       |
                                       v
+---------------------------------------------------------------------------------+
|                             FastAPI Backend                                     |
|                                                                                 |
|   +-----------------------+     +-----------------------+                       |
|   |   GET /api/health     |     |   GET /api/features   |                       |
|   +-----------------------+     +-----------------------+                       |
|   +-----------------------+     +-----------------------+                       |
|   |   POST /api/analyze   |     |   POST /api/verify    |                       |
|   +-----------------------+     +-----------------------+                       |
|   +-----------------------+     +-----------------------+                       |
|   |  POST /assistant/chat |     | GET /explainer/status |                       |
|   +-----------------------+     +-----------------------+                       |
|   +-----------------------+                                                     |
|   | POST /explain/finding |                                                     |
|   +-----------------------+                                                     |
|                                                                                 |
|   +-------------------------------------------------------------------------+   |
|   |                    Security Explanation Service                         |   |
|   |                                                                         |   |
|   |    [BEDROCK_ENABLED=true]                   [BEDROCK_ENABLED=false]     |   |
|   |              |                                         |                |   |
|   |              v                                         v                |   |
|   |   +---------------------+                    +---------------------+    |   |
|   |   |   Amazon Bedrock    |                    |    Deterministic    |    |   |
|   |   | Explanation Provider|                    |    Template Engine  |    |   |
|   |   | (boto3 Bedrock SDK) |                    | (100% Free Fallback)|    |   |
|   |   +---------------------+                    +---------------------+    |   |
|   |              |                                         ^                |   |
|   |              +----[On Timeout / AccessDenied / Err]----+                |   |
|   |                            (Safe Fallback)                              |   |
|   +-------------------------------------------------------------------------+   |
+---------------------------------------------------------------------------------+
                                       |
                         Zero Required Cloud Services
                                       |
                                       v
+---------------------------------------------------------------------------------+
|                     Synthetic AWS Configuration Payloads                        |
|   - samples/insecure_s3_config.json                                             |
|   - samples/secure_s3_config.json                                               |
+---------------------------------------------------------------------------------+
```

---

### 6. List of Technologies Actually Used
- **Language:** Python 3.11+ (tested on Python 3.11, 3.12, 3.14)
- **Web Framework:** FastAPI (v0.110+)
- **ASGI Server:** Uvicorn (v0.28+)
- **Data Validation & Typing:** Pydantic v2 (v2.6+)
- **AWS Python SDK:** Boto3 (v1.34+) & Botocore (Bedrock Runtime client)
- **Testing Framework:** Pytest (v8.0+) & HTTPX (v0.27+)
- **Frontend Stack:** Vanilla HTML5, modern CSS3 (custom CSS variables & flexbox/grid), Vanilla JavaScript (ES6+ fetch API, `localStorage`)
- **Containerization:** Docker & Docker Compose (`python:3.11-slim`, non-root user `shipsafe`)
- **CI/CD:** GitHub Actions (matrix testing on Python 3.11 and 3.12)
- **License:** MIT Open Source License

---

### 7. Explanation of the Simulated Alexa+ Experience
The **ShipSafe Assistant** models a voice-first cloud security copilot designed for the **Amazon Developer Hackathon Alexa+ Track**:
- **Why a Simulation?** Because direct production integration with consumer-facing Alexa+ devices and private preview developer consoles is restricted to closed-preview partners, hackathon participants operate via simulated web or Streamable HTTP client paths.
- **9-Step Agentic Workflow:**
  1. *Inspect:* Ingests synthetic JSON configuration.
  2. *Execute:* Runs deterministic rule engine checks.
  3. *Prioritize:* Isolates top vulnerabilities (e.g. `S3-PAB-001`, `S3-POL-001`).
  4. *Explain:* Details concrete evidence and architectural blast radius.
  5. *Remediate:* Generates actionable hardening guidance.
  6. *Ingest:* Accepts candidate remediated configuration.
  7. *Re-evaluate:* Reruns entire rule engine against the candidate file.
  8. *Compare:* Evaluates whether targeted rules still trigger.
  9. *Synthesize:* Returns final verification status (`ALL_RESOLVED`, `PARTIALLY_RESOLVED`).
- **Grounded Truth:** The assistant cannot fabricate findings or falsely claim compliance; it is bound directly to backend analysis and verification responses.
- **Suggested Prompt Chips:** Provides single-click prompts matching common developer voice interactions (*"What is the most serious issue?"*, *"Show me the evidence"*, *"Did the fix resolve the original issue?"*).

---

### 8. Setup & Testing Guide for Judges

#### Prerequisites
- Python 3.11 or newer (Windows, macOS, or Linux)
- Git

#### Quickstart in 4 Steps:
```powershell
# 1. Clone & enter repository
git clone https://github.com/YOUR_GITHUB_USERNAME/shipsafe-ai.git
cd shipsafe-ai

# 2. Set up virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1    # On Linux/macOS: source .venv/bin/activate

# 3. Install dependencies
pip install -r backend/requirements.txt

# 4. Start backend server
python -m uvicorn app.main:app --app-dir backend --reload --host 127.0.0.1 --port 8000
```

#### Launch the UI:
Open `frontend/index.html` directly in your browser, or visit [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) for the interactive Swagger API documentation.

#### Run Automated Tests:
```powershell
python -m pytest backend/tests -v
```
**Outcome:** **66 passed tests in ~1.2s** (100% offline, zero cloud credentials required).

---

### 9. Demo-Video Script (Under 3 Minutes / 150 Seconds)

- **0:00 - 0:25 (25s) | Introduction:**  
  *On-screen:* ShipSafe AI Dashboard with `API Status: Healthy`.  
  *Narration:* "Welcome to ShipSafe AI &mdash; Secure Every Change Before It Ships. Cloud misconfigurations remain the leading cause of data breaches. Most scanners alert too late or demand active IAM credentials. ShipSafe AI is an offline, pre-flight security advisor that reviews configurations locally and verifies remediations through real rule re-execution."
- **0:25 - 0:50 (25s) | Insecure Configuration Analysis:**  
  *On-screen:* Open Analyzer, load `insecure_s3_config.json`, click "Analyze Configuration".  
  *Narration:* "We load a synthetic S3 bucket configuration with disabled Public Access Block flags, open ACLs, and suspended versioning. Clicking Analyze instantly triggers our deterministic rule engine, detecting 5 confirmed risks."
- **0:50 - 1:15 (25s) | Concrete Evidence & Rationale:**  
  *On-screen:* Expand `S3-PAB-001` and `S3-POL-001` finding cards.  
  *Narration:* "Every finding is grounded in concrete evidence. For S3-PAB-001, we see the exact four disabled flags extracted from our JSON payload. It explains the blast radius &mdash; public exposure &mdash; and gives explicit remediation instructions."
- **1:15 - 1:40 (25s) | Simulated Alexa+ Assistant:**  
  *On-screen:* Navigate to ShipSafe Assistant, click *"What is the most serious issue?"*, then *"Explain why this configuration is risky."*  
  *Narration:* "For the Alexa+ Track, we built ShipSafe Assistant &mdash; an in-browser conversational simulation following a 9-step agentic workflow. It isolates the top vulnerability and synthesizes risk explanations using deterministic templates or Amazon Bedrock."
- **1:40 - 2:00 (20s) | Remediation Guidance:**  
  *On-screen:* Click *"How can I fix the public-access issue?"*, click *"Load Corrected Configuration"*.  
  *Narration:* "The assistant provides actionable steps: enable all 4 Public Access Block settings, enforce TLS via bucket policy, and enable KMS encryption. We transition directly into the verifier."
- **2:00 - 2:20 (20s) | Rule Re-Execution Verification:**  
  *On-screen:* Submit `secure_s3_config.json` in the Verifier, click "Verify Fixes".  
  *Narration:* "Rather than assuming the fix worked, POST /api/verify re-runs the rule catalog fresh against the updated configuration to verify whether each target issue is genuinely resolved."
- **2:20 - 2:30 (10s) | Final Verification Status & Conclusion:**  
  *On-screen:* Green `ALL RESOLVED` banner and resolution cards.  
  *Narration:* "All targeted issues are confirmed Resolved! The configuration is hardened and ready to ship. ShipSafe AI: Secure Every Change Before It Ships. Thank you!"

---

### 10. Developer Product Feedback (Mandatory Hackathon Section)

#### A. AWS SDK for Python (`boto3` & `botocore` Bedrock Runtime)
- **What we used it for:** Integrated `boto3.client("bedrock-runtime")` to optionally invoke foundation models (`anthropic.claude-3-haiku-20240307-v1:0` and `amazon.titan-text-express-v1`) for synthesizing natural language explanations of static security findings.
- **What worked well:**
  - Standardized client initialization and clean configuration via `botocore.config.Config(retries=..., connect_timeout=..., read_timeout=...)` made setting strict timeouts straightforward.
  - Streaming request/response body pattern (`response["body"].read()`) was predictable and easy to deserialize.
- **Friction points & What got in our way:**
  - *Payload Variance:* Different model families require distinct request formats (e.g. Anthropic Claude 3 requires the Messages API payload `{"anthropic_version": "bedrock-2023-05-31", "messages": [...]}`, while Amazon Titan requires `{"inputText": "...", "textGenerationConfig": {...}}`). A unified abstraction in the SDK across text-generation foundation models would significantly reduce boilerplate.
  - *Exception Introspection:* On certain connection errors (e.g. `ReadTimeoutError`), `e.response` is `None` rather than a dictionary, which can trigger subtle `AttributeError` bugs if not carefully guarded before accessing `e.response.get("Error")`.
- **Onboarding Experience & Would we build with it again?**
  - "Zero to hello world" took under 15 minutes once model access was configured in AWS console.
  - Yes, we would build with Bedrock again &mdash; the low latency of Claude 3 Haiku on Bedrock is outstanding for pre-commit developer tools.

#### B. Simulated Alexa+ Conversational Pattern (Web & Agentic Workflow)
- **What we used it for:** Modeled a voice-first conversational developer advisor implementing tool-grounded question answering, risk explanation, and remediation verification.
- **What worked well:**
  - The conversational paradigm is intuitive for developers: asking *"What is the most serious issue?"* or *"Did the fix resolve the original issue?"* is much faster than manually sifting through raw JSON outputs.
  - Prompt chips and structured card responses bridge the gap between voice prompts and rich visual evidence display.
- **Friction points & What got in our way:**
  - *Private Preview Console Access:* Direct deployment to the official Alexa+ hardware console was unavailable during the hackathon for independent developers. Having a public cloud emulator or sandbox CLI for Alexa+ tool-calling would streamline local development.
- **Onboarding Experience & Would we build with it again?**
  - Building the multi-step agentic conversation was smooth and enjoyable. We would definitely build production developer agents with this conversational pattern once the open Alexa+ agent standard is broadly accessible.

---

### 11. Eligibility & Scope Declarations
- **AWS Builder Mini-Challenge Eligibility:** ShipSafe AI contains an implemented Amazon Bedrock integration (`AmazonBedrockExplanationProvider` using `boto3` Bedrock Runtime), supporting Claude 3 and Titan. However, in keeping with hackathon integrity guidelines:
  - Automated tests mock Bedrock calls to prevent paid charges.
  - Live invocation requires explicit user configuration (`BEDROCK_ENABLED=true`) with valid AWS credentials.
  - If the judges require live production AWS calls on an active AWS account without local mock verification, evaluate this project under the Primary Track and Open Source Mini-Challenge.
- **Alexa+ Track Eligibility:** Fully satisfied through the complete 9-step simulated agentic web experience with natural language routing, prompt chips, and real backend tool execution.
