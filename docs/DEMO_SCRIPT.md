# ShipSafe AI &mdash; Hackathon Video Demonstration Script

> **Target Duration:** 2 minutes and 30 seconds (150 seconds)  
> **Tagline:** Secure Every Change Before It Ships.  
> **Track:** Amazon Developer Hackathon &mdash; Alexa+ Track Simulation

---

## Demonstration Timeline Overview

| Timestamp | Phase | On-Screen Action | Key Talking Point |
| :--- | :--- | :--- | :--- |
| **0:00 - 0:25** | **1. Project Introduction** | Browser displaying ShipSafe AI Dashboard Overview | Problem: Cloud breaches happen before deployment. ShipSafe AI is a zero-credential pre-flight security advisor. |
| **0:25 - 0:50** | **2. Analyzing Insecure Config** | Click "Analyzer", load `insecure_s3_config.json`, click "Analyze" | Deterministic rule engine inspects JSON, detecting 5 confirmed risks without live AWS keys. |
| **0:50 - 1:15** | **3. Actual Security Findings** | Expand `S3-PAB-001` and `S3-POL-001` finding cards | Real concrete evidence extracted from payload: 4 disabled PAB flags, wildcard `*` principal, unencrypted rules. |
| **1:15 - 1:40** | **4. Conversational Assistant** | Click "ShipSafe Assistant", ask: *"What is the most serious issue?"* | Voice-first simulation (Alexa+ Track) isolates the critical vulnerability and explains the blast radius. |
| **1:40 - 2:00** | **5. Recommended Remediation** | Click prompt: *"How can I fix the public-access issue?"* | Actionable guidance: enable 4 PAB flags, add TLS deny condition, enable KMS encryption. |
| **2:00 - 2:20** | **6. Verifying Corrected Config** | Switch to Verifier, load `secure_s3_config.json`, click "Verify Fixes" | Real rule re-execution (`POST /api/verify`) confirms fixes against original findings. |
| **2:20 - 2:30** | **7. Final Verification Status** | Display `ALL_RESOLVED` status banner and summary card | 100% verified resolution before shipping to production. Zero guesswork. |

---

## Detailed Step-by-Step Script

### Part 1: Project Introduction & Problem Statement (0:00 &ndash; 0:25)
- **On-Screen Display:** Open [http://127.0.0.1:3000](http://127.0.0.1:3000) showing the ShipSafe AI Dashboard with `API Status: Healthy`.
- **Presenter Narration:**
  > *"Welcome to ShipSafe AI &mdash; Secure Every Change Before It Ships. Cloud misconfigurations remain the number one cause of cloud data breaches. Most security tools only alert after resources are deployed, or require live IAM credentials just to inspect a configuration.*  
  > *ShipSafe AI acts as an intelligent pre-flight security advisor. It audits synthetic AWS configuration files locally, explains risks with concrete evidence, and verifies fixes through real rule re-execution &mdash; requiring zero cloud credentials and incurring zero cloud costs."*

---

### Part 2: Analyzing Insecure Sample Configuration (0:25 &ndash; 0:50)
- **On-Screen Action:**
  1. Click **Configuration Analyzer** in the navigation bar.
  2. Select the **Insecure S3** template from the dropdown selector.
  3. Show the JSON editor populated with `insecure_s3_config.json`.
  4. Click the blue **Analyze Configuration** button.
- **Presenter Narration:**
  > *"Here we have an insecure S3 bucket configuration. Notice that Public Access Block flags are disabled, encryption rules are empty, and object versioning is suspended.*  
  > *Let's click Analyze Configuration. Instantly, our deterministic rule engine parses the JSON, executes 14 baseline security checks, and identifies 5 confirmed security risks."*

---

### Part 3: Inspecting Actual Security Findings (0:50 &ndash; 1:15)
- **On-Screen Action:**
  1. The app automatically scrolls to **Security Findings**.
  2. Highlight the `RISKS DETECTED` verdict banner.
  3. Click to expand finding **`S3-PAB-001`** (Critical).
  4. Point out the extracted evidence box showing `{"block_public_acls": false, "ignore_public_acls": false...}`.
  5. Click to expand **`S3-POL-001`** showing the wildcard Principal `*`.
- **Presenter Narration:**
  > *"Unlike generic scanners, ShipSafe AI never returns hardcoded or fabricated results. Look at S3-PAB-001: it extracts the exact four disabled flags directly from our payload as concrete proof. It explains why it matters: the bucket is open to the internet. And it provides step-by-step remediation instructions."*

---

### Part 4: Conversational Explanation (Simulated Alexa+ Experience) (1:15 &ndash; 1:40)
- **On-Screen Action:**
  1. Click **ShipSafe Assistant** in the top navigation.
  2. Click the suggested prompt chip: *"What is the most serious issue?"*
  3. The assistant replies in real time with the prioritized finding and card.
  4. Click the prompt chip: *"Explain why this configuration is risky."*
- **Presenter Narration:**
  > *"For the Amazon Developer Hackathon Alexa+ Track, we built ShipSafe Assistant &mdash; an interactive, voice-first simulation. Developers can ask conversational questions like: 'What is the most serious issue?'*  
  > *The assistant executes a controlled 9-step agentic workflow grounded in our deterministic backend findings. It operates with zero paid API keys using our deterministic template engine, or with Amazon Bedrock when enabled."*

---

### Part 5: Recommended Correction (1:40 &ndash; 2:00)
- **On-Screen Action:**
  1. In the Assistant chat, click: *"How can I fix the public-access issue?"*
  2. The assistant responds with the hardening recipe.
  3. Click the button inside the chat: **"Load Corrected Configuration"** to transition to the Verifier.
- **Presenter Narration:**
  > *"When asked how to fix it, the assistant provides a concrete remediation recipe: enable all four Public Access Block flags, enforce TLS by denying insecure transport, and enable KMS encryption with bucket keys."*

---

### Part 6: Submitting Corrected Configuration (2:00 &ndash; 2:20)
- **On-Screen Action:**
  1. The screen transitions to **Remediation Verification**.
  2. The editor contains `secure_s3_config.json` with active target rules: `S3-PAB-001`, `S3-POL-001`, `S3-ENC-001`, `S3-VER-001`.
  3. Click **Verify Fixes Against S3 Configuration**.
- **Presenter Narration:**
  > *"Now we submit our corrected configuration. ShipSafe AI doesn't just assume the fix worked &mdash; it calls POST /api/verify, rerunning the entire rule engine fresh against the updated JSON to verify each specific rule."*

---

### Part 7: Final Verification Status & Conclusion (2:20 &ndash; 2:30)
- **On-Screen Action:**
  1. The green **`ALL RESOLVED`** status banner appears.
  2. Show the resolution breakdown: `4 Resolved`, `0 Still Present`.
  3. Show the green checkmark cards confirming each rule no longer triggers.
- **Presenter Narration:**
  > *"All 4 targeted risks are confirmed Resolved! The configuration now complies with our evaluated baseline, ready to deploy.*  
  > *ShipSafe AI: Secure Every Change Before It Ships. Thank you!"*
