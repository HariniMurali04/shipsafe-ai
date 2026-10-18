# ShipSafe AI &mdash; System Architecture &amp; Foundation

> **Tagline:** Secure Every Change Before It Ships.  
> **Mission:** Intelligent AWS configuration security and deployment-readiness advisor.

---

## 1. Overview

ShipSafe AI analyzes AWS resource configurations (such as S3 buckets) to detect dangerous misconfigurations before they reach production environments. It provides developers with:
1. **Clear Risk Explanations:** Pinpoints why a configuration is vulnerable.
2. **Remediation Blueprints:** Supplies secure, hardened configuration templates.
3. **Diff Verification:** Checks whether candidate fixes fully resolve identified risks without creating regressions.
4. **Conversational Assistant:** Simulated Alexa+ voice-first developer advisor.
5. **Optional AI Explanation Provider:** Pluggable Amazon Bedrock integration with automatic, zero-cost deterministic fallback.

---

## 2. System Architecture

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

## 3. Explanation Architecture & Amazon Bedrock Integration

ShipSafe AI implements a decoupled explanation provider architecture under `backend/app/explainer/`:

```text
               +-----------------------------+
               |   BaseExplanationProvider   | (ABC)
               +-----------------------------+
                              ^
                              |
              +---------------+---------------+
              |                               |
+-----------------------------+ +-----------------------------+
| DeterministicExplanation    | | AmazonBedrockExplanation    |
| Provider (Default Fallback) | | Provider (Optional AWS)     |
+-----------------------------+ +-----------------------------+
```

### Safety & Grounding Constraints
1. **Evidence-Grounded Only:** The AI explainer receives structured findings and evidence produced exclusively by the deterministic rule engine.
2. **Zero Mutation Authority:** The AI explainer cannot modify severities, alter finding counts, invent unverified risks, or declare a finding resolved.
3. **Resilient Transparent Fallback:** If Bedrock is disabled, unconfigured, throttled, times out, or receives `AccessDeniedException`, the service automatically falls back to `DeterministicExplanationProvider` without raising HTTP 500 errors.
4. **Credential Privacy:** AWS credentials and session tokens are never logged or echoed in fallback rationale.

---

## 4. Amazon Bedrock Prerequisites & Configuration

| Parameter | Default | Purpose |
| :--- | :--- | :--- |
| `BEDROCK_ENABLED` | `false` | Master toggle. Must be explicitly set to `true` to activate Bedrock. |
| `BEDROCK_REGION` | `us-east-1` | AWS region hosting the target Bedrock foundation model. |
| `BEDROCK_MODEL_ID` | `anthropic.claude-3-haiku-20240307-v1:0` | Target model identifier (supports Claude 3 and Titan). |
| `BEDROCK_MAX_TOKENS` | `400` | Token limit per explanation call. |
| `BEDROCK_TEMPERATURE` | `0.0` | Sampling temperature (0.0 for strict deterministic output). |
| `BEDROCK_TIMEOUT_SECONDS` | `5.0` | Socket read/connect timeout before triggering fallback. |

### AWS Prerequisites
- **AWS Account:** Active account with Amazon Bedrock enabled in target region.
- **Model Access:** Model access granted via the AWS Bedrock Console (**Bedrock > Model access**).
- **IAM Permission:** Required permission: `bedrock:InvokeModel` on the model ARN.
- **Cost Notice:** Bedrock calls incur AWS per-token API charges. When `BEDROCK_ENABLED=false` (default), ShipSafe AI is 100% free with zero network dependencies.

---

## 5. Synthetic Evaluation Philosophy
ShipSafe AI is designed to audit static resource representations (IaC outputs, CloudFormation/Terraform JSON, CLI query dumps) without making live AWS API calls. This enables:
- **Zero AWS Credential Risk:** No keys or secrets needed locally or in CI pipelines.
- **Zero Cloud Costs:** Fully local execution during development and testing.
- **Pre-deployment Verification:** Immediate feedback before shipping cloud changes.
