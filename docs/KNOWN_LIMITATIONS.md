# ShipSafe AI &mdash; Known Limitations &amp; Scope Disclaimers

> **Tagline:** Secure Every Change Before It Ships.  
> **Status:** Hackathon Demonstration &amp; Static Pre-Flight Advisor (Non-Production)

---

## 1. Static Synthetic Scope & Resource Coverage

1. **S3 Bucket Focus:** The deterministic security engine evaluates synthetic JSON definitions representing `AWS::S3::Bucket` resources. It does not evaluate other AWS service configurations (such as EC2 instances, IAM roles/users, RDS databases, or VPC security groups).
2. **Static Configuration vs. Runtime State:** ShipSafe AI audits static configuration declarations (such as Infrastructure as Code templates or CLI query exports). It does not inspect dynamic runtime state, active network traffic, or S3 object metadata.
3. **No Live AWS Mutation:** ShipSafe AI does not call mutating AWS APIs, deploy resources, or modify cloud environments.

---

## 2. Security Boundary & Guarantee Disclaimers

1. **No Guarantee of Absolute Cloud Security:** Passing all static checks confirms that the submitted JSON complies with ShipSafe AI's evaluated baseline rules. It does **not** guarantee that the S3 bucket is immune to cloud security vulnerabilities.
2. **Uninspected Cloud Boundaries:** A bucket configuration that passes ShipSafe AI checks could still be accessible or vulnerable if:
   - AWS Organizations Service Control Policies (SCPs) restrict or override bucket behavior.
   - IAM user/role policies grant unexpected cross-account permissions.
   - VPC endpoint policies restrict access in ways not declared in the bucket policy.
   - KMS key policies for customer-managed keys (CMKs) permit broader decryption access.
3. **Not a Certified Compliance Auditor:** ShipSafe AI is an educational project and hackathon demonstration tool. It is not certified for PCI-DSS, SOC 2, HIPAA, or ISO 27001 formal audits.

---

## 3. Simulated Alexa+ Assistant Scope

1. **In-Browser Web Simulation:** ShipSafe Assistant is an interactive, browser-based simulation built specifically for the **Amazon Developer Hackathon (Alexa+ Track)**.
2. **Not an Official Alexa Service:** The assistant does **not** connect to official Amazon Alexa devices, Amazon Echo hardware, or the Amazon Alexa+ cloud voice service.
3. **Controlled Agentic Boundaries:** The conversational assistant operates on a strict 9-step agentic workflow grounded in real backend rule results. It is intentionally constrained from speculating or generating unverified findings.

---

## 4. Optional Amazon Bedrock Integration

1. **Disabled by Default:** Amazon Bedrock is strictly opt-in (`BEDROCK_ENABLED=false`). When disabled, ShipSafe AI runs purely on the built-in, zero-cost deterministic template engine.
2. **Prerequisites for Live Usage:** Enabling Bedrock requires an active AWS account, manual model access approval in the AWS Bedrock Console (e.g. for Anthropic Claude 3 Haiku), and IAM `bedrock:InvokeModel` permissions.
3. **Billing Notice:** When enabled, Amazon Bedrock incurs AWS per-token API charges. ShipSafe AI will never automatically upgrade an account or enable paid services.
4. **Deterministic Source of Truth:** The AI layer functions solely as an explanation synthesizer. It cannot modify rule severities, alter finding counts, invent evidence, or mark findings resolved.

---

## 5. Storage & Persistence

1. **Browser-Local History Only:** Analysis history is stored exclusively in the user's browser `localStorage`.
2. **No Remote Database:** ShipSafe AI does not operate a persistent backend database (e.g. PostgreSQL, DynamoDB). Clearing browser cache or switching devices resets local history.
3. **Session Context:** The assistant maintains conversational context within the active browser session. Refreshing the browser resets the conversational thread.

---

## 6. Pre-Submission Verification Summary

All known limitations are transparently documented in the application UI, API responses, `README.md`, and this document.
ShipSafe AI is ready for demonstration and evaluation according to hackathon criteria.
