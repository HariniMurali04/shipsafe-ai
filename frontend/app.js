/**
 * ShipSafe AI - Developer Cloud Security Dashboard
 * Tagline: Secure Every Change Before It Ships.
 *
 * Handles:
 * 1. Multi-section SPA routing (Overview, Analyzer, Findings, Verification, History)
 * 2. API integration (/api/health, /api/features, /api/analyze, /api/verify)
 * 3. File upload & JSON editor formatting
 * 4. Client-side & backend 422 validation reporting
 * 5. Deterministic findings inspection with evidence & remediation
 * 6. Rule re-execution verification workflow
 * 7. Browser-local storage history management (localStorage)
 */

const API_BASE_URL = "http://127.0.0.1:8000";
const HISTORY_STORAGE_KEY = "shipsafe_ai_local_history_v1";

// ============================================================================
// Synthetic Configuration Sample Templates
// ============================================================================
const SAMPLES = {
  insecure: {
    "_notice": "SYNTHETIC DEMONSTRATION ARTIFACT ONLY. NOT A REAL AWS RESOURCE OR ACCOUNT.",
    "configuration_type": "AWS::S3::Bucket",
    "metadata": {
      "resource_id": "synthetic-bucket-insecure-demo-01",
      "bucket_name": "synthetic-demo-unprotected-app-uploads",
      "region": "us-east-1",
      "environment": "synthetic-testing"
    },
    "configurations": {
      "public_access_block": {
        "block_public_acls": false,
        "ignore_public_acls": false,
        "block_public_policy": false,
        "restrict_public_buckets": false
      },
      "access_control_list": {
        "grants": [
          {
            "grantee": {
              "type": "Group",
              "uri": "http://acs.amazonaws.com/groups/global/AllUsers"
            },
            "permission": "READ"
          }
        ]
      },
      "server_side_encryption": {
        "rules": []
      },
      "versioning": {
        "status": "Suspended",
        "mfa_delete": "Disabled"
      },
      "server_access_logging": {
        "enabled": false
      },
      "bucket_policy": {
        "version": "2012-10-17",
        "statement": [
          {
            "sid": "AllowPublicReadAll",
            "effect": "Allow",
            "principal": "*",
            "action": ["s3:GetObject"],
            "resource": "arn:aws:s3:::synthetic-demo-unprotected-app-uploads/*"
          }
        ]
      }
    }
  },

  secure: {
    "_notice": "SYNTHETIC DEMONSTRATION ARTIFACT ONLY. NOT A REAL AWS RESOURCE OR ACCOUNT.",
    "configuration_type": "AWS::S3::Bucket",
    "metadata": {
      "resource_id": "synthetic-bucket-secure-demo-01",
      "bucket_name": "synthetic-demo-secure-app-uploads",
      "region": "us-east-1",
      "environment": "synthetic-testing"
    },
    "configurations": {
      "public_access_block": {
        "block_public_acls": true,
        "ignore_public_acls": true,
        "block_public_policy": true,
        "restrict_public_buckets": true
      },
      "access_control_list": {
        "grants": []
      },
      "server_side_encryption": {
        "rules": [
          {
            "apply_server_side_encryption_by_default": {
              "sse_algorithm": "aws:kms",
              "kms_master_key_id": "arn:aws:kms:us-east-1:111122223333:key/synthetic-sample-key-id"
            },
            "bucket_key_enabled": true
          }
        ]
      },
      "versioning": {
        "status": "Enabled",
        "mfa_delete": "Disabled"
      },
      "server_access_logging": {
        "enabled": true,
        "target_bucket": "synthetic-demo-central-access-logs",
        "target_prefix": "synthetic-demo-secure-app-uploads/"
      },
      "bucket_policy": {
        "version": "2012-10-17",
        "statement": [
          {
            "sid": "EnforceTLSRequestsOnly",
            "effect": "Deny",
            "principal": "*",
            "action": "s3:*",
            "resource": [
              "arn:aws:s3:::synthetic-demo-secure-app-uploads",
              "arn:aws:s3:::synthetic-demo-secure-app-uploads/*"
            ],
            "condition": {
              "Bool": {
                "aws:SecureTransport": "false"
              }
            }
          }
        ]
      }
    }
  },

  missing: {
    "_notice": "SYNTHETIC DEMONSTRATION ARTIFACT ONLY. MISSING EVIDENCE EXAMPLE.",
    "configuration_type": "AWS::S3::Bucket",
    "metadata": {
      "resource_id": "synthetic-bucket-incomplete-demo-01",
      "bucket_name": "synthetic-demo-partially-configured-bucket"
    },
    "configurations": {
      "versioning": {
        "status": "Enabled"
      }
    }
  },

  blank: {
    "configuration_type": "AWS::S3::Bucket",
    "metadata": {
      "resource_id": "custom-s3-bucket-01",
      "bucket_name": "my-app-bucket"
    },
    "configurations": {
      "public_access_block": {
        "block_public_acls": true,
        "ignore_public_acls": true,
        "block_public_policy": true,
        "restrict_public_buckets": true
      },
      "server_side_encryption": {
        "rules": [
          {
            "apply_server_side_encryption_by_default": {
              "sse_algorithm": "AES256"
            }
          }
        ]
      }
    }
  }
};

// Application State
let activeAnalysisResult = null;
let currentRawConfig = null;

// ============================================================================
// Initialization & Navigation
// ============================================================================
document.addEventListener("DOMContentLoaded", () => {
  setupNavigation();
  setupEditor();
  setupEventListeners();
  loadLocalHistory();
  checkHealth();
  fetchCapabilities();

  // Load insecure sample by default into editor
  loadSampleIntoEditor("insecure");
});

function setupNavigation() {
  const navLinks = document.querySelectorAll(".nav-link");
  navLinks.forEach((link) => {
    link.addEventListener("click", (e) => {
      e.preventDefault();
      const targetSection = link.getAttribute("data-target");
      navigateToSection(targetSection);
    });
  });

  // Handle URL hash on initial load
  const hash = window.location.hash.replace("#", "");
  if (hash && document.getElementById(`section-${hash}`)) {
    navigateToSection(hash);
  }
}

function navigateToSection(sectionId) {
  const targetEl = document.getElementById(`section-${sectionId}`);
  if (!targetEl) return;

  // Toggle active class on sections
  document.querySelectorAll(".dashboard-section").forEach((sec) => sec.classList.remove("active"));
  targetEl.classList.add("active");

  // Toggle active class on nav links
  document.querySelectorAll(".nav-link").forEach((link) => {
    if (link.getAttribute("data-target") === sectionId) {
      link.classList.add("active");
    } else {
      link.classList.remove("active");
    }
  });

  window.location.hash = sectionId;
  window.scrollTo({ top: 0, behavior: "smooth" });
}

// ============================================================================
// Editor & Sample Management
// ============================================================================
function setupEditor() {
  const editor = document.getElementById("json-editor");
  const verifyEditor = document.getElementById("verify-json-editor");
  const feedback = document.getElementById("editor-validation-feedback");
  const verifyFeedback = document.getElementById("verify-validation-feedback");

  if (editor) {
    editor.addEventListener("input", () => validateJsonContent(editor.value, feedback));
  }
  if (verifyEditor) {
    verifyEditor.addEventListener("input", () => validateJsonContent(verifyEditor.value, verifyFeedback));
  }

  // Pre-load verify editor with secure baseline
  if (verifyEditor) {
    verifyEditor.value = JSON.stringify(SAMPLES.secure, null, 2);
  }
}

function validateJsonContent(text, feedbackEl) {
  if (!feedbackEl) return true;
  if (!text || text.trim() === "") {
    feedbackEl.className = "feedback-indicator feedback-error";
    feedbackEl.innerHTML = '<span class="indicator-icon">!</span> Empty configuration';
    return false;
  }
  try {
    JSON.parse(text);
    feedbackEl.className = "feedback-indicator feedback-valid";
    feedbackEl.innerHTML = '<span class="indicator-icon">✓</span> Valid JSON format';
    return true;
  } catch (err) {
    feedbackEl.className = "feedback-indicator feedback-error";
    feedbackEl.innerHTML = `<span class="indicator-icon">✗</span> JSON Syntax Error: ${escapeHtml(err.message)}`;
    return false;
  }
}

function loadSampleIntoEditor(sampleKey) {
  const editor = document.getElementById("json-editor");
  const feedback = document.getElementById("editor-validation-feedback");
  if (!editor || !SAMPLES[sampleKey]) return;

  editor.value = JSON.stringify(SAMPLES[sampleKey], null, 2);
  validateJsonContent(editor.value, feedback);
}

function setupEventListeners() {
  // Sample selector dropdown
  const sampleSelector = document.getElementById("sample-selector");
  if (sampleSelector) {
    sampleSelector.addEventListener("change", (e) => {
      loadSampleIntoEditor(e.target.value);
    });
  }

  // File Upload
  const fileInput = document.getElementById("file-upload");
  if (fileInput) {
    fileInput.addEventListener("change", handleFileUpload);
  }

  // Format JSON Buttons
  const formatBtn = document.getElementById("format-json-btn");
  if (formatBtn) {
    formatBtn.addEventListener("click", () => formatEditorContent("json-editor"));
  }

  // Clear Editor
  const clearBtn = document.getElementById("clear-editor-btn");
  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      const editor = document.getElementById("json-editor");
      if (editor) {
        editor.value = "";
        validateJsonContent("", document.getElementById("editor-validation-feedback"));
      }
    });
  }

  // Analyze Submit Button
  const analyzeBtn = document.getElementById("analyze-submit-btn");
  if (analyzeBtn) {
    analyzeBtn.addEventListener("click", runAnalysis);
  }

  // Overview CTA Buttons
  const ctaBtn = document.getElementById("overview-cta-btn");
  if (ctaBtn) {
    ctaBtn.addEventListener("click", () => navigateToSection("analyzer"));
  }

  const assistantBtn = document.getElementById("overview-assistant-btn");
  if (assistantBtn) {
    assistantBtn.addEventListener("click", () => navigateToSection("assistant"));
  }

  const loadSampleBtn = document.getElementById("overview-load-sample-btn");
  if (loadSampleBtn) {
    loadSampleBtn.addEventListener("click", () => {
      loadSampleIntoEditor("insecure");
      navigateToSection("analyzer");
    });
  }

  // Assistant Chat Form & Prompt Chips
  const chatForm = document.getElementById("assistant-chat-form");
  if (chatForm) {
    chatForm.addEventListener("submit", (e) => {
      e.preventDefault();
      const input = document.getElementById("assistant-input");
      if (input && input.value.trim()) {
        const text = input.value.trim();
        input.value = "";
        sendAssistantChat(text);
      }
    });
  }

  const chipsContainer = document.getElementById("assistant-prompt-chips");
  if (chipsContainer) {
    chipsContainer.addEventListener("click", (e) => {
      const chip = e.target.closest(".prompt-chip");
      if (chip) {
        const promptText = chip.getAttribute("data-prompt");
        if (promptText) {
          sendAssistantChat(promptText);
        }
      }
    });
  }

  const resetChatBtn = document.getElementById("assistant-clear-btn");
  if (resetChatBtn) {
    resetChatBtn.addEventListener("click", resetAssistantChat);
  }

  const ctxInsecureBtn = document.getElementById("ctx-load-insecure-btn");
  if (ctxInsecureBtn) {
    ctxInsecureBtn.addEventListener("click", () => {
      loadSampleIntoEditor("insecure");
      updateAssistantContext("synthetic-bucket-insecure-demo-01", "Step 1: Insecure Sample Loaded");
      sendAssistantChat("Analyze my sample S3 configuration.");
    });
  }

  const ctxSecureBtn = document.getElementById("ctx-load-secure-btn");
  if (ctxSecureBtn) {
    ctxSecureBtn.addEventListener("click", () => {
      loadSampleIntoEditor("secure");
      updateAssistantContext("synthetic-bucket-secure-demo-01", "Step 6: Corrected Sample Loaded");
      sendAssistantChat("Analyze the corrected configuration.");
    });
  }

  const ctxJumpBtn = document.getElementById("ctx-jump-findings-btn");
  if (ctxJumpBtn) {
    ctxJumpBtn.addEventListener("click", () => navigateToSection("findings"));
  }

  // Send to Verification Button
  const sendToVerifyBtn = document.getElementById("findings-send-to-verify-btn");
  if (sendToVerifyBtn) {
    sendToVerifyBtn.addEventListener("click", () => {
      const verifyEditor = document.getElementById("verify-json-editor");
      const mainEditor = document.getElementById("json-editor");
      if (verifyEditor && mainEditor) {
        verifyEditor.value = mainEditor.value;
      }
      navigateToSection("verification");
    });
  }

  // Verification load secure baseline
  const verifyLoadRemediatedBtn = document.getElementById("verify-load-remediated-btn");
  if (verifyLoadRemediatedBtn) {
    verifyLoadRemediatedBtn.addEventListener("click", () => {
      const verifyEditor = document.getElementById("verify-json-editor");
      if (verifyEditor) {
        verifyEditor.value = JSON.stringify(SAMPLES.secure, null, 2);
        validateJsonContent(verifyEditor.value, document.getElementById("verify-validation-feedback"));
      }
    });
  }

  // Verify Submit Button
  const verifyBtn = document.getElementById("verify-submit-btn");
  if (verifyBtn) {
    verifyBtn.addEventListener("click", runVerification);
  }

  // Severity and Type Filters
  const severityFilter = document.getElementById("severity-filter");
  const typeFilter = document.getElementById("type-filter");
  if (severityFilter) severityFilter.addEventListener("change", applyFindingsFilters);
  if (typeFilter) typeFilter.addEventListener("change", applyFindingsFilters);

  // Clear Activity in Overview & Clear History
  const clearActivityBtn = document.getElementById("overview-clear-activity-btn");
  if (clearActivityBtn) clearActivityBtn.addEventListener("click", clearLocalHistory);

  const clearHistoryBtn = document.getElementById("history-clear-all-btn");
  if (clearHistoryBtn) clearHistoryBtn.addEventListener("click", clearLocalHistory);

  // Retry Connection Banner Button
  const retryBtn = document.getElementById("banner-retry-btn");
  if (retryBtn) retryBtn.addEventListener("click", checkHealth);

  // Refresh Capabilities Button
  const refreshCapBtn = document.getElementById("refresh-capabilities-btn");
  if (refreshCapBtn) refreshCapBtn.addEventListener("click", fetchCapabilities);
}

function handleFileUpload(e) {
  const file = e.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = (event) => {
    const editor = document.getElementById("json-editor");
    const feedback = document.getElementById("editor-validation-feedback");
    if (editor) {
      editor.value = event.target.result;
      validateJsonContent(editor.value, feedback);
    }
  };
  reader.readAsText(file);
}

function formatEditorContent(editorId) {
  const editor = document.getElementById(editorId);
  if (!editor) return;
  try {
    const parsed = JSON.parse(editor.value);
    editor.value = JSON.stringify(parsed, null, 2);
  } catch (err) {
    alert(`Cannot format: ${err.message}`);
  }
}

// ============================================================================
// API Calls: /api/analyze & /api/verify
// ============================================================================
async function runAnalysis() {
  const editor = document.getElementById("json-editor");
  const analyzeBtn = document.getElementById("analyze-submit-btn");
  const feedback = document.getElementById("editor-validation-feedback");

  if (!editor || !validateJsonContent(editor.value, feedback)) {
    alert("Please ensure the configuration editor contains valid JSON before analyzing.");
    return;
  }

  let parsedPayload;
  try {
    parsedPayload = JSON.parse(editor.value);
  } catch (err) {
    return;
  }

  setButtonLoading(analyzeBtn, true, "Analyzing...");

  try {
    const response = await fetch(`${API_BASE_URL}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(parsedPayload),
    });

    const data = await response.json();

    if (!response.ok) {
      const errMsg = data.detail ? (data.detail.message || JSON.stringify(data.detail)) : response.statusText;
      showAnalysisError(`Validation Error (HTTP ${response.status}): ${errMsg}`);
      return;
    }

    activeAnalysisResult = data;
    currentRawConfig = parsedPayload;

    // Render findings in Findings section
    renderAnalysisFindings(data);

    // Save to local browser history
    saveHistoryRecord(data, parsedPayload);

    // Navigate user directly to Findings section
    navigateToSection("findings");
  } catch (err) {
    showBackendOfflineBanner(true);
    showAnalysisError(`Network error: Could not reach backend at ${API_BASE_URL}. Ensure Uvicorn is running.`);
  } finally {
    setButtonLoading(analyzeBtn, false, "Run Security Analysis");
  }
}

function showAnalysisError(message) {
  const container = document.getElementById("findings-list-container");
  const banner = document.getElementById("findings-verdict-banner");
  const label = document.getElementById("verdict-badge-label");

  if (banner) banner.className = "verdict-banner banner-risks";
  if (label) label.textContent = "Analysis Rejected";

  if (container) {
    container.innerHTML = `
      <div class="card" style="border-left: 4px solid #ef4444;">
        <h3 style="color: #991b1b; margin-bottom: 0.5rem;">Configuration Rejected</h3>
        <p class="text-secondary">${escapeHtml(message)}</p>
      </div>
    `;
  }
}

function renderAnalysisFindings(data) {
  const container = document.getElementById("findings-list-container");
  const banner = document.getElementById("findings-verdict-banner");
  const badgeLabel = document.getElementById("verdict-badge-label");
  const resourceIdEl = document.getElementById("verdict-resource-id");
  const descEl = document.getElementById("verdict-description-text");
  const disclaimerBox = document.getElementById("findings-disclaimer-box");
  const disclaimerText = document.getElementById("findings-disclaimer-text");
  const navBadge = document.getElementById("nav-findings-badge");

  // Summary counts
  const criticalHigh = (data.findings || []).filter(f => f.severity === "CRITICAL" || f.severity === "HIGH").length;
  const mediumLow = (data.findings || []).filter(f => f.severity === "MEDIUM" || f.severity === "LOW").length;

  document.getElementById("pill-count-critical").textContent = criticalHigh;
  document.getElementById("pill-count-warning").textContent = mediumLow;
  document.getElementById("pill-count-missing").textContent = data.missing_evidence_count || 0;
  document.getElementById("pill-count-info").textContent = data.informational_count || 0;

  // Nav badge update
  if (navBadge) {
    navBadge.textContent = data.total_findings;
    navBadge.classList.toggle("hidden", data.total_findings === 0);
  }

  // Verdict styling
  if (data.evaluation_verdict === "RISKS_DETECTED") {
    banner.className = "verdict-banner banner-risks";
    badgeLabel.textContent = "Risks Detected";
    badgeLabel.className = "badge badge-CRITICAL";
    descEl.textContent = `The engine confirmed ${data.confirmed_risks_count} security risk(s) in this configuration. Remediation required before shipping.`;
  } else if (data.evaluation_verdict === "NEEDS_EVIDENCE") {
    banner.className = "verdict-banner banner-missing";
    badgeLabel.textContent = "Missing Evidence";
    badgeLabel.className = "badge badge-HIGH";
    descEl.textContent = "Required configuration blocks are omitted from this payload. Verification cannot be confirmed without evidence.";
  } else {
    banner.className = "verdict-banner banner-clear";
    badgeLabel.textContent = "No Evaluated Risks Detected";
    badgeLabel.className = "badge badge-success";
    descEl.textContent = "No risks triggered by currently evaluated deterministic rules. See scope notice below.";
  }

  resourceIdEl.textContent = `Resource ID: ${data.resource_id} (${data.configuration_type})`;

  // Disclaimer
  if (disclaimerBox && disclaimerText && data.disclaimer) {
    disclaimerText.textContent = data.disclaimer;
    disclaimerBox.classList.remove("hidden");
  }

  applyFindingsFilters();
}

function applyFindingsFilters() {
  if (!activeAnalysisResult || !activeAnalysisResult.findings) return;

  const severityFilter = document.getElementById("severity-filter")?.value || "ALL";
  const typeFilter = document.getElementById("type-filter")?.value || "ALL";
  const container = document.getElementById("findings-list-container");
  const countText = document.getElementById("findings-display-count");

  let filtered = activeAnalysisResult.findings;

  if (severityFilter !== "ALL") {
    filtered = filtered.filter(f => f.severity === severityFilter);
  }
  if (typeFilter !== "ALL") {
    filtered = filtered.filter(f => f.finding_type === typeFilter);
  }

  if (countText) {
    countText.textContent = `Showing ${filtered.length} of ${activeAnalysisResult.findings.length} finding(s)`;
  }

  if (!container) return;

  if (filtered.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">✓</div>
        <p>No findings match the selected filters.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = "";
  filtered.forEach((finding) => {
    const card = document.createElement("div");
    card.className = `finding-card severity-${finding.severity}`;

    card.innerHTML = `
      <div class="finding-header">
        <div class="finding-title-wrap">
          <span class="finding-title">${escapeHtml(finding.title)}</span>
          <span class="finding-rule-pill">Rule: ${escapeHtml(finding.rule_id)} &bull; ID: ${escapeHtml(finding.finding_id)}</span>
        </div>
        <div class="finding-badges">
          <span class="badge badge-${finding.severity}">${escapeHtml(finding.severity)}</span>
          <span class="badge badge-outline">${escapeHtml(finding.finding_type)}</span>
          <span class="badge badge-outline">Confidence: ${escapeHtml(finding.confidence)}</span>
        </div>
      </div>

      <p class="finding-desc">${escapeHtml(finding.description)}</p>

      <div class="finding-section-box">
        <div class="section-box-title">Concrete Evidence Extracted:</div>
        <pre class="evidence-content"><code>${escapeHtml(JSON.stringify(finding.evidence, null, 2))}</code></pre>
      </div>

      <div class="finding-section-box" style="background-color: #fffbeb; border-color: #fef3c7;">
        <div class="section-box-title" style="color: #92400e;">Why It Matters:</div>
        <div style="color: #78350f;">${escapeHtml(finding.why_it_matters)}</div>
      </div>

      <div class="finding-remediation-box">
        <strong>Recommended Remediation:</strong>
        <div>${escapeHtml(finding.remediation)}</div>
      </div>
    `;
    container.appendChild(card);
  });
}

// Verification Call
async function runVerification() {
  const verifyEditor = document.getElementById("verify-json-editor");
  const verifyBtn = document.getElementById("verify-submit-btn");
  const feedback = document.getElementById("verify-validation-feedback");
  const overallBadge = document.getElementById("verify-overall-badge");
  const statsBar = document.getElementById("verify-summary-stats");
  const container = document.getElementById("verify-results-container");

  if (!verifyEditor || !validateJsonContent(verifyEditor.value, feedback)) {
    alert("Please provide a valid JSON configuration in the verification editor.");
    return;
  }

  let parsedPayload;
  try {
    parsedPayload = JSON.parse(verifyEditor.value);
  } catch (err) {
    return;
  }

  setButtonLoading(verifyBtn, true, "Re-executing Checks...");

  try {
    const response = await fetch(`${API_BASE_URL}/api/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ configuration: parsedPayload }),
    });

    const data = await response.json();

    if (!response.ok) {
      alert(`Verification rejected: ${data.detail ? data.detail.message : response.statusText}`);
      return;
    }

    // Render verification outcomes
    if (data.overall_verification_status === "ALL_RESOLVED") {
      overallBadge.className = "badge badge-success";
      overallBadge.textContent = "All Issues Resolved";
    } else if (data.overall_verification_status === "PARTIALLY_RESOLVED") {
      overallBadge.className = "badge badge-warning";
      overallBadge.textContent = "Partially Resolved";
    } else {
      overallBadge.className = "badge badge-danger";
      overallBadge.textContent = "Unresolved";
    }

    document.getElementById("verify-count-resolved").textContent = data.resolved_count;
    document.getElementById("verify-count-present").textContent = data.still_present_count;
    document.getElementById("verify-count-unable").textContent = data.unable_to_verify_count;
    statsBar.classList.remove("hidden");

    // Increment verified stats counter in localStorage
    if (data.resolved_count > 0) {
      incrementVerifiedCount(data.resolved_count);
    }

    container.innerHTML = "";
    data.verification_results.forEach((item) => {
      const card = document.createElement("div");
      card.className = "verify-item-card";

      const badgeClass = {
        "Resolved": "badge-success",
        "Still present": "badge-danger",
        "Unable to verify": "badge-warning",
      }[item.status] || "badge-outline";

      card.innerHTML = `
        <div class="verify-item-info">
          <strong>${escapeHtml(item.target_id)}</strong>
          <div class="verify-item-desc">${escapeHtml(item.explanation)}</div>
        </div>
        <span class="badge ${badgeClass}">${escapeHtml(item.status)}</span>
      `;
      container.appendChild(card);
    });
  } catch (err) {
    alert(`Could not complete verification: ${err.message}`);
  } finally {
    setButtonLoading(verifyBtn, false, "Re-execute Checks (POST /api/verify)");
  }
}

// ============================================================================
// Local Storage History Management (Strictly Browser-Local)
// ============================================================================
function getLocalHistory() {
  try {
    const raw = localStorage.getItem(HISTORY_STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch (e) {
    return [];
  }
}

function saveHistoryRecord(analysisData, rawConfig) {
  try {
    const history = getLocalHistory();
    const entry = {
      id: "scan-" + Date.now(),
      timestamp: new Date().toISOString(),
      resource_id: analysisData.resource_id,
      verdict: analysisData.evaluation_verdict,
      total_findings: analysisData.total_findings,
      confirmed_risks: analysisData.confirmed_risks_count,
      missing_evidence: analysisData.missing_evidence_count,
      critical_high_count: (analysisData.findings || []).filter(f => f.severity === "CRITICAL" || f.severity === "HIGH").length,
      medium_low_count: (analysisData.findings || []).filter(f => f.severity === "MEDIUM" || f.severity === "LOW").length,
      config: rawConfig,
      analysis: analysisData,
    };

    history.unshift(entry);
    // Keep maximum 25 items locally
    const trimmed = history.slice(0, 25);
    localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(trimmed));
    loadLocalHistory();
  } catch (e) {
    console.warn("Could not save to localStorage:", e);
  }
}

function clearLocalHistory() {
  if (confirm("Are you sure you want to clear your local analysis history from this browser?")) {
    localStorage.removeItem(HISTORY_STORAGE_KEY);
    loadLocalHistory();
  }
}

function deleteHistoryRecord(id) {
  try {
    let history = getLocalHistory();
    history = history.filter(item => item.id !== id);
    localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(history));
    loadLocalHistory();
  } catch (e) {
    console.warn("Could not delete item:", e);
  }
}

function loadLocalHistory() {
  const history = getLocalHistory();
  const totalScansEl = document.getElementById("stat-total-scans");
  const criticalRisksEl = document.getElementById("stat-critical-risks");
  const mediumRisksEl = document.getElementById("stat-medium-risks");
  const verifiedCountEl = document.getElementById("stat-verified-count");

  // Overview Stats
  const totalAnalyzed = history.length;
  let totalCriticalHigh = 0;
  let totalMediumLow = 0;

  history.forEach(item => {
    totalCriticalHigh += (item.critical_high_count || 0);
    totalMediumLow += (item.medium_low_count || 0);
  });

  if (totalScansEl) totalScansEl.textContent = totalAnalyzed;
  if (criticalRisksEl) criticalRisksEl.textContent = totalCriticalHigh;
  if (mediumRisksEl) mediumRisksEl.textContent = totalMediumLow;
  if (verifiedCountEl) verifiedCountEl.textContent = getVerifiedCount();

  // Populate Overview Activity Table
  const overviewTbody = document.getElementById("overview-activity-tbody");
  const overviewTable = document.getElementById("overview-activity-table");
  const overviewEmpty = document.getElementById("overview-empty-activity");

  if (overviewTbody && overviewTable && overviewEmpty) {
    if (history.length === 0) {
      overviewTable.classList.add("hidden");
      overviewEmpty.classList.remove("hidden");
    } else {
      overviewEmpty.classList.add("hidden");
      overviewTable.classList.remove("hidden");
      overviewTbody.innerHTML = "";

      history.slice(0, 5).forEach((item) => {
        const tr = document.createElement("tr");
        const timeStr = new Date(item.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
        const verdictBadge = item.verdict === "RISKS_DETECTED"
          ? '<span class="badge badge-CRITICAL">Risks</span>'
          : item.verdict === "NEEDS_EVIDENCE"
          ? '<span class="badge badge-HIGH">Missing Ev.</span>'
          : '<span class="badge badge-success">Clear</span>';

        tr.innerHTML = `
          <td>${escapeHtml(timeStr)}</td>
          <td class="font-mono">${escapeHtml(item.resource_id)}</td>
          <td>${verdictBadge}</td>
          <td><strong class="text-critical">${item.confirmed_risks}</strong></td>
          <td>${item.missing_evidence}</td>
          <td><button class="btn btn-sm btn-secondary inspect-btn" data-id="${item.id}">Inspect</button></td>
        `;
        overviewTbody.appendChild(tr);
      });

      overviewTbody.querySelectorAll(".inspect-btn").forEach(btn => {
        btn.addEventListener("click", () => inspectHistoryItem(btn.getAttribute("data-id")));
      });
    }
  }

  // Populate Section 5 History Table
  const historyTbody = document.getElementById("history-table-tbody");
  const historyTable = document.getElementById("history-data-table");
  const historyEmpty = document.getElementById("history-empty-state");

  if (historyTbody && historyTable && historyEmpty) {
    if (history.length === 0) {
      historyTable.classList.add("hidden");
      historyEmpty.classList.remove("hidden");
    } else {
      historyEmpty.classList.add("hidden");
      historyTable.classList.remove("hidden");
      historyTbody.innerHTML = "";

      history.forEach((item) => {
        const tr = document.createElement("tr");
        const dateStr = new Date(item.timestamp).toLocaleString();
        const verdictBadge = item.verdict === "RISKS_DETECTED"
          ? '<span class="badge badge-CRITICAL">Risks Detected</span>'
          : item.verdict === "NEEDS_EVIDENCE"
          ? '<span class="badge badge-HIGH">Needs Evidence</span>'
          : '<span class="badge badge-success">Clear</span>';

        tr.innerHTML = `
          <td>${escapeHtml(dateStr)}</td>
          <td class="font-mono">${escapeHtml(item.resource_id)}</td>
          <td>${verdictBadge}</td>
          <td>${item.total_findings}</td>
          <td><strong class="text-critical">${item.confirmed_risks}</strong></td>
          <td>${item.missing_evidence}</td>
          <td>
            <button class="btn btn-sm btn-secondary history-load-btn" data-id="${item.id}">Load in Analyzer</button>
            <button class="btn btn-sm btn-secondary history-del-btn" data-id="${item.id}">Delete</button>
          </td>
        `;
        historyTbody.appendChild(tr);
      });

      historyTbody.querySelectorAll(".history-load-btn").forEach(btn => {
        btn.addEventListener("click", () => inspectHistoryItem(btn.getAttribute("data-id")));
      });
      historyTbody.querySelectorAll(".history-del-btn").forEach(btn => {
        btn.addEventListener("click", () => deleteHistoryRecord(btn.getAttribute("data-id")));
      });
    }
  }
}

function inspectHistoryItem(id) {
  const history = getLocalHistory();
  const entry = history.find(item => item.id === id);
  if (!entry) return;

  const editor = document.getElementById("json-editor");
  if (editor && entry.config) {
    editor.value = JSON.stringify(entry.config, null, 2);
    validateJsonContent(editor.value, document.getElementById("editor-validation-feedback"));
  }

  if (entry.analysis) {
    activeAnalysisResult = entry.analysis;
    renderAnalysisFindings(entry.analysis);
  }

  navigateToSection("analyzer");
}

function getVerifiedCount() {
  return parseInt(localStorage.getItem("shipsafe_ai_verified_count") || "0", 10);
}

function incrementVerifiedCount(amount) {
  const current = getVerifiedCount();
  localStorage.setItem("shipsafe_ai_verified_count", (current + amount).toString());
  const el = document.getElementById("stat-verified-count");
  if (el) el.textContent = current + amount;
}

// ============================================================================
// Service Health & Capabilities
// ============================================================================
async function checkHealth() {
  const dot = document.getElementById("system-status-dot");
  const text = document.getElementById("system-status-text");

  try {
    const res = await fetch(`${API_BASE_URL}/api/health`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    dot.className = "status-indicator-dot online";
    text.textContent = `Backend: Online (v${data.version || "0.1.0"})`;
    showBackendOfflineBanner(false);
  } catch (err) {
    dot.className = "status-indicator-dot offline";
    text.textContent = "Backend: Offline";
    showBackendOfflineBanner(true);
  }
}

function showBackendOfflineBanner(show) {
  const banner = document.getElementById("backend-offline-banner");
  if (banner) {
    banner.classList.toggle("hidden", !show);
  }
}

async function fetchCapabilities() {
  const grid = document.getElementById("capabilities-grid");
  if (!grid) return;

  try {
    const res = await fetch(`${API_BASE_URL}/api/features`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    grid.innerHTML = "";
    (data.features || []).forEach(feat => {
      const card = document.createElement("div");
      card.className = "stat-card";
      const isImpl = feat.status === "implemented";
      const badge = isImpl
        ? '<span class="badge badge-success">Implemented</span>'
        : '<span class="badge badge-outline">Roadmap</span>';

      card.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 0.5rem; margin-bottom: 0.35rem;">
          <strong style="font-size: 0.95rem; color: var(--text-main);">${escapeHtml(feat.name)}</strong>
          ${badge}
        </div>
        <p class="text-sm text-secondary" style="margin-bottom: 0.5rem;">${escapeHtml(feat.description)}</p>
        <div class="text-sm font-mono text-muted">${feat.endpoint ? escapeHtml(feat.endpoint) : "Planned Engine"}</div>
      `;
      grid.appendChild(card);
    });
  } catch (err) {
    grid.innerHTML = `<div class="empty-state text-sm">Capabilities unavailable while backend is offline.</div>`;
  }
}

// ============================================================================
// Utilities
// ============================================================================
function setButtonLoading(button, isLoading, text) {
  if (!button) return;
  button.disabled = isLoading;
  button.innerHTML = isLoading ? `<span>⏳</span> ${escapeHtml(text)}` : `<span>🔍</span> ${escapeHtml(text)}`;
}

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// ============================================================================
// ShipSafe Assistant (Simulated Alexa+ Conversational Experience)
// ============================================================================
async function sendAssistantChat(messageText) {
  const streamContainer = document.getElementById("chat-stream-container");
  const sendBtn = document.getElementById("assistant-send-btn");
  if (!streamContainer || !messageText) return;

  // 1. Render User Message
  appendUserChatMessage(messageText);

  // 2. Render Temporary Thinking Bubble
  const typingBubble = document.createElement("div");
  typingBubble.className = "chat-message message-assistant typing-bubble";
  typingBubble.innerHTML = `
    <div class="msg-avatar">🎙️</div>
    <div class="msg-bubble">
      <div class="msg-author">ShipSafe Assistant</div>
      <div class="msg-text text-muted"><em>Thinking &amp; inspecting rules...</em></div>
    </div>
  `;
  streamContainer.appendChild(typingBubble);
  streamContainer.scrollTop = streamContainer.scrollHeight;

  // 3. Prepare Payload with Current Context
  let currentConfig = null;
  const editor = document.getElementById("json-editor");
  if (editor && editor.value.trim()) {
    try {
      currentConfig = JSON.parse(editor.value);
    } catch (e) {}
  }

  const payload = {
    message: messageText,
    session_id: "browser-session-" + Date.now(),
    current_config: currentConfig || SAMPLES.insecure,
    active_finding_ids: activeAnalysisResult ? activeAnalysisResult.findings.map(f => f.finding_id) : null,
    corrected_config: SAMPLES.secure,
  };

  if (sendBtn) sendBtn.disabled = true;

  try {
    const res = await fetch(`${API_BASE_URL}/api/assistant/chat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    const data = await res.json();
    typingBubble.remove();

    if (!res.ok) {
      appendAssistantErrorMessage(`Error (HTTP ${res.status}): ${data.detail ? data.detail.message : res.statusText}`);
      return;
    }

    // 4. Render Assistant Response
    appendAssistantChatMessage(data);

    // 5. Update Context Sidebar
    updateAssistantContext(
      data.analysis_data ? data.analysis_data.resource_id : (data.verification_data ? data.verification_data.resource_id : "synthetic-s3-bucket"),
      data.agentic_step,
      data.explanation_mode
    );

    // 6. Update Prompt Chips
    if (data.suggested_prompts && data.suggested_prompts.length > 0) {
      updatePromptChips(data.suggested_prompts);
    }

    // If analysis was returned, update active app state too!
    if (data.analysis_data) {
      activeAnalysisResult = data.analysis_data;
      renderAnalysisFindings(data.analysis_data);
    }
  } catch (err) {
    typingBubble.remove();
    appendAssistantErrorMessage(`Network error: Could not reach assistant at ${API_BASE_URL}/api/assistant/chat. Ensure backend is running.`);
  } finally {
    if (sendBtn) sendBtn.disabled = false;
  }
}

function appendUserChatMessage(text) {
  const container = document.getElementById("chat-stream-container");
  if (!container) return;

  const msgDiv = document.createElement("div");
  msgDiv.className = "chat-message message-user";
  msgDiv.innerHTML = `
    <div class="msg-avatar">👤</div>
    <div class="msg-bubble">
      <div class="msg-author">You</div>
      <div class="msg-text">${escapeHtml(text)}</div>
    </div>
  `;
  container.appendChild(msgDiv);
  container.scrollTop = container.scrollHeight;
}

function appendAssistantChatMessage(data) {
  const container = document.getElementById("chat-stream-container");
  if (!container) return;

  const cardsHtml = renderAssistantCardsHtml(data.cards || []);
  const modeBadge = data.explanation_mode === "deterministic_template"
    ? '<span class="badge badge-outline" style="font-size: 0.65rem;">Deterministic Template</span>'
    : '<span class="badge badge-info" style="font-size: 0.65rem;">AI Augmented</span>';

  const msgDiv = document.createElement("div");
  msgDiv.className = "chat-message message-assistant";
  msgDiv.innerHTML = `
    <div class="msg-avatar">🎙️</div>
    <div class="msg-bubble">
      <div class="msg-author">
        ShipSafe Assistant ${modeBadge}
        <span class="text-muted" style="font-size: 0.7rem; font-weight: normal; margin-left: auto;">${escapeHtml(data.agentic_step)}</span>
      </div>
      <div class="msg-text">${escapeHtml(data.reply)}</div>
      ${cardsHtml}
    </div>
  `;
  container.appendChild(msgDiv);
  container.scrollTop = container.scrollHeight;
}

function appendAssistantErrorMessage(errorText) {
  const container = document.getElementById("chat-stream-container");
  if (!container) return;

  const msgDiv = document.createElement("div");
  msgDiv.className = "chat-message message-assistant";
  msgDiv.innerHTML = `
    <div class="msg-avatar">⚠️</div>
    <div class="msg-bubble" style="border-left: 4px solid #ef4444; background-color: #fff5f5;">
      <div class="msg-author" style="color: #991b1b;">ShipSafe Assistant &bull; Notice</div>
      <div class="msg-text" style="color: #7f1d1d;">${escapeHtml(errorText)}</div>
    </div>
  `;
  container.appendChild(msgDiv);
  container.scrollTop = container.scrollHeight;
}

function renderAssistantCardsHtml(cards) {
  if (!cards || cards.length === 0) return "";

  return cards.map(card => {
    if (card.type === "summary_card") {
      return `
        <div class="chat-embedded-card card-danger">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.35rem;">
            <strong>Target: ${escapeHtml(card.resource_id)}</strong>
            <span class="badge badge-CRITICAL">${escapeHtml(card.verdict)}</span>
          </div>
          <div style="display: flex; gap: 0.75rem; margin-top: 0.35rem;">
            <span>🚨 <strong>${card.confirmed_risks}</strong> Confirmed Risks</span>
            <span>⚠️ <strong>${card.missing_evidence}</strong> Missing Evidence</span>
          </div>
        </div>
      `;
    } else if (card.type === "finding_card" && card.finding) {
      const f = card.finding;
      return `
        <div class="chat-embedded-card card-danger">
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <strong>${escapeHtml(f.title)}</strong>
            <span class="badge badge-${f.severity}">${escapeHtml(f.severity)}</span>
          </div>
          <div class="text-sm font-mono text-muted" style="margin-top: 0.2rem;">Rule: ${escapeHtml(f.rule_id)} &bull; Confidence: ${escapeHtml(f.confidence)}</div>
          <p class="text-sm" style="margin-top: 0.35rem;">${escapeHtml(f.description)}</p>
          <div class="text-sm" style="margin-top: 0.4rem; padding: 0.4rem; background: rgba(0,0,0,0.05); border-radius: 4px;">
            <strong>Remediation:</strong> ${escapeHtml(f.remediation)}
          </div>
        </div>
      `;
    } else if (card.type === "remediation_recipe") {
      const steps = (card.steps || []).map(s => `<li>${escapeHtml(s)}</li>`).join("");
      return `
        <div class="chat-embedded-card card-success">
          <strong>${escapeHtml(card.title)}</strong>
          <ul style="margin-top: 0.35rem; margin-left: 1.25rem;">${steps}</ul>
          <div class="text-sm font-mono text-muted" style="margin-top: 0.4rem;">Reference: ${escapeHtml(card.sample_reference)}</div>
        </div>
      `;
    } else if (card.type === "evidence_inspection") {
      return `
        <div class="chat-embedded-card">
          <strong class="font-mono text-sm">${escapeHtml(card.finding_id)}</strong>
          <pre class="evidence-content" style="margin-top: 0.35rem; max-height: 140px;"><code>${escapeHtml(JSON.stringify(card.evidence_payload, null, 2))}</code></pre>
        </div>
      `;
    } else if (card.type === "verification_card") {
      const badgeClass = card.overall_status === "ALL_RESOLVED" ? "badge-success" : "badge-warning";
      const itemsHtml = (card.items || []).map(item => `
        <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.25rem 0; border-bottom: 1px solid rgba(0,0,0,0.05);">
          <span class="font-mono text-sm">${escapeHtml(item.target_id)}</span>
          <span class="badge ${item.status === "Resolved" ? "badge-success" : "badge-danger"}">${escapeHtml(item.status)}</span>
        </div>
      `).join("");

      return `
        <div class="chat-embedded-card ${card.overall_status === "ALL_RESOLVED" ? "card-success" : "card-danger"}">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.4rem;">
            <strong>Verification Result</strong>
            <span class="badge ${badgeClass}">${escapeHtml(card.overall_status)}</span>
          </div>
          <div>${itemsHtml}</div>
        </div>
      `;
    }
    return "";
  }).join("");
}

function updatePromptChips(prompts) {
  const container = document.getElementById("assistant-prompt-chips");
  if (!container || !prompts) return;

  container.innerHTML = prompts.map(p => `
    <button class="prompt-chip" data-prompt="${escapeHtml(p)}">${escapeHtml(p)}</button>
  `).join("");
}

function updateAssistantContext(resourceId, step, mode) {
  const stepEl = document.getElementById("ctx-step");
  const stepBadge = document.getElementById("chat-agentic-step-badge");
  const resourceEl = document.getElementById("ctx-resource");
  const modeEl = document.getElementById("ctx-mode");

  if (stepEl && step) stepEl.textContent = step;
  if (stepBadge && step) stepBadge.textContent = step;
  if (resourceEl && resourceId) resourceEl.textContent = resourceId;
  if (modeEl && mode) {
    const label = mode === "deterministic_template" ? "Deterministic Template" : "AI Augmented";
    modeEl.innerHTML = `<span class="badge badge-outline">${escapeHtml(label)}</span>`;
  }
}

function resetAssistantChat() {
  const container = document.getElementById("chat-stream-container");
  if (!container) return;

  container.innerHTML = `
    <div class="chat-message message-assistant">
      <div class="msg-avatar">🎙️</div>
      <div class="msg-bubble">
        <div class="msg-author">ShipSafe Assistant <span class="badge badge-outline" style="font-size: 0.65rem;">Deterministic Engine</span></div>
        <div class="msg-text">
          Conversation reset. I am ready to inspect synthetic AWS S3 configurations, explain vulnerabilities, and verify fixes.
        </div>
        <div class="msg-subtext">Click any prompt chip below or type a question:</div>
      </div>
    </div>
  `;

  updatePromptChips([
    "Analyze my sample S3 configuration.",
    "What is the most serious issue?",
    "Explain why this configuration is risky.",
    "How can I fix the public-access issue?",
    "Show me the evidence.",
    "Analyze the corrected configuration.",
    "Did the fix resolve the original issue?",
    "Summarize the remaining risks.",
  ]);

  updateAssistantContext("synthetic-bucket-insecure-demo-01", "Step 1: Session Ready", "deterministic_template");
}

