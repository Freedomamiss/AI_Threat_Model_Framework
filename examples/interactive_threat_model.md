# AI Threat Model Report: Demo RAG Assistant

## System Overview

**System name:** Demo RAG Assistant  
**System type:** RAG application

A simplified RAG application profile created for local AI threat modeling practice.

## Users

- end users
- administrators

## Assets

- user prompts
- model responses
- system prompt
- chat logs
- retrieved documents
- document store
- citations
- access control rules

## Trust Boundaries

- user input to AI application
- AI application to model
- model output to end user
- AI application to logging system
- AI application to retrieval system
- retrieval system to document store
- retrieved context to model prompt

## Data Flows

- User submits a prompt to the AI system.
- The application sends a query to a retrieval system.
- The retrieval system returns document chunks.
- The application sends relevant input to the model.
- The model generates a response.
- The application returns the response to the user.
- The system may store logs for review or troubleshooting.

## Assumptions

- The system description is simplified for v1 threat modeling.
- All examples should use fake or sanitized data only.
- User input should be treated as untrusted.
- Model output should not automatically be treated as correct.
- This report is not a full professional security assessment.
- Retrieved documents may contain outdated or untrusted content.

## Risk Summary

| Risk Level | Count |
|---|---:|
| Critical | 2 |
| High | 14 |
| Medium | 5 |
| Low | 0 |
| Total | 21 |

## Threat Summary Table

| ID | Category | Likelihood | Impact | Risk |
|---|---|---|---|---|
| AI-TM-003 | Sensitive data exposure | high | high | critical |
| AI-TM-012 | Private document leakage | high | high | critical |
| AI-TM-001 | Prompt injection | high | medium | high |
| AI-TM-004 | RAG document poisoning | medium | high | high |
| AI-TM-005 | Untrusted retrieved context | high | medium | high |
| AI-TM-006 | Tool misuse | medium | high | high |
| AI-TM-007 | Over-permissioned agent actions | medium | high | high |
| AI-TM-008 | Missing human approval | medium | high | high |
| AI-TM-009 | Weak access control | medium | high | high |
| AI-TM-013 | Hallucinated output | high | medium | high |
| AI-TM-015 | Model over-trust | high | medium | high |
| AI-TM-017 | Insecure plugin/tool access | medium | high | high |
| AI-TM-019 | Jailbreak attempts | high | medium | high |
| AI-TM-020 | Data retention risk | medium | high | high |
| AI-TM-021 | Missing monitoring | medium | high | high |
| AI-TM-022 | Missing audit trail | medium | high | high |
| AI-TM-002 | System prompt leakage | medium | medium | medium |
| AI-TM-011 | Training data leakage | low | high | medium |
| AI-TM-014 | Unsupported citations | medium | medium | medium |
| AI-TM-024 | Inadequate output validation | medium | medium | medium |
| AI-TM-025 | Social engineering through AI responses | medium | medium | medium |

## Detailed Threat Findings

### AI-TM-003 — Sensitive data exposure

**Risk level:** critical  
**Likelihood:** high  
**Impact:** high

**Description:**  
The system may expose sensitive information through prompts, retrieved context, logs, tool results, or model responses.

**Affected assets:**  
- sensitive data
- chat logs
- retrieved documents
- model responses

**Reason:**  
The system handles sensitive data that could be exposed if controls are weak.

**Recommended mitigation:**  
Minimize sensitive data use, redact unnecessary fields, enforce access controls, and review logs for sensitive content.

**Residual risk:**  
medium

### AI-TM-012 — Private document leakage

**Risk level:** critical  
**Likelihood:** high  
**Impact:** high

**Description:**  
Private documents may be retrieved or summarized for users who should not have access to them.

**Affected assets:**  
- private documents
- retrieved documents
- model responses

**Reason:**  
The system handles private documents that require strong authorization controls.

**Recommended mitigation:**  
Enforce document-level access checks before retrieval and before response generation.

**Residual risk:**  
medium

### AI-TM-001 — Prompt injection

**Risk level:** high  
**Likelihood:** high  
**Impact:** medium

**Description:**  
User-controlled input may attempt to override system instructions or manipulate the model into producing unsafe or unauthorized output.

**Affected assets:**  
- user prompts
- system prompt
- model responses

**Reason:**  
The system accepts natural language input from users.

**Recommended mitigation:**  
Treat all user input as untrusted. Use instruction hierarchy, input validation, output filtering, and clear separation between user content and system instructions.

**Residual risk:**  
medium

### AI-TM-004 — RAG document poisoning

**Risk level:** high  
**Likelihood:** medium  
**Impact:** high

**Description:**  
Untrusted or manipulated documents in a retrieval system may influence the model to generate incorrect, unsafe, or misleading answers.

**Affected assets:**  
- retrieved documents
- document store
- model responses

**Reason:**  
RAG systems depend on retrieved documents that may not all be equally trustworthy.

**Recommended mitigation:**  
Use document source validation, ingestion review, document versioning, and trusted-source labeling.

**Residual risk:**  
medium

### AI-TM-005 — Untrusted retrieved context

**Risk level:** high  
**Likelihood:** high  
**Impact:** medium

**Description:**  
Retrieved context may contain outdated, inaccurate, malicious, or irrelevant content that the model treats as reliable.

**Affected assets:**  
- retrieved documents
- model responses
- citations

**Reason:**  
Retrieved context is often mixed directly into model prompts.

**Recommended mitigation:**  
Label retrieved content as untrusted context, validate document sources, and require citations or confidence notes where appropriate.

**Residual risk:**  
medium

### AI-TM-006 — Tool misuse

**Risk level:** high  
**Likelihood:** medium  
**Impact:** high

**Description:**  
An AI system with tools may select the wrong tool, misuse a tool, or act on tool output without enough validation.

**Affected assets:**  
- tools
- tool outputs
- model responses
- business workflows

**Reason:**  
Tool-using AI systems can affect workflows beyond text generation.

**Recommended mitigation:**  
Restrict tool permissions, validate tool inputs and outputs, and require human approval for sensitive actions.

**Residual risk:**  
medium

### AI-TM-007 — Over-permissioned agent actions

**Risk level:** high  
**Likelihood:** medium  
**Impact:** high

**Description:**  
An AI agent may have broader permissions than necessary, increasing the impact of mistakes or malicious instructions.

**Affected assets:**  
- agent permissions
- tools
- connected systems

**Reason:**  
Agents with unnecessary permissions create avoidable risk.

**Recommended mitigation:**  
Apply least privilege, separate read and write permissions, and limit high-impact actions to approved workflows.

**Residual risk:**  
medium

### AI-TM-008 — Missing human approval

**Risk level:** high  
**Likelihood:** medium  
**Impact:** high

**Description:**  
The system may perform or recommend sensitive actions without human review or approval.

**Affected assets:**  
- approval decisions
- business workflows
- tool actions

**Reason:**  
Human approval is important when AI output can affect users, records, or decisions.

**Recommended mitigation:**  
Require human review for sensitive, external, financial, legal, account, or irreversible actions.

**Residual risk:**  
low

### AI-TM-009 — Weak access control

**Risk level:** high  
**Likelihood:** medium  
**Impact:** high

**Description:**  
Users may access AI features, documents, logs, or outputs that should be restricted.

**Affected assets:**  
- access control rules
- private documents
- chat logs

**Reason:**  
Authentication alone does not guarantee proper authorization.

**Recommended mitigation:**  
Use role-based access control, document-level authorization, and regular permission reviews.

**Residual risk:**  
medium

### AI-TM-013 — Hallucinated output

**Risk level:** high  
**Likelihood:** high  
**Impact:** medium

**Description:**  
The model may generate incorrect or fabricated information that users mistakenly trust.

**Affected assets:**  
- model responses
- users
- business decisions

**Reason:**  
LLMs can generate confident but incorrect answers.

**Recommended mitigation:**  
Use uncertainty language, verification steps, citations, and human review for important decisions.

**Residual risk:**  
medium

### AI-TM-015 — Model over-trust

**Risk level:** high  
**Likelihood:** high  
**Impact:** medium

**Description:**  
Users may rely too heavily on model output without understanding its limitations or uncertainty.

**Affected assets:**  
- users
- model responses
- business decisions

**Reason:**  
AI systems can produce confident answers even when uncertain.

**Recommended mitigation:**  
Add clear disclaimers, confidence indicators, review workflows, and user training about model limitations.

**Residual risk:**  
medium

### AI-TM-017 — Insecure plugin/tool access

**Risk level:** high  
**Likelihood:** medium  
**Impact:** high

**Description:**  
Plugins or connected tools may expose more data or functionality than the AI system should access.

**Affected assets:**  
- plugins
- tools
- connected systems
- sensitive data

**Reason:**  
External plugins and tools increase system complexity and permission risk.

**Recommended mitigation:**  
Review plugin permissions, use allowlists, limit scopes, and monitor plugin usage.

**Residual risk:**  
medium

### AI-TM-019 — Jailbreak attempts

**Risk level:** high  
**Likelihood:** high  
**Impact:** medium

**Description:**  
Users may attempt to bypass system restrictions or safety instructions through adversarial prompting.

**Affected assets:**  
- system prompt
- model responses
- safety controls

**Reason:**  
Public or user-facing LLM systems are likely to receive adversarial prompts.

**Recommended mitigation:**  
Use layered safety controls, refusal handling, prompt hardening, and monitoring for repeated abuse patterns.

**Residual risk:**  
medium

### AI-TM-020 — Data retention risk

**Risk level:** high  
**Likelihood:** medium  
**Impact:** high

**Description:**  
The system may retain prompts, responses, files, or retrieved context longer than needed.

**Affected assets:**  
- chat logs
- uploaded files
- user prompts
- model responses

**Reason:**  
Stored AI interaction data can become a privacy and compliance risk.

**Recommended mitigation:**  
Define retention periods, delete unnecessary data, and document retention rules.

**Residual risk:**  
low

### AI-TM-021 — Missing monitoring

**Risk level:** high  
**Likelihood:** medium  
**Impact:** high

**Description:**  
The system may lack monitoring for abuse, failures, unsafe output, or unexpected model behavior.

**Affected assets:**  
- monitoring data
- alerts
- model responses
- logs

**Reason:**  
AI systems need monitoring because failures may be subtle or repeated over time.

**Recommended mitigation:**  
Track high-risk prompts, blocked responses, tool calls, access failures, and user reports.

**Residual risk:**  
low

### AI-TM-022 — Missing audit trail

**Risk level:** high  
**Likelihood:** medium  
**Impact:** high

**Description:**  
The system may not preserve enough evidence to understand what happened during a security or safety incident.

**Affected assets:**  
- audit trail
- logs
- tool actions
- approval decisions

**Reason:**  
Without audit trails, teams may not be able to investigate incidents effectively.

**Recommended mitigation:**  
Record important actions, approvals, tool calls, policy decisions, and access events.

**Residual risk:**  
low

### AI-TM-002 — System prompt leakage

**Risk level:** medium  
**Likelihood:** medium  
**Impact:** medium

**Description:**  
The model may reveal hidden system instructions, internal policies, or configuration details in its responses.

**Affected assets:**  
- system prompt
- model responses
- internal policies

**Reason:**  
LLM applications often rely on hidden instructions that users may try to extract.

**Recommended mitigation:**  
Avoid placing secrets or sensitive operational details in system prompts. Design prompts assuming they may be exposed.

**Residual risk:**  
low

### AI-TM-011 — Training data leakage

**Risk level:** medium  
**Likelihood:** low  
**Impact:** high

**Description:**  
The model may produce content that appears to reveal memorized or sensitive training data.

**Affected assets:**  
- training data
- model responses
- sensitive data

**Reason:**  
Some model outputs may reflect sensitive or memorized training examples.

**Recommended mitigation:**  
Use models and providers with clear data handling policies, avoid training on sensitive data unless approved, and test for leakage patterns.

**Residual risk:**  
medium

### AI-TM-014 — Unsupported citations

**Risk level:** medium  
**Likelihood:** medium  
**Impact:** medium

**Description:**  
The system may generate citations that do not support the answer or refer to sources that were not actually used.

**Affected assets:**  
- citations
- retrieved documents
- model responses

**Reason:**  
Citation-generating systems can create misleading confidence if sources are weak.

**Recommended mitigation:**  
Verify citations against retrieved source text and clearly indicate when an answer is unsupported.

**Residual risk:**  
low

### AI-TM-024 — Inadequate output validation

**Risk level:** medium  
**Likelihood:** medium  
**Impact:** medium

**Description:**  
The system may return model output without checking for format errors, unsafe content, unsupported claims, or policy violations.

**Affected assets:**  
- model responses
- users
- business workflows

**Reason:**  
Model output should not automatically be treated as safe or correct.

**Recommended mitigation:**  
Validate outputs for required format, policy compliance, citations, and sensitive content.

**Residual risk:**  
low

### AI-TM-025 — Social engineering through AI responses

**Risk level:** medium  
**Likelihood:** medium  
**Impact:** medium

**Description:**  
The system may produce responses that users interpret as authoritative, which could support manipulation, confusion, or unsafe decisions.

**Affected assets:**  
- users
- model responses
- business decisions

**Reason:**  
AI responses can appear confident and persuasive even when incomplete or wrong.

**Recommended mitigation:**  
Use careful wording, user education, escalation paths, and human review for high-impact guidance.

**Residual risk:**  
medium


## Prioritized Action Plan

| Priority | Risk | Threat ID | Category | Recommended Action |
|---:|---|---|---|---|
| 1 | critical | AI-TM-003 | Sensitive data exposure | Minimize sensitive data use, redact unnecessary fields, enforce access controls, and review logs for sensitive content. |
| 2 | critical | AI-TM-012 | Private document leakage | Enforce document-level access checks before retrieval and before response generation. |
| 3 | high | AI-TM-001 | Prompt injection | Treat all user input as untrusted. Use instruction hierarchy, input validation, output filtering, and clear separation between user content and system instructions. |
| 4 | high | AI-TM-004 | RAG document poisoning | Use document source validation, ingestion review, document versioning, and trusted-source labeling. |
| 5 | high | AI-TM-005 | Untrusted retrieved context | Label retrieved content as untrusted context, validate document sources, and require citations or confidence notes where appropriate. |
| 6 | high | AI-TM-006 | Tool misuse | Restrict tool permissions, validate tool inputs and outputs, and require human approval for sensitive actions. |
| 7 | high | AI-TM-007 | Over-permissioned agent actions | Apply least privilege, separate read and write permissions, and limit high-impact actions to approved workflows. |
| 8 | high | AI-TM-008 | Missing human approval | Require human review for sensitive, external, financial, legal, account, or irreversible actions. |
| 9 | high | AI-TM-009 | Weak access control | Use role-based access control, document-level authorization, and regular permission reviews. |
| 10 | high | AI-TM-013 | Hallucinated output | Use uncertainty language, verification steps, citations, and human review for important decisions. |
| 11 | high | AI-TM-015 | Model over-trust | Add clear disclaimers, confidence indicators, review workflows, and user training about model limitations. |
| 12 | high | AI-TM-017 | Insecure plugin/tool access | Review plugin permissions, use allowlists, limit scopes, and monitor plugin usage. |
| 13 | high | AI-TM-019 | Jailbreak attempts | Use layered safety controls, refusal handling, prompt hardening, and monitoring for repeated abuse patterns. |
| 14 | high | AI-TM-020 | Data retention risk | Define retention periods, delete unnecessary data, and document retention rules. |
| 15 | high | AI-TM-021 | Missing monitoring | Track high-risk prompts, blocked responses, tool calls, access failures, and user reports. |
| 16 | high | AI-TM-022 | Missing audit trail | Record important actions, approvals, tool calls, policy decisions, and access events. |
| 17 | medium | AI-TM-002 | System prompt leakage | Avoid placing secrets or sensitive operational details in system prompts. Design prompts assuming they may be exposed. |
| 18 | medium | AI-TM-011 | Training data leakage | Use models and providers with clear data handling policies, avoid training on sensitive data unless approved, and test for leakage patterns. |
| 19 | medium | AI-TM-014 | Unsupported citations | Verify citations against retrieved source text and clearly indicate when an answer is unsupported. |
| 20 | medium | AI-TM-024 | Inadequate output validation | Validate outputs for required format, policy compliance, citations, and sensitive content. |
| 21 | medium | AI-TM-025 | Social engineering through AI responses | Use careful wording, user education, escalation paths, and human review for high-impact guidance. |

## Disclaimer

This report is generated by a simple local rules-based tool for defensive education and portfolio demonstration. It is not a full professional security assessment, legal review, compliance audit, or production architecture review.
