# Threat Categories

AI Threat Model Framework v1 includes 25 safe, defensive threat categories for AI, LLM, RAG, and AI-agent systems.

These categories are used to generate structured findings in the JSON and Markdown reports.

This document explains each category at a high level. It does not include exploit steps, offensive instructions, credential theft, malware behavior, or real private data.

## 1. Prompt Injection

Prompt injection happens when user-controlled input attempts to manipulate the model into ignoring instructions, changing behavior, or producing unauthorized output.

Common concern:

- User input is mixed with system instructions.
- The model may follow malicious or misleading user instructions.
- Retrieved documents may contain instructions that influence the model.

Basic mitigations:

- Treat user input as untrusted.
- Separate system instructions from user content.
- Use input validation and output validation.
- Monitor repeated abuse patterns.

## 2. System Prompt Leakage

System prompt leakage happens when the model reveals hidden instructions, internal policy text, configuration details, or other information that was not meant for users.

Common concern:

- Hidden prompts may contain sensitive operational details.
- Users may ask the model to reveal its instructions.
- The model may expose internal behavior rules.

Basic mitigations:

- Do not put secrets in system prompts.
- Assume prompts may be exposed.
- Keep system instructions minimal and non-sensitive.
- Use output filtering for sensitive internal details.

## 3. Sensitive Data Exposure

Sensitive data exposure happens when private, confidential, regulated, or otherwise sensitive information appears in prompts, retrieved context, logs, tool outputs, or model responses.

Common concern:

- Sensitive data may be sent to the model.
- Sensitive data may be stored in logs.
- Sensitive data may be returned to the wrong user.

Basic mitigations:

- Minimize sensitive data collection.
- Redact sensitive fields.
- Restrict access to logs.
- Enforce authorization checks before retrieval or response generation.

## 4. RAG Document Poisoning

RAG document poisoning happens when untrusted, manipulated, outdated, or misleading documents enter the retrieval system and influence model output.

Common concern:

- Bad documents can affect answers.
- The model may treat retrieved text as trusted.
- Users may rely on poisoned or inaccurate output.

Basic mitigations:

- Validate document sources.
- Review document ingestion workflows.
- Track document versions.
- Label trusted and untrusted sources.

## 5. Untrusted Retrieved Context

Untrusted retrieved context happens when the model receives retrieved content that may be inaccurate, outdated, incomplete, or irrelevant.

Common concern:

- Retrieved context may not support the final answer.
- The model may over-trust retrieved chunks.
- Users may not know the source quality.

Basic mitigations:

- Treat retrieved content as untrusted input.
- Show source references where appropriate.
- Use confidence notes.
- Validate retrieved content before high-impact use.

## 6. Tool Misuse

Tool misuse happens when an AI system selects the wrong tool, passes incorrect input to a tool, or uses tool output without enough validation.

Common concern:

- Tool output may affect real workflows.
- The AI may misunderstand when a tool is appropriate.
- Tool output may be incomplete or misleading.

Basic mitigations:

- Limit tool permissions.
- Validate tool inputs and outputs.
- Use allowlisted tools.
- Require approval for sensitive actions.

## 7. Over-Permissioned Agent Actions

Over-permissioned agent actions happen when an AI agent has more access or authority than it needs.

Common concern:

- A small AI mistake may create a large impact.
- Broad permissions increase risk.
- Read and write permissions may not be separated.

Basic mitigations:

- Apply least privilege.
- Separate read-only and write actions.
- Use scoped permissions.
- Review permissions regularly.

## 8. Missing Human Approval

Missing human approval happens when the system can perform, recommend, or influence sensitive actions without human review.

Common concern:

- AI output may affect users, records, accounts, or business decisions.
- The system may act too quickly without review.
- Mistakes may be harder to reverse.

Basic mitigations:

- Require human approval for sensitive actions.
- Use approval logs.
- Add review workflows.
- Define which actions require escalation.

## 9. Weak Access Control

Weak access control happens when users can access features, documents, logs, or outputs that should be restricted.

Common concern:

- Authentication exists but authorization is weak.
- Users may retrieve documents they should not see.
- Admin-only features may be exposed.

Basic mitigations:

- Use role-based access control.
- Enforce document-level permissions.
- Review access regularly.
- Test access boundaries.

## 10. Insecure Logging

Insecure logging happens when prompts, responses, documents, tool results, or sensitive user data are stored in logs without proper protection.

Common concern:

- Logs may contain private information.
- Too many people may have access to logs.
- Logs may be retained longer than needed.

Basic mitigations:

- Redact sensitive data.
- Limit log access.
- Define retention periods.
- Avoid logging unnecessary prompt or document content.

## 11. Training Data Leakage

Training data leakage happens when a model appears to reveal memorized or sensitive training information.

Common concern:

- Model output may include sensitive examples.
- Training data policies may be unclear.
- Users may ask for private or proprietary information.

Basic mitigations:

- Avoid training on sensitive data unless approved.
- Use clear data handling policies.
- Test for leakage patterns.
- Use providers with documented privacy controls.

## 12. Private Document Leakage

Private document leakage happens when a system retrieves, summarizes, or exposes documents to users who should not have access.

Common concern:

- RAG retrieval may bypass document permissions.
- Private documents may appear in model output.
- Summaries may reveal protected information.

Basic mitigations:

- Enforce document-level authorization.
- Check permissions before retrieval.
- Check permissions before response generation.
- Separate public and private document stores.

## 13. Hallucinated Output

Hallucinated output happens when the model generates false, unsupported, or fabricated information.

Common concern:

- The model may sound confident while being wrong.
- Users may rely on incorrect answers.
- Business decisions may be affected.

Basic mitigations:

- Use uncertainty language.
- Require citations for factual claims.
- Add human review for important decisions.
- Validate high-impact output.

## 14. Unsupported Citations

Unsupported citations happen when the system provides sources that do not actually support the answer.

Common concern:

- Citations may create false confidence.
- The model may cite the wrong document.
- The answer may not match the source text.

Basic mitigations:

- Verify citations against source text.
- Show exact source references.
- Mark unsupported answers clearly.
- Avoid citations when no source supports the claim.

## 15. Model Over-Trust

Model over-trust happens when users treat AI output as more accurate, complete, or authoritative than it really is.

Common concern:

- Users may skip verification.
- AI may influence important decisions.
- Confident wording may hide uncertainty.

Basic mitigations:

- Add clear limitations.
- Use review workflows.
- Train users on AI limitations.
- Escalate high-impact decisions to humans.

## 16. Unsafe File Handling

Unsafe file handling happens when uploaded files introduce risky, malformed, sensitive, or misleading content.

Common concern:

- Files may contain sensitive information.
- Files may contain hidden or misleading text.
- File parsing may create unexpected results.

Basic mitigations:

- Restrict allowed file types.
- Limit file size.
- Validate file content.
- Isolate file processing.

## 17. Insecure Plugin or Tool Access

Insecure plugin or tool access happens when external integrations expose more data or functionality than the AI system needs.

Common concern:

- Plugins may have broad permissions.
- Tool access may not be monitored.
- Integrations may increase attack surface.

Basic mitigations:

- Review plugin scopes.
- Use allowlisted integrations.
- Limit permissions.
- Monitor plugin and tool usage.

## 18. Cross-Tenant Data Exposure

Cross-tenant data exposure happens when one customer, team, tenant, or user group can access another group’s data.

Common concern:

- Multi-tenant separation may fail.
- Retrieval may return another tenant’s documents.
- Logs or outputs may mix data across tenants.

Basic mitigations:

- Enforce tenant isolation.
- Include tenant checks in retrieval.
- Separate indexes where needed.
- Test cross-tenant boundaries.

## 19. Jailbreak Attempts

Jailbreak attempts happen when users try to bypass model rules, safety instructions, or application restrictions.

Common concern:

- Public-facing systems may receive adversarial prompts.
- Users may try to override restrictions.
- Repeated attempts may reveal weak controls.

Basic mitigations:

- Use layered safety controls.
- Monitor repeated abuse.
- Harden prompts.
- Validate outputs.

## 20. Data Retention Risk

Data retention risk happens when prompts, responses, files, logs, or retrieved context are stored longer than needed.

Common concern:

- Old data may create privacy risk.
- Users may not know what is stored.
- Stored data may be exposed later.

Basic mitigations:

- Define retention periods.
- Delete unnecessary data.
- Document retention rules.
- Give users clear data handling information.

## 21. Missing Monitoring

Missing monitoring happens when the system lacks visibility into misuse, failures, unsafe output, or abnormal behavior.

Common concern:

- Problems may go unnoticed.
- Abuse patterns may not be detected.
- Security teams may lack useful evidence.

Basic mitigations:

- Monitor high-risk prompts.
- Track blocked responses.
- Review tool calls.
- Alert on unusual activity.

## 22. Missing Audit Trail

Missing audit trail happens when the system does not preserve enough event history to investigate incidents or review important actions.

Common concern:

- Teams may not know what happened.
- Approval decisions may not be recorded.
- Tool actions may not be traceable.

Basic mitigations:

- Log important actions.
- Record approvals.
- Track tool calls.
- Preserve useful incident review data.

## 23. Unsafe Autonomous Actions

Unsafe autonomous actions happen when an AI agent can take action without enough review, limits, validation, or rollback planning.

Common concern:

- AI may act on bad instructions.
- AI may make incorrect decisions.
- Real-world systems may be affected.

Basic mitigations:

- Require human approval.
- Add action limits.
- Use rollback plans.
- Restrict autonomous capabilities.

## 24. Inadequate Output Validation

Inadequate output validation happens when model output is shown or used without checking for required format, unsafe content, unsupported claims, or policy violations.

Common concern:

- Output may be inaccurate.
- Output may be unsafe.
- Output may not match expected format.

Basic mitigations:

- Validate required format.
- Check for sensitive content.
- Verify citations and claims.
- Use human review where needed.

## 25. Social Engineering Through AI Responses

Social engineering through AI responses happens when AI-generated text persuades, misleads, or pressures users in harmful ways.

Common concern:

- AI responses may sound authoritative.
- Users may follow bad guidance.
- Attackers may use AI-generated language to manipulate users.

Basic mitigations:

- Use careful wording.
- Add escalation paths.
- Train users not to over-trust AI output.
- Require review for high-impact guidance.

## Summary

These categories are not a complete list of every possible AI security risk. They are a practical v1 threat library for a local portfolio project.

The goal is to help users identify likely risk areas, document assumptions, and create a clear starting point for safer AI system design.