"""
Threat library for AI Threat Model Framework v1.

This file contains safe, defensive AI security threat categories.
It does not include exploit steps, offensive instructions, malware behavior,
credential theft, or real private data.

Each threat entry is a rules-based check that the risk engine can evaluate
against a simple AI system profile.
"""


def get_threat_library():
    """
    Return the v1 threat library.

    Each threat has:
    - threat_id
    - category
    - description
    - affected_assets
    - trigger_features
    - likelihood
    - impact
    - reason
    - recommended_mitigation
    - residual_risk

    The risk engine will use likelihood and impact to calculate risk_level.
    """

    return [
        {
            "threat_id": "AI-TM-001",
            "category": "Prompt injection",
            "description": (
                "User-controlled input may attempt to override system instructions "
                "or manipulate the model into producing unsafe or unauthorized output."
            ),
            "affected_assets": ["user prompts", "system prompt", "model responses"],
            "trigger_features": ["uses_llm"],
            "likelihood": "high",
            "impact": "medium",
            "reason": "The system accepts natural language input from users.",
            "recommended_mitigation": (
                "Treat all user input as untrusted. Use instruction hierarchy, input "
                "validation, output filtering, and clear separation between user content "
                "and system instructions."
            ),
            "residual_risk": "medium",
        },
        {
            "threat_id": "AI-TM-002",
            "category": "System prompt leakage",
            "description": (
                "The model may reveal hidden system instructions, internal policies, "
                "or configuration details in its responses."
            ),
            "affected_assets": ["system prompt", "model responses", "internal policies"],
            "trigger_features": ["uses_llm"],
            "likelihood": "medium",
            "impact": "medium",
            "reason": "LLM applications often rely on hidden instructions that users may try to extract.",
            "recommended_mitigation": (
                "Avoid placing secrets or sensitive operational details in system prompts. "
                "Design prompts assuming they may be exposed."
            ),
            "residual_risk": "low",
        },
        {
            "threat_id": "AI-TM-003",
            "category": "Sensitive data exposure",
            "description": (
                "The system may expose sensitive information through prompts, retrieved "
                "context, logs, tool results, or model responses."
            ),
            "affected_assets": ["sensitive data", "chat logs", "retrieved documents", "model responses"],
            "trigger_features": ["handles_sensitive_data"],
            "likelihood": "high",
            "impact": "high",
            "reason": "The system handles sensitive data that could be exposed if controls are weak.",
            "recommended_mitigation": (
                "Minimize sensitive data use, redact unnecessary fields, enforce access "
                "controls, and review logs for sensitive content."
            ),
            "residual_risk": "medium",
        },
        {
            "threat_id": "AI-TM-004",
            "category": "RAG document poisoning",
            "description": (
                "Untrusted or manipulated documents in a retrieval system may influence "
                "the model to generate incorrect, unsafe, or misleading answers."
            ),
            "affected_assets": ["retrieved documents", "document store", "model responses"],
            "trigger_features": ["uses_rag"],
            "likelihood": "medium",
            "impact": "high",
            "reason": "RAG systems depend on retrieved documents that may not all be equally trustworthy.",
            "recommended_mitigation": (
                "Use document source validation, ingestion review, document versioning, "
                "and trusted-source labeling."
            ),
            "residual_risk": "medium",
        },
        {
            "threat_id": "AI-TM-005",
            "category": "Untrusted retrieved context",
            "description": (
                "Retrieved context may contain outdated, inaccurate, malicious, or "
                "irrelevant content that the model treats as reliable."
            ),
            "affected_assets": ["retrieved documents", "model responses", "citations"],
            "trigger_features": ["uses_rag"],
            "likelihood": "high",
            "impact": "medium",
            "reason": "Retrieved context is often mixed directly into model prompts.",
            "recommended_mitigation": (
                "Label retrieved content as untrusted context, validate document sources, "
                "and require citations or confidence notes where appropriate."
            ),
            "residual_risk": "medium",
        },
        {
            "threat_id": "AI-TM-006",
            "category": "Tool misuse",
            "description": (
                "An AI system with tools may select the wrong tool, misuse a tool, or "
                "act on tool output without enough validation."
            ),
            "affected_assets": ["tools", "tool outputs", "model responses", "business workflows"],
            "trigger_features": ["uses_tools"],
            "likelihood": "medium",
            "impact": "high",
            "reason": "Tool-using AI systems can affect workflows beyond text generation.",
            "recommended_mitigation": (
                "Restrict tool permissions, validate tool inputs and outputs, and require "
                "human approval for sensitive actions."
            ),
            "residual_risk": "medium",
        },
        {
            "threat_id": "AI-TM-007",
            "category": "Over-permissioned agent actions",
            "description": (
                "An AI agent may have broader permissions than necessary, increasing "
                "the impact of mistakes or malicious instructions."
            ),
            "affected_assets": ["agent permissions", "tools", "connected systems"],
            "trigger_features": ["uses_tools"],
            "likelihood": "medium",
            "impact": "high",
            "reason": "Agents with unnecessary permissions create avoidable risk.",
            "recommended_mitigation": (
                "Apply least privilege, separate read and write permissions, and limit "
                "high-impact actions to approved workflows."
            ),
            "residual_risk": "medium",
        },
        {
            "threat_id": "AI-TM-008",
            "category": "Missing human approval",
            "description": (
                "The system may perform or recommend sensitive actions without human "
                "review or approval."
            ),
            "affected_assets": ["approval decisions", "business workflows", "tool actions"],
            "trigger_features": ["has_human_approval"],
            "likelihood": "medium",
            "impact": "high",
            "reason": "Human approval is important when AI output can affect users, records, or decisions.",
            "recommended_mitigation": (
                "Require human review for sensitive, external, financial, legal, account, "
                "or irreversible actions."
            ),
            "residual_risk": "low",
        },
        {
            "threat_id": "AI-TM-009",
            "category": "Weak access control",
            "description": (
                "Users may access AI features, documents, logs, or outputs that should "
                "be restricted."
            ),
            "affected_assets": ["access control rules", "private documents", "chat logs"],
            "trigger_features": ["has_user_authentication"],
            "likelihood": "medium",
            "impact": "high",
            "reason": "Authentication alone does not guarantee proper authorization.",
            "recommended_mitigation": (
                "Use role-based access control, document-level authorization, and regular "
                "permission reviews."
            ),
            "residual_risk": "medium",
        },
        {
            "threat_id": "AI-TM-010",
            "category": "Insecure logging",
            "description": (
                "Prompts, responses, retrieved context, or tool results may be logged "
                "with sensitive data included."
            ),
            "affected_assets": ["chat logs", "user prompts", "model responses", "sensitive data"],
            "trigger_features": ["stores_logs"],
            "likelihood": "medium",
            "impact": "medium",
            "reason": "AI logs often contain user input and model output that may include sensitive content.",
            "recommended_mitigation": (
                "Redact sensitive data, limit log retention, restrict log access, and avoid "
                "logging unnecessary prompt or document content."
            ),
            "residual_risk": "low",
        },
        {
            "threat_id": "AI-TM-011",
            "category": "Training data leakage",
            "description": (
                "The model may produce content that appears to reveal memorized or "
                "sensitive training data."
            ),
            "affected_assets": ["training data", "model responses", "sensitive data"],
            "trigger_features": ["uses_llm"],
            "likelihood": "low",
            "impact": "high",
            "reason": "Some model outputs may reflect sensitive or memorized training examples.",
            "recommended_mitigation": (
                "Use models and providers with clear data handling policies, avoid training "
                "on sensitive data unless approved, and test for leakage patterns."
            ),
            "residual_risk": "medium",
        },
        {
            "threat_id": "AI-TM-012",
            "category": "Private document leakage",
            "description": (
                "Private documents may be retrieved or summarized for users who should "
                "not have access to them."
            ),
            "affected_assets": ["private documents", "retrieved documents", "model responses"],
            "trigger_features": ["handles_private_documents"],
            "likelihood": "high",
            "impact": "high",
            "reason": "The system handles private documents that require strong authorization controls.",
            "recommended_mitigation": (
                "Enforce document-level access checks before retrieval and before response "
                "generation."
            ),
            "residual_risk": "medium",
        },
        {
            "threat_id": "AI-TM-013",
            "category": "Hallucinated output",
            "description": (
                "The model may generate incorrect or fabricated information that users "
                "mistakenly trust."
            ),
            "affected_assets": ["model responses", "users", "business decisions"],
            "trigger_features": ["uses_llm"],
            "likelihood": "high",
            "impact": "medium",
            "reason": "LLMs can generate confident but incorrect answers.",
            "recommended_mitigation": (
                "Use uncertainty language, verification steps, citations, and human review "
                "for important decisions."
            ),
            "residual_risk": "medium",
        },
        {
            "threat_id": "AI-TM-014",
            "category": "Unsupported citations",
            "description": (
                "The system may generate citations that do not support the answer or "
                "refer to sources that were not actually used."
            ),
            "affected_assets": ["citations", "retrieved documents", "model responses"],
            "trigger_features": ["generates_citations"],
            "likelihood": "medium",
            "impact": "medium",
            "reason": "Citation-generating systems can create misleading confidence if sources are weak.",
            "recommended_mitigation": (
                "Verify citations against retrieved source text and clearly indicate when "
                "an answer is unsupported."
            ),
            "residual_risk": "low",
        },
        {
            "threat_id": "AI-TM-015",
            "category": "Model over-trust",
            "description": (
                "Users may rely too heavily on model output without understanding its "
                "limitations or uncertainty."
            ),
            "affected_assets": ["users", "model responses", "business decisions"],
            "trigger_features": ["uses_llm"],
            "likelihood": "high",
            "impact": "medium",
            "reason": "AI systems can produce confident answers even when uncertain.",
            "recommended_mitigation": (
                "Add clear disclaimers, confidence indicators, review workflows, and user "
                "training about model limitations."
            ),
            "residual_risk": "medium",
        },
        {
            "threat_id": "AI-TM-016",
            "category": "Unsafe file handling",
            "description": (
                "Uploaded files may contain unsafe, misleading, sensitive, or malformed "
                "content that affects processing or output."
            ),
            "affected_assets": ["uploaded files", "document parser", "model responses"],
            "trigger_features": ["allows_file_uploads"],
            "likelihood": "medium",
            "impact": "high",
            "reason": "File upload features introduce additional trust boundaries.",
            "recommended_mitigation": (
                "Restrict allowed file types, scan files, validate content, limit file size, "
                "and isolate file processing."
            ),
            "residual_risk": "medium",
        },
        {
            "threat_id": "AI-TM-017",
            "category": "Insecure plugin/tool access",
            "description": (
                "Plugins or connected tools may expose more data or functionality than "
                "the AI system should access."
            ),
            "affected_assets": ["plugins", "tools", "connected systems", "sensitive data"],
            "trigger_features": ["uses_plugins"],
            "likelihood": "medium",
            "impact": "high",
            "reason": "External plugins and tools increase system complexity and permission risk.",
            "recommended_mitigation": (
                "Review plugin permissions, use allowlists, limit scopes, and monitor plugin usage."
            ),
            "residual_risk": "medium",
        },
        {
            "threat_id": "AI-TM-018",
            "category": "Cross-tenant data exposure",
            "description": (
                "A user from one tenant, team, or customer group may receive information "
                "belonging to another tenant."
            ),
            "affected_assets": ["tenant data", "private documents", "retrieved documents", "logs"],
            "trigger_features": ["supports_multiple_tenants"],
            "likelihood": "medium",
            "impact": "high",
            "reason": "Multi-tenant systems require strong separation of data and permissions.",
            "recommended_mitigation": (
                "Enforce tenant isolation in retrieval, logging, authorization, and response generation."
            ),
            "residual_risk": "medium",
        },
        {
            "threat_id": "AI-TM-019",
            "category": "Jailbreak attempts",
            "description": (
                "Users may attempt to bypass system restrictions or safety instructions "
                "through adversarial prompting."
            ),
            "affected_assets": ["system prompt", "model responses", "safety controls"],
            "trigger_features": ["uses_llm"],
            "likelihood": "high",
            "impact": "medium",
            "reason": "Public or user-facing LLM systems are likely to receive adversarial prompts.",
            "recommended_mitigation": (
                "Use layered safety controls, refusal handling, prompt hardening, and monitoring "
                "for repeated abuse patterns."
            ),
            "residual_risk": "medium",
        },
        {
            "threat_id": "AI-TM-020",
            "category": "Data retention risk",
            "description": (
                "The system may retain prompts, responses, files, or retrieved context "
                "longer than needed."
            ),
            "affected_assets": ["chat logs", "uploaded files", "user prompts", "model responses"],
            "trigger_features": ["stores_logs"],
            "likelihood": "medium",
            "impact": "medium",
            "reason": "Stored AI interaction data can become a privacy and compliance risk.",
            "recommended_mitigation": (
                "Define retention periods, delete unnecessary data, and document retention rules."
            ),
            "residual_risk": "low",
        },
        {
            "threat_id": "AI-TM-021",
            "category": "Missing monitoring",
            "description": (
                "The system may lack monitoring for abuse, failures, unsafe output, or "
                "unexpected model behavior."
            ),
            "affected_assets": ["monitoring data", "alerts", "model responses", "logs"],
            "trigger_features": ["has_monitoring"],
            "likelihood": "medium",
            "impact": "medium",
            "reason": "AI systems need monitoring because failures may be subtle or repeated over time.",
            "recommended_mitigation": (
                "Track high-risk prompts, blocked responses, tool calls, access failures, and "
                "user reports."
            ),
            "residual_risk": "low",
        },
        {
            "threat_id": "AI-TM-022",
            "category": "Missing audit trail",
            "description": (
                "The system may not preserve enough evidence to understand what happened "
                "during a security or safety incident."
            ),
            "affected_assets": ["audit trail", "logs", "tool actions", "approval decisions"],
            "trigger_features": ["has_audit_trail"],
            "likelihood": "medium",
            "impact": "medium",
            "reason": "Without audit trails, teams may not be able to investigate incidents effectively.",
            "recommended_mitigation": (
                "Record important actions, approvals, tool calls, policy decisions, and access events."
            ),
            "residual_risk": "low",
        },
        {
            "threat_id": "AI-TM-023",
            "category": "Unsafe autonomous actions",
            "description": (
                "An AI agent may take actions without enough review, validation, or limits."
            ),
            "affected_assets": ["agent actions", "tools", "connected systems", "business workflows"],
            "trigger_features": ["can_take_autonomous_actions"],
            "likelihood": "high",
            "impact": "high",
            "reason": "Autonomous actions can create serious impact if the system acts incorrectly.",
            "recommended_mitigation": (
                "Require human approval, action limits, rollback plans, and clear policy checks "
                "before sensitive actions."
            ),
            "residual_risk": "medium",
        },
        {
            "threat_id": "AI-TM-024",
            "category": "Inadequate output validation",
            "description": (
                "The system may return model output without checking for format errors, "
                "unsafe content, unsupported claims, or policy violations."
            ),
            "affected_assets": ["model responses", "users", "business workflows"],
            "trigger_features": ["validates_outputs"],
            "likelihood": "medium",
            "impact": "medium",
            "reason": "Model output should not automatically be treated as safe or correct.",
            "recommended_mitigation": (
                "Validate outputs for required format, policy compliance, citations, and sensitive content."
            ),
            "residual_risk": "low",
        },
        {
            "threat_id": "AI-TM-025",
            "category": "Social engineering through AI responses",
            "description": (
                "The system may produce responses that users interpret as authoritative, "
                "which could support manipulation, confusion, or unsafe decisions."
            ),
            "affected_assets": ["users", "model responses", "business decisions"],
            "trigger_features": ["uses_llm"],
            "likelihood": "medium",
            "impact": "medium",
            "reason": "AI responses can appear confident and persuasive even when incomplete or wrong.",
            "recommended_mitigation": (
                "Use careful wording, user education, escalation paths, and human review for "
                "high-impact guidance."
            ),
            "residual_risk": "medium",
        },
    ]


def get_threat_count():
    """
    Return the number of threat checks in the v1 library.
    """

    return len(get_threat_library())


def get_threat_by_id(threat_id):
    """
    Return a single threat by threat_id.

    Args:
        threat_id: Threat ID string, such as AI-TM-001.

    Returns:
        The matching threat dictionary, or None if not found.
    """

    for threat in get_threat_library():
        if threat["threat_id"] == threat_id:
            return threat

    return None