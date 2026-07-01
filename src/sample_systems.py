"""
Sample AI system profiles for AI Threat Model Framework v1.

These are fake systems used for safe demo mode.
No real company data, private data, secrets, credentials, or production details
should be placed in this file.
"""


def get_sample_system():
    """
    Return a fake sample AI system profile.

    The structure here is intentionally simple so the rest of the tool can
    generate a threat model without needing a database, API, or external service.
    """

    return {
        "name": "Demo Internal RAG Assistant",
        "system_type": "RAG application",
        "description": (
            "A fake internal assistant that answers employee questions using "
            "retrieved company policy documents. This sample is for defensive "
            "AI security threat modeling practice only."
        ),
        "users": [
            "employees",
            "managers",
            "system administrators",
        ],
        "assets": [
            "user prompts",
            "retrieved documents",
            "internal policy documents",
            "model responses",
            "system prompt",
            "chat logs",
            "access control rules",
        ],
        "trust_boundaries": [
            "user input to AI application",
            "AI application to retrieval system",
            "retrieval system to document store",
            "AI application to logging system",
            "model output to end user",
        ],
        "data_flows": [
            "User submits a question to the assistant.",
            "The application sends the question to a retrieval system.",
            "The retrieval system returns relevant policy document chunks.",
            "The application combines user input and retrieved context into a model prompt.",
            "The model generates an answer.",
            "The application returns the answer to the user.",
            "The system stores basic logs for review and troubleshooting.",
        ],
        "assumptions": [
            "The system uses fake sample data for this project.",
            "The assistant may retrieve internal documents.",
            "Users may submit untrusted prompts.",
            "Retrieved documents may contain untrusted or outdated content.",
            "The model may produce inaccurate or unsupported answers.",
            "The system does not perform autonomous external actions in this sample.",
        ],
        "features": {
            "uses_llm": True,
            "uses_rag": True,
            "uses_tools": False,
            "uses_plugins": False,
            "handles_sensitive_data": True,
            "handles_private_documents": True,
            "has_user_authentication": True,
            "has_role_based_access": False,
            "stores_logs": True,
            "logs_sensitive_data": True,
            "has_human_approval": False,
            "has_monitoring": False,
            "has_audit_trail": False,
            "allows_file_uploads": False,
            "supports_multiple_tenants": False,
            "generates_citations": True,
            "validates_outputs": False,
            "has_data_retention_policy": False,
            "can_take_autonomous_actions": False,
        },
    }


def get_sample_agent_system():
    """
    Return a fake AI agent profile for future testing or manual use.

    This is not used as the default v1 sample, but it gives the project another
    safe profile that can be used later without adding complexity.
    """

    return {
        "name": "Demo Support Agent With Tools",
        "system_type": "AI agent with tools",
        "description": (
            "A fake customer support AI agent that can draft support responses "
            "and look up fake customer account status. This sample is for safe "
            "defensive review only."
        ),
        "users": [
            "support staff",
            "support managers",
        ],
        "assets": [
            "customer support questions",
            "fake account records",
            "tool outputs",
            "model responses",
            "system prompt",
            "chat logs",
            "approval decisions",
        ],
        "trust_boundaries": [
            "support user to AI agent",
            "AI agent to tool layer",
            "tool layer to fake account system",
            "tool output back to AI agent",
            "AI agent response to support user",
        ],
        "data_flows": [
            "Support user enters a customer support request.",
            "The AI agent decides whether tool lookup is needed.",
            "The tool layer returns fake customer account information.",
            "The agent drafts a response.",
            "A human support staff member reviews the response before sending.",
        ],
        "assumptions": [
            "The tool can only access fake sample records.",
            "The agent should not send messages without human review.",
            "Tool outputs should be treated as untrusted until validated.",
            "The system should not expose private customer data unnecessarily.",
        ],
        "features": {
            "uses_llm": True,
            "uses_rag": False,
            "uses_tools": True,
            "uses_plugins": False,
            "handles_sensitive_data": True,
            "handles_private_documents": False,
            "has_user_authentication": True,
            "has_role_based_access": True,
            "stores_logs": True,
            "logs_sensitive_data": False,
            "has_human_approval": True,
            "has_monitoring": True,
            "has_audit_trail": False,
            "allows_file_uploads": False,
            "supports_multiple_tenants": True,
            "generates_citations": False,
            "validates_outputs": True,
            "has_data_retention_policy": False,
            "can_take_autonomous_actions": False,
        },
    }