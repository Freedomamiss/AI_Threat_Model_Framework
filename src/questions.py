"""
Interactive questions for AI Threat Model Framework v1.

This file collects a simple AI system profile from the user.
It does not collect secrets, credentials, real private data, API keys, or
sensitive company information.

Use fake, generalized, or sanitized information only.
"""


SUPPORTED_SYSTEM_TYPES = [
    "general chatbot",
    "RAG application",
    "AI agent with tools",
    "document summarizer",
    "customer support bot",
    "internal enterprise assistant",
    "code assistant",
    "data analysis assistant",
]


FEATURE_KEYS = [
    "uses_llm",
    "uses_rag",
    "uses_tools",
    "uses_plugins",
    "handles_sensitive_data",
    "handles_private_documents",
    "has_user_authentication",
    "has_role_based_access",
    "stores_logs",
    "logs_sensitive_data",
    "has_human_approval",
    "has_monitoring",
    "has_audit_trail",
    "allows_file_uploads",
    "supports_multiple_tenants",
    "generates_citations",
    "validates_outputs",
    "has_data_retention_policy",
    "can_take_autonomous_actions",
]


def ask_text(question, default=None):
    """
    Ask a text question.

    Args:
        question: Prompt shown to the user.
        default: Optional default value.

    Returns:
        User answer or default value.
    """

    if default:
        prompt = f"{question} [{default}]: "
    else:
        prompt = f"{question}: "

    answer = input(prompt).strip()

    if not answer and default is not None:
        return default

    return answer


def ask_yes_no(question, default=False):
    """
    Ask a yes/no question.

    Args:
        question: Prompt shown to the user.
        default: Boolean default.

    Returns:
        True for yes, False for no.
    """

    default_text = "y" if default else "n"

    while True:
        answer = input(f"{question} (y/n) [{default_text}]: ").strip().lower()

        if not answer:
            return default

        if answer in ["y", "yes"]:
            return True

        if answer in ["n", "no"]:
            return False

        print("Please enter y or n.")


def ask_list(question, default_items=None):
    """
    Ask for a comma-separated list.

    Args:
        question: Prompt shown to the user.
        default_items: Optional list of default values.

    Returns:
        List of strings.
    """

    default_items = default_items or []
    default_text = ", ".join(default_items)

    if default_text:
        prompt = f"{question} [{default_text}]: "
    else:
        prompt = f"{question}: "

    answer = input(prompt).strip()

    if not answer:
        return default_items

    return [item.strip() for item in answer.split(",") if item.strip()]


def choose_system_type():
    """
    Ask the user to choose a supported AI system type.

    Returns:
        Selected system type string.
    """

    print("\nSupported AI system types:")

    for index, system_type in enumerate(SUPPORTED_SYSTEM_TYPES, start=1):
        print(f"{index}. {system_type}")

    while True:
        answer = input("\nChoose a system type by number or name: ").strip()

        if answer.isdigit():
            selected_index = int(answer)

            if 1 <= selected_index <= len(SUPPORTED_SYSTEM_TYPES):
                return SUPPORTED_SYSTEM_TYPES[selected_index - 1]

        normalized_answer = answer.lower()

        for system_type in SUPPORTED_SYSTEM_TYPES:
            if normalized_answer == system_type.lower():
                return system_type

        print("Please choose a valid system type.")


def get_default_assets(system_type):
    """
    Return default assets based on system type.

    Args:
        system_type: AI system type.

    Returns:
        List of asset strings.
    """

    common_assets = [
        "user prompts",
        "model responses",
        "system prompt",
        "chat logs",
    ]

    if system_type == "RAG application":
        return common_assets + [
            "retrieved documents",
            "document store",
            "citations",
            "access control rules",
        ]

    if system_type == "AI agent with tools":
        return common_assets + [
            "tools",
            "tool outputs",
            "agent permissions",
            "approval decisions",
        ]

    if system_type == "document summarizer":
        return common_assets + [
            "uploaded files",
            "private documents",
            "document summaries",
        ]

    if system_type == "customer support bot":
        return common_assets + [
            "customer questions",
            "support knowledge base",
            "fake customer records",
        ]

    if system_type == "internal enterprise assistant":
        return common_assets + [
            "internal documents",
            "employee questions",
            "private company knowledge",
            "access control rules",
        ]

    if system_type == "code assistant":
        return common_assets + [
            "source code",
            "developer prompts",
            "code suggestions",
            "repository metadata",
        ]

    if system_type == "data analysis assistant":
        return common_assets + [
            "datasets",
            "analysis results",
            "charts",
            "business decisions",
        ]

    return common_assets


def get_default_trust_boundaries(system_type):
    """
    Return default trust boundaries based on system type.

    Args:
        system_type: AI system type.

    Returns:
        List of trust boundary strings.
    """

    boundaries = [
        "user input to AI application",
        "AI application to model",
        "model output to end user",
        "AI application to logging system",
    ]

    if system_type == "RAG application":
        boundaries.extend(
            [
                "AI application to retrieval system",
                "retrieval system to document store",
                "retrieved context to model prompt",
            ]
        )

    if system_type == "AI agent with tools":
        boundaries.extend(
            [
                "AI agent to tool layer",
                "tool layer to connected systems",
                "tool output back to AI agent",
            ]
        )

    if system_type == "document summarizer":
        boundaries.extend(
            [
                "uploaded file to document parser",
                "document parser to model prompt",
            ]
        )

    return boundaries


def get_default_data_flows(system_type):
    """
    Return default data flows based on system type.

    Args:
        system_type: AI system type.

    Returns:
        List of data flow strings.
    """

    flows = [
        "User submits a prompt to the AI system.",
        "The application sends relevant input to the model.",
        "The model generates a response.",
        "The application returns the response to the user.",
        "The system may store logs for review or troubleshooting.",
    ]

    if system_type == "RAG application":
        flows.insert(1, "The application sends a query to a retrieval system.")
        flows.insert(2, "The retrieval system returns document chunks.")

    if system_type == "AI agent with tools":
        flows.insert(1, "The agent decides whether a tool is needed.")
        flows.insert(2, "The tool layer returns output to the agent.")

    if system_type == "document summarizer":
        flows.insert(1, "The user provides a document for summarization.")
        flows.insert(2, "The system extracts text from the document.")

    return flows


def get_default_assumptions(system_type):
    """
    Return default assumptions based on system type.

    Args:
        system_type: AI system type.

    Returns:
        List of assumption strings.
    """

    assumptions = [
        "The system description is simplified for v1 threat modeling.",
        "All examples should use fake or sanitized data only.",
        "User input should be treated as untrusted.",
        "Model output should not automatically be treated as correct.",
        "This report is not a full professional security assessment.",
    ]

    if system_type == "RAG application":
        assumptions.append("Retrieved documents may contain outdated or untrusted content.")

    if system_type == "AI agent with tools":
        assumptions.append("Tool outputs and agent actions require validation.")

    if system_type == "document summarizer":
        assumptions.append("Uploaded files may contain sensitive or untrusted content.")

    return assumptions


def get_default_features(system_type):
    """
    Return default feature values based on system type.

    Args:
        system_type: AI system type.

    Returns:
        Dictionary of feature flags.
    """

    features = {key: False for key in FEATURE_KEYS}

    features["uses_llm"] = True
    features["stores_logs"] = True
    features["has_user_authentication"] = True

    if system_type == "RAG application":
        features["uses_rag"] = True
        features["handles_private_documents"] = True
        features["handles_sensitive_data"] = True
        features["generates_citations"] = True

    if system_type == "AI agent with tools":
        features["uses_tools"] = True
        features["handles_sensitive_data"] = True
        features["has_human_approval"] = True

    if system_type == "document summarizer":
        features["allows_file_uploads"] = True
        features["handles_private_documents"] = True
        features["handles_sensitive_data"] = True

    if system_type == "customer support bot":
        features["handles_sensitive_data"] = True
        features["has_human_approval"] = True

    if system_type == "internal enterprise assistant":
        features["uses_rag"] = True
        features["handles_private_documents"] = True
        features["handles_sensitive_data"] = True
        features["generates_citations"] = True

    if system_type == "code assistant":
        features["handles_sensitive_data"] = True
        features["validates_outputs"] = False

    if system_type == "data analysis assistant":
        features["handles_sensitive_data"] = True
        features["validates_outputs"] = False

    return features


def ask_feature_questions(default_features):
    """
    Ask the user about AI system features.

    Args:
        default_features: Dictionary of default feature values.

    Returns:
        Dictionary of selected feature values.
    """

    print("\nAnswer these feature questions.")
    print("Use fake or generalized information only. Do not enter secrets or private data.\n")

    feature_questions = [
        ("uses_llm", "Does the system use an LLM or generative AI model?"),
        ("uses_rag", "Does the system use retrieval-augmented generation or a document knowledge base?"),
        ("uses_tools", "Does the system use tools or functions?"),
        ("uses_plugins", "Does the system use plugins or external integrations?"),
        ("handles_sensitive_data", "Could the system handle sensitive information?"),
        ("handles_private_documents", "Could the system access private documents?"),
        ("has_user_authentication", "Does the system require user login or authentication?"),
        ("has_role_based_access", "Does the system use role-based access control?"),
        ("stores_logs", "Does the system store prompts, responses, or activity logs?"),
        ("logs_sensitive_data", "Could logs contain sensitive data?"),
        ("has_human_approval", "Are sensitive actions reviewed by a human before completion?"),
        ("has_monitoring", "Does the system have monitoring for misuse, failures, or unsafe outputs?"),
        ("has_audit_trail", "Does the system keep an audit trail of important actions?"),
        ("allows_file_uploads", "Does the system allow file uploads?"),
        ("supports_multiple_tenants", "Does the system support multiple teams, customers, or tenants?"),
        ("generates_citations", "Does the system generate citations or source references?"),
        ("validates_outputs", "Does the system validate model outputs before showing or using them?"),
        ("has_data_retention_policy", "Does the system have a clear data retention policy?"),
        ("can_take_autonomous_actions", "Can the AI take actions without direct human approval?"),
    ]

    features = {}

    for key, question in feature_questions:
        default = default_features.get(key, False)
        features[key] = ask_yes_no(question, default)

    return features


def build_interactive_system_profile():
    """
    Build a system profile from interactive user input.

    Returns:
        Dictionary describing the AI system.
    """

    print("\nAI Threat Model Framework v1 — Interactive Mode")
    print("Use fake, generalized, or sanitized information only.")
    print("Do not enter passwords, API keys, real secrets, or private company data.\n")

    name = ask_text("System name", "Example AI System")
    system_type = choose_system_type()

    default_description = (
        f"A simplified {system_type} profile created for local AI threat modeling practice."
    )
    description = ask_text("Short system description", default_description)

    default_assets = get_default_assets(system_type)
    default_trust_boundaries = get_default_trust_boundaries(system_type)
    default_data_flows = get_default_data_flows(system_type)
    default_assumptions = get_default_assumptions(system_type)
    default_features = get_default_features(system_type)

    users = ask_list(
        "User groups, comma-separated",
        ["end users", "administrators"],
    )

    assets = ask_list(
        "Important assets, comma-separated",
        default_assets,
    )

    trust_boundaries = ask_list(
        "Trust boundaries, comma-separated",
        default_trust_boundaries,
    )

    data_flows = ask_list(
        "Data flows, comma-separated",
        default_data_flows,
    )

    assumptions = ask_list(
        "Assumptions, comma-separated",
        default_assumptions,
    )

    features = ask_feature_questions(default_features)

    return {
        "name": name,
        "system_type": system_type,
        "description": description,
        "users": users,
        "assets": assets,
        "trust_boundaries": trust_boundaries,
        "data_flows": data_flows,
        "assumptions": assumptions,
        "features": features,
    }