"""
Risk scoring and threat evaluation engine for AI Threat Model Framework v1.

This file evaluates a simple AI system profile against the threat library.
The logic is intentionally rules-based, beginner-friendly, and safe.

No real scanning, exploitation, network calls, API calls, or offensive behavior
happens here. The engine only reviews the provided system profile and generates
structured findings.
"""


VALID_LEVELS = ["low", "medium", "high"]


def normalize_level(level):
    """
    Normalize a likelihood or impact value.

    Args:
        level: A string such as low, medium, or high.

    Returns:
        A lowercase valid level.

    Raises:
        ValueError: If the level is not valid.
    """

    if not isinstance(level, str):
        raise ValueError("Level must be a string.")

    normalized = level.strip().lower()

    if normalized not in VALID_LEVELS:
        raise ValueError(f"Invalid level: {level}")

    return normalized


def calculate_risk_level(likelihood, impact):
    """
    Calculate risk level from likelihood and impact.

    Rules:
    - Critical: high likelihood and high impact
    - High: high likelihood with medium impact, or medium likelihood with high impact
    - Medium: moderate likelihood or moderate impact
    - Low: limited impact and unlikely

    Args:
        likelihood: low, medium, or high
        impact: low, medium, or high

    Returns:
        low, medium, high, or critical
    """

    likelihood = normalize_level(likelihood)
    impact = normalize_level(impact)

    if likelihood == "high" and impact == "high":
        return "critical"

    if likelihood == "high" and impact == "medium":
        return "high"

    if likelihood == "medium" and impact == "high":
        return "high"

    if likelihood == "high" and impact == "low":
        return "medium"

    if likelihood == "low" and impact == "high":
        return "medium"

    if likelihood == "medium" or impact == "medium":
        return "medium"

    return "low"


def get_feature(system_profile, feature_name):
    """
    Safely read a boolean feature from the system profile.

    Args:
        system_profile: Dictionary describing the AI system.
        feature_name: Feature name inside system_profile["features"].

    Returns:
        True or False.
    """

    features = system_profile.get("features", {})
    return bool(features.get(feature_name, False))


def has_any_feature(system_profile, feature_names):
    """
    Check whether any feature in a list is enabled.

    Args:
        system_profile: Dictionary describing the AI system.
        feature_names: List of feature names.

    Returns:
        True if any feature is enabled, otherwise False.
    """

    return any(get_feature(system_profile, feature) for feature in feature_names)


def should_include_threat(system_profile, threat):
    """
    Decide whether a threat applies to the system profile.

    Most threats apply when a matching feature is enabled.
    Some threats are inverse checks, meaning they apply when a control is missing.

    Args:
        system_profile: Dictionary describing the AI system.
        threat: Threat dictionary from threat_library.py.

    Returns:
        True if the threat should become a finding.
    """

    threat_id = threat.get("threat_id")

    # General LLM threats
    if threat_id in [
        "AI-TM-001",  # Prompt injection
        "AI-TM-002",  # System prompt leakage
        "AI-TM-011",  # Training data leakage
        "AI-TM-013",  # Hallucinated output
        "AI-TM-015",  # Model over-trust
        "AI-TM-019",  # Jailbreak attempts
        "AI-TM-025",  # Social engineering through AI responses
    ]:
        return get_feature(system_profile, "uses_llm")

    # RAG-specific threats
    if threat_id in [
        "AI-TM-004",  # RAG document poisoning
        "AI-TM-005",  # Untrusted retrieved context
    ]:
        return get_feature(system_profile, "uses_rag")

    # Tool and agent threats
    if threat_id in [
        "AI-TM-006",  # Tool misuse
        "AI-TM-007",  # Over-permissioned agent actions
    ]:
        return has_any_feature(system_profile, ["uses_tools", "can_take_autonomous_actions"])

    # Missing human approval should trigger when approval is missing
    # and the system has enough risk to justify review.
    if threat_id == "AI-TM-008":
        approval_missing = not get_feature(system_profile, "has_human_approval")
        review_needed = has_any_feature(
            system_profile,
            [
                "uses_tools",
                "can_take_autonomous_actions",
                "handles_sensitive_data",
                "handles_private_documents",
            ],
        )
        return approval_missing and review_needed

    # Access control risk should trigger when the system has authentication
    # but does not have role-based access control.
    if threat_id == "AI-TM-009":
        has_authentication = get_feature(system_profile, "has_user_authentication")
        missing_role_controls = not get_feature(system_profile, "has_role_based_access")
        protects_sensitive_assets = has_any_feature(
            system_profile,
            [
                "handles_sensitive_data",
                "handles_private_documents",
                "uses_rag",
                "supports_multiple_tenants",
            ],
        )
        return has_authentication and missing_role_controls and protects_sensitive_assets

    # Insecure logging should trigger only when logs may contain sensitive data.
    if threat_id == "AI-TM-010":
        return get_feature(system_profile, "stores_logs") and get_feature(
            system_profile, "logs_sensitive_data"
        )

    # Sensitive/private data threats
    if threat_id == "AI-TM-003":
        return get_feature(system_profile, "handles_sensitive_data")

    if threat_id == "AI-TM-012":
        return get_feature(system_profile, "handles_private_documents")

    # Citation risk
    if threat_id == "AI-TM-014":
        return get_feature(system_profile, "generates_citations")

    # File handling risk
    if threat_id == "AI-TM-016":
        return get_feature(system_profile, "allows_file_uploads")

    # Plugin risk
    if threat_id == "AI-TM-017":
        return get_feature(system_profile, "uses_plugins")

    # Cross-tenant risk
    if threat_id == "AI-TM-018":
        return get_feature(system_profile, "supports_multiple_tenants")

    # Data retention risk should trigger when data is stored but no retention policy exists.
    if threat_id == "AI-TM-020":
        stores_data = get_feature(system_profile, "stores_logs") or get_feature(
            system_profile, "allows_file_uploads"
        )
        missing_policy = not get_feature(system_profile, "has_data_retention_policy")
        return stores_data and missing_policy

    # Missing monitoring should trigger when monitoring is absent.
    if threat_id == "AI-TM-021":
        return not get_feature(system_profile, "has_monitoring")

    # Missing audit trail should trigger when audit trail is absent.
    if threat_id == "AI-TM-022":
        return not get_feature(system_profile, "has_audit_trail")

    # Unsafe autonomous actions
    if threat_id == "AI-TM-023":
        return get_feature(system_profile, "can_take_autonomous_actions")

    # Inadequate output validation should trigger when validation is missing.
    if threat_id == "AI-TM-024":
        return get_feature(system_profile, "uses_llm") and not get_feature(
            system_profile, "validates_outputs"
        )

    # Default behavior:
    # Include the threat if any listed trigger feature is enabled.
    trigger_features = threat.get("trigger_features", [])
    return has_any_feature(system_profile, trigger_features)


def adjust_likelihood_and_impact(system_profile, threat):
    """
    Make small context-aware adjustments to likelihood and impact.

    This keeps the engine simple while making the findings more useful.

    Args:
        system_profile: Dictionary describing the AI system.
        threat: Threat dictionary from threat_library.py.

    Returns:
        Tuple of likelihood and impact.
    """

    likelihood = threat.get("likelihood", "medium")
    impact = threat.get("impact", "medium")
    threat_id = threat.get("threat_id")

    handles_sensitive_data = get_feature(system_profile, "handles_sensitive_data")
    handles_private_documents = get_feature(system_profile, "handles_private_documents")
    uses_tools = get_feature(system_profile, "uses_tools")
    supports_multiple_tenants = get_feature(system_profile, "supports_multiple_tenants")
    can_take_autonomous_actions = get_feature(system_profile, "can_take_autonomous_actions")

    # Sensitive data and private documents increase impact for exposure-related threats.
    if threat_id in ["AI-TM-003", "AI-TM-010", "AI-TM-012", "AI-TM-020"]:
        if handles_sensitive_data or handles_private_documents:
            impact = "high"

    # Tools and autonomous actions increase impact.
    if threat_id in ["AI-TM-006", "AI-TM-007", "AI-TM-008", "AI-TM-023"]:
        if uses_tools or can_take_autonomous_actions:
            impact = "high"

    # Multi-tenant systems increase impact for data separation issues.
    if threat_id == "AI-TM-018" and supports_multiple_tenants:
        impact = "high"

    # Missing monitoring and missing audit trail become more serious when
    # the system handles sensitive data or uses tools.
    if threat_id in ["AI-TM-021", "AI-TM-022"]:
        if handles_sensitive_data or handles_private_documents or uses_tools:
            impact = "high"

    return likelihood, impact


def build_finding(system_profile, threat):
    """
    Build a single structured threat finding.

    Args:
        system_profile: Dictionary describing the AI system.
        threat: Threat dictionary from threat_library.py.

    Returns:
        A finding dictionary.
    """

    likelihood, impact = adjust_likelihood_and_impact(system_profile, threat)
    risk_level = calculate_risk_level(likelihood, impact)

    return {
        "threat_id": threat["threat_id"],
        "category": threat["category"],
        "description": threat["description"],
        "affected_assets": threat.get("affected_assets", []),
        "likelihood": likelihood,
        "impact": impact,
        "risk_level": risk_level,
        "reason": threat.get("reason", ""),
        "recommended_mitigation": threat.get("recommended_mitigation", ""),
        "residual_risk": threat.get("residual_risk", "medium"),
    }


def generate_findings(system_profile, threat_library):
    """
    Generate threat findings for an AI system profile.

    Args:
        system_profile: Dictionary describing the AI system.
        threat_library: List of threat dictionaries.

    Returns:
        List of finding dictionaries.
    """

    findings = []

    for threat in threat_library:
        if should_include_threat(system_profile, threat):
            finding = build_finding(system_profile, threat)
            findings.append(finding)

    return findings


def summarize_risks(findings):
    """
    Count findings by risk level.

    Args:
        findings: List of finding dictionaries.

    Returns:
        Dictionary with counts for low, medium, high, critical, and total.
    """

    summary = {
        "total": len(findings),
        "low": 0,
        "medium": 0,
        "high": 0,
        "critical": 0,
    }

    for finding in findings:
        risk_level = finding.get("risk_level", "medium")

        if risk_level not in summary:
            summary[risk_level] = 0

        summary[risk_level] += 1

    return summary


def sort_findings_by_priority(findings):
    """
    Sort findings from highest risk to lowest risk.

    Args:
        findings: List of finding dictionaries.

    Returns:
        Sorted list of finding dictionaries.
    """

    priority_order = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
    }

    return sorted(
        findings,
        key=lambda finding: priority_order.get(finding.get("risk_level", "low"), 0),
        reverse=True,
    )


def build_action_plan(findings):
    """
    Build a simple prioritized action plan from the findings.

    Args:
        findings: List of finding dictionaries.

    Returns:
        List of action plan items.
    """

    sorted_findings = sort_findings_by_priority(findings)
    action_plan = []

    for index, finding in enumerate(sorted_findings, start=1):
        action_plan.append(
            {
                "priority": index,
                "risk_level": finding["risk_level"],
                "threat_id": finding["threat_id"],
                "category": finding["category"],
                "action": finding["recommended_mitigation"],
            }
        )

    return action_plan


def build_threat_model(system_profile, threat_library):
    """
    Build the full threat model result.

    Args:
        system_profile: Dictionary describing the AI system.
        threat_library: List of threat dictionaries.

    Returns:
        Full threat model dictionary.
    """

    findings = generate_findings(system_profile, threat_library)
    sorted_findings = sort_findings_by_priority(findings)

    return {
        "title": f"AI Threat Model Report: {system_profile.get('name', 'Unnamed System')}",
        "system_overview": {
            "name": system_profile.get("name", "Unnamed System"),
            "system_type": system_profile.get("system_type", "Unknown"),
            "description": system_profile.get("description", ""),
            "users": system_profile.get("users", []),
        },
        "assets": system_profile.get("assets", []),
        "trust_boundaries": system_profile.get("trust_boundaries", []),
        "data_flows": system_profile.get("data_flows", []),
        "assumptions": system_profile.get("assumptions", []),
        "risk_summary": summarize_risks(sorted_findings),
        "findings": sorted_findings,
        "prioritized_action_plan": build_action_plan(sorted_findings),
        "disclaimer": (
            "This report is generated by a simple local rules-based tool for "
            "defensive education and portfolio demonstration. It is not a full "
            "professional security assessment, legal review, compliance audit, "
            "or production architecture review."
        ),
    }