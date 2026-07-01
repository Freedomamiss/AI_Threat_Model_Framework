"""
Tests for risk_engine.py.

These tests verify the simple rules-based scoring logic used by
AI Threat Model Framework v1.
"""

import os
import sys
import pytest

# Allow tests to import files from the src/ directory.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_PATH = os.path.join(PROJECT_ROOT, "src")
sys.path.insert(0, SRC_PATH)

from risk_engine import (  # noqa: E402
    calculate_risk_level,
    normalize_level,
    should_include_threat,
    generate_findings,
    summarize_risks,
    build_threat_model,
)
from sample_systems import get_sample_system, get_sample_agent_system  # noqa: E402
from threat_library import get_threat_library, get_threat_by_id, get_threat_count  # noqa: E402


def test_normalize_level_accepts_valid_levels():
    assert normalize_level("low") == "low"
    assert normalize_level("Medium") == "medium"
    assert normalize_level(" HIGH ") == "high"


def test_normalize_level_rejects_invalid_level():
    with pytest.raises(ValueError):
        normalize_level("severe")


def test_calculate_risk_level_low():
    assert calculate_risk_level("low", "low") == "low"


def test_calculate_risk_level_medium():
    assert calculate_risk_level("medium", "low") == "medium"
    assert calculate_risk_level("low", "medium") == "medium"
    assert calculate_risk_level("medium", "medium") == "medium"


def test_calculate_risk_level_high():
    assert calculate_risk_level("high", "medium") == "high"
    assert calculate_risk_level("medium", "high") == "high"


def test_calculate_risk_level_critical():
    assert calculate_risk_level("high", "high") == "critical"


def test_threat_library_has_at_least_25_checks():
    assert get_threat_count() >= 25


def test_prompt_injection_applies_to_llm_system():
    system_profile = get_sample_system()
    threat = get_threat_by_id("AI-TM-001")

    assert should_include_threat(system_profile, threat) is True


def test_rag_document_poisoning_applies_to_rag_system():
    system_profile = get_sample_system()
    threat = get_threat_by_id("AI-TM-004")

    assert should_include_threat(system_profile, threat) is True


def test_tool_misuse_does_not_apply_to_basic_rag_without_tools():
    system_profile = get_sample_system()
    threat = get_threat_by_id("AI-TM-006")

    assert should_include_threat(system_profile, threat) is False


def test_tool_misuse_applies_to_agent_with_tools():
    system_profile = get_sample_agent_system()
    threat = get_threat_by_id("AI-TM-006")

    assert should_include_threat(system_profile, threat) is True


def test_missing_human_approval_triggers_when_approval_missing():
    system_profile = get_sample_system()
    threat = get_threat_by_id("AI-TM-008")

    assert should_include_threat(system_profile, threat) is True


def test_missing_human_approval_does_not_trigger_when_approval_exists():
    system_profile = get_sample_agent_system()
    threat = get_threat_by_id("AI-TM-008")

    assert should_include_threat(system_profile, threat) is False


def test_weak_access_control_triggers_when_rbac_missing():
    system_profile = get_sample_system()
    threat = get_threat_by_id("AI-TM-009")

    assert should_include_threat(system_profile, threat) is True


def test_insecure_logging_triggers_when_sensitive_data_is_logged():
    system_profile = get_sample_system()
    threat = get_threat_by_id("AI-TM-010")

    assert should_include_threat(system_profile, threat) is True


def test_missing_monitoring_triggers_when_monitoring_missing():
    system_profile = get_sample_system()
    threat = get_threat_by_id("AI-TM-021")

    assert should_include_threat(system_profile, threat) is True


def test_missing_audit_trail_triggers_when_audit_trail_missing():
    system_profile = get_sample_system()
    threat = get_threat_by_id("AI-TM-022")

    assert should_include_threat(system_profile, threat) is True


def test_inadequate_output_validation_triggers_when_validation_missing():
    system_profile = get_sample_system()
    threat = get_threat_by_id("AI-TM-024")

    assert should_include_threat(system_profile, threat) is True


def test_generate_findings_returns_findings():
    system_profile = get_sample_system()
    threat_library = get_threat_library()

    findings = generate_findings(system_profile, threat_library)

    assert len(findings) > 0
    assert "threat_id" in findings[0]
    assert "risk_level" in findings[0]


def test_summarize_risks_counts_total_findings():
    findings = [
        {"risk_level": "low"},
        {"risk_level": "medium"},
        {"risk_level": "high"},
        {"risk_level": "critical"},
        {"risk_level": "critical"},
    ]

    summary = summarize_risks(findings)

    assert summary["total"] == 5
    assert summary["low"] == 1
    assert summary["medium"] == 1
    assert summary["high"] == 1
    assert summary["critical"] == 2


def test_build_threat_model_has_required_sections():
    system_profile = get_sample_system()
    threat_library = get_threat_library()

    threat_model = build_threat_model(system_profile, threat_library)

    assert "title" in threat_model
    assert "system_overview" in threat_model
    assert "assets" in threat_model
    assert "trust_boundaries" in threat_model
    assert "data_flows" in threat_model
    assert "assumptions" in threat_model
    assert "risk_summary" in threat_model
    assert "findings" in threat_model
    assert "prioritized_action_plan" in threat_model
    assert "disclaimer" in threat_model


def test_build_threat_model_sorts_critical_findings_first():
    system_profile = get_sample_system()
    threat_library = get_threat_library()

    threat_model = build_threat_model(system_profile, threat_library)
    findings = threat_model["findings"]

    risk_order = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
    }

    scores = [risk_order[finding["risk_level"]] for finding in findings]

    assert scores == sorted(scores, reverse=True)