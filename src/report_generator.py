"""
Report generation for AI Threat Model Framework v1.

This file writes threat model results to JSON and Markdown files.
It uses only the Python standard library.
"""

import json
import os


def ensure_output_directory(file_path):
    """
    Create the output directory if it does not already exist.

    Args:
        file_path: Output file path.
    """

    directory = os.path.dirname(file_path)

    if directory:
        os.makedirs(directory, exist_ok=True)


def write_json_report(threat_model, output_path):
    """
    Write the threat model to a JSON file.

    Args:
        threat_model: Full threat model dictionary.
        output_path: Path where the JSON file should be saved.
    """

    ensure_output_directory(output_path)

    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(threat_model, file, indent=2)


def format_list(items):
    """
    Format a list of strings as Markdown bullet points.

    Args:
        items: List of strings.

    Returns:
        Markdown-formatted bullet list.
    """

    if not items:
        return "- None listed"

    return "\n".join(f"- {item}" for item in items)


def format_risk_summary(risk_summary):
    """
    Format the risk summary as Markdown.

    Args:
        risk_summary: Dictionary of risk counts.

    Returns:
        Markdown table as a string.
    """

    return (
        "| Risk Level | Count |\n"
        "|---|---:|\n"
        f"| Critical | {risk_summary.get('critical', 0)} |\n"
        f"| High | {risk_summary.get('high', 0)} |\n"
        f"| Medium | {risk_summary.get('medium', 0)} |\n"
        f"| Low | {risk_summary.get('low', 0)} |\n"
        f"| Total | {risk_summary.get('total', 0)} |"
    )


def format_threat_summary_table(findings):
    """
    Format findings into a compact Markdown summary table.

    Args:
        findings: List of finding dictionaries.

    Returns:
        Markdown table as a string.
    """

    if not findings:
        return "No findings generated."

    lines = [
        "| ID | Category | Likelihood | Impact | Risk |",
        "|---|---|---|---|---|",
    ]

    for finding in findings:
        lines.append(
            "| {threat_id} | {category} | {likelihood} | {impact} | {risk_level} |".format(
                threat_id=finding.get("threat_id", ""),
                category=finding.get("category", ""),
                likelihood=finding.get("likelihood", ""),
                impact=finding.get("impact", ""),
                risk_level=finding.get("risk_level", ""),
            )
        )

    return "\n".join(lines)


def format_detailed_findings(findings):
    """
    Format detailed findings as Markdown sections.

    Args:
        findings: List of finding dictionaries.

    Returns:
        Markdown text.
    """

    if not findings:
        return "No detailed findings generated."

    sections = []

    for finding in findings:
        affected_assets = format_list(finding.get("affected_assets", []))

        section = f"""### {finding.get("threat_id", "")} — {finding.get("category", "")}

**Risk level:** {finding.get("risk_level", "")}  
**Likelihood:** {finding.get("likelihood", "")}  
**Impact:** {finding.get("impact", "")}

**Description:**  
{finding.get("description", "")}

**Affected assets:**  
{affected_assets}

**Reason:**  
{finding.get("reason", "")}

**Recommended mitigation:**  
{finding.get("recommended_mitigation", "")}

**Residual risk:**  
{finding.get("residual_risk", "")}
"""
        sections.append(section)

    return "\n".join(sections)


def format_action_plan(action_plan):
    """
    Format the prioritized action plan as Markdown.

    Args:
        action_plan: List of action plan dictionaries.

    Returns:
        Markdown table as a string.
    """

    if not action_plan:
        return "No action plan items generated."

    lines = [
        "| Priority | Risk | Threat ID | Category | Recommended Action |",
        "|---:|---|---|---|---|",
    ]

    for item in action_plan:
        lines.append(
            "| {priority} | {risk_level} | {threat_id} | {category} | {action} |".format(
                priority=item.get("priority", ""),
                risk_level=item.get("risk_level", ""),
                threat_id=item.get("threat_id", ""),
                category=item.get("category", ""),
                action=item.get("action", ""),
            )
        )

    return "\n".join(lines)


def build_markdown_report(threat_model):
    """
    Build a Markdown report from the threat model dictionary.

    Args:
        threat_model: Full threat model dictionary.

    Returns:
        Markdown report string.
    """

    overview = threat_model.get("system_overview", {})
    risk_summary = threat_model.get("risk_summary", {})
    findings = threat_model.get("findings", [])
    action_plan = threat_model.get("prioritized_action_plan", [])

    markdown = f"""# {threat_model.get("title", "AI Threat Model Report")}

## System Overview

**System name:** {overview.get("name", "Unnamed System")}  
**System type:** {overview.get("system_type", "Unknown")}

{overview.get("description", "")}

## Users

{format_list(overview.get("users", []))}

## Assets

{format_list(threat_model.get("assets", []))}

## Trust Boundaries

{format_list(threat_model.get("trust_boundaries", []))}

## Data Flows

{format_list(threat_model.get("data_flows", []))}

## Assumptions

{format_list(threat_model.get("assumptions", []))}

## Risk Summary

{format_risk_summary(risk_summary)}

## Threat Summary Table

{format_threat_summary_table(findings)}

## Detailed Threat Findings

{format_detailed_findings(findings)}

## Prioritized Action Plan

{format_action_plan(action_plan)}

## Disclaimer

{threat_model.get("disclaimer", "")}
"""

    return markdown


def write_markdown_report(threat_model, output_path):
    """
    Write the threat model to a Markdown file.

    Args:
        threat_model: Full threat model dictionary.
        output_path: Path where the Markdown file should be saved.
    """

    ensure_output_directory(output_path)
    markdown = build_markdown_report(threat_model)

    with open(output_path, "w", encoding="utf-8") as file:
        file.write(markdown)


def write_reports(threat_model, json_output_path, markdown_output_path):
    """
    Write both JSON and Markdown reports.

    Args:
        threat_model: Full threat model dictionary.
        json_output_path: JSON output path.
        markdown_output_path: Markdown output path.
    """

    write_json_report(threat_model, json_output_path)
    write_markdown_report(threat_model, markdown_output_path)