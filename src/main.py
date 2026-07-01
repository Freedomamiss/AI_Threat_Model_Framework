"""
Main CLI entry point for AI Threat Model Framework v1.

This tool generates simple defensive threat models for AI systems.
It supports sample mode and interactive mode.

No exploitation, scanning, API calls, network calls, secrets, or real private
data are used. This is a local rules-based educational tool.
"""

import argparse

from questions import build_interactive_system_profile
from report_generator import write_reports
from risk_engine import build_threat_model
from sample_systems import get_sample_system
from threat_library import get_threat_library


DEFAULT_JSON_OUTPUT = "examples/sample_threat_model.json"
DEFAULT_REPORT_OUTPUT = "examples/sample_threat_model.md"


def parse_arguments():
    """
    Parse command-line arguments.

    Returns:
        Parsed argparse namespace.
    """

    parser = argparse.ArgumentParser(
        description="Generate a basic AI security threat model."
    )

    parser.add_argument(
        "--mode",
        choices=["sample", "interactive"],
        default="sample",
        help="Run mode: sample or interactive. Default: sample.",
    )

    parser.add_argument(
        "--json-output",
        default=DEFAULT_JSON_OUTPUT,
        help=f"Path for JSON output. Default: {DEFAULT_JSON_OUTPUT}",
    )

    parser.add_argument(
        "--report-output",
        default=DEFAULT_REPORT_OUTPUT,
        help=f"Path for Markdown report output. Default: {DEFAULT_REPORT_OUTPUT}",
    )

    return parser.parse_args()


def get_system_profile(mode):
    """
    Get the AI system profile based on selected mode.

    Args:
        mode: sample or interactive.

    Returns:
        Dictionary describing the AI system.
    """

    if mode == "interactive":
        return build_interactive_system_profile()

    return get_sample_system()


def print_summary(threat_model, json_output, report_output):
    """
    Print a simple CLI summary after report generation.

    Args:
        threat_model: Full threat model dictionary.
        json_output: JSON output path.
        report_output: Markdown report output path.
    """

    overview = threat_model.get("system_overview", {})
    risk_summary = threat_model.get("risk_summary", {})

    print("\nAI Threat Model Framework v1")
    print("============================")
    print(f"System:      {overview.get('name', 'Unnamed System')}")
    print(f"System type: {overview.get('system_type', 'Unknown')}")
    print("")
    print(f"Total findings: {risk_summary.get('total', 0)}")
    print(f"Critical:       {risk_summary.get('critical', 0)}")
    print(f"High:           {risk_summary.get('high', 0)}")
    print(f"Medium:         {risk_summary.get('medium', 0)}")
    print(f"Low:            {risk_summary.get('low', 0)}")
    print("")
    print(f"JSON report saved to:     {json_output}")
    print(f"Markdown report saved to: {report_output}")
    print("")
    print("Defensive use only. This is not a full professional security assessment.")


def main():
    """
    Run the CLI application.
    """

    args = parse_arguments()

    system_profile = get_system_profile(args.mode)
    threat_library = get_threat_library()
    threat_model = build_threat_model(system_profile, threat_library)

    write_reports(
        threat_model=threat_model,
        json_output_path=args.json_output,
        markdown_output_path=args.report_output,
    )

    print_summary(
        threat_model=threat_model,
        json_output=args.json_output,
        report_output=args.report_output,
    )


if __name__ == "__main__":
    main()