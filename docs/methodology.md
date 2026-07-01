# Methodology

AI Threat Model Framework v1 uses a simple rules-based methodology to generate basic threat models for AI, LLM, RAG, and AI-agent systems.

This project is intentionally small and local. It does not perform live scanning, exploitation, API calls, network requests, or real security testing. It organizes likely AI security concerns based on system features provided by the user or by the sample profile.

## Purpose

The purpose of this methodology is to help users think clearly about AI system risk.

The tool focuses on:

- System description
- Assets
- Trust boundaries
- Data flows
- Assumptions
- Threat findings
- Likelihood
- Impact
- Risk level
- Mitigations
- Residual risk
- Prioritized action plan

The goal is not to prove that a system is secure or insecure. The goal is to create a structured starting point for review.

## Defensive Use Only

This tool is for defensive security education, documentation, portfolio work, and safe analysis.

It does not provide offensive exploit steps, malware behavior, credential theft instructions, unauthorized access guidance, or real-world attack automation.

All examples should use fake, generalized, or sanitized information.

## Core Design Principle

AI systems have unique trust boundaries.

A traditional application may treat user input, internal data, backend systems, and logs as separate security areas. AI systems add more complexity because they may also include:

- User prompts
- System prompts
- Retrieved documents
- Vector or document stores
- Tool outputs
- Plugin responses
- Uploaded files
- Model-generated text
- Citations
- Agent actions
- Logs containing prompts and responses

These pieces should not all be trusted equally.

For example:

- User input should be treated as untrusted.
- Retrieved documents should be treated as potentially incomplete, outdated, or manipulated.
- Tool outputs should be validated before use.
- Model responses should not automatically be treated as correct.
- Logs may contain sensitive data and should be protected.

## Inputs

The tool can build a threat model from two input modes.

### Sample Mode

Sample mode uses a fake prebuilt AI system profile.

This allows the project to work immediately after setup.

Default command:

```bash
python src/main.py --mode sample