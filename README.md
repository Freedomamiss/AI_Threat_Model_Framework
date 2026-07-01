AI Threat Model Framework v1

A beginner-friendly command-line Python tool for generating basic threat models for AI, LLM, RAG, and AI-agent systems.

This project is designed for defensive AI security education, portfolio use, and safe security review practice. It does not attack systems, exploit vulnerabilities, steal data, or use real secrets.

Project Purpose

AI systems introduce unique security risks because they often combine user input, model responses, retrieved documents, files, plugins, tools, APIs, and internal data. These components do not all deserve the same level of trust.

The purpose of this tool is to help organize those risks into a clear threat model that includes:

System description
Assets
Trust boundaries
Data flows
Assumptions
Threats
Likelihood
Impact
Risk level
Recommended mitigations
Residual risk
Prioritized action plan

This is not a replacement for a full professional security assessment. It is a structured local tool for learning, documentation, and portfolio demonstration.

Portfolio Context

This is Project 3 in an AI security portfolio.

Previous projects:

LLM Prompt Injection Tester
RAG Security Scanner
AI Threat Model Framework v1

Together, these projects show practical knowledge of AI security testing, RAG risk review, and AI threat modeling.

Features
Local command-line tool
No API keys required
No cloud deployment
No database
No web app
Sample mode with fake AI system profiles
Interactive mode for user-created AI system profiles
Rules-based threat identification
Simple risk scoring engine
JSON report output
Markdown report output
At least 25 AI-specific threat categories
Beginner-friendly Python code
Pytest tests for risk scoring
Safe fake examples only
Supported AI System Types

The tool supports basic threat modeling for:

General chatbot
RAG application
AI agent with tools
Document summarizer
Customer support bot
Internal enterprise assistant
Code assistant
Data analysis assistant
Threat Categories

The v1 threat library includes:

Prompt injection
System prompt leakage
Sensitive data exposure
RAG document poisoning
Untrusted retrieved context
Tool misuse
Over-permissioned agent actions
Missing human approval
Weak access control
Insecure logging
Training data leakage
Private document leakage
Hallucinated output
Unsupported citations
Model over-trust
Unsafe file handling
Insecure plugin/tool access
Cross-tenant data exposure
Jailbreak attempts
Data retention risk
Missing monitoring
Missing audit trail
Unsafe autonomous actions
Inadequate output validation
Social engineering through AI responses
Risk Scoring

The tool uses simple rules-based scoring.

Each threat finding includes:

Threat ID
Category
Description
Affected assets
Likelihood
Impact
Risk level
Reason
Recommended mitigation
Residual risk

Risk levels:

Risk Level	Meaning
Low	Limited impact and unlikely
Medium	Moderate likelihood or moderate impact
High	Likely issue with serious impact
Critical	High likelihood plus high impact, especially where sensitive data, tool actions, or cross-user exposure are involved
Repository Structure
AI_Threat_Model_Framework/

├── README.md
├── requirements.txt
├── .gitignore
├── LICENSE
├── pytest.ini

├── src/
│   ├── main.py
│   ├── questions.py
│   ├── sample_systems.py
│   ├── threat_library.py
│   ├── risk_engine.py
│   └── report_generator.py

├── tests/
│   └── test_risk_engine.py

├── examples/
│   ├── sample_threat_model.json
│   └── sample_threat_model.md

└── docs/
    ├── methodology.md
    └── threat_categories.md
Installation

Clone the repository:

git clone https://github.com/YOUR-USERNAME/AI_Threat_Model_Framework.git
cd AI_Threat_Model_Framework

Create a virtual environment:

python -m venv .venv

Activate the virtual environment on Windows:

.venv\Scripts\activate

Activate the virtual environment on macOS or Linux:

source .venv/bin/activate

Install dependencies:

pip install -r requirements.txt

The only non-standard dependency used for v1 testing is pytest.

Usage

Run sample mode:

python src/main.py --mode sample

Run interactive mode:

python src/main.py --mode interactive

Run sample mode with custom output paths:

python src/main.py --mode sample --json-output examples/sample_threat_model.json --report-output examples/sample_threat_model.md

Run tests:

python -m pytest
Example Output

The tool generates two report files:

examples/sample_threat_model.json
examples/sample_threat_model.md

The Markdown report includes:

Title
System overview
System type
Assets
Trust boundaries
Data flows
Assumptions
Threat summary table
Detailed threat findings
Recommended mitigations
Prioritized action plan
Safety disclaimer
Example Use Case

A security analyst wants to review a fake RAG-based internal assistant.

The tool may identify risks such as:

Prompt injection through user input
Poisoned documents in the knowledge base
Sensitive document leakage
Unsupported citations
Weak access control
Missing monitoring
Missing audit trail

The final report gives a structured list of findings and practical mitigations.

Safety Disclaimer

This project is for defensive security education and portfolio demonstration only.

It does not perform exploitation, credential theft, malware behavior, unauthorized access, data extraction, or offensive security testing. All examples use fake systems and fake data.

The generated reports are not a substitute for a full professional security assessment, legal review, compliance audit, or production security architecture review.

Screenshots

Screenshots will be added after the CLI is working and sample reports are generated.

Planned screenshots:

CLI sample mode output
CLI interactive mode output
Generated JSON report
Generated Markdown report
Passing pytest results
Future Improvements

Possible future improvements after v1:

More detailed system templates
More threat modeling methods
STRIDE-style mapping
OWASP LLM Top 10 mapping
NIST AI RMF mapping
CSV export
HTML report export
More test coverage
Better prioritization logic
Optional configuration file support

These are intentionally not included in v1 to keep the first version clean, local, and easy to finish.

Version

Current version:

v1.0.0