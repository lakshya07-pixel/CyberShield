# Cybersecurity Threat Advisory Engine

## Overview

This module generates cybersecurity advisories for three threat types:

- Intrusion
- Phishing
- Scam

It uses rule-based explanations, confidence-based severity classification, and recommended security actions.

Experimental Llama-generated text is currently disabled in the user-facing advisory because it may contain unsupported claims.

## Project Structure

```text
threat_engine/
├── advisory.py
├── severity.py
├── rules.py
├── recommendations.py
├── test_project.py
├── README.md
├── samples/
│   ├── intrusion.json
│   ├── phishing.json
│   └── scam.json
└── llama/
    ├── inference.py
    ├── prompt_builder.py
    └── test_prompt.py
```

## Requirements

- Python 3
- No additional packages are required for the current rule-based workflow and built-in `unittest` tests.

## Run the Advisory

From the `threat_engine` directory, run:

```bash
python advisory.py
```

By default, this runs the intrusion sample.

To run another sample, use:

```bash
python -c 'from advisory import generate_advisory; generate_advisory("samples/phishing.json")'
```

```bash
python -c 'from advisory import generate_advisory; generate_advisory("samples/scam.json")'
```

## Severity Classification

Severity is calculated from the confidence value, and the calculated severity is displayed in the advisory. Any `severity` value already present in the input JSON is not used by the current advisory workflow.

| Confidence | Severity |
|---|---|
| Below 0.50 | Low |
| 0.50 to below 0.75 | Medium |
| 0.75 to below 0.90 | High |
| 0.90 to 1.00 | Critical |

Confidence values outside the range 0 to 1, as well as non-numeric confidence values, are rejected.

## Run Automated Tests

Run:

```bash
python -m unittest test_project -v
```

The tests cover severity thresholds, invalid confidence values, threat explanations, recommendations, sample files, and all three advisory workflows.

## Integration Interface

The shared `schemas.py` file defines `create_threat_result()`, which returns a dictionary containing:

- `source`
- `threat_type`
- `severity`
- `confidence`
- `indicators`
- `metadata`
- `timestamp`

Integration with Person 1's detection module remains pending. The shared schema should be checked against the detection module's actual output before integration.

## Limitations

- The current examples use sample JSON inputs.
- The advisory engine has not yet been verified end to end with Person 1's module.
- Llama-generated text is disabled in the user-facing advisory until its claims can be verified.
- Completion against the official CyberShield Challenge requirements has not yet been confirmed.
