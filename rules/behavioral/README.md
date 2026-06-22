# Behavioral Detection Rules

This directory contains behavioral detection rules written in R3TRIVE's YAML-based rule DSL.

Rules detect suspicious behavior patterns such as:
- Encoded PowerShell execution
- Suspicious parent-child process chains
- LOLBIN abuse (certutil, mshta, regsvr32, etc.)
- Credential access tool execution
- Suspicious network beaconing

## Rule ID Format

- Core rules: `R3T-{CATEGORY}-{NNN}` (e.g., R3T-EXEC-001)
- Community rules: `COMM-{CATEGORY}-{NNN}`
- Draft rules: `DRAFT-{descriptive-name}`

See [RULE_ENGINE_SPEC.md](/RULE_ENGINE_SPEC.md) for rule authoring documentation.
