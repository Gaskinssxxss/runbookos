# Changelog

## 0.7.0

- Added versioned evidence-aware structured assessments and deterministic evidence-reference validation.
- Added an offline held-out evaluation framework and read-only incident assessment views in the CLI and authenticated dashboard.
- Integrated Minimal Semantic Reply v2 into the explicit incident investigation workflow. The provider returns semantic fields only; the adapter builds provenance metadata and the existing validator remains authoritative.
- Persisted sanitized investigation failures without storing raw prompts or model responses.
- Added an isolated offline operator demo for incident, evidence, assessment, CLI, and authenticated dashboard review.
- Synthetic evaluation and demo results do not establish production diagnostic accuracy or real-server readiness. Real remediation and operational deployment remain separately controlled.
