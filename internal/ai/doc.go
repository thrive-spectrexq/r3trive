// Package ai implements the AI Analyst Layer, providing natural-language
// security analysis powered by local (Ollama) or cloud (OpenAI-compatible)
// language models.
//
// See AI_ANALYST_SPEC.md for full specification.
package ai

// TODO: Implement AI Analyst Layer:
//
// Sub-packages:
//   context/ — Context builder for constructing AI prompts
//   prompt/  — Prompt templates for different analysis types
//   router/  — Model router (Ollama, OpenAI, Anthropic)
//   rag/     — RAG pipeline for ATT&CK knowledge base
//   parser/  — Response parser for structured AI output
//
// Features:
//   - explain: Natural-language incident/alert explanation
//   - summarize: Activity summary over time range
//   - generate-rule: Detection rule generation from incidents
//   - ask: Free-form security query
