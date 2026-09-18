// Package rule defines the detection rule types and DSL used by the
// R3TRIVE rule engine.
//
// Key capabilities include:
// - Rule struct with YAML serialization and condition evaluation
// - Multiple condition types (field match, temporal sequence, threshold)
// - Rich operator set (eq, ne, contains, regex, gt, lt, oneOf, noneOf)
// - Rule loading, validation, and ATT&CK tactic/technique tagging
//
// See RULE_ENGINE_SPEC.md for the full rule language specification.
package rule
