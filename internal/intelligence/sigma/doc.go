// Package sigma implements a Sigma rule transpiler that converts Sigma
// detection rules into native R3TRIVE correlation rules.
//
// The Sigma transpiler parses Sigma YAML rules, converts selection logic
// and modifiers (contains, startswith, endswith, re) into R3TRIVE condition schemas,
// and maps platform fields.
package sigma
