// Package yara provides a pure Go rule parser and string matching engine
// with a fallback structure for environments where libyara CGO is unavailable.
//
// Capabilities include:
// - Rule and string rule extraction from YARA rule files
// - Aho-Corasick and regular expression matching across byte streams
// - Match result reporting with byte offsets and identifiers
package yara
