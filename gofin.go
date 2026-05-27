// Package gofin is the top-level API for the browser-fingerprint diagnostics
// library.
//
// Usage:
//
//	result, err := gofin.AnalyzeJSON(rawJSON)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(result.Explanation)
//
// The three-step pipeline is:
//
//  1. fingerprint.Parse  — validate and decode the JSON payload
//  2. risk.Evaluate      — evaluate every detection rule, build a score
//  3. explain.Explain    — render a human-readable narrative
//
// Callers that need fine-grained control can invoke each step individually.
// The root package simply wires them together in the canonical order.
package gofin

import (
	"github.com/slyt/gofin/explain"
	"github.com/slyt/gofin/fingerprint"
	"github.com/slyt/gofin/risk"
)

// Analyze scores a pre-parsed Fingerprint and returns a fully populated
// Result, including the human-readable Explanation.
//
// It is safe for concurrent use.
func Analyze(fp *fingerprint.Fingerprint) risk.Result {
	result := risk.Evaluate(fp)
	result.Explanation = explain.Explain(result)
	return result
}

// AnalyzeJSON is the primary entry point for most integrations.
// It parses raw JSON, scores the payload, and returns a Result with a
// human-readable Explanation.
//
// The JSON schema mirrors the fingerprint.Fingerprint struct — every field is
// optional, and absent fields are silently skipped by the scorer.
func AnalyzeJSON(data []byte) (risk.Result, error) {
	fp, err := fingerprint.Parse(data)
	if err != nil {
		return risk.Result{}, err
	}
	return Analyze(fp), nil
}
