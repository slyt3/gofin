package risk

// SignalResult is what a Rule returns — did it fire, and why.
// This is the newer engine's equivalent of Signal.
type SignalResult struct {
	// Name is the rule identifier. Same value as Rule.Name().
	Name string `json:"name"`

	// Triggered is true when the rule condition matched.
	Triggered bool `json:"triggered"`

	// Reason explains why it fired. Empty when Triggered is false.
	Reason string `json:"reason,omitempty"`
}

// Score is what Engine.Run returns.
// Total is 0–1, where 1.0 means all rules fired at max weight.
type Score struct {
	// Total is the sum of triggered rule weights, clamped to 1.0.
	Total float64 `json:"total"`

	// Level is the risk bucket for this score.
	Level RiskLevel `json:"level"`

	// Signals has the result for every rule that ran.
	Signals []SignalResult `json:"signals"`
}
