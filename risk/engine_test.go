package risk_test

import (
	"fmt"
	"testing"

	"github.com/slyt/gofin/fingerprint"
	"github.com/slyt/gofin/risk"
)

func TestEngine_Run_NoRules(t *testing.T) {
	e := risk.NewEngine()
	s := e.Run(&fingerprint.Payload{})
	if s.Total != 0 {
		t.Errorf("Total: want 0, got %f", s.Total)
	}
	if s.Level != risk.RiskLow {
		t.Errorf("Level: want low, got %s", s.Level)
	}
}

func TestEngine_Run_SingleRule_Triggered(t *testing.T) {
	rule := risk.NewRuleFunc("webdriver", "automation", 0.35,
		func(p *fingerprint.Payload) risk.SignalResult {
			if p.Browser != nil && p.Browser.Webdriver {
				return risk.SignalResult{Name: "webdriver", Triggered: true, Reason: "WebDriver flag is set"}
			}
			return risk.SignalResult{Name: "webdriver"}
		})

	e := risk.NewEngine()
	e.AddRule(rule)

	s := e.Run(&fingerprint.Payload{
		Browser: &fingerprint.BrowserFingerprint{Webdriver: true},
	})

	if !s.Signals[0].Triggered {
		t.Error("expected signal to be triggered")
	}
	if s.Total != 0.35 {
		t.Errorf("Total: want 0.35, got %f", s.Total)
	}
}

func TestEngine_Run_TotalClamped(t *testing.T) {
	alwaysFire := func(name string) risk.Rule {
		return risk.NewRuleFunc(name, "automation", 0.9,
			func(p *fingerprint.Payload) risk.SignalResult {
				return risk.SignalResult{Name: name, Triggered: true}
			})
	}

	e := risk.NewEngine()
	e.AddRule(alwaysFire("rule_a"))
	e.AddRule(alwaysFire("rule_b"))

	s := e.Run(&fingerprint.Payload{})
	if s.Total > 1.0 {
		t.Errorf("Total must be clamped to 1.0, got %f", s.Total)
	}
	if s.Level != risk.RiskCritical {
		t.Errorf("Level: want critical, got %s", s.Level)
	}
}

// ExampleEngine_AddRule demonstrates defining a canvas-hash blocklist rule
// using NewRuleFunc and running it through the Engine.
func ExampleEngine_AddRule() {
	blocklist := map[string]bool{
		"d41d8cd98f00b204e9800998ecf8427e": true, // known automation canvas hash
	}

	canvasRule := risk.NewRuleFunc(
		"canvas_hash_blocklist",
		"spoofing",
		0.9,
		func(p *fingerprint.Payload) risk.SignalResult {
			if p.Browser == nil || !blocklist[p.Browser.CanvasHash] {
				return risk.SignalResult{Name: "canvas_hash_blocklist"}
			}
			return risk.SignalResult{
				Name:      "canvas_hash_blocklist",
				Triggered: true,
				Reason:    "canvas hash matched known automation tool",
			}
		},
	)

	e := risk.NewEngine()
	e.AddRule(canvasRule)

	s := e.Run(&fingerprint.Payload{
		Browser: &fingerprint.BrowserFingerprint{
			CanvasHash: "d41d8cd98f00b204e9800998ecf8427e",
		},
	})

	fmt.Printf("triggered: %v, level: %s\n", s.Signals[0].Triggered, s.Level)
	// Output: triggered: true, level: critical
}
