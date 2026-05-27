# gofin

Browser fingerprint analysis library for Go. Pass it a JSON fingerprint collected from a browser, get back a risk score and an explanation of what looks suspicious.

## What it does

- Runs ~21 detection rules (WebDriver, headless mode, SwiftShader GPU, timezone mismatch, canvas/WebGL/audio blocking, and more)
- Returns a score (0–100), a risk level, and a plain-English explanation
- No network calls, no external dependencies, safe for concurrent use

## Install

```bash
go get github.com/slyt3/gofin
```

## Quick start

```go
package main

import (
    "fmt"
    "github.com/slyt3/gofin"
)

func main() {
    result, err := gofin.AnalyzeJSON([]byte(`{
        "user_agent":    "Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/120",
        "webdriver":     true,
        "headless_mode": true
    }`))
    if err != nil {
        panic(err)
    }

    fmt.Println(result.Score, result.Risk) // e.g. "65 high"
    fmt.Println(result.Explanation)
}
```

## Fingerprint fields

Collect these from your JavaScript probe and send them as JSON to your server:

| Field | Type | Source |
|---|---|---|
| `user_agent` | string | `navigator.userAgent` |
| `platform` | string | `navigator.platform` |
| `webdriver` | bool | `navigator.webdriver` |
| `headless_mode` | bool | UA string + API checks |
| `timezone` | string | `Intl.DateTimeFormat().resolvedOptions().timeZone` |
| `timezone_offset` | int | `new Date().getTimezoneOffset()` |
| `screen_width` / `screen_height` | int | `screen.width/height` |
| `hardware_concurrency` | int | `navigator.hardwareConcurrency` |
| `device_memory` | float | `navigator.deviceMemory` |
| `canvas_hash` | string | hash of `canvas.toDataURL()` |
| `webgl_vendor` / `webgl_renderer` | string | WebGL debug info |
| `fonts` | []string | font enumeration |
| `plugins` | []string | `navigator.plugins` |
| `ja3_hash` | string | server-side TLS ClientHello hash |
| `ip` / `ip_country` / `ip_timezone` | string | server-side geo-IP |

All fields are optional — missing fields are skipped, they never cause false positives.

## Result fields

```go
result.Score       // int, 0–100
result.Risk        // "low" | "medium" | "high" | "critical"
result.Explanation // plain-English narrative
result.Signals     // []risk.Signal — per-rule detail
result.Categories  // map[string]int — score by category
```

## Packages

| Package | Purpose |
|---|---|
| `gofin` | Top-level API (`Analyze`, `AnalyzeJSON`) |
| `risk` | Scoring engine and detection rules |
| `explain` | Turns a score into human-readable text |
| `entropy` | Shannon entropy and field coverage analysis |
| `pkg/ja3` | JA3 TLS fingerprint hashing and lookup |
| `pkg/h2fp` | HTTP/2 SETTINGS frame fingerprinting |

## Run the example

```bash
go run ./examples/basic
```

## Custom rules

Add your own detection logic without touching the core:

```go
engine := risk.NewEngine()
engine.AddRule(risk.NewRuleFunc("my_rule", "automation", 0.8,
    func(p *fingerprint.Payload) risk.SignalResult {
        if p.Browser == nil || !p.Browser.Webdriver {
            return risk.SignalResult{Name: "my_rule"}
        }
        return risk.SignalResult{Name: "my_rule", Triggered: true, Reason: "webdriver active"}
    },
))
score := engine.Run(payload)
```

## When to use it

Call it server-side on sensitive endpoints — login, registration, checkout, API access. Collect the fingerprint JSON from your JS probe, send it to your backend, and pass it to `AnalyzeJSON`. The result tells you whether to allow, challenge, or block the request.

## Limitations

- Signal weights are hand-tuned heuristics, not trained on labeled traffic data
- JA3 and H2 fingerprint tables are curated from public sources (tls.peet.ws, AmIUnique, Statcounter) and may not cover every client
- A determined attacker who knows the rules can evade them — this is a signal, not a firewall

## License

MIT
