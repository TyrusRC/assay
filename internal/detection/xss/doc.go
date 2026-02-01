// Package xss provides Cross-Site Scripting (XSS) vulnerability detection.
//
// The detector uses context-aware analysis to determine where user input
// is reflected in the response and selects appropriate payloads based on
// the injection context (HTML, JavaScript, attribute, URL, CSS, or template).
//
// Features:
//   - Context-aware payload selection
//   - Polyglot payloads for multiple contexts
//   - WAF bypass techniques
//   - DOM-based XSS detection support
//   - OWASP framework mappings (WSTG-INPV-02, A03:2021, CWE-79)
//
// Usage:
//
//	client := http.NewClient()
//	detector := xss.New(client)
//	result, err := detector.Detect(ctx, targetURL, "param", "GET", xss.DefaultOptions())
//	if result.Vulnerable {
//	    for _, finding := range result.Findings {
//	        fmt.Printf("XSS found: %s\n", finding.Description)
//	    }
//	}
package xss
