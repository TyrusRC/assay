// Package ssti provides Server-Side Template Injection (SSTI) vulnerability detection.
//
// SSTI occurs when user input is embedded directly into template engines
// without proper sanitization, allowing attackers to execute arbitrary code
// on the server.
//
// Supported template engines:
//   - Jinja2/Flask (Python): {{7*7}}, {{config}}, {{self.__class__}}
//   - Twig (PHP): {{7*7}}, {{_self.env}}
//   - Freemarker (Java): ${7*7}, <#assign>
//   - Velocity (Java): #set($x=7*7)
//   - ERB (Ruby): <%= 7*7 %>
//   - Thymeleaf (Java): ${T(java.lang.Runtime)}
//   - Mako (Python): ${7*7}
//   - Smarty (PHP): {7*7}
//   - Pebble (Java): {{7*7}}
//   - Handlebars (JavaScript): {{this}}
//   - Mustache: {{.}}
//
// Detection methods:
//   - Mathematical expression detection (49 from 7*7)
//   - Error-based detection (template engine error messages)
//   - Reflection detection (config/class leakage)
//   - RCE verification (command execution output)
//
// OWASP mapping:
//   - WSTG-INPV-18 (Testing for Server-side Template Injection)
//   - A03:2021 (Injection)
//   - CWE-94 (Improper Control of Generation of Code)
//   - CWE-1336 (Improper Neutralization of Special Elements Used in a Template Engine)
//
// Example usage:
//
//	client := http.NewClient()
//	detector := ssti.New(client)
//
//	result, err := detector.Detect(ctx, "https://example.com?name=test", "name", "GET", ssti.DefaultOptions())
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	if result.Vulnerable {
//	    fmt.Printf("SSTI found! Engine: %s\n", result.DetectedEngine)
//	    for _, finding := range result.Findings {
//	        fmt.Printf("  - %s: %s\n", finding.Severity, finding.Description)
//	    }
//	}
package ssti
