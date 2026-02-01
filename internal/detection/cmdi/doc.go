// Package cmdi provides Command Injection vulnerability detection.
// It uses multiple detection techniques including:
//   - Error-based detection (command output in response)
//   - Time-based blind detection (sleep/delay commands)
//   - Platform-specific payload testing
package cmdi
