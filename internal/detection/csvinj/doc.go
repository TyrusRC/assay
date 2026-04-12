// Package csvinj provides CSV/Formula Injection vulnerability detection.
// It tests for improper handling of formula characters in user input by:
//   - Injecting payloads starting with formula characters (=, +, -, @)
//   - Checking if formula characters are reflected without sanitization
//   - Detecting potential spreadsheet formula injection vectors
package csvinj
