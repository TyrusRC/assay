// Package jsmining extracts endpoint URLs from JavaScript source code by
// regex-mining well-known call shapes and path-literal patterns.
//
// The miner is a pure string analyzer — it does not fetch anything over
// the network. Callers (typically a JS-aware crawler) feed in the body
// of a script file and receive a deduplicated, scope-resolved set of
// absolute URLs that the script appears to talk to. Recognized shapes
// include fetch / axios.* / $.ajax({url:...}) / XMLHttpRequest.open,
// API-style path literals like "/api/v1/users/{id}" or
// "/users/[0-9]+/profile", and string constants such as
// `const ENDPOINT = "/api/x"`.
package jsmining
