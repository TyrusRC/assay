// Package openapi expands an OpenAPI 3.x specification into a flat list
// of concrete (method, URL) endpoints with realistic placeholder values
// for path parameters.
//
// Unlike the broader discovery.OpenAPIDiscoverer, which surfaces
// abstract parameter metadata, this expander returns ready-to-fire
// Endpoint records the scanner can hand directly to the HTTP client.
// Path templates such as `/users/{id}/orders/{orderId}` are filled by
// consulting each parameter's `example`, `enum[0]`, or `default`, in
// that order. When none is available a synthetic but type-appropriate
// value is substituted.
package openapi
