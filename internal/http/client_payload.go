package http

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/TyrusRC/assay/internal/core"
)

// SendRawBody sends a request with raw body content.
func (c *Client) SendRawBody(ctx context.Context, url, method, body, contentType string) (*Response, error) {
	return c.Do(ctx, &Request{
		Method:      method,
		URL:         url,
		Body:        body,
		ContentType: contentType,
	})
}

// SendPayload sends a request with a payload injected into a parameter.
//
// When the client has a paramOverride (set via ForParam), the call routes
// through SendPayloadAt, which dispatches by the parameter's Location
// (JSON body, path segment, header, XML, cookie, query). This makes every
// detector location-aware without changing its code.
//
// Without a paramOverride, the legacy behavior applies: GET puts the payload
// in the query string, POST/PUT/PATCH puts it in a form-urlencoded body.
func (c *Client) SendPayload(ctx context.Context, baseURL, param, payload, method string) (*Response, error) {
	if c.paramOverride != nil {
		return c.SendPayloadAt(ctx, baseURL, *c.paramOverride, payload, method)
	}
	return c.sendPayloadDirect(ctx, baseURL, param, payload, method)
}

// sendPayloadDirect is the original query/form-body injection path. It is
// called directly by SendPayloadAt for the query and default-body cases to
// avoid infinite recursion through the paramOverride check in SendPayload.
func (c *Client) sendPayloadDirect(ctx context.Context, baseURL, param, payload, method string) (*Response, error) {
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	query := parsedURL.Query()
	originalValue := query.Get(param)

	req := &Request{Method: method}
	if method == "POST" || method == "PUT" || method == "PATCH" {
		bodyParams := url.Values{}
		for _, sp := range c.siblingParams {
			if sp.Location == core.ParamLocationBody && sp.Name != param {
				bodyParams.Set(sp.Name, "test")
			}
		}
		bodyParams.Set(param, payload)
		query.Del(param)
		parsedURL.RawQuery = query.Encode()
		req.URL = parsedURL.String()
		req.Body = bodyParams.Encode()
		req.ContentType = "application/x-www-form-urlencoded"
	} else {
		query.Set(param, payload)
		parsedURL.RawQuery = query.Encode()
		req.URL = parsedURL.String()
	}

	resp, err := c.Do(ctx, req)
	if err == nil && resp != nil {
		resp.OriginalValue = originalValue
	}

	// Content-type negotiation: if a form-urlencoded POST returned a
	// server error (500), the endpoint may only accept JSON. Retry once
	// with JSON body so JS-driven APIs (vuln-bank, SPAs) get tested.
	if resp != nil && resp.StatusCode == 500 && req.ContentType == "application/x-www-form-urlencoded" {
		return c.SendPayloadInJSON(ctx, baseURL, param, payload)
	}

	return resp, err
}

// SendPayloadInHeader sends a request with a payload injected as an HTTP header value.
// When siblingParams include body params, a JSON body with default values is attached
// so endpoints that require both header auth + JSON body reach the SQL/logic layer.
func (c *Client) SendPayloadInHeader(ctx context.Context, baseURL, headerName, payload, method string) (*Response, error) {
	req := &Request{
		Method:  method,
		URL:     baseURL,
		Headers: map[string]string{headerName: payload},
	}
	if body := c.siblingBodyJSON(); body != "" {
		req.Body = body
		req.ContentType = "application/json"
	}
	return c.Do(ctx, req)
}

// siblingBodyJSON builds a JSON object from sibling body params with default values.
// Returns "" when there are no body siblings.
func (c *Client) siblingBodyJSON() string {
	if len(c.siblingParams) == 0 {
		return ""
	}
	fields := make(map[string]string)
	for _, sp := range c.siblingParams {
		if sp.Location == core.ParamLocationBody {
			fields[sp.Name] = "test"
		}
	}
	if len(fields) == 0 {
		return ""
	}
	data, err := json.Marshal(fields)
	if err != nil {
		return ""
	}
	return string(data)
}

// SendPayloadInCookie sends a request with a payload injected as a cookie value.
// The test cookie is merged with any existing session cookies so authenticated
// scans are not silently degraded to unauthenticated.
func (c *Client) SendPayloadInCookie(ctx context.Context, baseURL, cookieName, payload, method string) (*Response, error) {
	existing := c.cookies
	if c.cookieSrc != nil {
		if live := c.cookieSrc(); live != "" {
			existing = live
		}
	}
	testCookie := cookieName + "=" + payload
	merged := testCookie
	if existing != "" {
		merged = existing + "; " + testCookie
	}
	req := &Request{
		Method:  method,
		URL:     baseURL,
		Headers: map[string]string{"Cookie": merged},
	}
	return c.Do(ctx, req)
}

// SendPayloadInJSON sends a POST request with a JSON body containing the payload
// at the specified field path. The fieldPath is a single-level field name.
// When siblingParams are set (via WithSiblings), all other body params from the
// same endpoint are included with a default value ("test") so the server accepts
// the request instead of returning a "missing field" error.
func (c *Client) SendPayloadInJSON(ctx context.Context, baseURL, fieldPath, payload string) (*Response, error) {
	fields := make(map[string]string)
	for _, sp := range c.siblingParams {
		if sp.Location == core.ParamLocationBody && sp.Name != fieldPath {
			fields[sp.Name] = "test"
		}
	}
	fields[fieldPath] = payload

	body, err := json.Marshal(fields)
	if err != nil {
		return nil, fmt.Errorf("json marshal payload: %w", err)
	}

	req := &Request{
		Method:      "POST",
		URL:         baseURL,
		Body:        string(body),
		ContentType: "application/json",
	}
	return c.Do(ctx, req)
}

// SendPayloadInPath sends a request with a payload injected into a URL path segment.
// The segmentIndex is 0-based and counts non-empty segments after splitting on '/'.
func (c *Client) SendPayloadInPath(ctx context.Context, baseURL string, segmentIndex int, payload, method string) (*Response, error) {
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	rawSegments := strings.Split(parsedURL.Path, "/")
	var segments []string
	var segmentPositions []int
	for i, seg := range rawSegments {
		if seg != "" {
			segments = append(segments, seg)
			segmentPositions = append(segmentPositions, i)
		}
	}

	if segmentIndex < 0 || segmentIndex >= len(segments) {
		return nil, fmt.Errorf("segment index %d out of range (path has %d segments)", segmentIndex, len(segments))
	}

	rawSegments[segmentPositions[segmentIndex]] = payload
	parsedURL.Path = strings.Join(rawSegments, "/")

	req := &Request{
		Method: method,
		URL:    parsedURL.String(),
	}
	return c.Do(ctx, req)
}

// validXMLName matches a well-formed XML element name (no namespace).
var validXMLName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9._-]*$`)

// SendPayloadInXML sends a POST request with an XML body wrapping the payload
// in the specified element name.
func (c *Client) SendPayloadInXML(ctx context.Context, baseURL, elementName, payload string) (*Response, error) {
	if !validXMLName.MatchString(elementName) {
		return nil, fmt.Errorf("invalid XML element name: %q", elementName)
	}
	xmlBody := fmt.Sprintf("<%s>%s</%s>", elementName, payload, elementName)

	req := &Request{
		Method:      "POST",
		URL:         baseURL,
		Body:        xmlBody,
		ContentType: "text/xml",
	}
	return c.Do(ctx, req)
}

// SendPayloadAt is the location-aware payload dispatcher. Given a fully-
// described core.Parameter (Name + Location + optional SegmentIndex /
// ContentType), it sends the payload through the right transport: query
// for ParamLocationQuery, the right body shape for ParamLocationBody,
// header for ParamLocationHeader, cookie for ParamLocationCookie, and
// path-segment substitution for ParamLocationPath.
//
// Why this exists: the legacy SendPayload always injects into the query
// string for GET and into a form-urlencoded body for POST/PUT/PATCH,
// which silently drops every parameter the discovery pipeline finds in
// JSON bodies, multipart bodies, XML bodies, paths, headers, and
// cookies. SendPayloadAt is the single point where param.Location is
// honored end-to-end.
//
// Body dispatch heuristic for ParamLocationBody:
//   - param.ContentType containing "json" → JSON body
//   - param.ContentType containing "xml"  → XML body
//   - param.Name contains "." (dotted path like "user.email") → JSON
//   - otherwise                            → form-urlencoded body
//
// LocalStorage / SessionStorage are not injectable from outside a real
// browser, so the dispatcher returns a baseline GET response — the
// caller's detector will see no payload reflection and produce no
// finding, which is the correct behavior for headless-only sinks.
func (c *Client) SendPayloadAt(ctx context.Context, baseURL string, param core.Parameter, payload, method string) (*Response, error) {
	switch param.Location {
	case core.ParamLocationHeader:
		return c.SendPayloadInHeader(ctx, baseURL, param.Name, payload, method)
	case core.ParamLocationCookie:
		return c.SendPayloadInCookie(ctx, baseURL, param.Name, payload, method)
	case core.ParamLocationPath:
		return c.SendPayloadInPath(ctx, baseURL, param.SegmentIndex, payload, method)
	case core.ParamLocationBody:
		ct := strings.ToLower(param.ContentType)
		if strings.Contains(ct, "xml") {
			return c.SendPayloadInXML(ctx, baseURL, param.Name, payload)
		}
		if strings.Contains(ct, "json") {
			return c.SendPayloadInJSON(ctx, baseURL, param.Name, payload)
		}
		// Params from HTML forms (no ContentType or text/html) use
		// form-urlencoded. Params from API specs with application/json
		// use JSON. Default to form-urlencoded since HTML forms are
		// more common than JSON APIs in general scanning.
		return c.sendPayloadDirect(ctx, baseURL, param.Name, payload, method)
	case core.ParamLocationLocalStorage, core.ParamLocationSessionStorage:
		req := &Request{Method: "GET", URL: baseURL}
		return c.Do(ctx, req)
	case core.ParamLocationQuery, "":
		fallthrough
	default:
		return c.sendPayloadDirect(ctx, baseURL, param.Name, payload, method)
	}
}
