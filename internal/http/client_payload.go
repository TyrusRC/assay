package http

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
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
// For GET requests, the payload is placed in the query string.
// For POST/PUT/PATCH requests, the payload goes into the form body only.
func (c *Client) SendPayload(ctx context.Context, baseURL, param, payload, method string) (*Response, error) {
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	query := parsedURL.Query()
	originalValue := query.Get(param)

	req := &Request{Method: method}
	if method == "POST" || method == "PUT" || method == "PATCH" {
		bodyParams := url.Values{}
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
	return resp, err
}

// SendPayloadInHeader sends a request with a payload injected as an HTTP header value.
func (c *Client) SendPayloadInHeader(ctx context.Context, baseURL, headerName, payload, method string) (*Response, error) {
	req := &Request{
		Method:  method,
		URL:     baseURL,
		Headers: map[string]string{headerName: payload},
	}
	return c.Do(ctx, req)
}

// SendPayloadInCookie sends a request with a payload injected as a cookie value.
func (c *Client) SendPayloadInCookie(ctx context.Context, baseURL, cookieName, payload, method string) (*Response, error) {
	cookieStr := cookieName + "=" + payload
	req := &Request{
		Method:  method,
		URL:     baseURL,
		Headers: map[string]string{"Cookie": cookieStr},
	}
	return c.Do(ctx, req)
}

// SendPayloadInJSON sends a POST request with a JSON body containing the payload
// at the specified field path. The fieldPath is a single-level field name.
func (c *Client) SendPayloadInJSON(ctx context.Context, baseURL, fieldPath, payload string) (*Response, error) {
	escaped := strings.NewReplacer(
		`\`, `\\`,
		`"`, `\"`,
		"\n", `\n`,
		"\r", `\r`,
		"\t", `\t`,
	).Replace(payload)

	jsonBody := fmt.Sprintf(`{%q:%q}`, fieldPath, escaped)

	req := &Request{
		Method:      "POST",
		URL:         baseURL,
		Body:        jsonBody,
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

// SendPayloadInXML sends a POST request with an XML body wrapping the payload
// in the specified element name.
func (c *Client) SendPayloadInXML(ctx context.Context, baseURL, elementName, payload string) (*Response, error) {
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
		if strings.Contains(ct, "json") || strings.Contains(param.Name, ".") {
			return c.SendPayloadInJSON(ctx, baseURL, param.Name, payload)
		}
		if strings.Contains(ct, "xml") {
			return c.SendPayloadInXML(ctx, baseURL, param.Name, payload)
		}
		return c.SendPayload(ctx, baseURL, param.Name, payload, method)
	case core.ParamLocationLocalStorage, core.ParamLocationSessionStorage:
		req := &Request{Method: "GET", URL: baseURL}
		return c.Do(ctx, req)
	case core.ParamLocationQuery, "":
		fallthrough
	default:
		return c.SendPayload(ctx, baseURL, param.Name, payload, method)
	}
}
