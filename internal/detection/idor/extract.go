package idor

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
)

// extractIDParameters extracts potential ID parameters from URL and body.
// Sources: URL query params, URL path segments (numeric / UUID-shaped),
// and request body (JSON or form-urlencoded).
func (d *Detector) extractIDParameters(targetURL, body, contentType string) []IDParameter {
	var params []IDParameter

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return params
	}

	// Query parameters.
	for key, values := range parsedURL.Query() {
		if len(values) == 0 {
			continue
		}
		value := values[0]
		if d.isLikelyID(key, value) {
			params = append(params, IDParameter{
				Name:     key,
				Value:    value,
				Type:     d.detectIDType(value),
				Location: LocationQuery,
			})
		}
	}

	// Path segments — numeric IDs and UUIDs only (other identifier
	// shapes are too ambiguous in a path context).
	for _, part := range strings.Split(parsedURL.Path, "/") {
		if part == "" {
			continue
		}
		switch {
		case d.idPatterns[IDTypeNumeric].MatchString(part):
			params = append(params, IDParameter{Name: part, Value: part, Type: IDTypeNumeric, Location: LocationPath})
		case d.idPatterns[IDTypeUUID].MatchString(part):
			params = append(params, IDParameter{Name: part, Value: part, Type: IDTypeUUID, Location: LocationPath})
		}
	}

	if body != "" {
		params = append(params, d.extractIDsFromBody(body, contentType)...)
	}
	return params
}

// extractIDsFromBody extracts ID parameters from request body.
// Supports application/json (recursive walk via extractIDsFromJSON) and
// application/x-www-form-urlencoded.
func (d *Detector) extractIDsFromBody(body, contentType string) []IDParameter {
	var params []IDParameter

	switch {
	case strings.Contains(contentType, "application/json"):
		var jsonData map[string]interface{}
		if err := json.Unmarshal([]byte(body), &jsonData); err == nil {
			params = d.extractIDsFromJSON(jsonData, "")
		}
	case strings.Contains(contentType, "application/x-www-form-urlencoded"):
		formData, err := url.ParseQuery(body)
		if err == nil {
			for key, values := range formData {
				if len(values) == 0 {
					continue
				}
				value := values[0]
				if d.isLikelyID(key, value) {
					params = append(params, IDParameter{
						Name:     key,
						Value:    value,
						Type:     d.detectIDType(value),
						Location: LocationBody,
					})
				}
			}
		}
	}
	return params
}

// extractIDsFromJSON recursively extracts ID parameters from a parsed
// JSON object. Nested object keys are joined with dots in the prefix.
func (d *Detector) extractIDsFromJSON(data map[string]interface{}, prefix string) []IDParameter {
	var params []IDParameter

	for key, value := range data {
		fullKey := key
		if prefix != "" {
			fullKey = prefix + "." + key
		}

		switch v := value.(type) {
		case float64:
			strValue := strconv.FormatFloat(v, 'f', -1, 64)
			// Drop the decimal point on whole numbers.
			if v == float64(int64(v)) {
				strValue = strconv.FormatInt(int64(v), 10)
			}
			if d.isLikelyID(key, strValue) {
				params = append(params, IDParameter{
					Name:     key,
					Value:    strValue,
					Type:     IDTypeNumeric,
					Location: LocationBody,
				})
			}
		case string:
			if d.isLikelyID(key, v) {
				params = append(params, IDParameter{
					Name:     key,
					Value:    v,
					Type:     d.detectIDType(v),
					Location: LocationBody,
				})
			}
		case map[string]interface{}:
			params = append(params, d.extractIDsFromJSON(v, fullKey)...)
		}
	}
	return params
}

// isLikelyID determines if a parameter is likely an object reference.
// Positive signals: name contains a known ID-naming substring (id, uuid,
// uid, …) OR the value matches the numeric / UUID regex.
func (d *Detector) isLikelyID(name, value string) bool {
	if value == "" {
		return false
	}
	nameLower := strings.ToLower(name)
	for _, idName := range d.idParameterNames {
		if strings.Contains(nameLower, strings.ToLower(idName)) {
			return true
		}
	}
	if d.idPatterns[IDTypeNumeric].MatchString(value) {
		return true
	}
	if d.idPatterns[IDTypeUUID].MatchString(value) {
		return true
	}
	return false
}

// detectIDType classifies an ID value's encoding. Returns the most
// specific matching type (numeric > UUID > hex > base64 > alphanumeric).
func (d *Detector) detectIDType(value string) IDType {
	if d.idPatterns[IDTypeNumeric].MatchString(value) {
		return IDTypeNumeric
	}
	if d.idPatterns[IDTypeUUID].MatchString(value) {
		return IDTypeUUID
	}
	if d.idPatterns[IDTypeHex].MatchString(value) && len(value) >= 12 {
		return IDTypeHex
	}
	if d.isBase64(value) {
		return IDTypeBase64
	}
	return IDTypeAlphanumeric
}

// isBase64 checks if a value is likely base64 encoded. Both pattern
// shape AND actual decode must succeed to avoid flagging random
// alphanumeric IDs as base64.
func (d *Detector) isBase64(value string) bool {
	if len(value) < 4 {
		return false
	}
	if !d.base64Pattern.MatchString(value) {
		return false
	}
	_, err := base64.StdEncoding.DecodeString(value)
	return err == nil
}
