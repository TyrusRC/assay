package idor

import (
	"net/url"
	"regexp"
	"strings"
)

// buildTestURL builds a URL with the named ID parameter set to newID.
// Honors the parameter's Location (Query vs Path); Body-located IDs are
// untouched here — those go through buildTestBody.
func (d *Detector) buildTestURL(originalURL *url.URL, param IDParameter, newID string) string {
	testURL := *originalURL

	switch param.Location {
	case LocationQuery:
		query := testURL.Query()
		query.Set(param.Name, newID)
		testURL.RawQuery = query.Encode()
	case LocationPath:
		// Replace the first occurrence of the original ID in the path.
		testURL.Path = strings.Replace(testURL.Path, param.Value, newID, 1)
	}
	return testURL.String()
}

// buildTestBody builds a request body with a manipulated ID. Supports
// application/json (both quoted-string and numeric forms) and
// application/x-www-form-urlencoded. Returns the original body unchanged
// for content types we don't know how to manipulate.
func (d *Detector) buildTestBody(body, contentType string, param IDParameter, newID string) string {
	switch {
	case strings.Contains(contentType, "application/json"):
		// String form: "key":"value"
		if result := strings.Replace(body, `"`+param.Value+`"`, `"`+newID+`"`, 1); result != body {
			return result
		}
		// Numeric form: "key":123 — match exact key/value pair so we
		// don't substitute identical numbers belonging to unrelated keys.
		numPattern := regexp.MustCompile(`("` + regexp.QuoteMeta(param.Name) + `"\s*:\s*)` + regexp.QuoteMeta(param.Value) + `(\s*[,}])`)
		if numPattern.MatchString(body) {
			return numPattern.ReplaceAllString(body, "${1}"+newID+"${2}")
		}
		return body
	case strings.Contains(contentType, "application/x-www-form-urlencoded"):
		formData, err := url.ParseQuery(body)
		if err != nil {
			return body
		}
		formData.Set(param.Name, newID)
		return formData.Encode()
	}
	return body
}
