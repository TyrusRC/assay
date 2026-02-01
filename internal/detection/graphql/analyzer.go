package graphql

import (
	"encoding/json"
	"fmt"
	"strings"
)

// AnalyzeIntrospectionResponse analyzes an introspection query response.
func (d *Detector) AnalyzeIntrospectionResponse(response string) *IntrospectionResult {
	result := &IntrospectionResult{
		Enabled:     false,
		Types:       make([]string, 0),
		RawResponse: response,
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(response), &parsed); err != nil {
		return result
	}

	// Check if data.__schema exists
	data, ok := parsed["data"].(map[string]interface{})
	if !ok {
		return result
	}

	schema, ok := data["__schema"].(map[string]interface{})
	if !ok {
		return result
	}

	// Introspection is enabled if we get schema data
	result.Enabled = true

	// Extract query type
	if queryType, ok := schema["queryType"].(map[string]interface{}); ok {
		if name, ok := queryType["name"].(string); ok {
			result.QueryType = name
		}
	}

	// Extract mutation type
	if mutationType, ok := schema["mutationType"].(map[string]interface{}); ok {
		if name, ok := mutationType["name"].(string); ok {
			result.MutationType = name
		}
	}

	// Extract types (excluding internal __ types)
	if types, ok := schema["types"].([]interface{}); ok {
		for _, t := range types {
			if typeMap, ok := t.(map[string]interface{}); ok {
				if name, ok := typeMap["name"].(string); ok {
					// Skip internal GraphQL types
					if !strings.HasPrefix(name, "__") {
						result.Types = append(result.Types, name)
					}
				}
			}
		}
	}

	return result
}

// AnalyzeBatchResponse analyzes a batch query response.
func (d *Detector) AnalyzeBatchResponse(response string) *BatchResult {
	result := &BatchResult{
		Vulnerable: false,
	}

	// Try to parse as array (batch response)
	var batchResponse []interface{}
	if err := json.Unmarshal([]byte(response), &batchResponse); err == nil {
		// Successfully parsed as array - batch queries are accepted
		if len(batchResponse) > 1 {
			result.Vulnerable = true
			result.ResponseCount = len(batchResponse)
			result.Evidence = fmt.Sprintf("Batch query accepted with %d responses", len(batchResponse))
		}
	}

	return result
}

// AnalyzeDepthResponse analyzes a deep query response.
func (d *Detector) AnalyzeDepthResponse(response string, depth int) *DepthResult {
	result := &DepthResult{
		Vulnerable:   false,
		MaxDepthTest: depth,
	}

	// Check for depth/complexity limit errors
	for _, pattern := range d.depthErrorPatterns {
		if pattern.MatchString(response) {
			result.Vulnerable = false
			result.Evidence = "Depth limit is enforced"
			return result
		}
	}

	// Check if we got a data response (no depth limit)
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(response), &parsed); err == nil {
		if _, hasData := parsed["data"]; hasData {
			// Check that data is not null/empty
			if data, ok := parsed["data"].(map[string]interface{}); ok && len(data) > 0 {
				result.Vulnerable = true
				result.Evidence = fmt.Sprintf("Deep query (depth=%d) was accepted", depth)
			}
		}
	}

	return result
}

// AnalyzeFieldSuggestionResponse analyzes a response for field suggestions.
func (d *Detector) AnalyzeFieldSuggestionResponse(response string) *FieldSuggestionResult {
	result := &FieldSuggestionResult{
		HasSuggestions:  false,
		SuggestedFields: make([]string, 0),
	}

	// Look for suggestion patterns in error messages
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(response), &parsed); err != nil {
		return result
	}

	errors, ok := parsed["errors"].([]interface{})
	if !ok {
		return result
	}

	for _, e := range errors {
		if errMap, ok := e.(map[string]interface{}); ok {
			if msg, ok := errMap["message"].(string); ok {
				// Check for suggestion pattern
				matches := d.suggestionPattern.FindStringSubmatch(msg)
				if len(matches) > 1 {
					result.HasSuggestions = true
					result.Evidence = msg
					for i := 1; i < len(matches); i++ {
						if matches[i] != "" {
							result.SuggestedFields = append(result.SuggestedFields, matches[i])
						}
					}
				}
			}
		}
	}

	return result
}

// AnalyzeInjectionResponse analyzes a response for injection indicators.
func (d *Detector) AnalyzeInjectionResponse(response string) *InjectionResult {
	result := &InjectionResult{
		Vulnerable: false,
	}

	// Check SQL error patterns
	for _, pattern := range d.sqlErrorPatterns {
		if pattern.MatchString(response) {
			result.Vulnerable = true
			result.InjectionType = InjectionTypeSQL
			result.Evidence = pattern.FindString(response)
			result.DatabaseType = d.detectDatabaseType(response)
			return result
		}
	}

	// Check NoSQL error patterns
	for _, pattern := range d.nosqlErrorPatterns {
		if pattern.MatchString(response) {
			result.Vulnerable = true
			result.InjectionType = InjectionTypeNoSQL
			result.Evidence = pattern.FindString(response)
			result.DatabaseType = "mongodb"
			return result
		}
	}

	return result
}

// detectDatabaseType identifies the database from error messages.
func (d *Detector) detectDatabaseType(response string) string {
	responseLower := strings.ToLower(response)

	if strings.Contains(responseLower, "mysql") || strings.Contains(response, "MariaDB") {
		return "mysql"
	}
	if strings.Contains(responseLower, "postgresql") || strings.Contains(responseLower, "pg_") {
		return "postgresql"
	}
	if strings.Contains(responseLower, "microsoft sql server") || strings.Contains(responseLower, "mssql") {
		return "mssql"
	}
	if strings.Contains(response, "ORA-") || strings.Contains(responseLower, "oracle") {
		return "oracle"
	}
	if strings.Contains(response, "SQLITE") {
		return "sqlite"
	}

	return "unknown"
}
