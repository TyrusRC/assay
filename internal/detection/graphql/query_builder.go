package graphql

import (
	"encoding/json"
	"fmt"
	"strings"
)

// BuildIntrospectionQuery builds a full introspection query.
func (d *Detector) BuildIntrospectionQuery() string {
	return `query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          name
          description
          type {
            kind
            name
            ofType {
              kind
              name
            }
          }
          defaultValue
        }
        type {
          kind
          name
          ofType {
            kind
            name
          }
        }
        isDeprecated
        deprecationReason
      }
      inputFields {
        name
        description
        type {
          kind
          name
          ofType {
            kind
            name
          }
        }
        defaultValue
      }
      interfaces {
        kind
        name
      }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes {
        kind
        name
      }
    }
    directives {
      name
      description
      locations
      args {
        name
        description
        type {
          kind
          name
          ofType {
            kind
            name
          }
        }
        defaultValue
      }
    }
  }
}`
}

// BuildTypeQuery builds a query for a specific type.
func (d *Detector) BuildTypeQuery(typeName string) string {
	return fmt.Sprintf(`query TypeQuery {
  __type(name: "%s") {
    kind
    name
    description
    fields {
      name
      type {
        kind
        name
      }
    }
  }
}`, typeName)
}

// BuildBatchQuery builds a batch of queries as JSON array.
func (d *Detector) BuildBatchQuery(queries []string) (string, error) {
	batch := make([]map[string]interface{}, len(queries))
	for i, q := range queries {
		batch[i] = map[string]interface{}{
			"query": q,
		}
	}
	result, err := json.Marshal(batch)
	if err != nil {
		return "", fmt.Errorf("failed to marshal batch query: %w", err)
	}
	return string(result), nil
}

// BuildAliasBatchQuery builds a query with aliases for batching.
func (d *Detector) BuildAliasBatchQuery(field, argName string, argValues []string) string {
	var parts []string
	for i, val := range argValues {
		parts = append(parts, fmt.Sprintf("alias%d: %s(%s: \"%s\") { id }", i, field, argName, val))
	}
	return fmt.Sprintf("query AliasBatch { %s }", strings.Join(parts, " "))
}

// BuildDeepQuery builds a deeply nested query for depth testing.
func (d *Detector) BuildDeepQuery(depth int) string {
	// Build a nested query structure
	query := "query DeepQuery { "

	// Use common field names that might exist
	fields := []string{"user", "posts", "comments", "author", "profile", "followers", "following", "items", "data", "node"}

	for i := 0; i < depth; i++ {
		field := fields[i%len(fields)]
		query += fmt.Sprintf("%s { ", field)
	}

	// Add a leaf field
	query += "id"

	// Close all braces
	for i := 0; i < depth; i++ {
		query += " }"
	}
	query += " }"

	return query
}

// BuildGraphQLRequest builds a GraphQL JSON request body.
func (d *Detector) BuildGraphQLRequest(query string, variables map[string]interface{}) (string, error) {
	request := map[string]interface{}{
		"query":     query,
		"variables": variables,
	}
	result, err := json.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("failed to marshal graphql request: %w", err)
	}
	return string(result), nil
}

// GetInjectionPayloads returns injection test payloads.
func (d *Detector) GetInjectionPayloads() []InjectionPayload {
	return []InjectionPayload{
		// SQL Injection payloads
		{Value: `'`, Type: InjectionTypeSQL, Description: "Single quote"},
		{Value: `"`, Type: InjectionTypeSQL, Description: "Double quote"},
		{Value: `' OR '1'='1`, Type: InjectionTypeSQL, Description: "Classic OR injection"},
		{Value: `" OR "1"="1`, Type: InjectionTypeSQL, Description: "Double quote OR injection"},
		{Value: `' OR 1=1--`, Type: InjectionTypeSQL, Description: "OR with comment"},
		{Value: `'; DROP TABLE users--`, Type: InjectionTypeSQL, Description: "Stacked query"},
		{Value: `' UNION SELECT NULL--`, Type: InjectionTypeSQL, Description: "UNION injection"},
		{Value: `1' AND '1'='1`, Type: InjectionTypeSQL, Description: "Boolean AND injection"},
		{Value: `' AND SLEEP(5)--`, Type: InjectionTypeSQL, Description: "Time-based injection"},

		// NoSQL Injection payloads
		{Value: `{"$gt": ""}`, Type: InjectionTypeNoSQL, Description: "MongoDB $gt operator"},
		{Value: `{"$ne": null}`, Type: InjectionTypeNoSQL, Description: "MongoDB $ne operator"},
		{Value: `{"$where": "1==1"}`, Type: InjectionTypeNoSQL, Description: "MongoDB $where injection"},
		{Value: `{"$regex": ".*"}`, Type: InjectionTypeNoSQL, Description: "MongoDB $regex injection"},
		{Value: `'; return true; var x='`, Type: InjectionTypeNoSQL, Description: "JavaScript injection"},
		{Value: `{"$or": [{}]}`, Type: InjectionTypeNoSQL, Description: "MongoDB $or injection"},
		{Value: `{$gt: ""}`, Type: InjectionTypeNoSQL, Description: "MongoDB unquoted operator"},
	}
}
