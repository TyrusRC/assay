// graphql_advanced_helpers.go — types, introspection parsing, and request
// helpers used by the GraphQL advanced-check functions.
package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/TyrusRC/assay/internal/detection/graphql"
	assayhttp "github.com/TyrusRC/assay/internal/http"
)

// gqlFieldInfo holds complete info about a GraphQL field for advanced checks.
type gqlFieldInfo struct {
	name        string
	isMut       bool
	args        []gqlArgInfo
	retKind     string // SCALAR, OBJECT, LIST, ENUM, etc.
	retTypeName string // leaf type name after unwrapping NON_NULL/LIST
}

type gqlArgInfo struct {
	name     string
	typeName string // String, Int, ID, Boolean, Float
	required bool
}

// ---------------------------------------------------------------------------
// Introspection parsing
// ---------------------------------------------------------------------------

func parseGQLFields(introResp string) []gqlFieldInfo {
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(introResp), &parsed); err != nil {
		return nil
	}
	data, _ := parsed["data"].(map[string]interface{})
	if data == nil {
		return nil
	}
	schema, _ := data["__schema"].(map[string]interface{})
	if schema == nil {
		return nil
	}

	queryTypeName := ""
	mutTypeName := ""
	if qt, ok := schema["queryType"].(map[string]interface{}); ok {
		queryTypeName, _ = qt["name"].(string)
	}
	if mt, ok := schema["mutationType"].(map[string]interface{}); ok {
		mutTypeName, _ = mt["name"].(string)
	}

	var fields []gqlFieldInfo
	types, _ := schema["types"].([]interface{})
	for _, t := range types {
		tMap, _ := t.(map[string]interface{})
		if tMap == nil {
			continue
		}
		typeName, _ := tMap["name"].(string)
		isMut := typeName == mutTypeName
		isQuery := typeName == queryTypeName
		if !isQuery && !isMut {
			continue
		}

		typeFields, _ := tMap["fields"].([]interface{})
		for _, f := range typeFields {
			fMap, _ := f.(map[string]interface{})
			if fMap == nil {
				continue
			}
			fieldName, _ := fMap["name"].(string)
			if strings.HasPrefix(fieldName, "__") {
				continue
			}

			gf := gqlFieldInfo{name: fieldName, isMut: isMut}
			if fType, ok := fMap["type"].(map[string]interface{}); ok {
				gf.retKind = gqlResolveTypeKind(fType)
				gf.retTypeName = resolveTypeName(fType)
			}

			fArgs, _ := fMap["args"].([]interface{})
			for _, a := range fArgs {
				aMap, _ := a.(map[string]interface{})
				if aMap == nil {
					continue
				}
				argName, _ := aMap["name"].(string)
				gf.args = append(gf.args, gqlArgInfo{
					name:     argName,
					typeName: resolveTypeName(aMap["type"]),
					required: gqlIsNonNull(aMap["type"]),
				})
			}
			fields = append(fields, gf)
		}
	}
	return fields
}

func gqlResolveTypeKind(raw interface{}) string {
	tMap, ok := raw.(map[string]interface{})
	if !ok {
		return ""
	}
	kind, _ := tMap["kind"].(string)
	if kind == "NON_NULL" {
		if ofType, ok := tMap["ofType"]; ok {
			return gqlResolveTypeKind(ofType)
		}
	}
	return kind
}

func gqlIsNonNull(raw interface{}) bool {
	tMap, ok := raw.(map[string]interface{})
	if !ok {
		return false
	}
	kind, _ := tMap["kind"].(string)
	return kind == "NON_NULL"
}

func gqlScalarFieldsOfType(introResp, typeName string) []string {
	if typeName == "" {
		return nil
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(introResp), &parsed); err != nil {
		return nil
	}
	data, _ := parsed["data"].(map[string]interface{})
	schema, _ := data["__schema"].(map[string]interface{})
	types, _ := schema["types"].([]interface{})
	for _, t := range types {
		tMap, _ := t.(map[string]interface{})
		name, _ := tMap["name"].(string)
		if name != typeName {
			continue
		}
		typeFields, _ := tMap["fields"].([]interface{})
		var result []string
		for _, f := range typeFields {
			fMap, _ := f.(map[string]interface{})
			fName, _ := fMap["name"].(string)
			if strings.HasPrefix(fName, "__") {
				continue
			}
			fType := resolveTypeName(fMap["type"])
			if fType == "String" || fType == "Int" || fType == "ID" || fType == "Boolean" {
				result = append(result, fName)
			}
		}
		if len(result) > 10 {
			result = result[:10]
		}
		return result
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func gqlSend(ctx context.Context, det *graphql.Detector, cl *assayhttp.Client, ep, field, query string, ns map[string]bool) (string, bool) {
	body, err := det.BuildGraphQLRequest(query, nil)
	if err != nil {
		return "", false
	}
	resp, err := cl.PostJSON(ctx, ep, body)
	if err != nil || resp == nil {
		return "", false
	}
	if strings.Contains(resp.Body, "must have a s") || strings.Contains(resp.Body, "subfields") || strings.Contains(resp.Body, "sub selection") {
		ns[field] = true
		return resp.Body, false
	}
	return resp.Body, true
}

func gqlSub(field string, ns map[string]bool) string {
	if ns[field] {
		return " { __typename }"
	}
	return ""
}

func gqlDefaultArg(a gqlArgInfo) string {
	switch a.typeName {
	case "String":
		return fmt.Sprintf(`%s: "test"`, a.name)
	case "Int":
		return fmt.Sprintf(`%s: 1`, a.name)
	case "Float":
		return fmt.Sprintf(`%s: 1.0`, a.name)
	case "Boolean":
		return fmt.Sprintf(`%s: true`, a.name)
	case "ID":
		return fmt.Sprintf(`%s: "1"`, a.name)
	default:
		return ""
	}
}

func gqlDataExists(resp, fieldName string) bool {
	if strings.Contains(resp, `"errors"`) && !strings.Contains(resp, `"data"`) {
		return false
	}
	return !strings.Contains(resp, `"`+fieldName+`":null`) &&
		!strings.Contains(resp, `"`+fieldName+`": null`)
}

func gqlIsIDArg(name string) bool {
	lower := strings.ToLower(name)
	return lower == "id" || lower == "pid" || lower == "uid" ||
		strings.HasSuffix(lower, "id") || strings.HasSuffix(lower, "_id")
}

// gqlSendRetry sends a query, retries once with __typename if sub-selection
// is required, and returns the final response.
func gqlSendRetry(ctx context.Context, det *graphql.Detector, cl *assayhttp.Client, ep, field string, ns map[string]bool, buildQuery func(sub string) string) string {
	sub := gqlSub(field, ns)
	q := buildQuery(sub)
	r, ok := gqlSend(ctx, det, cl, ep, field, q, ns)
	if !ok && ns[field] {
		q = buildQuery(" { __typename }")
		r, _ = gqlSend(ctx, det, cl, ep, field, q, ns)
	}
	return r
}
