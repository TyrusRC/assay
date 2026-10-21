package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/detection/graphql"
	assayhttp "github.com/TyrusRC/assay/internal/http"
)

// gqlArg represents a single injectable argument on a GraphQL field.
type gqlArg struct {
	fieldName string // e.g. "systemDebug"
	argName   string // e.g. "arg"
	argType   string // e.g. "String", "Int"
	isMut     bool   // true if this is a mutation
}

// runGraphQLInjection introspects the GraphQL schema, then injects payloads
// into every String argument on every query and mutation. Findings are emitted
// to findingsChan. This is the GraphQL equivalent of the parameter-injection
// phase — it builds { fieldName(argName: "PAYLOAD") } syntax for each arg.
func (s *InternalScanner) runGraphQLInjection(ctx context.Context, wg *sync.WaitGroup, findingsChan chan<- *core.Finding, gqlEndpoint string, scanClient *assayhttp.Client) {
	det := graphql.New(scanClient)

	// Full introspection to get all fields + args.
	introQuery := det.BuildIntrospectionQuery()
	body, err := det.BuildGraphQLRequest(introQuery, nil)
	if err != nil {
		return
	}
	resp, err := scanClient.PostJSON(ctx, gqlEndpoint, body)
	if err != nil || resp == nil {
		return
	}

	args := extractInjectableArgs(resp.Body)
	if len(args) == 0 {
		return
	}

	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] GraphQL injection: %d injectable args on %s\n", len(args), gqlEndpoint)
	}

	// Injection payloads — small focused set for speed.
	type payload struct {
		value string
		class string // sqli, cmdi, ssti, ssrf
		desc  string
	}
	payloads := []payload{
		// SQLi
		{"'", "sqli", "single quote"},
		{"' OR '1'='1' --", "sqli", "OR bypass"},
		// CMDI
		{"; id", "cmdi", "semicolon id"},
		{"| id", "cmdi", "pipe id"},
		{"$(id)", "cmdi", "subshell id"},
		// SSTI / code injection
		{"1337*7", "ssti", "arithmetic eval"},
		{"{{7*7}}", "ssti", "template math"},
		// SSRF marker (just checks reflection)
		{"http://169.254.169.254/latest/meta-data/", "ssrf", "AWS metadata"},
	}

	cmdiPattern := regexp.MustCompile(`uid=\d+\(\w+\)\s+gid=\d+`)
	evalPattern := regexp.MustCompile(`\b9359\b`)

	sem := make(chan struct{}, 3)
	for _, arg := range args {
		select {
		case <-ctx.Done():
			return
		default:
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(a gqlArg) {
			defer wg.Done()
			defer func() { <-sem }()

			// Baseline: send a clean value to compare against SQLi responses.
			var baselineLen int
			if a.argType != "Int" {
				prefix := "query"
				if a.isMut {
					prefix = "mutation"
				}
				bq := fmt.Sprintf(`%s { %s(%s: "assay_baseline_test") }`, prefix, a.fieldName, a.argName)
				bb, _ := det.BuildGraphQLRequest(bq, nil)
				if br, err := scanClient.PostJSON(ctx, gqlEndpoint, bb); err == nil && br != nil {
					baselineLen = len(br.Body)
				}
			}

			for _, p := range payloads {
				select {
				case <-ctx.Done():
					return
				default:
				}

				// Build the GraphQL query with the payload injected.
				var query string
				if a.argType == "Int" {
					// Int args: try numeric injection
					if p.class == "sqli" {
						query = fmt.Sprintf(`{ %s(%s: 1) }`, a.fieldName, a.argName)
					} else {
						continue
					}
				} else {
					prefix := "query"
					if a.isMut {
						prefix = "mutation"
					}
					query = fmt.Sprintf(`%s { %s(%s: "%s") }`, prefix, a.fieldName, a.argName, escapeGQLString(p.value))
				}

				reqBody, err := det.BuildGraphQLRequest(query, nil)
				if err != nil {
					continue
				}
				r, err := scanClient.PostJSON(ctx, gqlEndpoint, reqBody)
				if err != nil || r == nil {
					continue
				}

				// Check for SQLi — error-based + differential
				if p.class == "sqli" {
					injResult := det.AnalyzeInjectionResponse(r.Body)
					isDiff := false
					if !injResult.Vulnerable && p.value == "' OR '1'='1' --" && baselineLen > 0 {
						// Differential: OR bypass returns more data than baseline.
						diff := len(r.Body) - baselineLen
						if diff > 50 && len(r.Body) > baselineLen*2 {
							isDiff = true
						}
					}
					if injResult.Vulnerable || isDiff {
						f := core.NewFinding("SQL Injection (GraphQL)", core.SeverityCritical)
						f.URL = gqlEndpoint
						f.Parameter = a.fieldName + "." + a.argName
						evidence := ""
						if injResult.Vulnerable {
							evidence = fmt.Sprintf("Error-based (%s): %s", injResult.DatabaseType, injResult.Evidence)
						} else {
							evidence = fmt.Sprintf("Differential: baseline=%d bytes, OR-bypass=%d bytes (delta +%d)",
								baselineLen, len(r.Body), len(r.Body)-baselineLen)
						}
						f.Description = fmt.Sprintf("SQL Injection in GraphQL %s '%s' argument '%s'",
							fieldType(a.isMut), a.fieldName, a.argName)
						f.Evidence = fmt.Sprintf("Query: %s\n%s", query, evidence)
						f.Tool = "graphql-inject"
						f.WithOWASPMapping([]string{"WSTG-INPV-05"}, []string{"A05:2025"}, []string{"CWE-89"})
						emit(ctx, findingsChan, []*core.Finding{f})
						return
					}
				}

				// Check for CMDI
				if p.class == "cmdi" && cmdiPattern.MatchString(r.Body) {
					f := core.NewFinding("Command Injection (GraphQL)", core.SeverityCritical)
					f.URL = gqlEndpoint
					f.Parameter = a.fieldName + "." + a.argName
					f.Description = fmt.Sprintf("OS Command Injection in GraphQL %s '%s' argument '%s'",
						fieldType(a.isMut), a.fieldName, a.argName)
					f.Evidence = fmt.Sprintf("Query: %s\nOutput: %.200s", query, r.Body)
					f.Tool = "graphql-inject"
					f.WithOWASPMapping([]string{"WSTG-INPV-12"}, []string{"A05:2025"}, []string{"CWE-78"})
					emit(ctx, findingsChan, []*core.Finding{f})
					return
				}

				// Check for code injection (eval)
				if p.class == "ssti" && p.value == "1337*7" && evalPattern.MatchString(r.Body) {
					f := core.NewFinding("Code Injection (GraphQL)", core.SeverityCritical)
					f.URL = gqlEndpoint
					f.Parameter = a.fieldName + "." + a.argName
					f.Description = fmt.Sprintf("Code Injection (eval) in GraphQL %s '%s' argument '%s'",
						fieldType(a.isMut), a.fieldName, a.argName)
					f.Evidence = fmt.Sprintf("Query: %s\nResponse contains 9359 (1337*7)", query)
					f.Tool = "graphql-inject"
					f.WithOWASPMapping([]string{"WSTG-INPV-12"}, []string{"A05:2025"}, []string{"CWE-94"})
					emit(ctx, findingsChan, []*core.Finding{f})
					return
				}
			}
		}(arg)
	}
}

// extractInjectableArgs parses a full introspection response and returns
// all String/Int args on query and mutation fields.
func extractInjectableArgs(introResp string) []gqlArg {
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

	var args []gqlArg

	// Walk types to find Query and Mutation root types.
	queryTypeName := ""
	mutTypeName := ""
	if qt, ok := schema["queryType"].(map[string]interface{}); ok {
		queryTypeName, _ = qt["name"].(string)
	}
	if mt, ok := schema["mutationType"].(map[string]interface{}); ok {
		mutTypeName, _ = mt["name"].(string)
	}

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

		fields, _ := tMap["fields"].([]interface{})
		for _, f := range fields {
			fMap, _ := f.(map[string]interface{})
			if fMap == nil {
				continue
			}
			fieldName, _ := fMap["name"].(string)
			if strings.HasPrefix(fieldName, "__") {
				continue
			}

			fArgs, _ := fMap["args"].([]interface{})
			for _, a := range fArgs {
				aMap, _ := a.(map[string]interface{})
				if aMap == nil {
					continue
				}
				argName, _ := aMap["name"].(string)
				argType := resolveTypeName(aMap["type"])
				if argType == "String" || argType == "Int" || argType == "ID" {
					args = append(args, gqlArg{
						fieldName: fieldName,
						argName:   argName,
						argType:   argType,
						isMut:     isMut,
					})
				}
			}
		}
	}
	return args
}

// resolveTypeName walks a GraphQL type (which may be wrapped in NON_NULL/LIST)
// to find the leaf scalar name.
func resolveTypeName(raw interface{}) string {
	tMap, ok := raw.(map[string]interface{})
	if !ok {
		return ""
	}
	if name, ok := tMap["name"].(string); ok && name != "" {
		return name
	}
	if ofType, ok := tMap["ofType"]; ok {
		return resolveTypeName(ofType)
	}
	return ""
}

func escapeGQLString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

func fieldType(isMut bool) string {
	if isMut {
		return "mutation"
	}
	return "query"
}
