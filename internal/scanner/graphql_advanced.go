package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/TyrusRC/assay/internal/core"
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

// runGraphQLAdvancedChecks runs IDOR, SSRF, stored XSS, DoS, authenticated
// CMDI, and information-disclosure checks against a GraphQL endpoint.
func (s *InternalScanner) runGraphQLAdvancedChecks(ctx context.Context, findingsChan chan<- *core.Finding, gqlEndpoint string, scanClient *assayhttp.Client) {
	det := graphql.New(scanClient)
	introQuery := det.BuildIntrospectionQuery()
	body, err := det.BuildGraphQLRequest(introQuery, nil)
	if err != nil {
		return
	}
	resp, err := scanClient.PostJSON(ctx, gqlEndpoint, body)
	if err != nil || resp == nil {
		return
	}
	introResp := resp.Body

	fields := parseGQLFields(introResp)
	if len(fields) == 0 {
		return
	}

	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] GraphQL advanced: %d fields on %s\n", len(fields), gqlEndpoint)
	}

	ns := make(map[string]bool) // needsSub cache per field name

	s.checkGQLIDOR(ctx, findingsChan, gqlEndpoint, scanClient, det, fields, ns, introResp)
	s.checkGQLSSRF(ctx, findingsChan, gqlEndpoint, scanClient, det, fields, ns)
	s.checkGQLStoredXSS(ctx, findingsChan, gqlEndpoint, scanClient, det, fields, ns, introResp)
	s.checkGQLDepthLimit(ctx, findingsChan, gqlEndpoint, scanClient, det, fields, ns)
	s.checkGQLAuthCMDI(ctx, findingsChan, gqlEndpoint, scanClient, det, fields, ns)
	s.checkGQLInfoDisc(ctx, findingsChan, gqlEndpoint, scanClient, det, fields, ns)
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

// ---------------------------------------------------------------------------
// IDOR — sequential ID enumeration on query fields
// ---------------------------------------------------------------------------

func (s *InternalScanner) checkGQLIDOR(ctx context.Context, ch chan<- *core.Finding, ep string, cl *assayhttp.Client, det *graphql.Detector, fields []gqlFieldInfo, ns map[string]bool, introResp string) {
	for _, f := range fields {
		if f.isMut {
			continue
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
		for _, a := range f.args {
			if (a.typeName != "Int" && a.typeName != "ID") || !gqlIsIDArg(a.name) {
				continue
			}

			// Use scalar fields of return type to get distinguishable responses.
			selFields := gqlScalarFieldsOfType(introResp, f.retTypeName)
			mkQ := func(id int) func(string) string {
				return func(sub string) string {
					sel := sub
					if len(selFields) > 0 {
						sel = " { " + strings.Join(selFields, " ") + " }"
					}
					return fmt.Sprintf(`query { %s(%s: %d)%s }`, f.name, a.name, id, sel)
				}
			}

			r1 := gqlSendRetry(ctx, det, cl, ep, f.name, ns, mkQ(1))
			if r1 == "" || !gqlDataExists(r1, f.name) {
				continue
			}

			rBig := gqlSendRetry(ctx, det, cl, ep, f.name, ns, mkQ(99999))
			if len(r1)-len(rBig) < 10 {
				continue
			}

			r2 := gqlSendRetry(ctx, det, cl, ep, f.name, ns, mkQ(2))
			if r2 == "" || r1 == r2 || !gqlDataExists(r2, f.name) {
				continue
			}

			finding := core.NewFinding("IDOR (GraphQL)", core.SeverityHigh)
			finding.URL = ep
			finding.Parameter = f.name + "." + a.name
			finding.Description = fmt.Sprintf("Insecure Direct Object Reference in GraphQL query '%s' argument '%s' — sequential ID enumeration returns different records without authorization", f.name, a.name)
			finding.Evidence = fmt.Sprintf("ID=1: %d bytes, ID=2: %d bytes, ID=99999: %d bytes", len(r1), len(r2), len(rBig))
			finding.Tool = "graphql-inject"
			finding.WithOWASPMapping([]string{"WSTG-ATHZ-04"}, []string{"A01:2025"}, []string{"CWE-639"})
			emit(ctx, ch, []*core.Finding{finding})
		}
	}
}

// ---------------------------------------------------------------------------
// SSRF — mutations with URL-component arguments
// ---------------------------------------------------------------------------

var gqlSSRFArgNames = map[string]bool{
	"host": true, "url": true, "uri": true, "endpoint": true,
	"webhook": true, "callback": true, "redirect": true,
	"fetch": true, "load": true, "src": true, "source": true,
}

func (s *InternalScanner) checkGQLSSRF(ctx context.Context, ch chan<- *core.Finding, ep string, cl *assayhttp.Client, det *graphql.Detector, fields []gqlFieldInfo, ns map[string]bool) {
	for _, f := range fields {
		select {
		case <-ctx.Done():
			return
		default:
		}

		hasSSRF := false
		for _, a := range f.args {
			if gqlSSRFArgNames[strings.ToLower(a.name)] {
				hasSSRF = true
				break
			}
		}
		if !hasSSRF {
			continue
		}

		prefix := "query"
		if f.isMut {
			prefix = "mutation"
		}

		buildSSRFArgs := func(hostVal string) []string {
			var parts []string
			for _, a := range f.args {
				lower := strings.ToLower(a.name)
				switch {
				case lower == "host":
					parts = append(parts, fmt.Sprintf(`%s: "%s"`, a.name, hostVal))
				case lower == "port":
					if a.typeName == "Int" {
						parts = append(parts, fmt.Sprintf(`%s: 80`, a.name))
					} else {
						parts = append(parts, fmt.Sprintf(`%s: "80"`, a.name))
					}
				case lower == "path":
					parts = append(parts, fmt.Sprintf(`%s: "/"`, a.name))
				case lower == "scheme":
					parts = append(parts, fmt.Sprintf(`%s: "http"`, a.name))
				case gqlSSRFArgNames[lower]:
					parts = append(parts, fmt.Sprintf(`%s: "http://%s/"`, a.name, hostVal))
				default:
					if v := gqlDefaultArg(a); v != "" {
						parts = append(parts, v)
					}
				}
			}
			return parts
		}

		internalArgs := strings.Join(buildSSRFArgs("127.0.0.1"), ", ")
		r1 := gqlSendRetry(ctx, det, cl, ep, f.name, ns, func(sub string) string {
			return fmt.Sprintf(`%s { %s(%s)%s }`, prefix, f.name, internalArgs, sub)
		})
		if r1 == "" {
			continue
		}

		externalArgs := strings.Join(buildSSRFArgs("192.0.2.1"), ", ")
		r2 := gqlSendRetry(ctx, det, cl, ep, f.name, ns, func(sub string) string {
			return fmt.Sprintf(`%s { %s(%s)%s }`, prefix, f.name, externalArgs, sub)
		})

		lenDiff := len(r1) - len(r2)
		lowerR1 := strings.ToLower(r1)
		hasHTML := strings.Contains(lowerR1, "<html") || strings.Contains(lowerR1, "<!doctype")
		hasInternal := strings.Contains(r1, "127.0.0.1") || strings.Contains(r1, "localhost")

		if lenDiff > 100 || hasHTML || (hasInternal && !strings.Contains(r2, "127.0.0.1")) {
			finding := core.NewFinding("Server-Side Request Forgery (GraphQL)", core.SeverityHigh)
			finding.URL = ep
			finding.Parameter = f.name
			finding.Description = fmt.Sprintf("SSRF in GraphQL %s '%s' — server fetches content from attacker-controlled URL", fieldType(f.isMut), f.name)
			finding.Evidence = fmt.Sprintf("Internal (127.0.0.1): %d bytes\nExternal (192.0.2.1): %d bytes\nDelta: %+d bytes", len(r1), len(r2), lenDiff)
			finding.Tool = "graphql-inject"
			finding.WithOWASPMapping([]string{"WSTG-INPV-19"}, []string{"A10:2025"}, []string{"CWE-918"})
			emit(ctx, ch, []*core.Finding{finding})
		}
	}
}

// ---------------------------------------------------------------------------
// Stored XSS — inject via mutation, read back via list query
// ---------------------------------------------------------------------------

var gqlWritableArgNames = map[string]bool{
	"title": true, "content": true, "body": true, "text": true,
	"name": true, "description": true, "message": true, "comment": true,
	"input": true, "html": true, "note": true, "value": true,
}

func (s *InternalScanner) checkGQLStoredXSS(ctx context.Context, ch chan<- *core.Finding, ep string, cl *assayhttp.Client, det *graphql.Detector, fields []gqlFieldInfo, ns map[string]bool, introResp string) {
	xssPayload := `<img src=x onerror=alert(1)>`

	for _, f := range fields {
		if !f.isMut {
			continue
		}
		select {
		case <-ctx.Done():
			return
		default:
		}

		hasWritable := false
		for _, a := range f.args {
			if a.typeName == "String" && gqlWritableArgNames[strings.ToLower(a.name)] {
				hasWritable = true
				break
			}
		}
		if !hasWritable {
			continue
		}

		var aParts []string
		for _, a := range f.args {
			if a.typeName == "String" && gqlWritableArgNames[strings.ToLower(a.name)] {
				aParts = append(aParts, fmt.Sprintf(`%s: "%s"`, a.name, escapeGQLString(xssPayload)))
			} else if v := gqlDefaultArg(a); v != "" {
				aParts = append(aParts, v)
			}
		}

		argsStr := strings.Join(aParts, ", ")
		mr := gqlSendRetry(ctx, det, cl, ep, f.name, ns, func(sub string) string {
			return fmt.Sprintf(`mutation { %s(%s)%s }`, f.name, argsStr, sub)
		})

		if strings.Contains(mr, xssPayload) {
			emitGQLStoredXSS(ctx, ch, ep, f.name, f.name+" response", xssPayload)
			return
		}
		if strings.Contains(mr, `"errors"`) && !strings.Contains(mr, `"data"`) {
			continue
		}

		for _, qf := range fields {
			if qf.isMut || qf.retKind != "LIST" {
				continue
			}
			hasReq := false
			for _, a := range qf.args {
				if a.required {
					hasReq = true
					break
				}
			}
			if hasReq {
				continue
			}

			selFields := gqlScalarFieldsOfType(introResp, qf.retTypeName)
			sel := " { __typename }"
			if len(selFields) > 0 {
				sel = " { " + strings.Join(selFields, " ") + " }"
			}

			lr := gqlSendRetry(ctx, det, cl, ep, qf.name, ns, func(sub string) string {
				if len(selFields) > 0 {
					return fmt.Sprintf(`query { %s%s }`, qf.name, sel)
				}
				return fmt.Sprintf(`query { %s%s }`, qf.name, sub)
			})

			if strings.Contains(lr, xssPayload) {
				emitGQLStoredXSS(ctx, ch, ep, f.name, qf.name, xssPayload)
				return
			}
		}
	}
}

func emitGQLStoredXSS(ctx context.Context, ch chan<- *core.Finding, ep, mutName, readSource, payload string) {
	finding := core.NewFinding("Stored XSS (GraphQL)", core.SeverityHigh)
	finding.URL = ep
	finding.Parameter = mutName
	finding.Description = fmt.Sprintf("Stored Cross-Site Scripting via GraphQL mutation '%s' — payload reflected unescaped in '%s'", mutName, readSource)
	finding.Evidence = fmt.Sprintf("Payload '%s' stored via mutation '%s', returned unescaped in '%s'", payload, mutName, readSource)
	finding.Tool = "graphql-inject"
	finding.WithOWASPMapping([]string{"WSTG-INPV-02"}, []string{"A07:2025"}, []string{"CWE-79"})
	emit(ctx, ch, []*core.Finding{finding})
}

// ---------------------------------------------------------------------------
// DoS — batch alias query (no complexity limit)
// ---------------------------------------------------------------------------

func (s *InternalScanner) checkGQLDepthLimit(ctx context.Context, ch chan<- *core.Finding, ep string, cl *assayhttp.Client, det *graphql.Detector, fields []gqlFieldInfo, ns map[string]bool) {
	var listField *gqlFieldInfo
	for i, f := range fields {
		if !f.isMut && (f.retKind == "LIST" || f.retKind == "OBJECT") {
			hasReq := false
			for _, a := range f.args {
				if a.required {
					hasReq = true
					break
				}
			}
			if !hasReq {
				listField = &fields[i]
				break
			}
		}
	}
	if listField == nil {
		return
	}

	// Probe sub requirement
	gqlSendRetry(ctx, det, cl, ep, listField.name, ns, func(sub string) string {
		return fmt.Sprintf(`query { %s%s }`, listField.name, sub)
	})

	sub := gqlSub(listField.name, ns)
	var parts []string
	for i := 0; i < 100; i++ {
		parts = append(parts, fmt.Sprintf(`a%d: %s%s`, i, listField.name, sub))
	}
	dq := fmt.Sprintf(`query { %s }`, strings.Join(parts, " "))
	body, _ := det.BuildGraphQLRequest(dq, nil)
	resp, err := cl.PostJSON(ctx, ep, body)
	if err != nil || resp == nil {
		return
	}

	if strings.Contains(resp.Body, "must have a s") || strings.Contains(resp.Body, "subfields") {
		ns[listField.name] = true
		sub = " { __typename }"
		var parts2 []string
		for i := 0; i < 100; i++ {
			parts2 = append(parts2, fmt.Sprintf(`a%d: %s%s`, i, listField.name, sub))
		}
		dq = fmt.Sprintf(`query { %s }`, strings.Join(parts2, " "))
		body, _ = det.BuildGraphQLRequest(dq, nil)
		resp, err = cl.PostJSON(ctx, ep, body)
		if err != nil || resp == nil {
			return
		}
	}

	reject := strings.Contains(resp.Body, "complexity") || strings.Contains(resp.Body, "depth") ||
		strings.Contains(resp.Body, "too many") || strings.Contains(resp.Body, "rate limit") ||
		strings.Contains(resp.Body, "query cost")
	if !reject && len(resp.Body) > 500 {
		finding := core.NewFinding("Denial of Service — No Query Complexity Limit (GraphQL)", core.SeverityMedium)
		finding.URL = ep
		finding.Description = fmt.Sprintf("GraphQL endpoint processes batch queries without complexity limiting — 100 aliases of '%s' accepted in a single request", listField.name)
		finding.Evidence = fmt.Sprintf("100 aliases of '%s', response: %d bytes, no complexity/rate rejection", listField.name, len(resp.Body))
		finding.Tool = "graphql-inject"
		finding.WithOWASPMapping([]string{"WSTG-APIT-08"}, []string{"A06:2025"}, []string{"CWE-770"})
		emit(ctx, ch, []*core.Finding{finding})
	}
}

// ---------------------------------------------------------------------------
// Authenticated CMDI — mutations with cmd + credential arguments
// ---------------------------------------------------------------------------

func (s *InternalScanner) checkGQLAuthCMDI(ctx context.Context, ch chan<- *core.Finding, ep string, cl *assayhttp.Client, det *graphql.Detector, fields []gqlFieldInfo, ns map[string]bool) {
	creds := [][2]string{{"admin", "admin"}, {"admin", "password"}, {"test", "test"}}

	for _, f := range fields {
		select {
		case <-ctx.Done():
			return
		default:
		}

		var cmdArg, userArg, passArg string
		for _, a := range f.args {
			lower := strings.ToLower(a.name)
			switch {
			case lower == "cmd" || lower == "command":
				cmdArg = a.name
			case lower == "username" || lower == "user":
				userArg = a.name
			case lower == "password" || lower == "pass":
				passArg = a.name
			}
		}
		if cmdArg == "" {
			continue
		}

		for _, c := range creds {
			var aParts []string
			for _, a := range f.args {
				switch {
				case a.name == cmdArg:
					aParts = append(aParts, fmt.Sprintf(`%s: "id"`, a.name))
				case a.name == userArg && userArg != "":
					aParts = append(aParts, fmt.Sprintf(`%s: "%s"`, a.name, c[0]))
				case a.name == passArg && passArg != "":
					aParts = append(aParts, fmt.Sprintf(`%s: "%s"`, a.name, c[1]))
				default:
					if v := gqlDefaultArg(a); v != "" {
						aParts = append(aParts, v)
					}
				}
			}

			argsStr := strings.Join(aParts, ", ")
			pfx := "query"
			if f.isMut {
				pfx = "mutation"
			}
			r := gqlSendRetry(ctx, det, cl, ep, f.name, ns, func(sub string) string {
				return fmt.Sprintf(`%s { %s(%s)%s }`, pfx, f.name, argsStr, sub)
			})

			if cmdiPattern.MatchString(r) {
				finding := core.NewFinding("Command Injection (GraphQL)", core.SeverityCritical)
				finding.URL = ep
				finding.Parameter = f.name + "." + cmdArg
				finding.Description = fmt.Sprintf("OS Command Injection in GraphQL %s '%s' with default credentials (%s:%s)", fieldType(f.isMut), f.name, c[0], c[1])
				finding.Evidence = fmt.Sprintf("Credentials: %s:%s\nCommand: id\nOutput: uid= pattern detected in response (%d bytes)", c[0], c[1], len(r))
				finding.Tool = "graphql-inject"
				finding.WithOWASPMapping([]string{"WSTG-INPV-12"}, []string{"A05:2025"}, []string{"CWE-78"})
				emit(ctx, ch, []*core.Finding{finding})
				return
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Information Disclosure — sensitive queries accessible without auth
// ---------------------------------------------------------------------------

var gqlInfoDiscNames = map[string]bool{
	"systemhealth": true, "systemupdate": true, "systeminfo": true,
	"healthcheck": true, "health": true, "status": true,
	"serverinfo": true, "version": true, "debug": true,
	"diagnostics": true, "internal": true, "config": true,
	"metrics": true, "environment": true,
}

func (s *InternalScanner) checkGQLInfoDisc(ctx context.Context, ch chan<- *core.Finding, ep string, cl *assayhttp.Client, det *graphql.Detector, fields []gqlFieldInfo, ns map[string]bool) {
	for _, f := range fields {
		if f.isMut {
			continue
		}
		if !gqlInfoDiscNames[strings.ToLower(f.name)] {
			continue
		}
		select {
		case <-ctx.Done():
			return
		default:
		}

		hasReq := false
		for _, a := range f.args {
			if a.required {
				hasReq = true
				break
			}
		}
		if hasReq {
			continue
		}

		r := gqlSendRetry(ctx, det, cl, ep, f.name, ns, func(sub string) string {
			return fmt.Sprintf(`query { %s%s }`, f.name, sub)
		})
		if r == "" || !gqlDataExists(r, f.name) || len(r) < 50 {
			continue
		}

		finding := core.NewFinding("Information Disclosure (GraphQL)", core.SeverityMedium)
		finding.URL = ep
		finding.Parameter = f.name
		finding.Description = fmt.Sprintf("GraphQL query '%s' exposes system information without authorization", f.name)
		finding.Evidence = fmt.Sprintf("Query: { %s }\nResponse (%d bytes): %.300s", f.name, len(r), r)
		finding.Tool = "graphql-inject"
		finding.WithOWASPMapping([]string{"WSTG-INFO-02"}, []string{"A01:2025"}, []string{"CWE-200"})
		emit(ctx, ch, []*core.Finding{finding})
	}
}
