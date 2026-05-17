package openapisemantic

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// testCtx returns a context bound to the test deadline so a hanging request
// doesn't deadlock the suite under -race.
func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// readJSON reads the request body and decodes it into a map.
func readJSON(t *testing.T, r *http.Request) map[string]interface{} {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil
	}
	defer r.Body.Close()
	if len(body) == 0 {
		return nil
	}
	var data map[string]interface{}
	_ = json.Unmarshal(body, &data)
	return data
}

func TestParseSpec_HappyPath(t *testing.T) {
	doc := []byte(`{
		"openapi": "3.0.0",
		"paths": {
			"/users": {
				"post": {
					"operationId": "createUser",
					"requestBody": {
						"required": true,
						"content": {
							"application/json": {
								"schema": {
									"type": "object",
									"required": ["userId"],
									"properties": {
										"userId": {"type": "integer"},
										"password": {"type": "string", "nullable": true}
									},
									"additionalProperties": false
								}
							}
						}
					}
				}
			}
		}
	}`)
	spec, err := ParseSpec(doc)
	if err != nil {
		t.Fatalf("ParseSpec: %v", err)
	}
	if spec.OpenAPI != "3.0.0" {
		t.Errorf("OpenAPI version = %q", spec.OpenAPI)
	}
	if len(spec.Paths) != 1 {
		t.Fatalf("paths len = %d", len(spec.Paths))
	}
	op := spec.Paths["/users"].Post
	if op == nil {
		t.Fatal("expected POST operation on /users")
	}
	schema := op.JSONSchema()
	if schema == nil {
		t.Fatal("expected json schema")
	}
	if schema.Properties["userId"].Type != "integer" {
		t.Errorf("userId type = %q", schema.Properties["userId"].Type)
	}
	if !schema.Properties["password"].Nullable {
		t.Error("password should be nullable")
	}
	if schema.AdditionalProperties == nil || !schema.AdditionalProperties.Set || schema.AdditionalProperties.Allowed {
		t.Error("additionalProperties should decode to set + disallowed")
	}
}

func TestParseSpec_AdditionalPropertiesAsSchema(t *testing.T) {
	doc := []byte(`{"openapi":"3.0.0","paths":{"/x":{"post":{"requestBody":{"content":{"application/json":{"schema":{"type":"object","additionalProperties":{"type":"string"}}}}}}}}}`)
	spec, err := ParseSpec(doc)
	if err != nil {
		t.Fatalf("ParseSpec: %v", err)
	}
	ap := spec.Paths["/x"].Post.JSONSchema().AdditionalProperties
	if ap == nil || !ap.Set || !ap.Allowed || ap.Schema == nil || ap.Schema.Type != "string" {
		t.Fatalf("AdditionalProps schema form not decoded: %+v", ap)
	}
}

func TestDetector_NameDescription(t *testing.T) {
	d := New(nil)
	if d.Name() != "openapi-semantic" {
		t.Errorf("Name = %q", d.Name())
	}
	if d.Description() == "" {
		t.Error("Description empty")
	}
}

func TestDetect_RequiresSpecSource(t *testing.T) {
	d := New(skwshttp.NewClient())
	if _, err := d.DetectTypeCoercion(testCtx(t), DetectOptions{BaseURL: "http://x"}); err == nil {
		t.Error("expected error when neither SpecJSON nor SpecURL is set")
	}
}

// --- Type coercion ---------------------------------------------------------

// typeCoercionSpec returns a minimal spec with one POST /items endpoint
// whose only field is `quantity: integer`.
func typeCoercionSpec() []byte {
	return []byte(`{
		"openapi": "3.0.0",
		"paths": {
			"/items": {
				"post": {
					"requestBody": {
						"content": {
							"application/json": {
								"schema": {
									"type": "object",
									"properties": {
										"quantity": {"type": "integer"}
									}
								}
							}
						}
					}
				}
			}
		}
	}`)
}

func TestDetectTypeCoercion_VulnerableServer_High(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data := readJSON(t, r)
		// Vulnerable: echoes whatever you send back, so injection payload
		// produces a discriminably different response from the integer
		// baseline.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"echo": data})
	}))
	defer srv.Close()

	d := New(skwshttp.NewClient())
	res, err := d.DetectTypeCoercion(testCtx(t), DetectOptions{
		SpecJSON: typeCoercionSpec(),
		BaseURL:  srv.URL,
	})
	if err != nil {
		t.Fatalf("DetectTypeCoercion: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("expected vulnerability")
	}
	hasHigh := false
	for _, f := range res.Findings {
		if f.Severity == core.SeverityHigh {
			hasHigh = true
		}
		if f.Tool != detectorTool {
			t.Errorf("Tool = %q", f.Tool)
		}
		if !contains(f.APITop10, "API3:2023") {
			t.Errorf("APITop10 missing API3:2023: %v", f.APITop10)
		}
	}
	if !hasHigh {
		t.Error("expected at least one High-severity finding")
	}
}

func TestDetectTypeCoercion_StrictServer_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data := readJSON(t, r)
		// Strict: reject string-typed values for `quantity`.
		if v, ok := data["quantity"]; ok {
			if _, isFloat := v.(float64); !isFloat {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"quantity must be integer"}`))
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	d := New(skwshttp.NewClient())
	res, err := d.DetectTypeCoercion(testCtx(t), DetectOptions{
		SpecJSON: typeCoercionSpec(),
		BaseURL:  srv.URL,
	})
	if err != nil {
		t.Fatalf("DetectTypeCoercion: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("expected no findings, got %d: %+v", len(res.Findings), res.Findings)
	}
}

// --- Discriminator confusion ----------------------------------------------

func discriminatorSpec() []byte {
	return []byte(`{
		"openapi": "3.0.0",
		"paths": {
			"/accounts": {
				"post": {
					"requestBody": {
						"content": {
							"application/json": {
								"schema": {
									"oneOf": [
										{
											"type": "object",
											"required": ["type", "email"],
											"properties": {
												"type": {"type": "string", "enum": ["user"]},
												"email": {"type": "string"}
											}
										},
										{
											"type": "object",
											"required": ["type", "email", "isAdmin", "role"],
											"properties": {
												"type": {"type": "string", "enum": ["admin"]},
												"email": {"type": "string"},
												"isAdmin": {"type": "boolean"},
												"role": {"type": "string"}
											}
										}
									],
									"discriminator": {"propertyName": "type"}
								}
							}
						}
					}
				}
			}
		}
	}`)
}

func TestDetectDiscriminatorConfusion_Vulnerable_Critical(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Vulnerable: accepts any combination of fields regardless of
		// discriminator branch.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"created":true}`))
	}))
	defer srv.Close()

	d := New(skwshttp.NewClient())
	res, err := d.DetectDiscriminatorConfusion(testCtx(t), DetectOptions{
		SpecJSON: discriminatorSpec(),
		BaseURL:  srv.URL,
	})
	if err != nil {
		t.Fatalf("DetectDiscriminatorConfusion: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("expected vulnerability")
	}
	if res.Findings[0].Severity != core.SeverityCritical {
		t.Errorf("severity = %v, want Critical", res.Findings[0].Severity)
	}
}

func TestDetectDiscriminatorConfusion_Strict_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data := readJSON(t, r)
		// Strict: when type=user, reject any admin-only fields.
		if typ, _ := data["type"].(string); typ == "user" {
			if _, ok := data["isAdmin"]; ok {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"isAdmin not allowed for user"}`))
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	d := New(skwshttp.NewClient())
	res, err := d.DetectDiscriminatorConfusion(testCtx(t), DetectOptions{
		SpecJSON: discriminatorSpec(),
		BaseURL:  srv.URL,
	})
	if err != nil {
		t.Fatalf("DetectDiscriminatorConfusion: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("expected no findings, got %+v", res.Findings)
	}
}

// --- Nullable leak --------------------------------------------------------

func nullableSpec() []byte {
	return []byte(`{
		"openapi": "3.0.0",
		"paths": {
			"/register": {
				"post": {
					"requestBody": {
						"content": {
							"application/json": {
								"schema": {
									"type": "object",
									"required": ["email", "password"],
									"properties": {
										"email": {"type": "string"},
										"password": {"type": "string", "nullable": true}
									}
								}
							}
						}
					}
				}
			}
		}
	}`)
}

func TestDetectNullableLeak_Vulnerable_Critical(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Vulnerable: happily creates an account with password = null.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":1}`))
	}))
	defer srv.Close()

	d := New(skwshttp.NewClient())
	res, err := d.DetectNullableLeak(testCtx(t), DetectOptions{
		SpecJSON: nullableSpec(),
		BaseURL:  srv.URL,
	})
	if err != nil {
		t.Fatalf("DetectNullableLeak: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("expected vulnerability")
	}
	f := res.Findings[0]
	if f.Severity != core.SeverityCritical {
		t.Errorf("severity = %v, want Critical", f.Severity)
	}
	if f.Parameter != "password" {
		t.Errorf("parameter = %q, want password", f.Parameter)
	}
}

func TestDetectNullableLeak_Strict_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data := readJSON(t, r)
		if v, ok := data["password"]; ok && v == nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"password required"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":1}`))
	}))
	defer srv.Close()

	d := New(skwshttp.NewClient())
	res, err := d.DetectNullableLeak(testCtx(t), DetectOptions{
		SpecJSON: nullableSpec(),
		BaseURL:  srv.URL,
	})
	if err != nil {
		t.Fatalf("DetectNullableLeak: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("expected no findings, got %+v", res.Findings)
	}
}

// --- additionalProperties bypass ------------------------------------------

func additionalPropsSpec() []byte {
	return []byte(`{
		"openapi": "3.0.0",
		"paths": {
			"/profile": {
				"put": {
					"requestBody": {
						"content": {
							"application/json": {
								"schema": {
									"type": "object",
									"required": ["name"],
									"properties": {
										"name": {"type": "string"}
									},
									"additionalProperties": false
								}
							}
						}
					}
				}
			}
		}
	}`)
}

func TestDetectAdditionalPropertiesBypass_Vulnerable_High(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data := readJSON(t, r)
		// Vulnerable: persists and echoes whatever extras were sent.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(data)
	}))
	defer srv.Close()

	d := New(skwshttp.NewClient())
	res, err := d.DetectAdditionalPropertiesBypass(testCtx(t), DetectOptions{
		SpecJSON: additionalPropsSpec(),
		BaseURL:  srv.URL,
	})
	if err != nil {
		t.Fatalf("DetectAdditionalPropertiesBypass: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("expected vulnerability")
	}
	if res.Findings[0].Severity != core.SeverityHigh {
		t.Errorf("severity = %v, want High", res.Findings[0].Severity)
	}
	if !strings.Contains(res.Findings[0].Description, "additionalProperties") {
		t.Errorf("description missing keyword: %q", res.Findings[0].Description)
	}
}

func TestDetectAdditionalPropertiesBypass_Strict_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data := readJSON(t, r)
		// Strict: reject any key other than the declared `name`.
		for k := range data {
			if k != "name" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"unknown field"}`))
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"name":"ok"}`))
	}))
	defer srv.Close()

	d := New(skwshttp.NewClient())
	res, err := d.DetectAdditionalPropertiesBypass(testCtx(t), DetectOptions{
		SpecJSON: additionalPropsSpec(),
		BaseURL:  srv.URL,
	})
	if err != nil {
		t.Fatalf("DetectAdditionalPropertiesBypass: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("expected no findings, got %+v", res.Findings)
	}
}

// --- DetectAll merges --------------------------------------------------------

func TestDetectAll_MergesFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Universally permissive: every probe should pop.
		data := readJSON(t, r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(data)
	}))
	defer srv.Close()

	// Combine all four schemas in a single spec so DetectAll has something
	// for every probe to find.
	spec := []byte(`{
		"openapi": "3.0.0",
		"paths": {
			"/items": {
				"post": {
					"requestBody": {
						"content": {
							"application/json": {
								"schema": {
									"type": "object",
									"properties": {"quantity": {"type": "integer"}}
								}
							}
						}
					}
				}
			},
			"/accounts": {
				"post": {
					"requestBody": {
						"content": {
							"application/json": {
								"schema": {
									"oneOf": [
										{"type":"object","required":["type"],"properties":{"type":{"type":"string","enum":["user"]}}},
										{"type":"object","required":["type","isAdmin"],"properties":{"type":{"type":"string","enum":["admin"]},"isAdmin":{"type":"boolean"}}}
									],
									"discriminator":{"propertyName":"type"}
								}
							}
						}
					}
				}
			},
			"/register": {
				"post": {
					"requestBody": {
						"content": {
							"application/json": {
								"schema": {
									"type":"object",
									"required":["password"],
									"properties":{"password":{"type":"string","nullable":true}}
								}
							}
						}
					}
				}
			},
			"/profile": {
				"put": {
					"requestBody": {
						"content": {
							"application/json": {
								"schema": {
									"type":"object",
									"required":["name"],
									"properties":{"name":{"type":"string"}},
									"additionalProperties": false
								}
							}
						}
					}
				}
			}
		}
	}`)

	d := New(skwshttp.NewClient())
	res, err := d.DetectAll(testCtx(t), DetectOptions{SpecJSON: spec, BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("DetectAll: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("expected aggregate vulnerability")
	}
	if len(res.Findings) < 4 {
		t.Errorf("expected at least one finding per probe (>=4), got %d", len(res.Findings))
	}
	for _, f := range res.Findings {
		if err := f.Validate(); err != nil {
			t.Errorf("invalid finding: %v", err)
		}
		if f.Tool != detectorTool {
			t.Errorf("Tool = %q, want %q", f.Tool, detectorTool)
		}
	}
}

// --- spec via SpecURL -------------------------------------------------------

func TestLoad_FromSpecURL(t *testing.T) {
	spec := typeCoercionSpec()
	// Mux: /spec.json serves the spec, /items echoes back.
	mux := http.NewServeMux()
	mux.HandleFunc("/spec.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(spec)
	})
	mux.HandleFunc("/items", func(w http.ResponseWriter, r *http.Request) {
		data := readJSON(t, r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"echo": data})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d := New(skwshttp.NewClient())
	res, err := d.DetectTypeCoercion(testCtx(t), DetectOptions{
		SpecURL: srv.URL + "/spec.json",
		BaseURL: srv.URL,
	})
	if err != nil {
		t.Fatalf("DetectTypeCoercion: %v", err)
	}
	if !res.Vulnerable {
		t.Error("expected vulnerability when spec is fetched via SpecURL")
	}
}

// --- helpers ---------------------------------------------------------------

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
