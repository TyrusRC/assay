package smuggling

import (
	"strings"
	"testing"
)

func TestPayloadType_String(t *testing.T) {
	tests := []struct {
		payloadType PayloadType
		want        string
	}{
		{PayloadCLTE, "CL.TE"},
		{PayloadTECL, "TE.CL"},
		{PayloadTETE, "TE.TE"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if string(tt.payloadType) != tt.want {
				t.Errorf("PayloadType = %q, want %q", tt.payloadType, tt.want)
			}
		})
	}
}

func TestGetCLTEPayloads(t *testing.T) {
	payloads := GetCLTEPayloads()

	if len(payloads) == 0 {
		t.Fatal("GetCLTEPayloads() returned no payloads")
	}

	for i, p := range payloads {
		if p.Type != PayloadCLTE {
			t.Errorf("Payload %d has type %s, want %s", i, p.Type, PayloadCLTE)
		}
		if p.Name == "" {
			t.Errorf("Payload %d has empty name", i)
		}
		if p.Description == "" {
			t.Errorf("Payload %d has empty description", i)
		}
		if p.RequestTemplate == "" {
			t.Errorf("Payload %d has empty request template", i)
		}
	}
}

func TestGetTECLPayloads(t *testing.T) {
	payloads := GetTECLPayloads()

	if len(payloads) == 0 {
		t.Fatal("GetTECLPayloads() returned no payloads")
	}

	for i, p := range payloads {
		if p.Type != PayloadTECL {
			t.Errorf("Payload %d has type %s, want %s", i, p.Type, PayloadTECL)
		}
		if p.Name == "" {
			t.Errorf("Payload %d has empty name", i)
		}
		if p.Description == "" {
			t.Errorf("Payload %d has empty description", i)
		}
		if p.RequestTemplate == "" {
			t.Errorf("Payload %d has empty request template", i)
		}
	}
}

func TestGetTETEPayloads(t *testing.T) {
	payloads := GetTETEPayloads()

	if len(payloads) == 0 {
		t.Fatal("GetTETEPayloads() returned no payloads")
	}

	for i, p := range payloads {
		if p.Type != PayloadTETE {
			t.Errorf("Payload %d has type %s, want %s", i, p.Type, PayloadTETE)
		}
		if p.Name == "" {
			t.Errorf("Payload %d has empty name", i)
		}
		if p.Description == "" {
			t.Errorf("Payload %d has empty description", i)
		}
		if p.RequestTemplate == "" {
			t.Errorf("Payload %d has empty request template", i)
		}
	}
}

func TestGetTimingPayloads(t *testing.T) {
	payloads := GetTimingPayloads()

	if len(payloads) == 0 {
		t.Fatal("GetTimingPayloads() returned no payloads")
	}

	for i, p := range payloads {
		if p.DetectionMethod != DetectTiming {
			t.Errorf("Payload %d has detection method %s, want %s", i, p.DetectionMethod, DetectTiming)
		}
	}
}

func TestGetAllPayloads(t *testing.T) {
	all := GetAllPayloads()

	clte := GetCLTEPayloads()
	tecl := GetTECLPayloads()
	tete := GetTETEPayloads()

	expected := len(clte) + len(tecl) + len(tete)
	if len(all) != expected {
		t.Errorf("GetAllPayloads() returned %d payloads, expected %d", len(all), expected)
	}
}

func TestGetTEObfuscations(t *testing.T) {
	obfuscations := GetTEObfuscations()

	if len(obfuscations) == 0 {
		t.Fatal("GetTEObfuscations() returned no obfuscations")
	}

	// Verify each obfuscation relates to Transfer-Encoding
	for i, obf := range obfuscations {
		lower := strings.ToLower(obf)
		if !strings.Contains(lower, "transfer") && !strings.Contains(lower, "encoding") {
			t.Errorf("Obfuscation %d %q doesn't appear to be TE-related", i, obf)
		}
	}
}

func TestPayload_RequestTemplateContainsPlaceholders(t *testing.T) {
	all := GetAllPayloads()

	for _, p := range all {
		// Every payload should have HOST placeholder
		if !strings.Contains(p.RequestTemplate, "{{HOST}}") {
			t.Errorf("Payload %q missing {{HOST}} placeholder", p.Name)
		}
		// Every payload should have PATH placeholder
		if !strings.Contains(p.RequestTemplate, "{{PATH}}") {
			t.Errorf("Payload %q missing {{PATH}} placeholder", p.Name)
		}
	}
}

func TestPayload_DetectionMethod(t *testing.T) {
	all := GetAllPayloads()

	validMethods := map[DetectionMethod]bool{
		DetectTiming:       true,
		DetectDifferential: true,
		DetectSocket:       true,
	}

	for _, p := range all {
		if !validMethods[p.DetectionMethod] {
			t.Errorf("Payload %q has invalid detection method: %s", p.Name, p.DetectionMethod)
		}
	}
}

func TestCLTEPayloads_ContainsBothHeaders(t *testing.T) {
	payloads := GetCLTEPayloads()

	for _, p := range payloads {
		template := strings.ToLower(p.RequestTemplate)
		if !strings.Contains(template, "content-length") {
			t.Errorf("CL.TE payload %q missing Content-Length header", p.Name)
		}
		if !strings.Contains(template, "transfer-encoding") {
			t.Errorf("CL.TE payload %q missing Transfer-Encoding header", p.Name)
		}
	}
}

func TestTECLPayloads_ContainsBothHeaders(t *testing.T) {
	payloads := GetTECLPayloads()

	for _, p := range payloads {
		template := strings.ToLower(p.RequestTemplate)
		if !strings.Contains(template, "content-length") {
			t.Errorf("TE.CL payload %q missing Content-Length header", p.Name)
		}
		if !strings.Contains(template, "transfer-encoding") {
			t.Errorf("TE.CL payload %q missing Transfer-Encoding header", p.Name)
		}
	}
}

func TestTETEPayloads_ContainsObfuscation(t *testing.T) {
	payloads := GetTETEPayloads()

	for _, p := range payloads {
		// TE.TE payloads should have some form of Transfer-Encoding
		template := strings.ToLower(p.RequestTemplate)
		if !strings.Contains(template, "transfer") {
			t.Errorf("TE.TE payload %q missing Transfer-Encoding variant", p.Name)
		}
	}
}

func TestPayload_UniqueNames(t *testing.T) {
	all := GetAllPayloads()
	names := make(map[string]bool)

	for _, p := range all {
		if names[p.Name] {
			t.Errorf("Duplicate payload name: %s", p.Name)
		}
		names[p.Name] = true
	}
}

func TestDetectionMethod_Values(t *testing.T) {
	tests := []struct {
		method DetectionMethod
		want   string
	}{
		{DetectTiming, "timing"},
		{DetectDifferential, "differential"},
		{DetectSocket, "socket"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if string(tt.method) != tt.want {
				t.Errorf("DetectionMethod = %q, want %q", tt.method, tt.want)
			}
		})
	}
}

func TestTEObfuscations_Diversity(t *testing.T) {
	obfuscations := GetTEObfuscations()

	// Check for specific obfuscation techniques
	techniques := map[string]bool{
		"space_before_colon":  false,
		"tab":                 false,
		"uppercase":           false,
		"xchunked":            false,
		"double_header":       false,
		"trailing_whitespace": false,
	}

	for _, obf := range obfuscations {
		if strings.Contains(obf, " :") || strings.Contains(obf, ": ") {
			techniques["space_before_colon"] = true
		}
		if strings.Contains(obf, "\t") {
			techniques["tab"] = true
		}
		if strings.Contains(obf, "CHUNKED") || strings.Contains(obf, "ChUnKeD") {
			techniques["uppercase"] = true
		}
		if strings.Contains(obf, "xchunked") {
			techniques["xchunked"] = true
		}
		if strings.Contains(obf, "Transfer-Encoding: chunked\r\n") {
			techniques["double_header"] = true
		}
		if strings.HasSuffix(obf, " ") || strings.HasSuffix(obf, "\t") {
			techniques["trailing_whitespace"] = true
		}
	}

	// Verify we have diverse techniques
	for technique, found := range techniques {
		if !found {
			t.Logf("Note: Obfuscation technique %q not found in variants", technique)
		}
	}
}

func TestPayload_ExpectedBehavior(t *testing.T) {
	all := GetAllPayloads()

	for _, p := range all {
		if p.ExpectedBehavior == "" {
			t.Errorf("Payload %q has empty ExpectedBehavior", p.Name)
		}
	}
}
