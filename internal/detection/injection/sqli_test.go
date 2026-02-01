package injection

import (
	"testing"
)

func TestSQLiDetector_Name(t *testing.T) {
	detector := NewSQLiDetector()
	if detector.Name() != "sqli" {
		t.Errorf("Name() = %q, want %q", detector.Name(), "sqli")
	}
}

func TestSQLiDetector_Description(t *testing.T) {
	detector := NewSQLiDetector()
	desc := detector.Description()
	if desc == "" {
		t.Error("Description() should not be empty")
	}
}

func TestSQLiDetector_AnalyzeResponse_ErrorBased(t *testing.T) {
	detector := NewSQLiDetector()

	tests := []struct {
		name     string
		response string
		detected bool
	}{
		{
			name:     "MySQL syntax error",
			response: "You have an error in your SQL syntax; check the manual",
			detected: true,
		},
		{
			name:     "PostgreSQL error",
			response: "ERROR: syntax error at or near",
			detected: true,
		},
		{
			name:     "MSSQL error",
			response: "Unclosed quotation mark after the character string",
			detected: true,
		},
		{
			name:     "Oracle error",
			response: "ORA-01756: quoted string not properly terminated",
			detected: true,
		},
		{
			name:     "SQLite error",
			response: "SQLITE_ERROR: near \"'\": syntax error",
			detected: true,
		},
		{
			name:     "generic SQL error",
			response: "SQL syntax error in query",
			detected: true,
		},
		{
			name:     "normal response",
			response: "Welcome to our website! Here is your content.",
			detected: false,
		},
		{
			name:     "empty response",
			response: "",
			detected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.AnalyzeResponse(tt.response)
			if result.IsVulnerable != tt.detected {
				t.Errorf("AnalyzeResponse() detected = %v, want %v", result.IsVulnerable, tt.detected)
			}
			if tt.detected && result.DetectionType == "" {
				t.Error("DetectionType should not be empty when vulnerable")
			}
		})
	}
}

func TestSQLiDetector_GetPayloads(t *testing.T) {
	detector := NewSQLiDetector()
	payloads := detector.GetPayloads()

	if len(payloads) == 0 {
		t.Error("GetPayloads() should return at least one payload")
	}

	// Check that basic SQLi payloads are included
	basicPayloads := []string{"'", "\"", "' OR '1'='1", "1 OR 1=1"}
	for _, bp := range basicPayloads {
		found := false
		for _, p := range payloads {
			if p == bp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected payload %q not found in GetPayloads()", bp)
		}
	}
}

func TestSQLiDetector_GetContextPayloads(t *testing.T) {
	detector := NewSQLiDetector()

	tests := []struct {
		name        string
		context     PayloadContext
		minPayloads int
	}{
		{
			name:        "string context",
			context:     ContextString,
			minPayloads: 3,
		},
		{
			name:        "numeric context",
			context:     ContextNumeric,
			minPayloads: 2,
		},
		{
			name:        "unknown context",
			context:     ContextUnknown,
			minPayloads: 5, // Should return more payloads for unknown context
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloads := detector.GetContextPayloads(tt.context)
			if len(payloads) < tt.minPayloads {
				t.Errorf("GetContextPayloads(%v) returned %d payloads, want at least %d",
					tt.context, len(payloads), tt.minPayloads)
			}
		})
	}
}

func TestSQLiDetector_DetectDBType(t *testing.T) {
	detector := NewSQLiDetector()

	tests := []struct {
		name     string
		response string
		dbType   DatabaseType
	}{
		{
			name:     "MySQL error",
			response: "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
			dbType:   DBMySQL,
		},
		{
			name:     "PostgreSQL error",
			response: "ERROR: syntax error at or near \"'\"",
			dbType:   DBPostgreSQL,
		},
		{
			name:     "MSSQL error",
			response: "Microsoft SQL Server error",
			dbType:   DBMSSQL,
		},
		{
			name:     "Oracle error",
			response: "ORA-01756: quoted string not properly terminated",
			dbType:   DBOracle,
		},
		{
			name:     "SQLite error",
			response: "SQLITE_ERROR",
			dbType:   DBSQLite,
		},
		{
			name:     "unknown database",
			response: "An error occurred while processing your request",
			dbType:   DBUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbType := detector.DetectDBType(tt.response)
			if dbType != tt.dbType {
				t.Errorf("DetectDBType() = %v, want %v", dbType, tt.dbType)
			}
		})
	}
}

func TestAnalysisResult(t *testing.T) {
	result := &AnalysisResult{
		IsVulnerable:  true,
		DetectionType: "error-based",
		Confidence:    0.9,
		Evidence:      "SQL syntax error",
		DatabaseType:  DBMySQL,
	}

	if !result.IsVulnerable {
		t.Error("IsVulnerable should be true")
	}
	if result.DetectionType != "error-based" {
		t.Errorf("DetectionType = %q, want %q", result.DetectionType, "error-based")
	}
	if result.Confidence != 0.9 {
		t.Errorf("Confidence = %f, want %f", result.Confidence, 0.9)
	}
}

func TestPayloadContext_String(t *testing.T) {
	tests := []struct {
		context PayloadContext
		want    string
	}{
		{ContextString, "string"},
		{ContextNumeric, "numeric"},
		{ContextUnknown, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if tt.context.String() != tt.want {
				t.Errorf("String() = %q, want %q", tt.context.String(), tt.want)
			}
		})
	}
}

func TestDatabaseType_String(t *testing.T) {
	tests := []struct {
		dbType DatabaseType
		want   string
	}{
		{DBMySQL, "mysql"},
		{DBPostgreSQL, "postgresql"},
		{DBMSSQL, "mssql"},
		{DBOracle, "oracle"},
		{DBSQLite, "sqlite"},
		{DBUnknown, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if tt.dbType.String() != tt.want {
				t.Errorf("String() = %q, want %q", tt.dbType.String(), tt.want)
			}
		})
	}
}
