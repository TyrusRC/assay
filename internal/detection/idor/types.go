package idor

// IDType represents the type of identifier being tested.
type IDType string

const (
	// IDTypeNumeric represents numeric identifiers (e.g., 123, 456).
	IDTypeNumeric IDType = "numeric"
	// IDTypeUUID represents UUID identifiers.
	IDTypeUUID IDType = "uuid"
	// IDTypeBase64 represents base64-encoded identifiers.
	IDTypeBase64 IDType = "base64"
	// IDTypeHex represents hexadecimal identifiers.
	IDTypeHex IDType = "hex"
	// IDTypeAlphanumeric represents alphanumeric identifiers.
	IDTypeAlphanumeric IDType = "alphanumeric"
)

// Location represents where an ID parameter is found.
type Location string

const (
	// LocationQuery indicates the ID is in query parameters.
	LocationQuery Location = "query"
	// LocationPath indicates the ID is in the URL path.
	LocationPath Location = "path"
	// LocationBody indicates the ID is in the request body.
	LocationBody Location = "body"
	// LocationHeader indicates the ID is in a header.
	LocationHeader Location = "header"
)

// IDParameter represents an identified parameter that may be an object reference.
type IDParameter struct {
	Name     string
	Value    string
	Type     IDType
	Location Location
}

// IDOREvidence contains evidence collected during IDOR detection.
type IDOREvidence struct {
	OriginalID                string
	TestedID                  string
	OriginalStatusCode        int
	TestedStatusCode          int
	OriginalContentLength     int
	TestedContentLength       int
	StatusCodeIndicatesAccess bool
	ContentDifferent          bool
	SensitiveDataExposed      bool
	ResponseSnippet           string
}

// ResponseComparison contains the results of comparing two responses.
type ResponseComparison struct {
	HasSignificantDifference bool
	StatusCodeDiff           bool
	ContentLengthDiff        int
	ContentDiff              float64
	SensitiveDataFound       bool
}

// StatusCodeAnalysis contains the analysis of status code changes.
type StatusCodeAnalysis struct {
	PotentialIDOR bool
	Reason        string
}
