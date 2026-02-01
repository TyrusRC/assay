package techstack

import (
	"net/http"
	"strings"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

// Technology represents a detected technology.
type Technology struct {
	Name       string   `json:"name"`
	Version    string   `json:"version,omitempty"`
	Categories []string `json:"categories,omitempty"`
	Website    string   `json:"website,omitempty"`
	CPE        string   `json:"cpe,omitempty"`
}

// String returns a string representation of the technology.
func (t Technology) String() string {
	if t.Version != "" {
		return t.Name + " " + t.Version
	}
	return t.Name
}

// DetectionResult contains detected technologies.
type DetectionResult struct {
	URL          string       `json:"url"`
	Technologies []Technology `json:"technologies"`
}

// HasTechnology checks if a technology was detected.
func (r *DetectionResult) HasTechnology(name string) bool {
	for _, tech := range r.Technologies {
		if strings.EqualFold(tech.Name, name) {
			return true
		}
	}
	return false
}

// GetByCategory returns technologies in a specific category.
func (r *DetectionResult) GetByCategory(category string) []Technology {
	result := make([]Technology, 0)
	for _, tech := range r.Technologies {
		for _, cat := range tech.Categories {
			if strings.EqualFold(cat, category) {
				result = append(result, tech)
				break
			}
		}
	}
	return result
}

// SecurityImplication describes security implications of a technology.
type SecurityImplication struct {
	Technology            string   `json:"technology"`
	CommonVulnerabilities []string `json:"common_vulnerabilities"`
	TestCases             []string `json:"test_cases"`
	WSTG                  []string `json:"wstg"`
}

// Detector detects web technologies.
type Detector struct {
	wappalyzer *wappalyzer.Wappalyze
}

// NewDetector creates a new technology detector.
func NewDetector() (*Detector, error) {
	wappalyzerClient, err := wappalyzer.New()
	if err != nil {
		return nil, err
	}

	return &Detector{
		wappalyzer: wappalyzerClient,
	}, nil
}

// Analyze detects technologies from HTTP response.
func (d *Detector) Analyze(url string, headers map[string]string, body string) *DetectionResult {
	result := &DetectionResult{
		URL:          url,
		Technologies: make([]Technology, 0),
	}

	// Convert headers to map[string][]string for wappalyzer
	wapHeaders := make(map[string][]string)
	for k, v := range headers {
		wapHeaders[k] = []string{v}
	}

	// Fingerprint with wappalyzer - use FingerprintWithInfo for detailed info
	fingerprints := d.wappalyzer.FingerprintWithInfo(wapHeaders, []byte(body))

	// Convert to our Technology struct
	for name, info := range fingerprints {
		tech := Technology{
			Name:       name,
			Categories: info.Categories,
			Website:    info.Website,
			CPE:        info.CPE,
		}
		result.Technologies = append(result.Technologies, tech)
	}

	return result
}

// AnalyzeResponse detects technologies from an HTTP response.
func (d *Detector) AnalyzeResponse(resp *http.Response, body []byte) *DetectionResult {
	result := &DetectionResult{
		URL:          resp.Request.URL.String(),
		Technologies: make([]Technology, 0),
	}

	// Convert http.Header to map[string][]string
	wapHeaders := make(map[string][]string)
	for k, v := range resp.Header {
		wapHeaders[k] = v
	}

	fingerprints := d.wappalyzer.FingerprintWithInfo(wapHeaders, body)

	for name, info := range fingerprints {
		tech := Technology{
			Name:       name,
			Categories: info.Categories,
			Website:    info.Website,
			CPE:        info.CPE,
		}
		result.Technologies = append(result.Technologies, tech)
	}

	return result
}

// GetSecurityImplications returns security implications for a technology.
func (d *Detector) GetSecurityImplications(techName string) *SecurityImplication {
	implications := securityImplications[strings.ToLower(techName)]
	if implications != nil {
		return implications
	}
	return &SecurityImplication{
		Technology:            techName,
		CommonVulnerabilities: []string{},
		TestCases:             []string{},
		WSTG:                  []string{},
	}
}

// securityImplications maps technologies to their security implications.
var securityImplications = map[string]*SecurityImplication{
	"php": {
		Technology: "PHP",
		CommonVulnerabilities: []string{
			"Remote Code Execution via deserialization",
			"Local/Remote File Inclusion (LFI/RFI)",
			"SQL Injection",
			"Type Juggling vulnerabilities",
			"Object Injection",
		},
		TestCases: []string{
			"Test for PHP object injection",
			"Test for type juggling in comparisons",
			"Test for LFI via php://filter",
			"Test for RFI if allow_url_include is enabled",
		},
		WSTG: []string{"WSTG-INPV-05", "WSTG-INPV-11", "WSTG-INPV-12"},
	},
	"wordpress": {
		Technology: "WordPress",
		CommonVulnerabilities: []string{
			"Plugin vulnerabilities",
			"Theme vulnerabilities",
			"XML-RPC attacks",
			"User enumeration via REST API",
			"Privilege escalation",
		},
		TestCases: []string{
			"Enumerate users via /wp-json/wp/v2/users",
			"Test XML-RPC for brute force",
			"Check for vulnerable plugins",
			"Test wp-config.php exposure",
		},
		WSTG: []string{"WSTG-IDNT-04", "WSTG-ATHN-03", "WSTG-CONF-05"},
	},
	"apache": {
		Technology: "Apache",
		CommonVulnerabilities: []string{
			"Path traversal",
			"Server-status/server-info exposure",
			"mod_cgi vulnerabilities",
			"Misconfigured .htaccess",
		},
		TestCases: []string{
			"Check /server-status and /server-info",
			"Test for .htaccess bypass",
			"Test for path traversal",
		},
		WSTG: []string{"WSTG-CONF-05", "WSTG-CONF-10"},
	},
	"nginx": {
		Technology: "Nginx",
		CommonVulnerabilities: []string{
			"Alias path traversal",
			"CRLF injection",
			"Off-by-slash misconfiguration",
			"Stub_status exposure",
		},
		TestCases: []string{
			"Test for alias path traversal",
			"Check /nginx_status",
			"Test for CRLF in redirects",
		},
		WSTG: []string{"WSTG-CONF-05", "WSTG-INPV-15"},
	},
	"jquery": {
		Technology: "jQuery",
		CommonVulnerabilities: []string{
			"XSS via DOM manipulation",
			"Prototype pollution (older versions)",
			"CORS bypass in AJAX requests",
		},
		TestCases: []string{
			"Check jQuery version for known CVEs",
			"Test for DOM-based XSS",
		},
		WSTG: []string{"WSTG-CLNT-01", "WSTG-CLNT-02"},
	},
	"react": {
		Technology: "React",
		CommonVulnerabilities: []string{
			"XSS via dangerouslySetInnerHTML",
			"Server-Side Rendering (SSR) issues",
			"Exposed source maps",
		},
		TestCases: []string{
			"Check for exposed source maps",
			"Test for XSS in user-controlled props",
		},
		WSTG: []string{"WSTG-CLNT-01"},
	},
	"node.js": {
		Technology: "Node.js",
		CommonVulnerabilities: []string{
			"Prototype pollution",
			"Command injection",
			"Path traversal",
			"Insecure deserialization",
			"Server-Side Request Forgery (SSRF)",
		},
		TestCases: []string{
			"Test for prototype pollution",
			"Test for SSRF in URL parameters",
			"Check for command injection",
		},
		WSTG: []string{"WSTG-INPV-05", "WSTG-INPV-12", "WSTG-INPV-19"},
	},
	"spring": {
		Technology: "Spring",
		CommonVulnerabilities: []string{
			"Spring4Shell (CVE-2022-22965)",
			"SpEL injection",
			"Actuator endpoint exposure",
			"Mass assignment",
		},
		TestCases: []string{
			"Check for exposed actuator endpoints",
			"Test for SpEL injection",
			"Test for mass assignment",
		},
		WSTG: []string{"WSTG-CONF-05", "WSTG-INPV-12"},
	},
	"laravel": {
		Technology: "Laravel",
		CommonVulnerabilities: []string{
			"Debug mode information disclosure",
			"Insecure deserialization",
			"SQL injection in Eloquent",
			"CSRF token bypass",
		},
		TestCases: []string{
			"Check for debug mode (/telescope, /_ignition)",
			"Test for deserialization in cookies",
			"Check APP_KEY exposure",
		},
		WSTG: []string{"WSTG-CONF-05", "WSTG-INPV-05"},
	},
	"django": {
		Technology: "Django",
		CommonVulnerabilities: []string{
			"Debug mode information disclosure",
			"SSTI in templates",
			"SQL injection in raw queries",
			"Admin panel brute force",
		},
		TestCases: []string{
			"Check for debug mode (DEBUG=True)",
			"Test /admin/ for default credentials",
			"Test for SSTI",
		},
		WSTG: []string{"WSTG-CONF-05", "WSTG-INPV-18"},
	},
	"iis": {
		Technology: "IIS",
		CommonVulnerabilities: []string{
			"Short filename disclosure",
			"web.config exposure",
			"Tilde enumeration",
			"ASP.NET padding oracle",
		},
		TestCases: []string{
			"Test for tilde enumeration (~1)",
			"Check for web.config exposure",
			"Test for ViewState vulnerabilities",
		},
		WSTG: []string{"WSTG-CONF-05", "WSTG-CONF-10"},
	},
}
