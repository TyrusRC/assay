// Package templates provides nuclei-compatible template parsing and execution.
// Templates define vulnerability detection rules using a declarative YAML format
// compatible with ProjectDiscovery's nuclei templates.
package templates

import (
	"fmt"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
)

// Template represents a nuclei-compatible security template.
type Template struct {
	ID   string `yaml:"id"`
	Info Info   `yaml:"info"`

	// Protocol handlers
	HTTP       []HTTPRequest    `yaml:"http,omitempty"`
	Network    []NetworkProbe   `yaml:"network,omitempty"`
	TCP        []NetworkProbe   `yaml:"tcp,omitempty"`
	DNS        []DNSQuery       `yaml:"dns,omitempty"`
	File       []FileMatch      `yaml:"file,omitempty"`
	Headless   []HeadlessStep   `yaml:"headless,omitempty"`
	SSL        []SSLProbe       `yaml:"ssl,omitempty"`
	Websocket  []WebsocketProbe `yaml:"websocket,omitempty"`
	Whois      []WhoisQuery     `yaml:"whois,omitempty"`
	Code       []CodeExec       `yaml:"code,omitempty"`
	Javascript []JavascriptExec `yaml:"javascript,omitempty"`

	// Flow control
	Flow string `yaml:"flow,omitempty"`

	// Variables for dynamic content
	Variables map[string]interface{} `yaml:"variables,omitempty"`

	// Workflow composition
	Workflows []WorkflowStep `yaml:"workflows,omitempty"`

	// Self-contained template
	SelfContained bool `yaml:"self-contained,omitempty"`

	// Signature verification
	Signature string `yaml:"signature,omitempty"`

	// Source file path
	Path string `yaml:"-"`
}

// Info contains template metadata.
type Info struct {
	Name           string                 `yaml:"name"`
	Author         interface{}            `yaml:"author"` // Can be string or []string
	Severity       core.Severity          `yaml:"severity"`
	Description    string                 `yaml:"description,omitempty"`
	Impact         string                 `yaml:"impact,omitempty"`
	Reference      interface{}            `yaml:"reference,omitempty"` // Can be string or []string
	Tags           string                 `yaml:"tags,omitempty"`
	Classification Classification         `yaml:"classification,omitempty"`
	Metadata       map[string]interface{} `yaml:"metadata,omitempty"`
	Remediation    string                 `yaml:"remediation,omitempty"`
}

// GetReferences returns references as a string slice.
func (i *Info) GetReferences() []string {
	switch v := i.Reference.(type) {
	case string:
		return []string{v}
	case []interface{}:
		refs := make([]string, 0, len(v))
		for _, r := range v {
			if s, ok := r.(string); ok {
				refs = append(refs, s)
			}
		}
		return refs
	case []string:
		return v
	default:
		return nil
	}
}

// SeverityUnknown is an alias for an unrecognized severity value.
// Templates using this value will typically be treated as info-level.
const SeverityUnknown core.Severity = "unknown"

// Classification contains vulnerability classification info.
type Classification struct {
	CVSSMetrics string   `yaml:"cvss-metrics,omitempty"`
	CVSSScore   float64  `yaml:"cvss-score,omitempty"`
	CVEID       string   `yaml:"cve-id,omitempty"`
	CWEID       string   `yaml:"cwe-id,omitempty"`
	CPE         string   `yaml:"cpe,omitempty"`
	EPSS        float64  `yaml:"epss-score,omitempty"`
	EPSSPerc    float64  `yaml:"epss-percentile,omitempty"`
	OWASP       []string `yaml:"owasp,omitempty"`
}

// HTTPRequest defines an HTTP-based detection request.
type HTTPRequest struct {
	// Basic request configuration
	Method               string            `yaml:"method,omitempty"`
	Path                 []string          `yaml:"path,omitempty"`
	Raw                  []string          `yaml:"raw,omitempty"`
	Body                 string            `yaml:"body,omitempty"`
	Headers              map[string]string `yaml:"headers,omitempty"`
	Redirects            bool              `yaml:"redirects,omitempty"`
	HostRedirects        bool              `yaml:"host-redirects,omitempty"`
	MaxRedirects         int               `yaml:"max-redirects,omitempty"`
	CookieReuse          bool              `yaml:"cookie-reuse,omitempty"`
	ReqCondition         bool              `yaml:"req-condition,omitempty"`
	StopAtFirstMatch     bool              `yaml:"stop-at-first-match,omitempty"`
	SkipVariablesCheck   bool              `yaml:"skip-variables-check,omitempty"`
	UnsafeRaw            bool              `yaml:"unsafe,omitempty"`
	RaceCount            int               `yaml:"race_count,omitempty"`
	Race                 bool              `yaml:"race,omitempty"`
	DisablePathAutomerge bool              `yaml:"disable-path-automerge,omitempty"`

	// Request identification
	ID string `yaml:"id,omitempty"`

	// Payloads for fuzzing
	Payloads map[string]interface{} `yaml:"payloads,omitempty"`

	// Attack mode for payloads
	AttackType string `yaml:"attack,omitempty"` // batteringram, pitchfork, clusterbomb

	// Thread and concurrency
	Threads     int `yaml:"threads,omitempty"`
	Concurrency int `yaml:"concurrency,omitempty"`

	// Fuzzing configuration
	Fuzzing []FuzzingRule `yaml:"fuzzing,omitempty"`

	// Pre-condition for filtering requests
	PreCondition []Matcher `yaml:"pre-condition,omitempty"`

	// Matchers for response validation
	Matchers          []Matcher `yaml:"matchers,omitempty"`
	MatchersCondition string    `yaml:"matchers-condition,omitempty"` // and, or

	// Extractors for data extraction
	Extractors []Extractor `yaml:"extractors,omitempty"`

	// Pipeline mode
	Pipeline            bool `yaml:"pipeline,omitempty"`
	PipelineConcurrency int  `yaml:"pipeline-concurrent-connections,omitempty"`
	PipelineSize        int  `yaml:"pipeline-requests-per-connection,omitempty"`

	// Read all
	ReadAll bool `yaml:"read-all,omitempty"`

	// Digest for template verification
	Digest string `yaml:"digest,omitempty"`

	// Iterate all
	IterateAll bool `yaml:"iterate-all,omitempty"`
}

// FuzzingRule defines how to fuzz request parameters.
type FuzzingRule struct {
	Part    string   `yaml:"part"` // query, body, header, path, cookie
	Type    string   `yaml:"type"` // replace, prefix, postfix
	Mode    string   `yaml:"mode"` // single, multiple
	Keys    []string `yaml:"keys,omitempty"`
	KeysAll bool     `yaml:"keys-all,omitempty"`
	Values  []string `yaml:"values,omitempty"`
	Fuzz    []string `yaml:"fuzz,omitempty"`
	Filters []string `yaml:"filters,omitempty"`
}

// Matcher defines response matching rules.
type Matcher struct {
	Type            string   `yaml:"type"`           // word, regex, status, size, binary, dsl, xpath, time
	Part            string   `yaml:"part,omitempty"` // body, header, all, interactsh_protocol
	Words           []string `yaml:"words,omitempty"`
	Regex           []string `yaml:"regex,omitempty"`
	Status          []int    `yaml:"status,omitempty"`
	Size            []int    `yaml:"size,omitempty"`
	Binary          []string `yaml:"binary,omitempty"`
	DSL             []string `yaml:"dsl,omitempty"`
	XPath           []string `yaml:"xpath,omitempty"`
	Condition       string   `yaml:"condition,omitempty"` // and, or
	Negative        bool     `yaml:"negative,omitempty"`
	Internal        bool     `yaml:"internal,omitempty"`
	Name            string   `yaml:"name,omitempty"`
	Encoding        string   `yaml:"encoding,omitempty"`
	CaseInsensitive bool     `yaml:"case-insensitive,omitempty"`
	MatchAll        bool     `yaml:"match-all,omitempty"`
}

// Extractor defines data extraction rules.
type Extractor struct {
	Type            string   `yaml:"type"`           // regex, kval, json, xpath, dsl
	Part            string   `yaml:"part,omitempty"` // body, header, all
	Name            string   `yaml:"name,omitempty"`
	Regex           []string `yaml:"regex,omitempty"`
	Group           int      `yaml:"group,omitempty"`
	KVal            []string `yaml:"kval,omitempty"`
	JSON            []string `yaml:"json,omitempty"`
	XPath           []string `yaml:"xpath,omitempty"`
	DSL             []string `yaml:"dsl,omitempty"`
	Attribute       string   `yaml:"attribute,omitempty"`
	Internal        bool     `yaml:"internal,omitempty"`
	CaseInsensitive bool     `yaml:"case-insensitive,omitempty"`
}

// NetworkProbe defines network-level probing.
type NetworkProbe struct {
	Host       []string    `yaml:"host,omitempty"`
	Address    []string    `yaml:"address,omitempty"`
	Port       string      `yaml:"port,omitempty"`
	Inputs     []NetInput  `yaml:"inputs,omitempty"`
	ReadSize   int         `yaml:"read-size,omitempty"`
	ReadAll    bool        `yaml:"read-all,omitempty"`
	Matchers   []Matcher   `yaml:"matchers,omitempty"`
	Extractors []Extractor `yaml:"extractors,omitempty"`
}

// NetInput defines network input data.
type NetInput struct {
	Data string `yaml:"data,omitempty"`
	Type string `yaml:"type,omitempty"` // hex, text
	Read int    `yaml:"read,omitempty"`
	Name string `yaml:"name,omitempty"`
}

// DNSQuery defines DNS-based detection.
type DNSQuery struct {
	Name       string      `yaml:"name"`
	Type       string      `yaml:"type"`
	Class      string      `yaml:"class,omitempty"`
	Recursion  bool        `yaml:"recursion,omitempty"`
	Retries    int         `yaml:"retries,omitempty"`
	Matchers   []Matcher   `yaml:"matchers,omitempty"`
	Extractors []Extractor `yaml:"extractors,omitempty"`
}

// FileMatch defines file-based detection.
type FileMatch struct {
	Extensions []string    `yaml:"extensions,omitempty"`
	DenyList   []string    `yaml:"denylist,omitempty"`
	MaxSize    string      `yaml:"max-size,omitempty"`
	Matchers   []Matcher   `yaml:"matchers,omitempty"`
	Extractors []Extractor `yaml:"extractors,omitempty"`
}

// HeadlessStep defines headless browser actions.
type HeadlessStep struct {
	Actions     []HeadlessAction `yaml:"actions,omitempty"`
	Steps       []HeadlessAction `yaml:"steps,omitempty"`
	Matchers    []Matcher        `yaml:"matchers,omitempty"`
	Extractors  []Extractor      `yaml:"extractors,omitempty"`
	UserAgent   string           `yaml:"user-agent,omitempty"`
	CookieReuse bool             `yaml:"cookie-reuse,omitempty"`
}

// HeadlessAction defines a single headless browser action.
type HeadlessAction struct {
	Action  string            `yaml:"action"`
	Args    map[string]string `yaml:"args,omitempty"`
	Name    string            `yaml:"name,omitempty"`
	Timeout int               `yaml:"timeout,omitempty"`
}

// SSLProbe defines SSL/TLS probing.
type SSLProbe struct {
	Address    []string    `yaml:"address,omitempty"`
	MinVersion string      `yaml:"min_version,omitempty"`
	MaxVersion string      `yaml:"max_version,omitempty"`
	Matchers   []Matcher   `yaml:"matchers,omitempty"`
	Extractors []Extractor `yaml:"extractors,omitempty"`
}

// WebsocketProbe defines WebSocket probing.
type WebsocketProbe struct {
	Address    string      `yaml:"address,omitempty"`
	Inputs     []NetInput  `yaml:"inputs,omitempty"`
	Matchers   []Matcher   `yaml:"matchers,omitempty"`
	Extractors []Extractor `yaml:"extractors,omitempty"`
}

// WhoisQuery defines WHOIS lookup.
type WhoisQuery struct {
	Query      string      `yaml:"query,omitempty"`
	Server     string      `yaml:"server,omitempty"`
	Matchers   []Matcher   `yaml:"matchers,omitempty"`
	Extractors []Extractor `yaml:"extractors,omitempty"`
}

// CodeExec defines code execution templates (not supported for execution).
type CodeExec struct {
	Engine     string      `yaml:"engine,omitempty"`
	Source     string      `yaml:"source,omitempty"`
	Args       []string    `yaml:"args,omitempty"`
	Matchers   []Matcher   `yaml:"matchers,omitempty"`
	Extractors []Extractor `yaml:"extractors,omitempty"`
}

// JavascriptExec defines JavaScript execution templates (not supported for execution).
type JavascriptExec struct {
	Code       string      `yaml:"code,omitempty"`
	Args       interface{} `yaml:"args,omitempty"`
	Matchers   []Matcher   `yaml:"matchers,omitempty"`
	Extractors []Extractor `yaml:"extractors,omitempty"`
}

// WorkflowStep defines workflow composition.
type WorkflowStep struct {
	Template     string         `yaml:"template,omitempty"`
	Tags         string         `yaml:"tags,omitempty"`
	Subtemplates []WorkflowStep `yaml:"subtemplates,omitempty"`
	Matchers     []Matcher      `yaml:"matchers,omitempty"`
}

// ExecutionResult contains template execution results.
type ExecutionResult struct {
	TemplateID    string
	TemplateName  string
	Matched       bool
	Severity      core.Severity
	URL           string
	MatchedAt     string
	ExtractedData map[string][]string
	Timestamp     time.Time
	Request       string
	Response      string
	IP            string
	Error         error
}

// String returns a string representation of the result.
func (r *ExecutionResult) String() string {
	if r.Error != nil {
		return fmt.Sprintf("[%s] %s - Error: %v", r.TemplateID, r.URL, r.Error)
	}
	if r.Matched {
		return fmt.Sprintf("[%s] [%s] %s", r.TemplateID, r.Severity, r.URL)
	}
	return fmt.Sprintf("[%s] %s - No match", r.TemplateID, r.URL)
}
