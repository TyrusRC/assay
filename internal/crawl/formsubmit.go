package crawl

import (
	"net/url"
	"regexp"
	"strings"
)

const maxFormSubmissions = 20

var dangerousActionRe = regexp.MustCompile(`(?i)(logout|log[_-]?out|sign[_-]?out|log[_-]?off|delete[_-]?account|account/delete|/delete|/remove)`)

// FormSubmitter fills and submits discovered forms during a crawl.
type FormSubmitter struct {
	Fetcher     Fetcher
	PostFetcher PostFetcher
	submitted   map[string]bool
	count       int
}

// PostFetcher submits a form via POST (or GET with encoded query).
type PostFetcher interface {
	Post(ctx interface{}, url, contentType, body string) (string, error)
}

// NewFormSubmitter creates a form submitter wrapping the given fetchers.
func NewFormSubmitter(fetcher Fetcher, postFetcher PostFetcher) *FormSubmitter {
	return &FormSubmitter{
		Fetcher:     fetcher,
		PostFetcher: postFetcher,
		submitted:   make(map[string]bool),
	}
}

// CanSubmit returns true if the form is safe and hasn't been submitted yet.
func (fs *FormSubmitter) CanSubmit(f Form, baseURL string) bool {
	if fs.count >= maxFormSubmissions {
		return false
	}
	actionURL := resolveURL(baseURL, f.Action)
	if actionURL == "" {
		return false
	}
	if dangerousActionRe.MatchString(actionURL) {
		return false
	}
	sig := formSubmitSig(f)
	return !fs.submitted[sig]
}

// FillForm generates plausible test data for the form's fields.
func FillForm(f Form) url.Values {
	vals := url.Values{}
	for _, fd := range f.FieldDetails {
		name := fd.Name
		if name == "" {
			continue
		}
		// Preserve hidden, csrf, token, and nonce fields
		if fd.Type == "hidden" || isTokenField(name) {
			if fd.Value != "" {
				vals.Set(name, fd.Value)
			}
			continue
		}
		vals.Set(name, smartValue(name, fd.Type))
	}
	// Fallback: if no FieldDetails, use field names with generic values
	if len(f.FieldDetails) == 0 {
		for _, name := range f.Fields {
			vals.Set(name, smartValue(name, ""))
		}
	}
	return vals
}

func smartValue(name, fieldType string) string {
	lower := strings.ToLower(name)
	switch {
	case fieldType == "email" || containsAny(lower, "email", "mail"):
		return "test@example.com"
	case fieldType == "password" || containsAny(lower, "password", "passwd", "pwd"):
		return "TestPass123!"
	case containsAny(lower, "username", "user", "login"):
		return "testuser"
	case containsAny(lower, "name", "fullname", "full_name"):
		return "Test User"
	case fieldType == "tel" || containsAny(lower, "phone", "tel", "mobile"):
		return "5551234567"
	case fieldType == "url" || containsAny(lower, "url", "website", "homepage"):
		return "https://example.com"
	case containsAny(lower, "search", "query", "q", "keyword"):
		return "test"
	case fieldType == "number" || containsAny(lower, "number", "amount", "quantity", "count", "age"):
		return "1"
	case fieldType == "date" || containsAny(lower, "date", "birthday", "dob"):
		return "2024-01-01"
	case fieldType == "checkbox":
		return "on"
	case containsAny(lower, "city"):
		return "TestCity"
	case containsAny(lower, "zip", "postal"):
		return "12345"
	case containsAny(lower, "country"):
		return "US"
	case containsAny(lower, "address", "street"):
		return "123 Test St"
	case containsAny(lower, "company", "org"):
		return "TestCorp"
	case containsAny(lower, "message", "comment", "description", "text", "body", "content"):
		return "test message"
	default:
		return "test"
	}
}

func isTokenField(name string) bool {
	lower := strings.ToLower(name)
	return containsAny(lower, "csrf", "token", "nonce", "_token", "xsrf", "authenticity")
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func formSubmitSig(f Form) string {
	fields := append([]string(nil), f.Fields...)
	return f.Method + "|" + f.Action + "|" + strings.Join(fields, ",")
}

// SubmitResults collects URLs discovered from form responses.
type SubmitResults struct {
	DiscoveredURLs []string
}

// MarkSubmitted records a form as submitted and increments the count.
func (fs *FormSubmitter) MarkSubmitted(f Form) {
	fs.submitted[formSubmitSig(f)] = true
	fs.count++
}

// Count returns the number of forms submitted so far.
func (fs *FormSubmitter) Count() int {
	return fs.count
}
