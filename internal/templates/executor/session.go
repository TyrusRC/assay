package executor

import (
	"net/url"
	"strings"
	"sync"
)

// Session manages cookie persistence across requests within a template execution.
type Session struct {
	cookies map[string]map[string]string // domain -> name -> value
	mu      sync.RWMutex
}

// NewSession creates a new Session instance.
func NewSession() *Session {
	return &Session{
		cookies: make(map[string]map[string]string),
	}
}

// normalizeDomain strips the scheme and lowercases the domain string.
func normalizeDomain(domain string) string {
	// Strip scheme if present
	for _, prefix := range []string{"https://", "http://"} {
		if strings.HasPrefix(domain, prefix) {
			domain = strings.TrimPrefix(domain, prefix)
			break
		}
	}
	// Strip path and port-free host; keep host:port as-is
	if idx := strings.IndexByte(domain, '/'); idx >= 0 {
		domain = domain[:idx]
	}
	return strings.ToLower(domain)
}

// SetCookie stores a cookie for the given domain.
func (s *Session) SetCookie(domain, name, value string) {
	domain = normalizeDomain(domain)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cookies[domain] == nil {
		s.cookies[domain] = make(map[string]string)
	}
	s.cookies[domain][name] = value
}

// GetCookies returns a copy of the cookies for the given domain.
func (s *Session) GetCookies(domain string) map[string]string {
	domain = normalizeDomain(domain)
	s.mu.RLock()
	defer s.mu.RUnlock()
	src := s.cookies[domain]
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

// CookieHeader returns a Cookie header value for the given domain in the form
// "name1=val1; name2=val2". Returns an empty string when no cookies are stored.
func (s *Session) CookieHeader(domain string) string {
	domain = normalizeDomain(domain)
	s.mu.RLock()
	defer s.mu.RUnlock()
	jar := s.cookies[domain]
	if len(jar) == 0 {
		return ""
	}
	var sb strings.Builder
	first := true
	for name, value := range jar {
		if !first {
			sb.WriteString("; ")
		}
		sb.WriteString(name)
		sb.WriteByte('=')
		sb.WriteString(value)
		first = false
	}
	return sb.String()
}

// ParseResponseCookies parses Set-Cookie headers from a response header map
// and stores any cookies found for the given domain.
func (s *Session) ParseResponseCookies(domain string, headers map[string]string) {
	for key, value := range headers {
		if !strings.EqualFold(key, "Set-Cookie") {
			continue
		}
		// A Set-Cookie header can contain a single cookie directive.
		// Format: name=value[; attr=val]*
		parts := strings.SplitN(value, ";", 2)
		if len(parts) == 0 {
			continue
		}
		nameVal := strings.TrimSpace(parts[0])
		eqIdx := strings.IndexByte(nameVal, '=')
		if eqIdx < 0 {
			continue
		}
		name := strings.TrimSpace(nameVal[:eqIdx])
		val := strings.TrimSpace(nameVal[eqIdx+1:])
		if name != "" {
			s.SetCookie(domain, name, val)
		}
	}
}

// ParseResponseURL extracts the domain from rawURL and then calls ParseResponseCookies.
func (s *Session) ParseResponseURL(rawURL string, headers map[string]string) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return
	}
	s.ParseResponseCookies(parsed.Host, headers)
}
