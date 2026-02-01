package jwt

import "time"

// GetNoneAlgVariants returns all variants of the "none" algorithm to test.
func (d *Detector) GetNoneAlgVariants() []string {
	return d.noneVariants
}

// GetWeakSecrets returns the list of weak secrets used for testing.
func (d *Detector) GetWeakSecrets() []string {
	return d.weakSecrets
}

// WithWeakSecrets adds additional weak secrets to test.
func (d *Detector) WithWeakSecrets(secrets []string) *Detector {
	d.weakSecrets = append(d.weakSecrets, secrets...)
	return d
}

// WithMaxExpiration sets the maximum recommended token expiration duration.
func (d *Detector) WithMaxExpiration(duration time.Duration) *Detector {
	d.maxExpDuration = duration
	return d
}

// defaultWeakSecrets returns a list of common weak JWT secrets.
func defaultWeakSecrets() []string {
	return []string{
		// Common defaults
		"secret",
		"password",
		"123456",
		"12345678",
		"1234567890",
		"key",
		"secret_key",
		"jwt_secret",
		"jwt-secret",
		"jwtsecret",
		"mysecret",
		"my-secret",
		"supersecret",
		"secretkey",
		"private",
		"privatekey",
		"private_key",
		"public",
		"publickey",
		"public_key",

		// Framework defaults
		"your-256-bit-secret",
		"your-secret-key",
		"change-me",
		"changeme",
		"default",
		"test",
		"testing",
		"dev",
		"development",
		"prod",
		"production",

		// Application specific
		"api_secret",
		"api-secret",
		"apisecret",
		"app_secret",
		"app-secret",
		"appsecret",
		"auth_secret",
		"auth-secret",
		"authsecret",
		"token_secret",
		"token-secret",
		"tokensecret",

		// Company/product names (common patterns)
		"admin",
		"administrator",
		"root",
		"master",
		"server",
		"client",

		// Keyboard patterns
		"qwerty",
		"qwertyuiop",
		"asdfghjkl",
		"zxcvbnm",

		// Common phrases
		"letmein",
		"welcome",
		"hello",
		"goodbye",

		// Empty/null values
		"",
		"null",
		"none",
		"undefined",
	}
}

// defaultNoneVariants returns variants of the "none" algorithm.
func defaultNoneVariants() []string {
	return []string{
		"none",
		"None",
		"NONE",
		"nOnE",
		"noNe",
		"NoNe",
		"nONE",
		"NonE",
	}
}
