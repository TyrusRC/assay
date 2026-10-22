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

		// Framework defaults (generic)
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

		// Flask defaults (Werkzeug/itsdangerous)
		"super secret key",
		"development key",
		"flask-secret-key",
		"this-is-a-secret",
		"hard to guess string",
		"you-will-never-guess",
		"dev-secret-key",
		"my_precious",
		"something really really secret",

		// Django defaults (settings.py SECRET_KEY)
		"django-insecure-)",
		"my-secret-key",
		"unsafe-secret-key",
		"change_me_in_production",
		"secretkey12345",
		"pk_test_secret",
		"pl3aseChang3m3",
		"n0ts3cr3t",
		"=d=!($kip%jh9f*5@g^w6+$f8r^@ix$=6fj!4r_ut^s7=7p$+do",

		// Express.js (cookie-session / express-session)
		"keyboard cat",
		"my secret",
		"session_secret",
		"ssshhhhh",
		"express-session-secret",
		"cookie-session-secret",

		// Rails (secret_key_base)
		"abcdef0123456789",
		"secret_key_base",
		"3eb6db5a9026c547c72708438d496d942e976b252138db7e4e0ee5edd7539457d3ed0fa02ee5e7179420ce5290462018591571b5c11b3c2ea1c81571bb0b0c8a1",

		// Laravel (APP_KEY)
		"base64:Otpw0X/a0FUfUhFAXLw7sJ0M3VmjGOkzfgJsfHajYpY=",
		"SomeRandomString",
		"base64:yourbase64encodedkeyhere",

		// Tornado (cookie_secret)
		"__TODO:_GENERATE_YOUR_OWN_RANDOM_VALUE_HERE__",
		"61oETzKXQAGaYdkL5gEmGeJJFuYh7EQnp2XdTP1o/Vo=",

		// Yii2 (cookieValidationKey)
		"insert-your-cookie-validation-key",

		// Play Framework (play.http.secret.key)
		"changethissecretkey",
		"QCY?tAnfk?aZ?iwrNwnxIlR6CTf:G3gf:90Latabg@5241ABR5W:1uDFN];Ik@n",

		// Spring Boot (application.properties)
		"mySecretKey",
		"spring-boot-secret",

		// Next.js (NEXTAUTH_SECRET)
		"my-nextauth-secret",

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
